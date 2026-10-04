mod lookup;
mod store;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name};
use hickory_proto::serialize::txt::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use store::Store;

/// The EDNS UDP payload we advertise and honour (the DNS Flag Day 2020 value).
const OUR_UDP_PAYLOAD: u16 = 1232;
const PLAIN_UDP_LIMIT: u16 = 512;

#[derive(Clone, Copy, PartialEq)]
enum Transport {
    Udp,
    Tcp,
}

/// Builds a response for a raw query. Returns None for packets we can't parse (dropped).
fn answer(store: &Store, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
    let req = Message::from_vec(query).ok()?;
    if req.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;

    let mut limit = match transport {
        Transport::Tcp => u16::MAX,
        Transport::Udp => PLAIN_UDP_LIMIT,
    };
    if let Some(edns) = &req.edns {
        let mut ours = Edns::new();
        ours.set_max_payload(OUR_UDP_PAYLOAD).set_version(0);
        resp.set_edns(ours);
        if transport == Transport::Udp {
            limit = edns.max_payload().clamp(PLAIN_UDP_LIMIT, OUR_UDP_PAYLOAD);
        }
        if edns.version() > 0 {
            resp.metadata.response_code = ResponseCode::BADVERS;
            return resp.to_vec().ok();
        }
    }

    if req.metadata.op_code != OpCode::Query {
        resp.metadata.response_code = ResponseCode::NotImp;
        return resp.to_vec().ok();
    }
    let [q] = &req.queries[..] else {
        resp.metadata.response_code = ResponseCode::FormErr;
        return resp.to_vec().ok();
    };
    resp.add_query(q.clone());
    if q.query_class() != DNSClass::IN {
        resp.metadata.response_code = ResponseCode::Refused;
        return resp.to_vec().ok();
    }

    match lookup::lookup(store, q.name(), q.query_type()) {
        Ok(a) => {
            resp.metadata.response_code = a.rcode;
            resp.metadata.authoritative = a.authoritative;
            resp.answers = a.answers;
            resp.authorities = a.authority;
            resp.additionals = a.additional;
        }
        Err(e) => {
            eprintln!("lookup {} {}: {e}", q.name(), q.query_type());
            resp.metadata.response_code = ResponseCode::ServFail;
        }
    }

    let bytes = resp.to_vec().ok()?;
    if bytes.len() <= limit as usize {
        return Some(bytes);
    }
    // Too big for this UDP client: header + question only, TC set, so it retries over TCP.
    resp.answers.clear();
    resp.authorities.clear();
    resp.additionals.clear();
    resp.metadata.truncation = true;
    resp.to_vec().ok()
}

async fn serve_udp(store: Arc<Store>, sock: Arc<UdpSocket>) {
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        if let Some(resp) = answer(&store, &buf[..n], Transport::Udp) {
            let _ = sock.send_to(&resp, peer).await;
        }
    }
}

async fn serve_tcp_conn(store: Arc<Store>, mut stream: TcpStream) -> std::io::Result<()> {
    loop {
        let len = stream.read_u16().await? as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let Some(resp) = answer(&store, &buf, Transport::Tcp) else { return Ok(()) };
        stream.write_u16(resp.len() as u16).await?;
        stream.write_all(&resp).await?;
    }
}

async fn serve(store: Store, addr: &str) -> std::io::Result<()> {
    let store = Arc::new(store);
    let udp = Arc::new(UdpSocket::bind(addr).await?);
    let tcp = TcpListener::bind(addr).await?;
    println!("listening on {addr} (udp+tcp)");

    tokio::spawn(serve_udp(store.clone(), udp));
    loop {
        let (stream, _) = tcp.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            let _ = serve_tcp_conn(store, stream).await;
        });
    }
}

/// Parses an RFC 1035 zone file and atomically replaces that zone in the store.
fn load(store: &Store, file: &Path, origin: Option<Name>) -> store::Result<(Name, usize)> {
    let text = std::fs::read_to_string(file)?;
    let (origin, rrsets) = Parser::new(text, Some(file.to_path_buf()), origin).parse()?;
    let records = rrsets
        .values()
        .flat_map(|rs| rs.records_without_rrsigs().cloned())
        .collect();
    let names = store.load_zone(&origin, records)?;
    Ok((origin, names))
}

const USAGE: &str = "usage:
  dns-server load  <db-dir> <zone-file> [origin]
  dns-server serve <db-dir> [listen-addr, default 127.0.0.1:5300]";

#[tokio::main]
async fn main() -> store::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["load", db, file, ref rest @ ..] if rest.len() <= 1 => {
            let origin = rest.first().map(|o| Name::from_ascii(o)).transpose()?;
            let store = Store::open(&PathBuf::from(db))?;
            let (origin, names) = load(&store, Path::new(file), origin)?;
            println!("loaded {origin}: {names} names");
        }
        ["serve", db, ref rest @ ..] if rest.len() <= 1 => {
            let addr = rest.first().copied().unwrap_or("127.0.0.1:5300");
            serve(Store::open(&PathBuf::from(db))?, addr).await?;
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::RecordType;
    use std::str::FromStr;

    /// Formats a response the way the golden file spells it.
    fn render(m: &Message) -> String {
        let mut flags = vec![format!("{:?}", m.metadata.response_code).to_uppercase()];
        if m.metadata.authoritative {
            flags.push("aa".into());
        }
        if m.metadata.truncation {
            flags.push("tc".into());
        }
        let mut out = flags.join(" ");
        for (section, records) in [
            ("ANSWER", &m.answers),
            ("AUTHORITY", &m.authorities),
            ("ADDITIONAL", &m.additionals),
        ] {
            for r in records {
                out += &format!("\n{section} {r}");
            }
        }
        out
    }

    /// testdata/cases.txt: blocks separated by blank lines. The first line is
    /// `> qname qtype [tcp] [noedns]` (default: UDP with EDNS 1232, like dig); the rest is
    /// the expected render().
    #[test]
    fn golden() {
        let dir = std::env::temp_dir().join(format!("dns-golden-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        for zone in ["example.com.zone", "child.example.com.zone", "other.test.zone"] {
            load(&store, &Path::new("testdata").join(zone), None).unwrap();
        }

        let cases = std::fs::read_to_string("testdata/cases.txt").unwrap();
        let mut failures = vec![];
        let blocks = cases
            .split("\n\n")
            .map(|b| b.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>())
            .filter(|b| !b.is_empty());
        for block in blocks {
            let words: Vec<&str> = block[0].trim_start_matches("> ").split_whitespace().collect();
            let mut m = Message::query();
            m.add_query(Query::query(
                Name::from_str(words[0]).unwrap(),
                RecordType::from_str(words[1]).unwrap(),
            ));
            if !words.contains(&"noedns") {
                let mut e = Edns::new();
                e.set_max_payload(1232);
                m.set_edns(e);
            }
            let transport = if words.contains(&"tcp") { Transport::Tcp } else { Transport::Udp };
            let resp = answer(&store, &m.to_vec().unwrap(), transport).unwrap();
            let got = render(&Message::from_vec(&resp).unwrap());
            let want = block[1..].join("\n");
            if got != want {
                failures.push(format!("{}\n--- want\n{want}\n--- got\n{got}\n", block[0]));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    }

    #[test]
    fn drops_garbage() {
        let dir = std::env::temp_dir().join(format!("dns-garbage-{}", std::process::id()));
        let store = Store::open(&dir).unwrap();
        assert!(answer(&store, b"garbage", Transport::Udp).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

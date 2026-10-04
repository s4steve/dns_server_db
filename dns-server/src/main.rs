mod follow;
mod lookup;
mod script;
mod store;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
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

/// This node's ID, handed to scripts as `q.node` (`--node-id`).
static NODE_ID: OnceLock<String> = OnceLock::new();

/// Builds a response for a raw query from `source`. Returns None for packets we can't parse.
fn answer(store: &Store, query: &[u8], transport: Transport, source: IpAddr) -> Option<Vec<u8>> {
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

    // EDNS Client Subnet (RFC 7871): scripts see the resolver's client subnet when it sends one.
    let ecs = req
        .edns
        .as_ref()
        .and_then(|e| match e.options().get(EdnsCode::Subnet) {
            Some(EdnsOption::Subnet(s)) => Some(s.clone()),
            _ => None,
        });
    let client = lookup::Client {
        addr: ecs.as_ref().map_or(source, |s| s.addr()),
        prefix: ecs
            .as_ref()
            .map_or(if source.is_ipv4() { 32 } else { 128 }, |s| {
                s.source_prefix()
            }),
        source,
        node: NODE_ID.get().map_or("", String::as_str),
    };

    match lookup::lookup(store, q.name(), q.query_type(), &client) {
        Ok(a) => {
            if let (Some(mut subnet), Some(edns)) = (ecs, resp.edns.as_mut()) {
                // Scope = how much of the subnet the answer depends on: all of it if a script
                // tailored it, none if it's the same for everyone (so resolvers cache it once).
                subnet.set_scope_prefix(if a.tailored {
                    subnet.source_prefix()
                } else {
                    0
                });
                edns.options_mut().insert(EdnsOption::Subnet(subnet));
            }
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
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if let Some(resp) = answer(&store, &buf[..n], Transport::Udp, peer.ip()) {
            let _ = sock.send_to(&resp, peer).await;
        }
    }
}

async fn serve_tcp_conn(store: Arc<Store>, mut stream: TcpStream) -> std::io::Result<()> {
    let peer = stream.peer_addr()?.ip();
    loop {
        let len = stream.read_u16().await? as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let Some(resp) = answer(&store, &buf, Transport::Tcp, peer) else {
            return Ok(());
        };
        stream.write_u16(resp.len() as u16).await?;
        stream.write_all(&resp).await?;
    }
}

async fn serve(store: Arc<Store>, addr: &str) -> std::io::Result<()> {
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
  dns-server serve <db-dir> [--listen ADDR] [--follow CONTROL_PLANE_URL] [--poll-ms N] [--node-id ID]

  --listen   address for UDP+TCP (default 127.0.0.1:5300)
  --follow   apply the control plane's changelog continuously; zones stop being served
             (SERVFAIL) once the node goes longer than their SOA EXPIRE without syncing
  --poll-ms  changelog poll interval (default 1000)
  --node-id  this node's name, visible to LUA scripts as q.node (default: $HOSTNAME)";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

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
        ["serve", db, ref flags @ ..] => {
            let (mut listen, mut follow, mut poll_ms) = ("127.0.0.1:5300", None, 1000);
            for pair in flags.chunks(2) {
                match pair {
                    ["--listen", v] => listen = v,
                    ["--follow", v] => follow = Some(v.trim_end_matches('/').to_string()),
                    ["--poll-ms", v] => poll_ms = v.parse().unwrap_or_else(|_| usage()),
                    ["--node-id", v] => {
                        let _ = NODE_ID.set(v.to_string());
                    }
                    _ => usage(),
                }
            }
            let _ = NODE_ID.set(std::env::var("HOSTNAME").unwrap_or_default());
            let mut store = Store::open(&PathBuf::from(db))?;
            store.enforce_expiry = follow.is_some();
            let store = Arc::new(store);
            if let Some(url) = follow {
                println!("following {url}");
                let store = store.clone();
                let poll = std::time::Duration::from_millis(poll_ms);
                std::thread::spawn(move || follow::run(store, url, poll));
            }
            serve(store, listen).await?;
        }
        _ => usage(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::RecordType;
    use std::str::FromStr;

    const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

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
        for zone in [
            "example.com.zone",
            "child.example.com.zone",
            "other.test.zone",
        ] {
            load(&store, &Path::new("testdata").join(zone), None).unwrap();
        }

        let cases = std::fs::read_to_string("testdata/cases.txt").unwrap();
        let mut failures = vec![];
        let blocks = cases
            .split("\n\n")
            .map(|b| {
                b.lines()
                    .filter(|l| !l.starts_with('#'))
                    .collect::<Vec<_>>()
            })
            .filter(|b| !b.is_empty());
        for block in blocks {
            let words: Vec<&str> = block[0]
                .trim_start_matches("> ")
                .split_whitespace()
                .collect();
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
            let transport = if words.contains(&"tcp") {
                Transport::Tcp
            } else {
                Transport::Udp
            };
            let resp = answer(&store, &m.to_vec().unwrap(), transport, LOCALHOST).unwrap();
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
        assert!(answer(&store, b"garbage", Transport::Udp, LOCALHOST).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ask(store: &Store, name: &str, qtype: RecordType) -> String {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        let resp = answer(store, &m.to_vec().unwrap(), Transport::Tcp, LOCALHOST).unwrap();
        render(&Message::from_vec(&resp).unwrap())
    }

    /// Changelog entries in the exact JSON shape the control plane serves.
    fn entries(json: serde_json::Value) -> Vec<follow::Entry> {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn follows_changelog_and_expires() {
        let dir = std::env::temp_dir().join(format!("dns-follow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::open(&dir).unwrap();
        store.enforce_expiry = true;
        let soa = |serial: u32| {
            serde_json::json!({
                "type": "SOA", "ttl": 300,
                "data": format!("ns1.f.test. hostmaster.f.test. {serial} 3600 600 60 300"),
            })
        };
        let ns = serde_json::json!({ "type": "NS", "ttl": 300, "data": "ns1.f.test." });
        let a = |ip: &str| serde_json::json!({ "type": "A", "ttl": 300, "data": ip });

        // Never synced: nothing is fresh, so even known zones SERVFAIL.
        follow::apply(
            &store,
            &entries(serde_json::json!([
                { "seq": 1, "zone": "f.test.", "op": "names",
                  "payload": { "f.test.": [soa(1), ns], "www.f.test.": [a("192.0.2.10")] } },
            ])),
            None,
        )
        .unwrap();
        assert_eq!(ask(&store, "www.f.test.", RecordType::A), "SERVFAIL");

        // Caught up: served.
        follow::apply(&store, &[], Some(store::now())).unwrap();
        assert_eq!(
            ask(&store, "www.f.test.", RecordType::A),
            "NOERROR aa\nANSWER www.f.test. 300 IN A 192.0.2.10"
        );

        // A later entry replaces whole names; [] removes one.
        follow::apply(&store, &entries(serde_json::json!([
            { "seq": 2, "zone": "f.test.", "op": "names",
              "payload": { "f.test.": [soa(2), ns], "www.f.test.": [], "new.f.test.": [a("192.0.2.20")] } },
        ])), Some(store::now())).unwrap();
        assert!(ask(&store, "www.f.test.", RecordType::A).starts_with("NXDOMAIN aa"));
        assert!(ask(&store, "new.f.test.", RecordType::A).ends_with("IN A 192.0.2.20"));
        let txn = store.read_txn().unwrap();
        assert_eq!(store.get_meta(&txn, store::APPLIED_SEQ).unwrap(), Some(2));
        drop(txn);

        // Last sync older than EXPIRE (60s): stop serving. Fresh again: serve again.
        follow::apply(&store, &[], Some(store::now() - 61)).unwrap();
        assert_eq!(ask(&store, "new.f.test.", RecordType::A), "SERVFAIL");
        follow::apply(&store, &[], Some(store::now() - 59)).unwrap();
        assert!(ask(&store, "new.f.test.", RecordType::A).starts_with("NOERROR aa"));

        // An entry the node can't understand is rejected whole, and applied_seq stays put.
        let bad = entries(serde_json::json!([
            { "seq": 3, "zone": "f.test.", "op": "names", "payload": { "x.f.test.": [a("192.0.2.30")] } },
            { "seq": 4, "zone": "f.test.", "op": "names", "payload": { "y.f.test.": [{ "type": "A", "ttl": 1, "data": "nope" }] } },
        ]));
        assert!(follow::apply(&store, &bad, Some(store::now())).is_err());
        assert!(ask(&store, "x.f.test.", RecordType::A).starts_with("NXDOMAIN"));
        let txn = store.read_txn().unwrap();
        assert_eq!(store.get_meta(&txn, store::APPLIED_SEQ).unwrap(), Some(2));
        drop(txn);

        // delete_zone: no longer ours.
        follow::apply(
            &store,
            &entries(serde_json::json!([
                { "seq": 5, "zone": "f.test.", "op": "delete_zone", "payload": {} },
            ])),
            Some(store::now()),
        )
        .unwrap();
        assert_eq!(ask(&store, "new.f.test.", RecordType::A), "REFUSED");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sends a query with an optional ECS subnet; returns the rendered response and the
    /// ECS scope prefix echoed back (if any).
    fn ask_ecs(
        store: &Store,
        name: &str,
        qtype: RecordType,
        ecs: Option<(&str, u8)>,
    ) -> (String, Option<u8>) {
        use hickory_proto::rr::rdata::opt::ClientSubnet;
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        let mut e = Edns::new();
        e.set_max_payload(1232);
        if let Some((addr, prefix)) = ecs {
            e.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(
                addr.parse().unwrap(),
                prefix,
                0,
            )));
        }
        m.set_edns(e);
        let resp = Message::from_vec(
            &answer(store, &m.to_vec().unwrap(), Transport::Udp, LOCALHOST).unwrap(),
        )
        .unwrap();
        let scope = resp
            .edns
            .as_ref()
            .and_then(|e| match e.options().get(EdnsCode::Subnet) {
                Some(EdnsOption::Subnet(s)) => Some(s.scope_prefix()),
                _ => None,
            });
        (render(&resp), scope)
    }

    #[test]
    fn lua_records() {
        let _ = NODE_ID.set("node-test".into());
        let dir = std::env::temp_dir().join(format!("dns-lua-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let r =
            |t: &str, ttl: u32, d: &str| serde_json::json!({ "type": t, "ttl": ttl, "data": d });
        follow::apply(&store, &entries(serde_json::json!([{ "seq": 1, "zone": "l.test.", "op": "names", "payload": {
            "l.test.": [r("SOA", 300, "ns1.l.test. h.l.test. 1 3600 600 86400 300"), r("NS", 300, "ns1.l.test.")],
            "geo.l.test.": [r("LUA", 30, r#"A if in_cidr(q.client, "10.0.0.0/8") then return "192.0.2.10" end return { "192.0.2.20", "192.0.2.21" }"#)],
            "over.l.test.": [r("A", 300, "198.51.100.1"), r("AAAA", 300, "2001:db8::1"), r("LUA", 60, r#"A return "192.0.2.1""#)],
            "broken.l.test.": [r("A", 300, "198.51.100.2"), r("LUA", 60, r#"A error("boom")"#)],
            "broken-only.l.test.": [r("LUA", 60, r#"A error("boom")"#)],
            "spin.l.test.": [r("LUA", 60, "A while true do end")],
            "nothing.l.test.": [r("LUA", 60, "A return nil")],
            "decline.l.test.": [r("A", 300, "198.51.100.3"), r("LUA", 60, "A return nil")],
            "badtype.l.test.": [r("LUA", 60, r#"A return "not-an-ip""#)],
            "escape.l.test.": [r("LUA", 60, r#"A return os.getenv("HOME")"#)],
            "who.l.test.": [r("LUA", 60, r#"TXT return '"' .. q.node .. ' ' .. q.static[1] .. '"'"#), r("TXT", 60, "\"fallback\"")],
            "*.ip.l.test.": [r("LUA", 60, r#"A local a, b, c, d = q.name:match("^(%d+)-(%d+)-(%d+)-(%d+)%.") if a then return a.."."..b.."."..c.."."..d end"#)],
        }}])), Some(store::now())).unwrap();

        // Tailored by client subnet; the ECS scope says the answer depends on the whole /24.
        assert_eq!(
            ask_ecs(&store, "geo.l.test.", RecordType::A, Some(("10.1.2.0", 24))),
            (
                "NOERROR aa\nANSWER geo.l.test. 30 IN A 192.0.2.10".into(),
                Some(24)
            )
        );
        assert_eq!(ask_ecs(&store, "geo.l.test.", RecordType::A, Some(("203.0.113.0", 24))).0,
                   "NOERROR aa\nANSWER geo.l.test. 30 IN A 192.0.2.20\nANSWER geo.l.test. 30 IN A 192.0.2.21");
        // No ECS: the source IP (127.0.0.1) is the client, and no ECS option is echoed.
        assert_eq!(ask_ecs(&store, "geo.l.test.", RecordType::A, None).1, None);
        // Static answers are the same for everyone: scope 0.
        assert_eq!(
            ask_ecs(
                &store,
                "over.l.test.",
                RecordType::AAAA,
                Some(("10.1.2.0", 24))
            )
            .1,
            Some(0)
        );

        // A script overrides static records of its type only.
        assert_eq!(
            ask(&store, "over.l.test.", RecordType::A),
            "NOERROR aa\nANSWER over.l.test. 60 IN A 192.0.2.1"
        );
        assert_eq!(
            ask(&store, "over.l.test.", RecordType::AAAA),
            "NOERROR aa\nANSWER over.l.test. 300 IN AAAA 2001:db8::1"
        );

        // Errors fall back to the static records, or SERVFAIL without any. Same for runaway
        // loops (instruction budget), bad output, and sandbox escapes.
        assert_eq!(
            ask(&store, "broken.l.test.", RecordType::A),
            "NOERROR aa\nANSWER broken.l.test. 300 IN A 198.51.100.2"
        );
        for name in ["broken-only", "spin", "badtype", "escape"] {
            assert_eq!(
                ask(&store, &format!("{name}.l.test."), RecordType::A),
                "SERVFAIL",
                "{name}"
            );
        }

        // Returning nil declines: static records if any, else NODATA.
        assert_eq!(
            ask(&store, "decline.l.test.", RecordType::A),
            "NOERROR aa\nANSWER decline.l.test. 300 IN A 198.51.100.3"
        );
        assert!(ask(&store, "nothing.l.test.", RecordType::A)
            .starts_with("NOERROR aa\nAUTHORITY l.test."));

        // Scripts see the node ID and the static records they override.
        assert_eq!(
            ask(&store, "who.l.test.", RecordType::TXT),
            "NOERROR aa\nANSWER who.l.test. 60 IN TXT node-test fallback"
        );

        // Name patterns via wildcard: the answer is built from the query name.
        assert_eq!(
            ask(&store, "1-2-3-4.ip.l.test.", RecordType::A),
            "NOERROR aa\nANSWER 1-2-3-4.ip.l.test. 60 IN A 1.2.3.4"
        );
        assert!(ask(&store, "nope.ip.l.test.", RecordType::A).starts_with("NOERROR aa\nAUTHORITY"));

        // LUA records themselves are never served, not even to ANY or TYPE65402 queries.
        assert_eq!(
            ask(&store, "over.l.test.", RecordType::ANY)
                .matches("ANSWER")
                .count(),
            2
        );
        assert!(ask(&store, "geo.l.test.", script::LUA).starts_with("NOERROR aa\nAUTHORITY"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `cargo test --release -p dns-server -- --ignored --nocapture script_latency`
    #[test]
    #[ignore]
    fn script_latency() {
        let dir = std::env::temp_dir().join(format!("dns-bench-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let r = |t: &str, d: &str| serde_json::json!({ "type": t, "ttl": 60, "data": d });
        follow::apply(&store, &entries(serde_json::json!([{ "seq": 1, "zone": "b.test.", "op": "names", "payload": {
            "b.test.": [r("SOA", "ns1.b.test. h.b.test. 1 3600 600 86400 300"), r("NS", "ns1.b.test.")],
            "static.b.test.": [r("A", "192.0.2.1")],
            "geo.b.test.": [r("LUA", r#"A
                local regions = { {"10.0.0.0/8", "192.0.2.10"}, {"172.16.0.0/12", "192.0.2.11"},
                                  {"192.168.0.0/16", "192.0.2.12"}, {"100.64.0.0/10", "192.0.2.13"} }
                for _, r in ipairs(regions) do
                    if in_cidr(q.client, r[1]) then return r[2] end
                end
                return { "192.0.2.20", "192.0.2.21" }"#)],
        }}])), Some(store::now())).unwrap();

        let query = |name: &str| {
            use hickory_proto::rr::rdata::opt::ClientSubnet;
            let mut m = Message::query();
            m.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
            let mut e = Edns::new();
            e.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(
                "203.0.113.0".parse().unwrap(),
                24,
                0,
            )));
            m.set_edns(e);
            m.to_vec().unwrap()
        };
        for (label, q) in [
            ("static", query("static.b.test.")),
            ("script", query("geo.b.test.")),
        ] {
            let mut times: Vec<std::time::Duration> = (0..50_000)
                .map(|_| {
                    let t = std::time::Instant::now();
                    std::hint::black_box(answer(&store, &q, Transport::Udp, LOCALHOST).unwrap());
                    t.elapsed()
                })
                .collect();
            times.sort();
            let pct = |p: usize| times[times.len() * p / 100 - 1];
            println!(
                "{label:>6}: p50 {:>8.1?}  p99 {:>8.1?}  p99.9 {:>8.1?}",
                pct(50),
                pct(99),
                times[times.len() * 999 / 1000]
            );
            assert!(
                pct(99) < std::time::Duration::from_millis(1),
                "{label} p99 over 1ms"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

use std::net::Ipv4Addr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{rdata::A, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

// ponytail: Stage 0 hard-coded answer, replaced by the LMDB lookup in Stage 1.
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TTL: u32 = 300;

/// Builds a response for a raw query. Returns None for packets we can't parse (dropped).
fn answer(query: &[u8]) -> Option<Vec<u8>> {
    let req = Message::from_bytes(query).ok()?;
    if req.message_type() != MessageType::Query {
        return None;
    }
    let mut resp = Message::new();
    resp.set_id(req.id())
        .set_message_type(MessageType::Response)
        .set_op_code(req.op_code())
        .set_recursion_desired(req.recursion_desired())
        .set_authoritative(true);

    match req.queries() {
        [q] => {
            resp.add_query(q.clone());
            if q.query_type() == RecordType::A {
                resp.add_answer(Record::from_rdata(q.name().clone(), TTL, RData::A(A(ANSWER_IP))));
            }
            // Other types: NOERROR with no answers (NODATA).
            resp.set_response_code(ResponseCode::NoError);
        }
        _ => {
            resp.set_response_code(ResponseCode::FormErr);
        }
    }
    resp.to_bytes().ok()
}

async fn serve_udp(sock: Arc<UdpSocket>) {
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        if let Some(resp) = answer(&buf[..n]) {
            // ponytail: no truncation yet; Stage 1 adds TC + EDNS buffer sizing.
            let _ = sock.send_to(&resp, peer).await;
        }
    }
}

async fn serve_tcp_conn(mut stream: TcpStream) -> std::io::Result<()> {
    loop {
        let len = stream.read_u16().await? as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let Some(resp) = answer(&buf) else { return Ok(()) };
        stream.write_u16(resp.len() as u16).await?;
        stream.write_all(&resp).await?;
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Port 53 needs root; default to an unprivileged port for development.
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:5300".into());
    let udp = Arc::new(UdpSocket::bind(&addr).await?);
    let tcp = TcpListener::bind(&addr).await?;
    println!("listening on {addr} (udp+tcp)");

    tokio::spawn(serve_udp(udp));
    loop {
        let (stream, _) = tcp.accept().await?;
        tokio::spawn(async move {
            let _ = serve_tcp_conn(stream).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn query(qtype: RecordType) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(4242)
            .add_query(Query::query(Name::from_str("example.com.").unwrap(), qtype));
        m.to_bytes().unwrap()
    }

    #[test]
    fn answers_a_and_nodata() {
        let a = Message::from_bytes(&answer(&query(RecordType::A)).unwrap()).unwrap();
        assert_eq!(a.id(), 4242);
        assert!(a.authoritative());
        assert_eq!(a.response_code(), ResponseCode::NoError);
        assert_eq!(a.answers().len(), 1);
        assert_eq!(a.answers()[0].data(), Some(&RData::A(A(ANSWER_IP))));

        let aaaa = Message::from_bytes(&answer(&query(RecordType::AAAA)).unwrap()).unwrap();
        assert_eq!(aaaa.response_code(), ResponseCode::NoError);
        assert!(aaaa.answers().is_empty());

        assert!(answer(b"garbage").is_none());
    }
}

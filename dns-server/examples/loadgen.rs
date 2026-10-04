//! Closed-loop UDP load generator: each of N threads keeps one query in flight on its own
//! socket and records round-trip latency. Measures what a client sees (loopback included).
//!
//! cargo run --release -p dns-server --example loadgen -- <server> <seconds> <threads> [name/TYPE ...]
//! e.g. cargo run --release -p dns-server --example loadgen -- 127.0.0.1:5300 10 32 www.example.com/A

use std::net::UdpSocket;
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [server, secs, threads, names @ ..] = &args[..] else {
        eprintln!("usage: loadgen <server> <seconds> <threads> [name/TYPE ...]");
        std::process::exit(2);
    };
    let secs: u64 = secs.parse().expect("seconds");
    let threads: usize = threads.parse().expect("threads");
    let names: Vec<String> = if names.is_empty() {
        [
            "www.example.com/A",
            "mail.example.com/AAAA",
            "nope.example.com/A",
            "alias.example.com/A",
            "x.wild.example.com/TXT",
        ]
        .map(String::from)
        .to_vec()
    } else {
        names.to_vec()
    };
    let queries: Vec<Vec<u8>> = names
        .iter()
        .map(|n| {
            let (name, rtype) = n.split_once('/').unwrap_or((n, "A"));
            let mut m = Message::query();
            m.add_query(Query::query(
                Name::from_str(name).unwrap(),
                RecordType::from_str(rtype).unwrap(),
            ));
            m.to_vec().unwrap()
        })
        .collect();

    let deadline = Instant::now() + Duration::from_secs(secs);
    let workers: Vec<_> = (0..threads)
        .map(|t| {
            let (server, queries) = (server.clone(), queries.clone());
            std::thread::spawn(move || {
                let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
                sock.connect(&server).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let (mut lat, mut timeouts, mut buf) = (Vec::new(), 0u64, [0u8; 4096]);
                let mut id = (t as u16).wrapping_mul(4099);
                while Instant::now() < deadline {
                    let mut q = queries[id as usize % queries.len()].clone();
                    q[..2].copy_from_slice(&id.to_be_bytes());
                    let start = Instant::now();
                    sock.send(&q).unwrap();
                    loop {
                        match sock.recv(&mut buf) {
                            Ok(n) if n >= 2 && buf[..2] == id.to_be_bytes() => {
                                lat.push(start.elapsed().as_micros() as u32);
                                break;
                            }
                            Ok(_) => continue, // a late reply to an earlier, timed-out query
                            Err(_) => {
                                timeouts += 1;
                                break;
                            }
                        }
                    }
                    id = id.wrapping_add(1);
                }
                (lat, timeouts)
            })
        })
        .collect();

    let (mut lat, mut timeouts) = (Vec::new(), 0);
    for w in workers {
        let (l, t) = w.join().unwrap();
        lat.extend(l);
        timeouts += t;
    }
    lat.sort_unstable();
    let pct = |p: f64| {
        lat.get(((lat.len() as f64 * p) as usize).min(lat.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0)
    };
    println!(
        "{threads:>3} threads: {:>8.0} qps  p50 {:>5}µs  p99 {:>5}µs  p99.9 {:>5}µs  max {:>6}µs  timeouts {timeouts}",
        lat.len() as f64 / secs as f64,
        pct(0.50),
        pct(0.99),
        pct(0.999),
        lat.last().copied().unwrap_or(0),
    );
}

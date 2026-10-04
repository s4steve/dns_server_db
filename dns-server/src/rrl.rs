//! Response rate limiting (RRL), after BIND's design.
//!
//! Spoofed-source floods turn an authoritative server into a reflector: many identical
//! answers sent to one victim. RRL caps identical responses per client network:
//!
//! - key: client block (IPv4 /24, IPv6 /56), the response's name, qtype and rcode. Negative
//!   answers use the zone (the SOA owner in the authority section) as the name, so random-
//!   subdomain floods share one bucket; errors are keyed by client block and rcode alone.
//! - each key is a token bucket refilled at `rps` per second, holding at most `rps` tokens.
//! - over the limit, responses are dropped, except every `slip`th one, which is sent
//!   truncated (TC, no records): a real client retries over TCP, a spoofed victim gets
//!   nothing bigger than its query.
//!
//! Only UDP is limited (TCP proves the source address), and clients presenting a valid DNS
//! server cookie are exempt (see `cookie.rs`).

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};

const SHARDS: usize = 64;
// ponytail: buckets are pruned only when a shard passes this size. Fine for floods from many
// sources at modest scale; switch to a fixed-size table if memory under attack matters.
const MAX_BUCKETS_PER_SHARD: usize = 16_384;

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Send,
    Slip,
    Drop,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    limited: u32,
}

pub struct Rrl {
    rps: f64,
    slip: u32,
    hasher: RandomState,
    shards: Vec<Mutex<HashMap<u64, Bucket>>>,
}

impl Rrl {
    pub fn new(rps: u32, slip: u32) -> Self {
        Self {
            rps: rps.max(1) as f64,
            slip,
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// `name` is the response's qname, or the zone for negative answers; ignored for errors.
    pub fn check(
        &self,
        client: IpAddr,
        name: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
    ) -> Verdict {
        self.check_at(client, name, qtype, rcode, Instant::now())
    }

    fn check_at(
        &self,
        client: IpAddr,
        name: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        now: Instant,
    ) -> Verdict {
        let mut h = self.hasher.build_hasher();
        match client {
            IpAddr::V4(ip) => (u32::from(ip) & 0xffff_ff00).hash(&mut h),
            IpAddr::V6(ip) => (u128::from(ip) & !((1u128 << 72) - 1)).hash(&mut h),
        }
        u16::from(rcode).hash(&mut h);
        if matches!(rcode, ResponseCode::NoError | ResponseCode::NXDomain) {
            name.to_lowercase().hash(&mut h);
            u16::from(qtype).hash(&mut h);
        }
        let key = h.finish();

        let mut shard = self.shards[key as usize % SHARDS].lock().unwrap();
        if shard.len() >= MAX_BUCKETS_PER_SHARD {
            // Idle buckets have refilled anyway; forgetting them changes nothing.
            shard.retain(|_, b| now.duration_since(b.last).as_secs_f64() * self.rps < self.rps);
        }
        let b = shard.entry(key).or_insert(Bucket {
            tokens: self.rps,
            last: now,
            limited: 0,
        });
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * self.rps).min(self.rps);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            b.limited = 0;
            return Verdict::Send;
        }
        b.limited += 1;
        if self.slip > 0 && b.limited % self.slip == 0 {
            Verdict::Slip
        } else {
            Verdict::Drop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn limits_per_client_block_and_name() {
        let rrl = Rrl::new(5, 2);
        let t0 = Instant::now();
        let www = Name::from_str("www.example.com.").unwrap();
        let other = Name::from_str("other.example.com.").unwrap();
        let a = |ip: &str, name: &Name, rcode, t| {
            rrl.check_at(ip.parse().unwrap(), name, RecordType::A, rcode, t)
        };

        // A burst of `rps` passes; then every 2nd response slips, the rest drop.
        let burst: Vec<Verdict> = (0..9)
            .map(|_| a("192.0.2.1", &www, ResponseCode::NoError, t0))
            .collect();
        assert_eq!(
            &burst[..5],
            &[
                Verdict::Send,
                Verdict::Send,
                Verdict::Send,
                Verdict::Send,
                Verdict::Send
            ]
        );
        assert_eq!(
            &burst[5..],
            &[Verdict::Drop, Verdict::Slip, Verdict::Drop, Verdict::Slip]
        );

        // Same /24 shares the bucket; another /24, or another name, doesn't.
        assert_eq!(
            a("192.0.2.200", &www, ResponseCode::NoError, t0),
            Verdict::Drop
        );
        assert_eq!(
            a("192.0.3.1", &www, ResponseCode::NoError, t0),
            Verdict::Send
        );
        assert_eq!(
            a("192.0.2.1", &other, ResponseCode::NoError, t0),
            Verdict::Send
        );

        // Tokens refill at rps: after 1s, five more.
        let t1 = t0 + Duration::from_secs(1);
        assert!((0..5).all(|_| a("192.0.2.1", &www, ResponseCode::NoError, t1) == Verdict::Send));
        assert_ne!(
            a("192.0.2.1", &www, ResponseCode::NoError, t1),
            Verdict::Send
        );

        // Errors are keyed by client and rcode only: different names share a bucket.
        let names: Vec<Name> = (0..10)
            .map(|i| Name::from_str(&format!("n{i}.example.com.")).unwrap())
            .collect();
        let sent = names
            .iter()
            .filter(|n| a("198.51.100.1", n, ResponseCode::Refused, t0) == Verdict::Send)
            .count();
        assert_eq!(sent, 5);
    }
}

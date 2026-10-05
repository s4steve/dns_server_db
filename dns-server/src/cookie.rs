//! DNS Cookies (RFC 7873), with RFC 9018 interoperable server cookies.
//!
//! A client sends an 8-byte client cookie; we answer with it plus a 16-byte server cookie:
//! version 1, 3 reserved bytes, a 32-bit timestamp, and SipHash-2-4 over (client cookie,
//! version, reserved, timestamp, client IP) under a secret. A client that echoes a valid
//! server cookie has proved it receives packets at its address, so it is exempt from RRL.
//!
//! Cookies are optional here: an invalid or missing server cookie just gets a fresh one and
//! a normal answer (never BADCOOKIE). Nodes behind one anycast address should share
//! `--cookie-secret` so a cookie from one node validates on the others.

use std::io::Read;
use std::net::IpAddr;

use siphasher::sip::SipHasher24;

const VERSION: u8 = 1;
/// RFC 9018 §4.3: accept cookies up to an hour old, and up to 5 minutes in the future.
const MAX_AGE: u32 = 3600;
const MAX_SKEW: u32 = 300;

pub struct Cookies {
    secret: [u8; 16],
}

/// What a query's COOKIE option means for the response.
#[derive(Debug, PartialEq)]
pub enum Check {
    /// Malformed option: answer FORMERR.
    Malformed,
    /// Reply with this COOKIE option payload; `valid` = the query had a valid server cookie.
    Reply { payload: Vec<u8>, valid: bool },
}

impl Cookies {
    pub fn new(secret: [u8; 16]) -> Self {
        Self { secret }
    }

    /// A secret from the OS RNG (each node different: cookies won't validate across nodes).
    pub fn random() -> std::io::Result<Self> {
        let mut secret = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
        Ok(Self::new(secret))
    }

    /// `option` is the query's COOKIE option payload.
    pub fn check(&self, option: &[u8], client: IpAddr, now: u32) -> Check {
        // RFC 7873 §5.2.2: client cookie alone (8), or with a server cookie of 8-32 bytes.
        if option.len() != 8 && !(16..=40).contains(&option.len()) {
            return Check::Malformed;
        }
        let client_cookie: [u8; 8] = option[..8].try_into().unwrap();
        let valid = option.len() == 24 && {
            let server = &option[8..];
            let stamp = u32::from_be_bytes(server[4..8].try_into().unwrap());
            let fresh = stamp <= now.wrapping_add(MAX_SKEW) && now.wrapping_sub(stamp) <= MAX_AGE;
            // Constant-time comparison, so response timing says nothing about the expected hash.
            let expected = self.hash(&client_cookie, stamp, client);
            let diff = server[8..]
                .iter()
                .zip(expected)
                .fold(0, |acc, (a, b)| acc | (a ^ b));
            server[0] == VERSION && fresh && diff == 0
        };
        let mut payload = client_cookie.to_vec();
        payload.extend_from_slice(&[VERSION, 0, 0, 0]);
        payload.extend_from_slice(&now.to_be_bytes());
        payload.extend_from_slice(&self.hash(&client_cookie, now, client));
        Check::Reply { payload, valid }
    }

    fn hash(&self, client_cookie: &[u8; 8], stamp: u32, client: IpAddr) -> [u8; 8] {
        let mut input = client_cookie.to_vec();
        input.extend_from_slice(&[VERSION, 0, 0, 0]);
        input.extend_from_slice(&stamp.to_be_bytes());
        match client {
            IpAddr::V4(ip) => input.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => input.extend_from_slice(&ip.octets()),
        }
        SipHasher24::new_with_key(&self.secret)
            .hash(&input)
            .to_le_bytes()
    }
}

/// Parses a 32-hex-digit `--cookie-secret`.
pub fn parse_secret(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejections() {
        let c = Cookies::new([7; 16]);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let client = [1, 2, 3, 4, 5, 6, 7, 8];
        let now = 1_800_000_000;

        let Check::Reply { payload, valid } = c.check(&client, ip, now) else {
            panic!()
        };
        assert!(!valid);
        assert_eq!(payload.len(), 24);
        assert_eq!(&payload[..8], &client);

        // Echoed back: valid, for a while.
        assert!(matches!(
            c.check(&payload, ip, now + 10),
            Check::Reply { valid: true, .. }
        ));
        assert!(matches!(
            c.check(&payload, ip, now + MAX_AGE),
            Check::Reply { valid: true, .. }
        ));
        // Too old, from another address, tampered, or under another secret: not valid.
        assert!(matches!(
            c.check(&payload, ip, now + MAX_AGE + 1),
            Check::Reply { valid: false, .. }
        ));
        assert!(matches!(
            c.check(&payload, "192.0.2.2".parse().unwrap(), now),
            Check::Reply { valid: false, .. }
        ));
        let mut tampered = payload.clone();
        tampered[23] ^= 1;
        assert!(matches!(
            c.check(&tampered, ip, now),
            Check::Reply { valid: false, .. }
        ));
        assert!(matches!(
            Cookies::new([8; 16]).check(&payload, ip, now),
            Check::Reply { valid: false, .. }
        ));
        // A node with the same secret accepts it (anycast).
        assert!(matches!(
            Cookies::new([7; 16]).check(&payload, ip, now),
            Check::Reply { valid: true, .. }
        ));

        assert_eq!(c.check(&[0; 7], ip, now), Check::Malformed);
        assert_eq!(c.check(&[0; 12], ip, now), Check::Malformed);
        assert_eq!(c.check(&[0; 41], ip, now), Check::Malformed);

        assert_eq!(
            parse_secret("000102030405060708090a0b0c0d0e0f").unwrap()[15],
            15
        );
        assert!(parse_secret("xyz").is_none());
    }
}

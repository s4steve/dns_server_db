//! Managed SPF by flattening: a name's allowed senders (domains such as `_spf.google.com`,
//! or literal IPs and CIDRs) are resolved into `ip4:`/`ip6:` terms and published as plain
//! TXT records, so receivers spend one lookup per chunk instead of one per nested include.
//!
//! Every receiver gets the same records: queries carry nothing about the sender (no SPF
//! macros), and the DNS nodes serve them like any other static TXT record.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

use hickory_proto::rr::{Name, RData, RecordType};
use hickory_resolver::TokioResolver;

const MAX_DEPTH: usize = 10;
const MAX_LOOKUPS: usize = 200;
/// Bytes per chunk record. Keeps each answer within 512 bytes (RFC 7208 §3.4).
const CHUNK_BYTES: usize = 450;
/// Chunks the root record includes: 9 lookups, under SPF's limit of 10.
pub const MAX_CHUNKS: usize = 9;
pub const QUALIFIERS: [&str; 3] = ["~all", "-all", "?all"];

/// DNS lookups flattening needs: TXT strings joined, A/AAAA addresses, MX exchanges, as
/// text. No records (or NXDOMAIN) is an empty list, not an error.
trait Resolve {
    async fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<String>, String>;
}

impl Resolve for TokioResolver {
    async fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<String>, String> {
        let fqdn = format!("{name}."); // no search domains
        let lookup = match self.lookup(fqdn.as_str(), rtype).await {
            Ok(l) => l,
            Err(e) if e.is_no_records_found() || e.is_nx_domain() => return Ok(vec![]),
            Err(e) => return Err(format!("{rtype} lookup for {name} failed: {e}")),
        };
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(t) => Some(
                    t.txt_data
                        .iter()
                        .map(|s| String::from_utf8_lossy(s))
                        .collect(),
                ),
                RData::A(a) => Some(a.to_string()),
                RData::AAAA(a) => Some(a.to_string()),
                RData::MX(mx) => Some(mx.exchange.to_string()),
                _ => None,
            })
            .collect())
    }
}

/// Flattens `senders` using the system resolver.
pub async fn flatten_live(senders: &[String]) -> Result<Vec<String>, String> {
    static RESOLVER: OnceLock<Result<TokioResolver, String>> = OnceLock::new();
    let resolver = RESOLVER
        .get_or_init(|| {
            TokioResolver::builder_tokio()
                .and_then(|b| b.build())
                .map_err(|e| format!("no DNS resolver available: {e}"))
        })
        .as_ref()?;
    flatten(resolver, senders).await
}

/// Resolves each sender into `ip4:`/`ip6:` terms: sorted, without duplicates.
async fn flatten(r: &impl Resolve, senders: &[String]) -> Result<Vec<String>, String> {
    let mut terms = BTreeSet::new();
    let mut lookups = 0;
    let mut query = async |name: &str, rtype| {
        lookups += 1;
        if lookups > MAX_LOOKUPS {
            return Err(format!("more than {MAX_LOOKUPS} DNS lookups"));
        }
        r.query(name, rtype).await
    };

    let mut work = vec![];
    for s in senders {
        match literal(s) {
            Some(term) => {
                terms.insert(term?);
            }
            None => work.push((domain(s)?, 0)),
        }
    }
    let mut seen = HashSet::new();
    while let Some((d, depth)) = work.pop() {
        if !seen.insert(d.clone()) {
            continue; // already flattened (a loop, or the same include reached twice)
        }
        if depth > MAX_DEPTH {
            return Err(format!("{d}: includes nested more than {MAX_DEPTH} deep"));
        }
        let records: Vec<String> = query(&d, RecordType::TXT)
            .await?
            .into_iter()
            .filter(|t| {
                let t = t.to_ascii_lowercase();
                t == "v=spf1" || t.starts_with("v=spf1 ")
            })
            .collect();
        let record = match records.as_slice() {
            [one] => one,
            [] => return Err(format!("{d} has no SPF record")),
            _ => return Err(format!("{d} has more than one SPF record")),
        };
        let parts: Vec<&str> = record.split_whitespace().skip(1).collect();
        let has_all = parts.iter().any(|p| {
            p.trim_start_matches(['+', '-', '~', '?'])
                .eq_ignore_ascii_case("all")
        });

        for part in parts {
            if part.contains('%') {
                return Err(format!(
                    "{d}: {part:?} uses an SPF macro, which can't be flattened"
                ));
            }
            if let Some((key, value)) = part.split_once('=') {
                if key.eq_ignore_ascii_case("redirect") && !has_all {
                    work.push((domain(value)?, depth + 1));
                }
                continue; // exp= and unknown modifiers don't affect which IPs pass
            }
            // ponytail: only pass terms are kept. A non-pass term (`-ip4:...`) in an included
            // record makes that include not match, which is what leaving it out does, except
            // when it carves an exception out of a later, wider pass term.
            let Some(mech) = part
                .strip_prefix('+')
                .or((!part.starts_with(['-', '~', '?'])).then_some(part))
            else {
                continue;
            };
            let (name, arg) = match mech.split_once(':') {
                Some((n, a)) => (n.to_ascii_lowercase(), Some(a)),
                None => match mech.split_once('/') {
                    Some((n, _)) => (n.to_ascii_lowercase(), None),
                    None => (mech.to_ascii_lowercase(), None),
                },
            };
            match name.as_str() {
                "all" => {}
                "ip4" | "ip6" => {
                    terms.insert(cidr(arg.unwrap_or(""))?);
                }
                "include" => work.push((domain(arg.unwrap_or(""))?, depth + 1)),
                "a" | "mx" => {
                    // a[:domain][/v4len][//v6len]
                    let spec = arg.unwrap_or(mech.get(name.len()..).unwrap_or(""));
                    let (host, lens) = match spec.find('/') {
                        Some(i) => (&spec[..i], &spec[i..]),
                        None => (spec, ""),
                    };
                    let host = if host.is_empty() {
                        d.clone()
                    } else {
                        domain(host)?
                    };
                    let (v4, v6) = dual_cidr(lens).map_err(|e| format!("{d}: {part:?}: {e}"))?;
                    let hosts = if name == "mx" {
                        let mut hosts = vec![];
                        for mx in query(&host, RecordType::MX).await? {
                            hosts.push(domain(&mx)?);
                        }
                        hosts
                    } else {
                        vec![host]
                    };
                    for h in hosts {
                        for (rtype, len) in [(RecordType::A, v4), (RecordType::AAAA, v6)] {
                            for ip in query(&h, rtype).await? {
                                terms.insert(cidr(&format!("{ip}/{len}"))?);
                            }
                        }
                    }
                }
                "exists" | "ptr" => {
                    return Err(format!(
                        "{d}: {part:?} depends on the sender and can't be flattened"
                    ));
                }
                _ => return Err(format!("{d}: unknown SPF mechanism {part:?}")),
            }
        }
    }
    Ok(terms.into_iter().collect())
}

/// A literal sender: `ip4:…`, `ip6:…`, or a bare address or CIDR. `None` if it's a domain.
fn literal(s: &str) -> Option<Result<String, String>> {
    let s = s.trim();
    let bare = s
        .strip_prefix("ip4:")
        .or_else(|| s.strip_prefix("ip6:"))
        .unwrap_or(s);
    let addr = bare.split('/').next().unwrap_or("");
    (addr.parse::<IpAddr>().is_ok() || bare != s).then(|| cidr(bare))
}

/// `addr[/len]` as an `ip4:`/`ip6:` term, with the length dropped when it covers one host.
fn cidr(s: &str) -> Result<String, String> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid IP address {addr:?}"))?;
    let (kind, max) = if ip.is_ipv4() {
        ("ip4", 32)
    } else {
        ("ip6", 128)
    };
    let len: u8 = match len {
        Some(l) => l
            .parse()
            .ok()
            .filter(|l| *l <= max)
            .ok_or_else(|| format!("invalid prefix length in {s:?}"))?,
        None => max,
    };
    Ok(if len == max {
        format!("{kind}:{ip}")
    } else {
        format!("{kind}:{ip}/{len}")
    })
}

/// `""`, `/24`, `//64` or `/24//64`, as (IPv4 length, IPv6 length).
fn dual_cidr(s: &str) -> Result<(u8, u8), String> {
    let (v4, v6) = match s.split_once("//") {
        Some((v4, v6)) => (v4, Some(v6)),
        None => (s, None),
    };
    let v4 = match v4.strip_prefix('/') {
        Some(l) => l.parse().ok().filter(|l| *l <= 32),
        None if v4.is_empty() => Some(32),
        None => None,
    };
    let v6 = match v6 {
        Some(l) => l.parse().ok().filter(|l| *l <= 128),
        None => Some(128),
    };
    v4.zip(v6)
        .ok_or_else(|| format!("invalid prefix lengths {s:?}"))
}

/// A sender domain, lowercase, without the trailing dot.
fn domain(s: &str) -> Result<String, String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    match Name::from_ascii(&s) {
        Ok(n) if n.num_labels() >= 2 && !s.contains(['%', '/', ' ']) => Ok(s),
        _ => Err(format!("invalid sender domain {s:?}")),
    }
}

/// The TXT records publishing `terms` for `name`: the root record (which includes each
/// chunk) and the chunks `_spf0.name`, `_spf1.name`, …, as (owner, raw text).
pub fn render(
    name: &Name,
    terms: &[String],
    qualifier: &str,
) -> Result<Vec<(String, String)>, String> {
    let mut chunks: Vec<String> = vec![];
    for term in terms {
        match chunks.last_mut() {
            Some(c) if c.len() + 1 + term.len() <= CHUNK_BYTES => {
                c.push(' ');
                c.push_str(term);
            }
            _ => chunks.push(format!("v=spf1 {term}")),
        }
    }
    if chunks.len() > MAX_CHUNKS {
        return Err(format!(
            "{} addresses need {} records, more than the {MAX_CHUNKS} that fit SPF's lookup limit",
            terms.len(),
            chunks.len()
        ));
    }
    let base = name.to_string();
    let mut root = String::from("v=spf1");
    let mut out = vec![];
    for (i, chunk) in chunks.into_iter().enumerate() {
        let owner = format!("_spf{i}.{base}");
        root.push_str(&format!(" include:{}", owner.trim_end_matches('.')));
        out.push((owner, chunk));
    }
    root.push(' ');
    root.push_str(qualifier);
    out.insert(0, (base, root));
    Ok(out)
}

/// Every owner name `render` may produce for `name`, so stale chunks can be found.
pub fn chunk_names(name: &Name) -> Vec<String> {
    (0..MAX_CHUNKS).map(|i| format!("_spf{i}.{name}")).collect()
}

/// TXT presentation form of `text`, split into <character-string>s of at most 255 bytes.
/// SPF joins them without spaces (RFC 7208 §3.3), so splitting anywhere is fine.
pub fn txt_data(text: &str) -> String {
    text.as_bytes()
        .chunks(255)
        .map(|c| format!("\"{}\"", String::from_utf8_lossy(c)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake(HashMap<(String, RecordType), Vec<String>>);

    impl Resolve for Fake {
        async fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<String>, String> {
            Ok(self
                .0
                .get(&(name.to_string(), rtype))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn fake(entries: &[(&str, RecordType, &[&str])]) -> Fake {
        Fake(
            entries
                .iter()
                .map(|(n, t, v)| {
                    (
                        (n.to_string(), *t),
                        v.iter().map(|s| s.to_string()).collect(),
                    )
                })
                .collect(),
        )
    }

    fn run(r: &Fake, senders: &[&str]) -> Result<Vec<String>, String> {
        let senders: Vec<String> = senders.iter().map(|s| s.to_string()).collect();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(flatten(r, &senders))
    }

    use RecordType::{A, AAAA, MX, TXT};

    #[test]
    fn flattens_nested_records() {
        let r = fake(&[
            (
                "_spf.mail.test",
                TXT,
                &["v=spf1 include:_n1.mail.test redirect=_r.mail.test"],
            ),
            (
                "_n1.mail.test",
                TXT,
                &[
                    "google-site-verification=x",
                    "v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.0/24 -ip4:198.51.100.1 ~all",
                ],
            ),
            (
                "_r.mail.test",
                TXT,
                &["v=spf1 a mx:mx.mail.test/28 ip6:2001:db8::/32 exp=e.mail.test -all"],
            ),
            ("_r.mail.test", A, &["203.0.113.5"]),
            ("mx.mail.test", MX, &["in.mail.test."]),
            ("in.mail.test", A, &["203.0.113.17"]),
            ("in.mail.test", AAAA, &["2001:db8::1"]),
        ]);
        assert_eq!(
            run(
                &r,
                &[
                    "_SPF.mail.test.",
                    "ip4:10.0.0.1",
                    "10.1.0.0/16",
                    "2001:db8::/32"
                ]
            )
            .unwrap(),
            [
                "ip4:10.0.0.1",
                "ip4:10.1.0.0/16",
                "ip4:192.0.2.0/24",
                "ip4:203.0.113.17/28",
                "ip4:203.0.113.5",
                "ip6:2001:db8::/32",
                "ip6:2001:db8::1",
            ]
        );
    }

    #[test]
    fn rejects_what_cant_be_flattened() {
        let err = |txt: &str| {
            let r = fake(&[
                ("d.test", TXT, &[txt]),
                ("loop.test", TXT, &["v=spf1 include:loop.test"]),
            ]);
            run(&r, &["d.test"]).unwrap_err()
        };
        assert!(err("v=spf1 exists:%{i}._spf.d.test").contains("macro"));
        assert!(err("v=spf1 include:%{d}.x.test").contains("macro"));
        assert!(err("v=spf1 exists:x.d.test").contains("can't be flattened"));
        assert!(err("v=spf1 ptr").contains("can't be flattened"));
        assert!(err("v=spf1 bogus:1").contains("unknown"));
        assert!(err("v=spf1 ip4:300.0.0.1").contains("invalid IP"));
        assert!(err("not spf").contains("no SPF record"));
        // A loop terminates; it isn't an error by itself.
        assert_eq!(
            err("v=spf1 include:loop.test include:nowhere.test"),
            "nowhere.test has no SPF record"
        );

        let deep: Vec<(String, RecordType, Vec<String>)> = (0..=MAX_DEPTH + 1)
            .map(|i| {
                (
                    format!("d{i}.test"),
                    TXT,
                    vec![format!("v=spf1 include:d{}.test", i + 1)],
                )
            })
            .collect();
        let r = Fake(deep.into_iter().map(|(n, t, v)| ((n, t), v)).collect());
        assert!(run(&r, &["d0.test"]).unwrap_err().contains("nested"));
        assert!(
            run(&r, &["not a domain"])
                .unwrap_err()
                .contains("invalid sender")
        );
        assert!(
            run(&r, &["ip4:10.0.0.0/33"])
                .unwrap_err()
                .contains("prefix")
        );
    }

    #[test]
    fn renders_chunks_within_limits() {
        let name = Name::from_ascii("example.test.").unwrap();
        assert_eq!(
            render(&name, &[], "~all").unwrap(),
            [("example.test.".to_string(), "v=spf1 ~all".to_string())]
        );
        let terms: Vec<String> = (0..60).map(|i| format!("ip4:192.0.{i}.0/24")).collect();
        let out = render(&name, &terms, "-all").unwrap();
        assert_eq!(out.len(), 4); // root + 3 chunks
        assert_eq!(
            out[0].1,
            "v=spf1 include:_spf0.example.test include:_spf1.example.test include:_spf2.example.test -all"
        );
        assert!(
            out[1..]
                .iter()
                .all(|(n, t)| n.starts_with("_spf") && t.len() <= CHUNK_BYTES)
        );
        let joined: Vec<&str> = out[1..]
            .iter()
            .flat_map(|(_, t)| t.split(' ').skip(1))
            .collect();
        assert_eq!(joined, terms.iter().map(String::as_str).collect::<Vec<_>>());

        let many: Vec<String> = (0..1000).map(|i| format!("ip6:2001:db8::{i:x}")).collect();
        assert!(
            render(&name, &many, "~all")
                .unwrap_err()
                .contains("lookup limit")
        );

        let long = "x".repeat(300);
        assert_eq!(
            txt_data(&long),
            format!("\"{}\" \"{}\"", &long[..255], &long[255..])
        );
    }
}

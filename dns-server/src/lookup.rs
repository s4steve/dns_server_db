//! Authoritative answer logic (RFC 1034 §4.3.2, RFC 2308, RFC 4592), with no recursion.

use std::collections::HashSet;

use heed::RoTxn;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::store::{Result, Store};

const MAX_CNAME_CHAIN: usize = 8;

#[derive(Debug)]
pub struct Answer {
    pub rcode: ResponseCode,
    pub authoritative: bool,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

enum Step {
    Found(Vec<Record>),
    Cname(Record, Name),
    Referral { ns: Vec<Record>, glue: Vec<Record> },
    NoData,
    NxDomain,
}

pub fn lookup(store: &Store, qname: &Name, qtype: RecordType) -> Result<Answer> {
    let txn = store.read_txn()?;
    let mut ans = Answer {
        rcode: ResponseCode::NoError,
        authoritative: false,
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };
    let mut name = qname.clone();
    let mut seen = HashSet::new();

    for hop in 0..MAX_CNAME_CHAIN {
        let Some(zone) = store.find_zone(&txn, &name)? else {
            if hop == 0 {
                ans.rcode = ResponseCode::Refused;
            }
            // A CNAME pointing outside our zones: return the chain, the resolver follows it.
            return Ok(ans);
        };
        if store.zone_expired(&txn, &zone)? {
            // Stale past SOA EXPIRE: refuse to vouch for anything (RFC 1035 §4.3.5 semantics).
            ans.rcode = ResponseCode::ServFail;
            ans.authoritative = false;
            ans.answers.clear();
            return Ok(ans);
        }
        let step = step(store, &txn, &zone, &name, qtype)?;
        // AA describes the original qname (RFC 1034 §6.2.7): only a referral at the first hop clears it.
        if hop == 0 {
            ans.authoritative = !matches!(step, Step::Referral { .. });
        }
        match step {
            Step::Found(records) => {
                ans.answers.extend(records);
                return Ok(ans);
            }
            Step::Cname(record, target) => {
                ans.answers.push(record);
                seen.insert(name.to_lowercase());
                if seen.contains(&target.to_lowercase()) {
                    return Ok(ans); // CNAME loop: stop where it repeats
                }
                name = target;
            }
            Step::Referral { ns, glue } => {
                ans.authority = ns;
                ans.additional = glue;
                return Ok(ans);
            }
            Step::NoData => {
                ans.authority.push(negative_soa(store, &txn, &zone)?);
                return Ok(ans);
            }
            Step::NxDomain => {
                ans.rcode = ResponseCode::NXDomain;
                ans.authority.push(negative_soa(store, &txn, &zone)?);
                return Ok(ans);
            }
        }
    }
    Ok(ans) // chain longer than MAX_CNAME_CHAIN: return what we have
}

fn step(store: &Store, txn: &RoTxn, zone: &Name, qname: &Name, qtype: RecordType) -> Result<Step> {
    if qname == zone {
        let recs = store.records(txn, zone, zone)?.ok_or("zone apex has no records")?;
        return Ok(at_node(recs, qtype));
    }

    // Walk down from just below the apex to qname, stopping at a zone cut or a missing name.
    let labels: Vec<&[u8]> = qname.iter().collect();
    let zone_depth = zone.iter().count();
    let mut encloser = zone.clone();
    for depth in zone_depth + 1..=labels.len() {
        let node = Name::from_labels(labels[labels.len() - depth..].iter().copied())?;
        match store.records(txn, zone, &node)? {
            // ponytail: no DS special case at the cut; DS isn't a supported type until DNSSEC.
            Some(recs) if recs.iter().any(|r| r.record_type() == RecordType::NS) => {
                return referral(store, txn, zone, recs);
            }
            Some(recs) if depth == labels.len() => return Ok(at_node(recs, qtype)),
            Some(_) => encloser = node,
            None if store.exists(txn, zone, &node)? => {
                if depth == labels.len() {
                    return Ok(Step::NoData); // empty non-terminal
                }
                encloser = node;
            }
            None => break, // nothing exists here or below
        }
    }

    // qname doesn't exist: try the wildcard at the closest encloser (RFC 4592 §4.1).
    let wildcard = Name::from_ascii("*")?.append_name(&encloser)?;
    match store.records(txn, zone, &wildcard)? {
        Some(mut recs) => {
            for r in &mut recs {
                r.name = qname.clone();
            }
            Ok(at_node(recs, qtype))
        }
        None => Ok(Step::NxDomain),
    }
}

fn at_node(recs: Vec<Record>, qtype: RecordType) -> Step {
    let cname = recs.iter().find(|r| r.record_type() == RecordType::CNAME).cloned();
    let matching: Vec<Record> = recs
        .into_iter()
        .filter(|r| qtype == RecordType::ANY || r.record_type() == qtype)
        .collect();
    if !matching.is_empty() {
        return Step::Found(matching);
    }
    match cname {
        Some(r) => {
            let RData::CNAME(target) = &r.data else { unreachable!() };
            let target = target.0.clone();
            Step::Cname(r, target)
        }
        None => Step::NoData,
    }
}

fn referral(store: &Store, txn: &RoTxn, zone: &Name, recs: Vec<Record>) -> Result<Step> {
    let ns: Vec<Record> = recs.into_iter().filter(|r| r.record_type() == RecordType::NS).collect();
    let mut glue = vec![];
    for r in &ns {
        let RData::NS(target) = &r.data else { continue };
        // Glue is read directly, ignoring the cut: it sits below the delegation on purpose.
        if !zone.zone_of(&target.0) {
            continue;
        }
        if let Some(addrs) = store.records(txn, zone, &target.0)? {
            glue.extend(
                addrs
                    .into_iter()
                    .filter(|a| matches!(a.record_type(), RecordType::A | RecordType::AAAA)),
            );
        }
    }
    Ok(Step::Referral { ns, glue })
}

/// The zone's SOA with TTL = min(SOA TTL, SOA MINIMUM), per RFC 2308 §5.
fn negative_soa(store: &Store, txn: &RoTxn, zone: &Name) -> Result<Record> {
    let recs = store.records(txn, zone, zone)?.ok_or("zone apex has no records")?;
    let mut soa = recs
        .into_iter()
        .find(|r| r.record_type() == RecordType::SOA)
        .ok_or("zone has no SOA")?;
    if let RData::SOA(data) = &soa.data {
        soa.ttl = soa.ttl.min(data.minimum);
    }
    Ok(soa)
}

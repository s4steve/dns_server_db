//! Follows the control plane's changelog into the local LMDB store.
//!
//! Each poll asks for entries after the last applied seq and applies the whole page in one
//! LMDB write transaction, together with the new `applied_seq`, so a crash can never leave
//! the store half-updated or out of step with its seq. A brand-new node starts from seq 0
//! and replays the full changelog; entries carry complete per-name record sets, so the
//! replay converges to the current state.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;

use crate::store::{self, APPLIED_SEQ, LAST_SYNC, Result, Store};

const PAGE: usize = 1000;
const MAX_BACKOFF: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
struct Page {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub zone: String,
    pub op: String,
    #[serde(default)]
    pub payload: BTreeMap<String, Vec<Rec>>,
}

#[derive(Deserialize)]
pub struct Rec {
    #[serde(rename = "type")]
    pub rtype: String,
    pub ttl: u32,
    pub data: String,
}

/// Polls forever. Meant for its own thread: LMDB writes and the HTTP client both block.
pub fn run(store: Arc<Store>, control_plane: String, poll: Duration) {
    let mut wait = poll;
    loop {
        match sync_once(&store, &control_plane) {
            Ok(true) => continue, // more pages waiting
            Ok(false) => wait = poll,
            Err(e) => {
                eprintln!("follow {control_plane}: {e}");
                wait = (wait * 2).min(MAX_BACKOFF);
            }
        }
        std::thread::sleep(wait);
    }
}

/// Fetches and applies one page. Returns whether more pages are waiting.
fn sync_once(store: &Store, control_plane: &str) -> Result<bool> {
    let txn = store.read_txn()?;
    let after = store.get_meta(&txn, APPLIED_SEQ)?.unwrap_or(0);
    drop(txn);
    let url = format!("{control_plane}/changelog?after={after}&limit={PAGE}");
    let page: Page = ureq::get(&url).call()?.body_mut().read_json()?;
    let caught_up = page.entries.len() < PAGE;
    apply(store, &page.entries, caught_up.then(store::now))?;
    Ok(!caught_up)
}

/// Applies `entries` in order in one transaction. `synced_at` records that the node is now
/// fully caught up as of that time, which is what keeps its zones from expiring.
pub fn apply(store: &Store, entries: &[Entry], synced_at: Option<u64>) -> Result<()> {
    let mut w = store.write_txn()?;
    for e in entries {
        let zone = Name::from_str(&e.zone)?;
        match e.op.as_str() {
            "names" => {
                for (name, recs) in &e.payload {
                    let name = Name::from_str(name)?;
                    let records = to_records(&name, recs)?;
                    if name == zone {
                        // The apex is in every entry, and its SOA carries the current EXPIRE.
                        let expire = store::soa_expire(&records)
                            .ok_or_else(|| format!("seq {}: apex of {zone} has no SOA", e.seq))?;
                        store.put_zone(&mut w, &zone, expire)?;
                    }
                    store.put_name(&mut w, &zone, &name, &records)?;
                }
                if !store.has_zone(&w, &zone)? {
                    return Err(format!("seq {}: {zone} has no SOA yet", e.seq).into());
                }
            }
            "delete_zone" => store.delete_zone(&mut w, &zone)?,
            // Halting beats guessing: the node stops advancing (and eventually expires its
            // zones) rather than serve data it doesn't understand.
            op => return Err(format!("seq {}: unknown op {op:?}", e.seq).into()),
        }
        store.set_meta(&mut w, APPLIED_SEQ, e.seq)?;
    }
    // ponytail: persisted on every caught-up poll (one LMDB fsync per poll interval) so freshness
    // survives restarts. Write it every N polls if that fsync rate ever matters.
    if let Some(t) = synced_at {
        store.set_meta(&mut w, LAST_SYNC, t)?;
    }
    w.commit()?;
    Ok(())
}

fn to_records(name: &Name, recs: &[Rec]) -> Result<Vec<Record>> {
    recs.iter()
        .map(|r| {
            let rtype = RecordType::from_str(&r.rtype)?;
            let data = RData::try_from_str(rtype, &r.data)
                .map_err(|e| format!("{name} {rtype} {:?}: {e}", r.data))?;
            Ok(Record::from_rdata(name.clone(), r.ttl, data))
        })
        .collect()
}

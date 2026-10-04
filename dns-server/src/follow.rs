//! Follows the control plane's changelog into the local LMDB store.
//!
//! Each poll asks for entries after the last applied seq and applies the whole page in one
//! LMDB write transaction, together with the new `applied_seq`, so a crash can never leave
//! the store half-updated or out of step with its seq. A brand-new node starts from seq 0
//! and replays the full changelog; entries carry complete per-name record sets, so the
//! replay converges to the current state.
//!
//! The changelog delivers changes within a second. On top of that, each zone is verified
//! the way RFC 1035 secondaries do it: every SOA REFRESH seconds the node compares its
//! serial with the control plane's and re-fetches the whole zone if they differ (RETRY
//! seconds after a failed check). That repairs drift the changelog can't see, such as a
//! local edit. Following makes the node a mirror: zones the control plane doesn't have are
//! removed. EXPIRE counts from the last successful sync (see `Store::zone_expired`).

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;

use crate::store::{self, Result, Store, APPLIED_SEQ, LAST_SYNC};

const PAGE: usize = 1000;
const MAX_BACKOFF: Duration = Duration::from_secs(10);
/// Longest gap between verification passes, so newly created zones get checked too.
const MAX_PASS_GAP: Duration = Duration::from_secs(60);

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
    let mut checks = Checks::default();
    loop {
        match sync_once(&store, &control_plane) {
            Ok((more, zones)) => {
                checks.track(zones);
                if more {
                    continue;
                }
                wait = poll;
                if let Err(e) = checks.run_due(&store, &control_plane) {
                    eprintln!("refresh check: {e}");
                }
            }
            Err(e) => {
                eprintln!("follow {control_plane}: {e}");
                crate::metrics::inc(&crate::metrics::FOLLOW_ERRORS);
                wait = (wait * 2).min(MAX_BACKOFF);
            }
        }
        std::thread::sleep(wait);
    }
}

/// Fetches and applies one page. Returns whether more pages are waiting, and the zones
/// the page touched.
fn sync_once(store: &Store, control_plane: &str) -> Result<(bool, Vec<Name>)> {
    let txn = store.read_txn()?;
    let after = store.get_meta(&txn, APPLIED_SEQ)?.unwrap_or(0);
    drop(txn);
    let url = format!("{control_plane}/changelog?after={after}&limit={PAGE}");
    let page: Page = ureq::get(&url).call()?.body_mut().read_json()?;
    let caught_up = page.entries.len() < PAGE;
    apply(store, &page.entries, caught_up.then(store::now))?;
    let zones = page
        .entries
        .iter()
        .filter_map(|e| Name::from_str(&e.zone).ok())
        .collect();
    Ok((!caught_up, zones))
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
    recs.iter().map(|r| to_record(name, r)).collect()
}

fn to_record(name: &Name, r: &Rec) -> Result<Record> {
    if r.rtype == "LUA" {
        return Ok(crate::script::lua_record(name, r.ttl, &r.data)?);
    }
    let rtype = RecordType::from_str(&r.rtype)?;
    let data = RData::try_from_str(rtype, &r.data)
        .map_err(|e| format!("{name} {rtype} {:?}: {e}", r.data))?;
    Ok(Record::from_rdata(name.clone(), r.ttl, data))
}

// ---------- SOA REFRESH / RETRY verification ----------

#[derive(Deserialize)]
struct RemoteZones {
    seq: u64,
    zones: Vec<RemoteZone>,
}

#[derive(Deserialize)]
struct RemoteZone {
    name: String,
    serial: u32,
}

#[derive(Deserialize)]
struct Snapshot {
    default_ttl: u32,
    serial: u32,
    soa: SnapshotSoa,
    records: Vec<SnapshotRecord>,
}

#[derive(Deserialize)]
struct SnapshotSoa {
    mname: String,
    rname: String,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

#[derive(Deserialize)]
struct SnapshotRecord {
    name: String,
    #[serde(flatten)]
    rec: Rec,
}

/// When each zone is next due for a serial check. Kept in memory: after a restart every
/// zone is checked straight away, which is what a restarted secondary does too.
#[derive(Default)]
struct Checks {
    due: HashMap<Name, Instant>,
    next_pass: Option<Instant>,
}

fn secs(v: i32) -> Duration {
    Duration::from_secs(v.max(1) as u64)
}

impl Checks {
    /// Zones the changelog brought in that have no check scheduled yet get one on the next
    /// pass, which starts their REFRESH timer. Existing timers are left alone.
    fn track(&mut self, zones: Vec<Name>) {
        let now = Instant::now();
        for zone in zones {
            if !self.due.contains_key(&zone) {
                self.due.insert(zone, now);
                self.next_pass = Some(now);
            }
        }
    }

    fn run_due(&mut self, store: &Store, control_plane: &str) -> Result<()> {
        let now = Instant::now();
        if self.next_pass.is_some_and(|t| now < t) {
            return Ok(());
        }
        let (local, applied) = {
            let txn = store.read_txn()?;
            (
                store.zones(&txn)?,
                store.get_meta(&txn, APPLIED_SEQ)?.unwrap_or(0),
            )
        };
        let is_due = |due: &HashMap<Name, Instant>, z: &Name| due.get(z).is_none_or(|t| *t <= now);

        let remote: RemoteZones = match ureq::get(&format!("{control_plane}/zones"))
            .call()
            .and_then(|mut r| r.body_mut().read_json())
        {
            Ok(r) => r,
            Err(e) => {
                for (zone, soa) in &local {
                    if is_due(&self.due, zone) {
                        self.due.insert(zone.clone(), now + secs(soa.retry));
                    }
                }
                self.schedule(now);
                return Err(format!("listing zones: {e}").into());
            }
        };
        if remote.seq != applied {
            // A change is in flight; comparing now would report a false mismatch.
            self.next_pass = Some(now + Duration::from_secs(1));
            return Ok(());
        }
        let remote: HashMap<Name, u32> = remote
            .zones
            .iter()
            .filter_map(|z| Some((Name::from_str(&z.name).ok()?, z.serial)))
            .collect();

        for (zone, soa) in &local {
            if !is_due(&self.due, zone) {
                continue;
            }
            let checked = match remote.get(zone) {
                Some(&serial) if serial == soa.serial => Ok(()),
                Some(&serial) => {
                    eprintln!(
                        "refresh: {zone} serial {} here, {serial} upstream; re-fetching",
                        soa.serial
                    );
                    crate::metrics::inc(&crate::metrics::REFRESH_REPAIRS);
                    refetch(store, control_plane, zone)
                }
                None => {
                    eprintln!("refresh: {zone} is not on the control plane; removing it");
                    crate::metrics::inc(&crate::metrics::REFRESH_REPAIRS);
                    remove(store, zone)
                }
            };
            let wait = match checked {
                Ok(()) => secs(soa.refresh),
                Err(e) => {
                    eprintln!("refresh: {zone}: {e}");
                    secs(soa.retry)
                }
            };
            self.due.insert(zone.clone(), now + wait);
        }
        for zone in remote
            .keys()
            .filter(|z| !local.iter().any(|(l, _)| l == *z))
        {
            eprintln!("refresh: {zone} is missing here; fetching it");
            if let Err(e) = refetch(store, control_plane, zone) {
                eprintln!("refresh: {zone}: {e}"); // retried on the next pass
            }
        }
        self.due.retain(|z, _| remote.contains_key(z));
        self.schedule(now);
        Ok(())
    }

    fn schedule(&mut self, now: Instant) {
        let earliest = self
            .due
            .values()
            .min()
            .copied()
            .unwrap_or(now + MAX_PASS_GAP);
        self.next_pass = Some(earliest.min(now + MAX_PASS_GAP));
    }
}

/// Replaces the local copy of `zone` with the control plane's current contents.
fn refetch(store: &Store, control_plane: &str, zone: &Name) -> Result<()> {
    let snap: Snapshot = ureq::get(&format!("{control_plane}/zones/{zone}"))
        .call()?
        .body_mut()
        .read_json()?;
    let s = &snap.soa;
    let soa = Rec {
        rtype: "SOA".into(),
        ttl: snap.default_ttl,
        data: format!(
            "{} {} {} {} {} {} {}",
            s.mname, s.rname, snap.serial, s.refresh, s.retry, s.expire, s.minimum
        ),
    };
    let mut records = vec![to_record(zone, &soa)?];
    for r in &snap.records {
        records.push(to_record(&Name::from_str(&r.name)?, &r.rec)?);
    }
    store.load_zone(zone, records)?;
    Ok(())
}

fn remove(store: &Store, zone: &Name) -> Result<()> {
    let mut w = store.write_txn()?;
    store.delete_zone(&mut w, zone)?;
    w.commit()?;
    Ok(())
}

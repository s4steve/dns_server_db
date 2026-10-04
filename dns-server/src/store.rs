//! LMDB-backed record store.
//!
//! Three databases:
//! - `zones`: zone apex key -> the zone's SOA EXPIRE (u32, big-endian)
//! - `names`: record key -> every record at that owner name, wire-encoded back to back
//! - `meta`: node sync state (`applied_seq`, `last_sync`), u64 big-endian
//!
//! A name key is the name's labels, root-first, each length-prefixed and lowercased:
//! `www.Example.com.` -> `\x03com\x07example\x03www`. Length prefixes make the encoding
//! prefix-free per label, so the keys of a name's descendants all start with that name's key.
//!
//! A record key is `zone key ++ 0x00 ++ the rest of the name's key`. A label length is never
//! 0, so the 0x00 separates zones: a hosted child zone (sub.example.com) never shares a key
//! prefix with its parent's records, and reloading the parent can't touch the child.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, RoTxn, RwTxn, WithTls};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ponytail: fixed 1 GiB map (sparse, virtual). Make it configurable when a dataset nears it.
const MAP_SIZE: usize = 1 << 30;

/// Changelog seq of the last entry applied to this node.
pub const APPLIED_SEQ: &[u8] = b"applied_seq";
/// Unix time of the last poll that found this node fully caught up.
pub const LAST_SYNC: &[u8] = b"last_sync";

pub struct Store {
    env: Env,
    zones: Database<Bytes, Bytes>,
    names: Database<Bytes, Bytes>,
    meta: Database<Bytes, Bytes>,
    /// When following a control plane, a zone stops being served (SERVFAIL) once the node
    /// has gone longer than the zone's SOA EXPIRE without a successful sync.
    pub enforce_expiry: bool,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        // SAFETY: the env is opened once per process and the files are only touched through LMDB.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(MAP_SIZE)
                .max_dbs(3)
                .open(path)?
        };
        let mut w = env.write_txn()?;
        let zones = env.create_database(&mut w, Some("zones"))?;
        let names = env.create_database(&mut w, Some("names"))?;
        let meta = env.create_database(&mut w, Some("meta"))?;
        w.commit()?;
        Ok(Self {
            env,
            zones,
            names,
            meta,
            enforce_expiry: false,
        })
    }

    pub fn read_txn(&self) -> Result<RoTxn<'_, WithTls>> {
        Ok(self.env.read_txn()?)
    }

    pub fn write_txn(&self) -> Result<RwTxn<'_>> {
        Ok(self.env.write_txn()?)
    }

    /// The deepest zone we host that contains `name`.
    pub fn find_zone(&self, txn: &RoTxn, name: &Name) -> Result<Option<Name>> {
        // ponytail: we never host the root zone (its key would be empty, which LMDB rejects).
        let mut n = name.clone();
        while !n.is_root() {
            if self.zones.get(txn, &name_key(&n))?.is_some() {
                return Ok(Some(n));
            }
            n = n.base_name();
        }
        Ok(None)
    }

    /// Whether `zone` has passed its SOA EXPIRE since the node last synced. A node that has
    /// never synced has nothing fresh to serve.
    pub fn zone_expired(&self, txn: &RoTxn, zone: &Name) -> Result<bool> {
        if !self.enforce_expiry {
            return Ok(false);
        }
        let Some(expire) = self.zones.get(txn, &name_key(zone))? else {
            return Ok(true);
        };
        let expire = u32::from_be_bytes(expire.try_into()?);
        Ok(match self.get_meta(txn, LAST_SYNC)? {
            Some(last) => now() > last + u64::from(expire),
            None => true,
        })
    }

    /// Every zone with its SOA.
    pub fn zones(&self, txn: &RoTxn) -> Result<Vec<(Name, SOA)>> {
        let mut out = vec![];
        for entry in self.zones.iter(txn)? {
            let zone = key_to_name(entry?.0)?;
            let apex = self.records(txn, &zone, &zone)?.unwrap_or_default();
            let soa = apex.into_iter().find_map(|r| match r.data {
                RData::SOA(soa) => Some(soa),
                _ => None,
            });
            out.push((
                zone.clone(),
                soa.ok_or_else(|| format!("zone {zone} has no SOA"))?,
            ));
        }
        Ok(out)
    }

    pub fn has_zone(&self, txn: &RoTxn, zone: &Name) -> Result<bool> {
        Ok(self.zones.get(txn, &name_key(zone))?.is_some())
    }

    /// Every record at exactly `name`, or None if the name has no records.
    pub fn records(&self, txn: &RoTxn, zone: &Name, name: &Name) -> Result<Option<Vec<Record>>> {
        match self.names.get(txn, &record_key(zone, name))? {
            Some(bytes) => Ok(Some(decode(bytes)?)),
            None => Ok(None),
        }
    }

    /// Whether `name` exists in the RFC 4592 sense: it has records or any descendant does,
    /// so empty non-terminals count.
    pub fn exists(&self, txn: &RoTxn, zone: &Name, name: &Name) -> Result<bool> {
        Ok(self
            .names
            .prefix_iter(txn, &record_key(zone, name))?
            .next()
            .is_some())
    }

    /// Atomically replaces everything in `origin` with `records`.
    pub fn load_zone(&self, origin: &Name, records: Vec<Record>) -> Result<usize> {
        let mut by_name: BTreeMap<Vec<u8>, (Name, Vec<Record>)> = BTreeMap::new();
        for r in records {
            if !origin.zone_of(&r.name) {
                return Err(format!("{} is outside zone {origin}", &r.name).into());
            }
            let entry = by_name.entry(record_key(origin, &r.name));
            entry.or_insert_with(|| (r.name.clone(), vec![])).1.push(r);
        }
        let apex = by_name
            .get(&record_key(origin, origin))
            .map(|(_, recs)| recs.as_slice());
        let expire = soa_expire(apex.unwrap_or_default())
            .ok_or_else(|| format!("zone {origin} has no SOA at its apex"))?;

        let mut w = self.write_txn()?;
        self.delete_zone(&mut w, origin)?;
        for (name, recs) in by_name.values() {
            self.put_name(&mut w, origin, name, recs)?;
        }
        self.put_zone(&mut w, origin, expire)?;
        w.commit()?;
        Ok(by_name.len())
    }

    pub fn put_zone(&self, w: &mut RwTxn, zone: &Name, expire: u32) -> Result<()> {
        Ok(self.zones.put(w, &name_key(zone), &expire.to_be_bytes())?)
    }

    /// Removes the zone and all of its records.
    pub fn delete_zone(&self, w: &mut RwTxn, zone: &Name) -> Result<()> {
        let mut prefix = name_key(zone);
        self.zones.delete(w, &prefix)?;
        prefix.push(0);
        let mut old = self.names.prefix_iter_mut(w, &prefix)?;
        while old.next().transpose()?.is_some() {
            // SAFETY: no references into the database are held across the delete.
            unsafe { old.del_current()? };
        }
        Ok(())
    }

    /// Replaces every record at `name`; an empty slice removes the name.
    pub fn put_name(
        &self,
        w: &mut RwTxn,
        zone: &Name,
        name: &Name,
        records: &[Record],
    ) -> Result<()> {
        let key = record_key(zone, name);
        if records.is_empty() {
            self.names.delete(w, &key)?;
        } else {
            self.names.put(w, &key, &encode(records)?)?;
        }
        Ok(())
    }

    pub fn get_meta(&self, txn: &RoTxn, key: &[u8]) -> Result<Option<u64>> {
        match self.meta.get(txn, key)? {
            Some(v) => Ok(Some(u64::from_be_bytes(v.try_into()?))),
            None => Ok(None),
        }
    }

    pub fn set_meta(&self, w: &mut RwTxn, key: &[u8], value: u64) -> Result<()> {
        Ok(self.meta.put(w, key, &value.to_be_bytes())?)
    }
}

/// The SOA EXPIRE among `records`, if they include an SOA.
pub fn soa_expire(records: &[Record]) -> Option<u32> {
    records.iter().find_map(|r| match &r.data {
        RData::SOA(soa) => Some(soa.expire.max(0) as u32),
        _ => None,
    })
}

fn name_key(name: &Name) -> Vec<u8> {
    let labels: Vec<&[u8]> = name.iter().collect();
    let mut key = Vec::with_capacity(name.len());
    for label in labels.iter().rev() {
        key.push(label.len() as u8);
        key.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    key
}

fn key_to_name(key: &[u8]) -> Result<Name> {
    let mut labels = vec![];
    let mut rest = key;
    while let Some((&len, tail)) = rest.split_first() {
        let (label, tail) = tail
            .split_at_checked(len as usize)
            .ok_or("corrupt name key")?;
        labels.push(label);
        rest = tail;
    }
    labels.reverse();
    Ok(Name::from_labels(labels)?)
}

fn record_key(zone: &Name, name: &Name) -> Vec<u8> {
    let zkey = name_key(zone);
    let nkey = name_key(name);
    debug_assert!(nkey.starts_with(&zkey), "{name} is not in {zone}");
    let mut key = zkey;
    key.push(0);
    key.extend_from_slice(&nkey[key.len() - 1..]);
    key
}

// Name compression pointers are offsets into this buffer, and decoding always starts from
// the same buffer, so they resolve correctly and keep the stored owner-name case.
fn encode(records: &[Record]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut enc = BinEncoder::new(&mut buf);
    for r in records {
        r.emit(&mut enc)?;
    }
    Ok(buf)
}

fn decode(bytes: &[u8]) -> Result<Vec<Record>> {
    let mut dec = BinDecoder::new(bytes);
    let mut out = Vec::new();
    while !dec.is_empty() {
        out.push(Record::read(&mut dec)?);
    }
    Ok(out)
}

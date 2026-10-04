//! LMDB-backed record store.
//!
//! Two databases:
//! - `zones`: zone apex key -> ()
//! - `names`: record key -> every record at that owner name, wire-encoded back to back
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

use heed::types::{Bytes, Unit};
use heed::{Database, Env, EnvOpenOptions, RoTxn, WithTls};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ponytail: fixed 1 GiB map (sparse, virtual). Make it configurable when a dataset nears it.
const MAP_SIZE: usize = 1 << 30;

pub struct Store {
    env: Env,
    zones: Database<Bytes, Unit>,
    names: Database<Bytes, Bytes>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        // SAFETY: the env is opened once per process and the files are only touched through LMDB.
        let env = unsafe { EnvOpenOptions::new().map_size(MAP_SIZE).max_dbs(2).open(path)? };
        let mut w = env.write_txn()?;
        let zones = env.create_database(&mut w, Some("zones"))?;
        let names = env.create_database(&mut w, Some("names"))?;
        w.commit()?;
        Ok(Self { env, zones, names })
    }

    pub fn read_txn(&self) -> Result<RoTxn<'_, WithTls>> {
        Ok(self.env.read_txn()?)
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
        Ok(self.names.prefix_iter(txn, &record_key(zone, name))?.next().is_some())
    }

    /// Atomically replaces everything in `origin` with `records`.
    pub fn load_zone(&self, origin: &Name, records: Vec<Record>) -> Result<usize> {
        let mut by_name: BTreeMap<Vec<u8>, Vec<Record>> = BTreeMap::new();
        let mut has_soa = false;
        for r in records {
            if !origin.zone_of(&r.name) {
                return Err(format!("{} is outside zone {origin}", &r.name).into());
            }
            has_soa |= r.record_type() == RecordType::SOA && r.name == *origin;
            by_name.entry(record_key(origin, &r.name)).or_default().push(r);
        }
        if !has_soa {
            return Err(format!("zone {origin} has no SOA at its apex").into());
        }

        let zkey = name_key(origin);
        let mut prefix = zkey.clone();
        prefix.push(0);

        let mut w = self.env.write_txn()?;
        let mut old = self.names.prefix_iter_mut(&mut w, &prefix)?;
        while old.next().transpose()?.is_some() {
            // SAFETY: no references into the database are held across the delete.
            unsafe { old.del_current()? };
        }
        drop(old);
        for (key, recs) in &by_name {
            self.names.put(&mut w, key, &encode(recs)?)?;
        }
        self.zones.put(&mut w, &zkey, &())?;
        w.commit()?;
        Ok(by_name.len())
    }
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

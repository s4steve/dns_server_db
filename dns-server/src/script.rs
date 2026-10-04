//! LuaJIT scripts that tailor answers per query (`LUA` records).
//!
//! A script is the body of a function. It reads the query from the table `q`:
//!
//! | field | value |
//! |---|---|
//! | `q.name` | query name, lowercase FQDN (the real name, even when the script is on a wildcard) |
//! | `q.type` | query type, e.g. `"A"` |
//! | `q.client` | client address: the EDNS Client Subnet address if sent, else the source IP |
//! | `q.client_prefix` | ECS source prefix length, or 32/128 for a plain source IP |
//! | `q.source` | the packet's source IP (usually a resolver) |
//! | `q.node` | this node's ID (`--node-id`) |
//! | `q.static` | list of the static records this script overrides, as text |
//!
//! It returns record data in zone-file syntax: one string, or a list of strings. `nil` (or
//! an empty list) means "no tailored answer": the static records are served instead.
//!
//! Sandbox: one Lua state per worker thread (LuaJIT states aren't thread-safe), each script
//! in its own environment over a read-only base of `math`, `string`, `table`, a few safe
//! builtins and `in_cidr(ip, "10.0.0.0/8")`. No `io`, `os`, `require`, `debug`, `ffi` or
//! `load`. Each call gets an instruction budget and the state has a memory limit.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;

use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use mlua::{Function, HookTriggers, Lua, LuaOptions, StdLib, Table, Value, VmState};

/// `LUA` records are stored under a private-use type code (RFC 6895 §3.1) and never served.
/// RDATA: the record type the script answers for (u16, big-endian), then the script source.
pub const LUA: RecordType = RecordType::Unknown(65402);

/// Builds a stored `LUA` record from changelog text: `"<TYPE> <script>"`.
pub fn lua_record(name: &Name, ttl: u32, data: &str) -> Result<Record, String> {
    let (target, source) = data
        .trim_start()
        .split_once(char::is_whitespace)
        .ok_or("LUA data must be \"<TYPE> <script>\"")?;
    let target: RecordType = target
        .parse()
        .map_err(|_| format!("unknown record type {target:?}"))?;
    let mut rdata = u16::from(target).to_be_bytes().to_vec();
    rdata.extend_from_slice(source.as_bytes());
    Ok(Record::from_rdata(
        name.clone(),
        ttl,
        RData::Unknown {
            code: LUA,
            rdata: NULL::with(rdata),
        },
    ))
}

/// The (answered type, script source) of a stored `LUA` record.
pub fn decode_lua(r: &Record) -> Option<(RecordType, &str)> {
    let RData::Unknown { code, rdata } = &r.data else {
        return None;
    };
    if *code != LUA || rdata.anything.len() < 2 {
        return None;
    }
    let target = RecordType::from(u16::from_be_bytes([rdata.anything[0], rdata.anything[1]]));
    Some((target, std::str::from_utf8(&rdata.anything[2..]).ok()?))
}

/// Per-call instruction budget. Interpreted LuaJIT runs very roughly 100-500M instructions/s,
/// so this is well under a millisecond for any script that stays within it.
const INSTRUCTION_BUDGET: u64 = 200_000;
const HOOK_EVERY: u32 = 1_000;
const MEMORY_LIMIT: usize = 64 << 20; // per worker thread
                                      // ponytail: unbounded per-thread compile cache; scripts are few. Evict if that changes.

pub struct Input<'a> {
    pub qname: &'a str,
    pub qtype: &'a str,
    pub client: IpAddr,
    pub client_prefix: u8,
    pub source: IpAddr,
    pub node: &'a str,
    pub statics: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Answer(Vec<String>),
    Empty,
    Error(String),
}

struct Engine {
    lua: Lua,
    base: Table,
    scripts: HashMap<String, (Function, Table)>,
    instructions: Rc<Cell<u64>>,
}

thread_local! {
    static ENGINE: RefCell<Option<Engine>> = const { RefCell::new(None) };
}

pub fn run(source: &str, input: &Input) -> Outcome {
    ENGINE.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            match Engine::new() {
                Ok(e) => *slot = Some(e),
                Err(e) => return Outcome::Error(format!("starting Lua: {e}")),
            }
        }
        let engine = slot.as_mut().unwrap();
        match engine.call(source, input) {
            Ok(outcome) => outcome,
            Err(e) => Outcome::Error(e.to_string()),
        }
    })
}

impl Engine {
    fn new() -> mlua::Result<Self> {
        let lua = Lua::new_with(
            StdLib::MATH | StdLib::STRING | StdLib::TABLE | StdLib::JIT,
            LuaOptions::default(),
        )?;
        // Count hooks don't fire inside JIT-compiled traces, so a runaway loop could never be
        // stopped. Interpreted LuaJIT is still fast; the budget only works without the JIT.
        // ponytail: JIT off for safety. Revisit with a watchdog if scripts become CPU-heavy.
        lua.load("jit.off()").exec()?;
        let _ = lua.set_memory_limit(MEMORY_LIMIT); // unsupported on some LuaJIT builds

        let globals = lua.globals();
        let deny_write = lua.create_function(|_, ()| -> mlua::Result<()> {
            Err(mlua::Error::runtime(
                "the script base environment is read-only",
            ))
        })?;
        // An empty proxy that reads through to `t` and rejects every write. (`__newindex`
        // alone only fires for missing keys, so it can't protect `t` itself.)
        let read_only = |t: Table| -> mlua::Result<Table> {
            let meta = lua.create_table()?;
            meta.set("__index", t)?;
            meta.set("__newindex", deny_write.clone())?;
            meta.set("__metatable", false)?;
            let proxy = lua.create_table()?;
            proxy.set_metatable(Some(meta))?;
            Ok(proxy)
        };
        let base = lua.create_table()?;
        for name in ["math", "string", "table"] {
            base.set(name, read_only(globals.get::<Table>(name)?)?)?;
        }
        for name in [
            "pairs", "ipairs", "next", "select", "type", "tostring", "tonumber", "error", "pcall",
            "unpack", "assert",
        ] {
            base.set(name, globals.get::<Value>(name)?)?;
        }
        base.set(
            "in_cidr",
            lua.create_function(|_, (ip, cidr): (String, String)| Ok(in_cidr(&ip, &cidr)))?,
        )?;
        let base = read_only(base)?;

        let instructions = Rc::new(Cell::new(0));
        let counter = instructions.clone();
        lua.set_hook(
            HookTriggers::new().every_nth_instruction(HOOK_EVERY),
            move |_, _| {
                counter.set(counter.get() + u64::from(HOOK_EVERY));
                if counter.get() > INSTRUCTION_BUDGET {
                    return Err(mlua::Error::runtime("instruction budget exceeded"));
                }
                Ok(VmState::Continue)
            },
        )?;
        Ok(Self {
            lua,
            base,
            scripts: HashMap::new(),
            instructions,
        })
    }

    fn call(&mut self, source: &str, input: &Input) -> mlua::Result<Outcome> {
        if !self.scripts.contains_key(source) {
            // Each script gets its own globals, reading through to the shared base.
            let env = self.lua.create_table()?;
            let meta = self.lua.create_table()?;
            meta.set("__index", self.base.clone())?;
            env.set_metatable(Some(meta))?;
            let f = self
                .lua
                .load(source)
                .set_environment(env.clone())
                .into_function()?;
            self.scripts.insert(source.to_string(), (f, env));
        }
        let (f, env) = &self.scripts[source];

        let q = self.lua.create_table()?;
        q.set("name", input.qname)?;
        q.set("type", input.qtype)?;
        q.set("client", input.client.to_string())?;
        q.set("client_prefix", input.client_prefix)?;
        q.set("source", input.source.to_string())?;
        q.set("node", input.node)?;
        q.set("static", input.statics.clone())?;
        env.set("q", q)?;

        self.instructions.set(0);
        Ok(match f.call::<Value>(())? {
            Value::Nil => Outcome::Empty,
            Value::String(s) => Outcome::Answer(vec![s.to_str()?.to_string()]),
            Value::Table(t) => {
                let items = t
                    .sequence_values::<String>()
                    .collect::<mlua::Result<Vec<_>>>()?;
                if items.is_empty() {
                    Outcome::Empty
                } else {
                    Outcome::Answer(items)
                }
            }
            other => Outcome::Error(format!(
                "script returned a {}, expected a string, a list of strings, or nil",
                other.type_name()
            )),
        })
    }
}

fn in_cidr(ip: &str, cidr: &str) -> bool {
    let Some((net, len)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(ip), Ok(net), Ok(len)) = (
        ip.parse::<IpAddr>(),
        net.parse::<IpAddr>(),
        len.parse::<u32>(),
    ) else {
        return false;
    };
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) if len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) if len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input<'static> {
        Input {
            qname: "www.example.com.",
            qtype: "A",
            client: "10.1.2.0".parse().unwrap(),
            client_prefix: 24,
            source: "192.0.2.53".parse().unwrap(),
            node: "node1",
            statics: vec!["198.51.100.1".into()],
        }
    }

    #[test]
    fn runs_and_sandboxes() {
        let i = input();
        assert_eq!(
            run(r#"return "192.0.2.1""#, &i),
            Outcome::Answer(vec!["192.0.2.1".into()])
        );
        assert_eq!(
            run(
                r#"return { q.client, q.node, q.static[1], tostring(q.client_prefix) }"#,
                &i
            ),
            Outcome::Answer(vec![
                "10.1.2.0".into(),
                "node1".into(),
                "198.51.100.1".into(),
                "24".into()
            ])
        );
        assert_eq!(run("return nil", &i), Outcome::Empty);
        assert_eq!(run("return {}", &i), Outcome::Empty);
        assert!(matches!(run("return 42", &i), Outcome::Error(_)));
        assert!(matches!(run(r#"error("boom")"#, &i), Outcome::Error(e) if e.contains("boom")));
        assert!(matches!(run("while true do end", &i), Outcome::Error(e) if e.contains("budget")));
        for escape in [
            "return os.getenv('HOME')",
            "return io.open('/etc/passwd')",
            "return require('x')",
            "return load('return 1')()",
            "return debug.getinfo(1)",
            "return jit.on()",
        ] {
            assert!(
                matches!(run(escape, &i), Outcome::Error(_)),
                "{escape} escaped the sandbox"
            );
        }
        // Scripts can't write the shared base, and their globals don't leak into each other.
        assert!(matches!(
            run("string.rep = nil return 'x'", &i),
            Outcome::Error(_)
        ));
        assert_eq!(
            run("in_cidr = nil return 'x'", &i),
            Outcome::Answer(vec!["x".into()])
        ); // shadows only its own global
        assert_eq!(
            run("return string.rep('a', 2)", &i),
            Outcome::Answer(vec!["aa".into()])
        );
        assert_eq!(
            run("return tostring(in_cidr ~= nil)", &i),
            Outcome::Answer(vec!["true".into()])
        );
        assert_eq!(
            run("leak = 1 return 'ok'", &i),
            Outcome::Answer(vec!["ok".into()])
        );
        assert_eq!(
            run("return tostring(leak)", &i),
            Outcome::Answer(vec!["nil".into()])
        );
        // The budget is per call: a heavy-but-finite script still works afterwards.
        assert_eq!(
            run(
                "local s = 0 for i = 1, 10000 do s = s + i end return tostring(s)",
                &i
            ),
            Outcome::Answer(vec!["50005000".into()])
        );
    }

    #[test]
    fn cidr() {
        assert!(in_cidr("10.1.2.3", "10.0.0.0/8"));
        assert!(!in_cidr("11.1.2.3", "10.0.0.0/8"));
        assert!(in_cidr("1.2.3.4", "0.0.0.0/0"));
        assert!(in_cidr("2001:db8::1", "2001:db8::/32"));
        assert!(!in_cidr("2001:db9::1", "2001:db8::/32"));
        assert!(!in_cidr("10.1.2.3", "2001:db8::/32"));
        assert!(!in_cidr("garbage", "10.0.0.0/8"));
    }
}

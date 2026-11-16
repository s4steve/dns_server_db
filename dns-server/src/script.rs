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
//! Sandbox: each query thread hands its scripts to its own runner thread, which owns one Lua
//! state (LuaJIT states aren't thread-safe). Each script runs in its own environment over a
//! read-only base of `math`, `string`, `table`, a few safe builtins and
//! `in_cidr(ip, "10.0.0.0/8")`. No `io`, `os`, `require`, `debug`, `ffi`, `load` or `pcall`
//! (which could catch the budget error). Source text only, never bytecode. Each call gets an
//! instruction budget and a wall-clock limit, the state has a memory limit, and `string.rep`
//! output is capped.
//!
//! The wall-clock limit covers what the instruction budget can't: time spent inside C
//! functions (pattern matching, big concatenations). A script that exceeds it is disabled on
//! this node while that call is still running and for a cooldown afterwards, and its runner
//! thread is abandoned and replaced, so a hung script never holds a query thread for longer
//! than the limit. Abandoned runners are counted: past a cap, the node stops running scripts.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU8, Ordering::SeqCst};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, LazyLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use mlua::chunk::ChunkMode;
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
const HOOK_EVERY: u32 = 100;
/// A script that hit the time limit stays off this long after its call returns. Under heavy
/// load a healthy script can miss the limit; this lets it come back by itself.
const COOLDOWN: Duration = Duration::from_secs(60);
/// Abandoned runners still inside a call. At this many the node stops running scripts, so
/// hung scripts can't keep taking threads.
// ponytail: calls already in flight when a script first hangs can each strand a runner, so
// one burst can pass the cap (by up to the worker count). A killable child process is the
// upgrade if that matters.
pub const MAX_STUCK: i64 = 4;
const MEMORY_LIMIT: usize = 64 << 20; // per worker thread
/// Largest string `string.rep` may build. It runs in C, where the instruction budget can't stop it.
const MAX_REP_BYTES: usize = 64 * 1024;
/// Wall-clock limit per call, including time in C functions. Well-behaved scripts take
/// microseconds; this only has to stay under resolvers' retry timeouts.
const TIME_LIMIT: Duration = Duration::from_millis(100);
/// Compiled scripts kept per runner. Past this the cache starts over, so scripts that were
/// edited or deleted don't pile up for the life of the process.
// ponytail: clear-all eviction; an LRU only if a node serves more distinct scripts than this.
const MAX_CACHED_SCRIPTS: usize = 1000;

#[derive(Clone)]
pub struct Input {
    pub qname: String,
    pub qtype: String,
    pub client: IpAddr,
    pub client_prefix: u8,
    pub source: IpAddr,
    pub node: String,
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

/// A thread that runs one query thread's scripts, one call at a time, so a call never waits
/// in a queue and the time limit measures only the script.
struct Runner {
    jobs: mpsc::Sender<(String, Input)>,
    results: mpsc::Receiver<Outcome>,
    /// Decides the race between "the call finished" and "the caller gave up".
    state: Arc<AtomicU8>,
    /// The runner's OS thread ID (Linux), so an abandoned one can be deprioritised.
    tid: Arc<AtomicI32>,
}

const RUNNING: u8 = 0;
const DONE: u8 = 1;
const ABANDONED: u8 = 2;

/// Why a script is off: calls of it still stuck in abandoned runners, and a cooldown.
struct Strike {
    stuck: usize,
    until: Instant,
}

/// Abandoned runners that are still inside a call (`dns_lua_stuck_runners`).
pub static STUCK: AtomicI64 = AtomicI64::new(0);

/// Lets an abandoned runner have only CPU nobody else wants, so a call that never returns
/// can't slow the query threads down.
fn deprioritise(_tid: i32) {
    // SAFETY: setpriority only reads its arguments. On Linux, PRIO_PROCESS with a thread ID
    // sets that one thread's nice value, and raising it needs no privilege.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, _tid as libc::id_t, 19);
    }
}

impl Runner {
    fn spawn() -> std::io::Result<Runner> {
        let (jobs, job_rx) = mpsc::channel::<(String, Input)>();
        let (result_tx, results) = mpsc::channel();
        let state = Arc::new(AtomicU8::new(DONE));
        let tid = Arc::new(AtomicI32::new(0));
        let (thread_state, thread_tid) = (state.clone(), tid.clone());
        std::thread::Builder::new()
            .name("lua".into())
            .spawn(move || {
                #[cfg(target_os = "linux")]
                // SAFETY: gettid takes no arguments and can't fail.
                thread_tid.store(unsafe { libc::syscall(libc::SYS_gettid) } as i32, SeqCst);
                let _ = &thread_tid;
                let mut engine = Engine::new();
                for (source, input) in job_rx {
                    let outcome = match &mut engine {
                        Ok(e) => e
                            .call(&source, &input)
                            .unwrap_or_else(|e| Outcome::Error(e.to_string())),
                        Err(e) => Outcome::Error(format!("starting Lua: {e}")),
                    };
                    if thread_state.swap(DONE, SeqCst) == ABANDONED {
                        // The caller gave up on this call, which has now returned after all.
                        // Taking the lock orders this after the caller's own bookkeeping.
                        let mut off = DISABLED.write().unwrap_or_else(PoisonError::into_inner);
                        STUCK.fetch_sub(1, SeqCst);
                        if let Some(strike) = off.get_mut(&source) {
                            strike.stuck -= 1;
                        }
                        break;
                    }
                    if result_tx.send(outcome).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Runner {
            jobs,
            results,
            state,
            tid,
        })
    }
}

thread_local! {
    static RUNNER: RefCell<Option<Runner>> = const { RefCell::new(None) };
}

/// Scripts that exceeded the time limit. They fail fast here while a call of theirs is still
/// stuck, and until the cooldown ends.
static DISABLED: LazyLock<RwLock<HashMap<String, Strike>>> = LazyLock::new(Default::default);

pub fn run(source: &str, input: &Input) -> Outcome {
    if STUCK.load(SeqCst) >= MAX_STUCK {
        return Outcome::Error("scripts are off on this node: too many calls are stuck".into());
    }
    // The read guard is a temporary of the condition, so it's released before the call
    // below, which may need the write lock.
    if DISABLED
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(source)
        .is_some_and(|s| s.stuck > 0 || Instant::now() < s.until)
    {
        return Outcome::Error("disabled on this node after exceeding the time limit".into());
    }
    RUNNER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            match Runner::spawn() {
                Ok(r) => *slot = Some(r),
                Err(e) => return Outcome::Error(format!("starting a script thread: {e}")),
            }
        }
        let runner = slot.as_ref().unwrap();
        runner.state.store(RUNNING, SeqCst);
        if runner
            .jobs
            .send((source.to_string(), input.clone()))
            .is_err()
        {
            *slot = None; // the runner died (a panic); the next call gets a fresh one
            return Outcome::Error("script thread exited".into());
        }
        match runner.results.recv_timeout(TIME_LIMIT) {
            Ok(outcome) => outcome,
            Err(RecvTimeoutError::Timeout) => {
                let mut off = DISABLED.write().unwrap_or_else(PoisonError::into_inner);
                if runner
                    .state
                    .compare_exchange(RUNNING, ABANDONED, SeqCst, SeqCst)
                    .is_err()
                {
                    // It finished just as the limit passed: its result is on the way.
                    drop(off);
                    return runner
                        .results
                        .recv_timeout(TIME_LIMIT)
                        .unwrap_or_else(|_| Outcome::Error("script thread exited".into()));
                }
                // Abandon the runner (it exits when the call returns, if ever) and turn the
                // script off so it can't strand another one.
                let now = Instant::now();
                off.retain(|_, s| s.stuck > 0 || now < s.until);
                let strike = off.entry(source.to_string()).or_insert(Strike {
                    stuck: 0,
                    until: now,
                });
                strike.stuck += 1;
                strike.until = now + COOLDOWN;
                STUCK.fetch_add(1, SeqCst);
                drop(off);
                deprioritise(runner.tid.load(SeqCst));
                *slot = None;
                crate::metrics::inc(&crate::metrics::LUA_TIMEOUTS);
                Outcome::Error(format!(
                    "exceeded the {}ms time limit; disabled on this node",
                    TIME_LIMIT.as_millis()
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                *slot = None;
                Outcome::Error("script thread exited".into())
            }
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
        // A hard limit needs mlua's allocator, which LuaJIT refuses where heap addresses exceed
        // 47 bits (e.g. aarch64 Linux). Then the hook checks the GC's count instead, after
        // every instruction, so growth across instructions is caught at once.
        // ponytail: a single instruction can still allocate past the limit (one big
        // concatenation, up to LuaJIT's 2 GiB string cap). A separate script process with an
        // rlimit is the upgrade if that matters.
        let hard_limit = lua.set_memory_limit(MEMORY_LIMIT).is_ok();
        let hook_every = if hard_limit { HOOK_EVERY } else { 1 };

        let globals = lua.globals();
        // Replaced in the real string table, so `("x"):rep(n)` method calls are capped too.
        let string: Table = globals.get("string")?;
        let rep: Function = string.get("rep")?;
        string.set(
            "rep",
            lua.create_function(
                move |_, (s, n, sep): (mlua::LuaString, i64, Option<mlua::LuaString>)| {
                    let sep_len = sep.as_ref().map_or(0, |s| s.as_bytes().len());
                    let size = (s.as_bytes().len() + sep_len).saturating_mul(n.max(0) as usize);
                    if size > MAX_REP_BYTES {
                        return Err(mlua::Error::runtime(format!(
                            "string.rep result over {MAX_REP_BYTES} bytes"
                        )));
                    }
                    rep.call::<mlua::LuaString>((s, n, sep))
                },
            )?,
        )?;
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
            "pairs", "ipairs", "next", "select", "type", "tostring", "tonumber", "error", "unpack",
            "assert",
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
            HookTriggers::new().every_nth_instruction(hook_every),
            move |lua, _| {
                if !hard_limit && lua.used_memory() > MEMORY_LIMIT {
                    return Err(mlua::Error::runtime("memory limit exceeded"));
                }
                counter.set(counter.get() + u64::from(hook_every));
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
                .set_mode(ChunkMode::Text) // LuaJIT doesn't verify bytecode
                .set_environment(env.clone())
                .into_function()?;
            if self.scripts.len() >= MAX_CACHED_SCRIPTS {
                self.scripts.clear();
            }
            self.scripts.insert(source.to_string(), (f, env));
        }
        let (f, env) = &self.scripts[source];

        let q = self.lua.create_table()?;
        q.set("name", input.qname.as_str())?;
        q.set("type", input.qtype.as_str())?;
        q.set("client", input.client.to_string())?;
        q.set("client_prefix", input.client_prefix)?;
        q.set("source", input.source.to_string())?;
        q.set("node", input.node.as_str())?;
        q.set("static", input.statics.clone())?;
        env.set("q", q)?;

        // Garbage from earlier calls counts toward the soft limit; clear it before it matters.
        if self.lua.used_memory() > MEMORY_LIMIT / 2 {
            self.lua.gc_collect()?;
        }
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

    fn input() -> Input {
        Input {
            qname: "www.example.com.".into(),
            qtype: "A".into(),
            client: "10.1.2.0".parse().unwrap(),
            client_prefix: 24,
            source: "192.0.2.53".parse().unwrap(),
            node: "node1".into(),
            statics: vec!["198.51.100.1".into()],
        }
    }

    #[test]
    fn time_limit_disables_scripts_stuck_in_c() {
        let i = input();
        // Backtracking pattern matching runs in C, where the instruction budget never fires.
        let stuck = "local s = ('a'):rep(60000) return s:find('.-.-.-.-.-.-b')";
        run("return 'ok'", &i); // start this thread's runner, to learn its thread ID
        let tid = RUNNER.with(|r| r.borrow().as_ref().unwrap().tid.load(SeqCst));
        let t = std::time::Instant::now();
        assert!(matches!(run(stuck, &i), Outcome::Error(e) if e.contains("time limit")));
        // On Linux the abandoned runner now has the lowest priority (nice 19).
        if cfg!(target_os = "linux") {
            let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).unwrap();
            let nice = stat
                .rsplit_once(") ")
                .unwrap()
                .1
                .split(' ')
                .nth(16)
                .unwrap();
            assert_eq!(nice, "19", "{stat}");
        }
        assert!(t.elapsed() < TIME_LIMIT * 5, "took {:?}", t.elapsed());
        // Disabled from now on, without running; other scripts still run on a fresh runner.
        let t = std::time::Instant::now();
        assert!(matches!(run(stuck, &i), Outcome::Error(e) if e.contains("disabled")));
        assert!(t.elapsed() < TIME_LIMIT);
        assert_eq!(run("return 'ok'", &i), Outcome::Answer(vec!["ok".into()]));
        assert_eq!(STUCK.load(SeqCst), 1);

        // A script that is only slow: abandoned too, but its call returns, so it stops
        // counting as stuck. It stays off for the cooldown.
        let slow = "local s = ('a'):rep(900) return tostring(s:find('^.-.-.-b'))";
        assert!(matches!(run(slow, &i), Outcome::Error(e) if e.contains("time limit")));
        let t = std::time::Instant::now();
        while STUCK.load(SeqCst) > 1 {
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "slow script never returned"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let off = DISABLED.read().unwrap();
        assert_eq!((off[stuck].stuck, off[slow].stuck), (1, 0));
        assert!(Instant::now() < off[slow].until);
    }

    /// Leaves MAX_STUCK threads spinning, so it runs alone:
    /// `cargo test -p dns-server -- --ignored stuck_cap`
    #[test]
    #[ignore]
    fn stuck_cap_turns_scripts_off() {
        let i = input();
        for n in 0..MAX_STUCK {
            let stuck = format!("local s = ('a'):rep(6000{n}) return s:find('.-.-.-.-.-.-b')");
            assert!(matches!(run(&stuck, &i), Outcome::Error(e) if e.contains("time limit")));
        }
        assert!(
            matches!(run("return 'ok'", &i), Outcome::Error(e) if e.contains("scripts are off"))
        );
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
            "return pcall(error)",
            "local function f() while true do end end while true do pcall(f) end",
            "\x1bLJ\x02\x00",
            "return string.rep('x', 1e9)",
            "return ('x'):rep(1e9)",
            "local t, s = {}, ('x'):rep(65536) for i = 1, 2000 do t[i] = s .. i end",
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
            run("return string.rep('a', 2) .. ('b'):rep(2, ',')", &i),
            Outcome::Answer(vec!["aab,b".into()])
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

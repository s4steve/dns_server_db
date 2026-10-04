# DNS server backed by a live database: plan and as-built record

This started as the plan, written before any code. It now records what was built: the
decisions as they stand, each stage's outcome, and where the build departed from the plan
and why. [README.md](README.md) is the user guide; this file is the design record.

## Context
An authoritative DNS server with no caching. It answers from a database that can change while
the server runs, and it can tailor each answer with in-process scripts.

| Target | Result |
|---|---|
| 50k+ QPS per node, p99 under 1 ms, scripts included | ✅ ~99k QPS static, ~85k QPS with a `LUA` script, p99 under 100 µs (10-core Mac, client on the same machine) |
| Millions of records | Not load-tested at that size. The LMDB map is fixed at 1 GiB. |
| Several nodes with anycast | ✅ Multi-node tested in Docker. `/health` drives route withdrawal; shared cookie secret across nodes. |
| Changes reach every node within ~5 s | ✅ Under 1–2 s in the multi-node test |

## Decisions as built
| Area | Decision |
|---|---|
| Language | Rust, as a Cargo workspace: `dns-server`, `control-plane`, `mcp-server` |
| Read store | **LMDB** on each node (`heed`). The follower thread is the only writer; query threads are lock-free readers. |
| Wire format | `hickory-proto` **0.26**, for parsing and encoding only. Upgraded from 0.24, whose zone-file parser ignored `$TTL` and set the SOA's TTL to its EXPIRE value. Our own UDP/TCP loop on tokio. |
| UDP | One shared socket, drained by one task per CPU core. Not `SO_REUSEPORT` (see Open items). |
| Record types | A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, plus **`LUA`** (scripts). ALIAS was skipped. |
| Correctness | RFC-correct answers: NXDOMAIN vs NODATA, the SOA in the authority section for negatives with its TTL = min(SOA TTL, MINIMUM) (RFC 2308), empty non-terminals, wildcards (RFC 4592), delegations with glue, CNAME chasing across all hosted zones with loop detection, REFUSED for zones not hosted. EDNS0 with a 1232-byte payload and BADVERS. Truncation with TCP retry. |
| Zone transfers | None (no AXFR, IXFR or NOTIFY) |
| Source of truth | **Postgres**. SOA fields are columns on the zone, so the serial can't be edited by hand. |
| Changelog | Append-only, with a sequence number. Each entry carries the **complete new record set of every name it touches** (`[]` deletes a name), so applying an entry twice is harmless. A global advisory lock makes sequence order match commit order. |
| Atomicity | A changeset is all-or-nothing. The SOA serial bumps on every committed change (RFC 1982 wraparound). |
| Validation | In the control plane, before commit: per-type syntax (canonical forms are parsed back and compared, which caught TXT's lossy text form); name inside the zone; CNAME exclusivity; no CNAME at the apex; at least one NS at the apex; one TTL per RRset; no records belonging to a hosted child zone. For `LUA`: an allowed answer type, a script that compiles under LuaJIT, one script per type. |
| Writers | Humans and automation via the REST API, and an MCP server that calls the same API. No permissions in v1. |
| Propagation | Each node polls the changelog every second and applies each page in one LMDB transaction, together with its changelog position. |
| SOA REFRESH and RETRY | A per-zone serial check, as standard secondary servers do it. Every REFRESH seconds a node compares each zone's serial with the control plane's and re-fetches the zone if they differ. A failed check is retried after RETRY seconds. The check only runs when the node is caught up (`GET /zones` returns the changelog head), so changes still on their way aren't mistaken for drift. Following makes a node an exact mirror: zones the control plane doesn't have are removed. |
| SOA EXPIRE | A node returns SERVFAIL for a zone once EXPIRE has passed since its last fully caught-up sync. A node that has never synced serves nothing. The default EXPIRE is 7 days. |
| Bootstrap | A new node replays the whole changelog from position 0. There's no snapshot endpoint (see Open items). |
| Bad data | A node stops advancing at a changelog entry it can't parse, and never skips it; its zones then expire safely. Consequence: upgrade every node before using a new record type. |
| Scripts | `LUA` records with data `"<TYPE> <script>"`, stored under private-use type 65402 and never served. A script overrides static records of its type at that name; wildcard `LUA` records give name-pattern answers. Results: `nil` falls back to the static records; an error, invalid output or an exhausted budget falls back to the static records, or SERVFAIL if there are none. |
| Script sandbox | `mlua` with vendored LuaJIT. One state per worker thread; separate globals per script; read-only proxies over `math`, `string` and `table`; no `io`, `os`, `require`, `load`, `debug` or `ffi`. Budget: 200k instructions per call. Memory: 64 MiB per state (verified to stop a large allocation). **The JIT compiler is off**, because instruction hooks don't fire inside compiled code, so a runaway loop couldn't be stopped. |
| Script context | `q.name`, `q.type`, `q.client` (the ECS address, otherwise the source IP), `q.client_prefix`, `q.source`, `q.node` (`--node-id`), `q.static`. Helper: `in_cidr`. |
| ECS | Tailored answers carry an ECS scope equal to the client's prefix, so resolvers cache them per subnet. Answers that aren't tailored carry scope 0. |
| TTL | Per record. A record added without a TTL takes its RRset's TTL, otherwise the zone default (300). |
| Geo | No GeoIP database. Scripts match the client's network with `in_cidr`. |
| Ops | Prometheus `/metrics` and `/health` on `--http`; RRL modelled on BIND; DNS cookies (RFC 7873 with RFC 9018 server cookies). |
| MCP | A stdio JSON-RPC server written directly (no SDK); a thin HTTP client of the REST API. |
| Out of scope | Recursion, caching, DoT/DoH, zone transfers, permissions, DNSSEC, ALIAS |

## Architecture
```
 Control plane                                   Data plane (each node)
 ┌──────────────────────────────┐   changelog   ┌───────────────────────────────────┐
 │ REST API ◀── MCP server       │ ────────────▶ │ follower thread (only LMDB writer) │
 │ validation, atomic changesets │  1s polling,  │  - applies changelog pages         │
 │ serial bumps, changelog       │  seq-numbered │  - REFRESH/RETRY serial checks     │
 │ Postgres (source of truth)    │ ◀──────────── │ LMDB: zones (+EXPIRE), names, meta │
 └──────────────────────────────┘ GET /zones,    │ UDP/TCP workers: parse → lookup    │
                                  /zones/{zone}  │   → LUA? → RRL/cookies → send      │
                                                 │ --http: /metrics, /health          │
                                                 └───────────────────────────────────┘
```

Query path:
1. Parse the packet, and handle EDNS (payload size, cookies, ECS).
2. Find the closest enclosing zone. If it has expired, answer SERVFAIL.
3. Walk down from the apex: delegations, empty non-terminals, wildcards.
4. At the matching name, run a `LUA` script if one exists for the query type; otherwise use the static records. Follow CNAME chains.
5. Apply RRL (UDP only; clients with a valid cookie are exempt) and truncation, set the ECS scope, and send.

## Stages
Each stage ended with something runnable and a test that fails if it breaks.

**Stage 0: Skeleton. ✅** A UDP+TCP listener returning a hard-coded A record. It started as a single crate and became a workspace in Stage 2, when the control plane needed its own crate.

**Stage 1: LMDB data model and lookup engine. ✅**
- Name keys are length-prefixed, reversed labels, so a name's descendants share its key prefix. That makes empty non-terminals a prefix scan.
- A record key is `zone key + 0x00 + rest of the name`, so a hosted child zone never shares a prefix with its parent.
- Finding the enclosing zone walks up the labels with point lookups, not a range scan.
- The golden test (`testdata/cases.txt`) has 37 cases.

**Stage 2: Control plane. ✅** The Postgres schema with migrations, the validation listed above, atomic changesets, automatic serial bumps, the REST API, and the changelog. The end-to-end test confirms a changeset with one good and one bad change applies neither.

**Stage 3: Replication. ✅**
- Built as planned except for bootstrap: new nodes replay the full changelog instead of loading a snapshot.
- REFRESH and RETRY were first left unused, with continuous polling instead. They were then added as the per-zone serial check described above.
- `scripts/multinode-test.sh` checks:
  - propagation within 5 s;
  - a tampered copy of a zone repaired within REFRESH;
  - a zone only one node had, removed;
  - SERVFAIL once EXPIRE passes;
  - recovery once the control plane is back.

**Stage 4: Lua tailoring. ✅**
- Scripts are a record type (`LUA`) instead of a separate mechanism, so they reuse storage, validation, replication and LMDB. Name patterns are wildcard `LUA` records rather than a separate pattern feature.
- There's no record-building helper: scripts return record data as text.
- Release-mode benchmark: script queries take 9.2 µs at p99, against 2.7 µs for static ones.

**Stage 5: ALIAS. ⏭ Skipped**, by decision. It can be added later.

**Stage 6: Operations. ✅**
- Metrics, health, RRL and cookies were built as planned.
- The load test uses a small closed-loop generator of our own (`dns-server/examples/loadgen.rs`) instead of `dnsperf` or `flamethrower`, which weren't installed.
- The README has an ExaBGP health-check example; BIRD wasn't tried.

**Stage 7: MCP server. ✅**
- Seven tools map one-to-one onto the REST endpoints.
- API rejections come back as tool errors listing every problem.
- Tested by driving the real binary over stdio against a real control plane.

## Verification
- **Unit and integration tests:** 16 across the workspace (`cargo test`, with Postgres from `docker compose up -d`). They cover the golden answers, follower apply and expiry, `LUA` behaviour and sandbox escapes, RRL, cookies, metrics and health, control-plane validation and the API end to end, and the MCP server over stdio.
- **Multi-node:** `scripts/multinode-test.sh` covers propagation, REFRESH repair, `LUA` scripts on each node, health, metrics, cookies across nodes, expiry and recovery.
- **Load:** `loadgen` plus the release-mode `script_latency` benchmark.
- **Not done from the original plan:** no CI pipeline is set up, and no `zonemaster` or `dnsviz` checks have been run against a public zone.

## Open items
- **ALIAS** (Stage 5), if needed.
- **Permissions** on the API, and therefore on the MCP server.
- **`SO_REUSEPORT`**, one UDP socket per core, on Linux. On macOS, throughput levels off around 71–78k QPS because every worker shares one socket.
- **A snapshot endpoint** for bootstrapping new nodes, needed once old changelog entries are pruned.
- **The JIT compiler** is off by decision. Turning it on needs a watchdog that can stop runaway scripts.
- **Smaller items, each marked in the code:**
  - RRL buckets are pruned only when a shard fills;
  - `last_sync` is written on every poll (one fsync per second);
  - the Lua compile cache is unbounded;
  - script errors are logged without a rate limit;
  - the LMDB map size is fixed at 1 GiB.
- **Script gaps:** a CNAME-producing script doesn't trigger CNAME chasing, and `q.static` shows TXT records in hickory's lossy text form.
- **Upgrade order:** upgrade every DNS node before using a new record type, or nodes on the old version halt at the first entry they can't parse.

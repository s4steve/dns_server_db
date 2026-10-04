# DNS server backed by a live database: decisions and stages

## Context
This is a new side project, and the repo is empty. The goal is an authoritative DNS server with no caching. It answers from a database that can change while the server runs, and it can tailor each answer with in-process scripts.

Targets:
- over 50k QPS per node, with p99 under 1 ms, scripts included;
- millions of records;
- several nodes with anycast;
- changes reach every node within about 5 seconds.

## Decisions so far
| Area | Decision |
|---|---|
| Language | Rust |
| Read store | **LMDB** on each node (`heed` crate). The node's applier is the only writer; query threads are lock-free readers. |
| Wire format | `hickory-proto` for parsing and encoding only. Our own UDP/TCP loop (tokio, `SO_REUSEPORT`, one socket per core). |
| Record types | A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, ALIAS |
| Correctness | RFC-correct answers: NXDOMAIN vs NODATA, SOA in authority for negatives (RFC 2308), wildcards (RFC 4592), delegation with glue, CNAME chasing inside our own zones |
| Zone transfers | None (no AXFR/IXFR/NOTIFY) |
| Atomicity | A changeset is all-or-nothing, and the SOA serial bumps on every committed change |
| Precedence | A dynamic (script) answer overrides a static record for the same name and type |
| Validation | Before commit: CNAME exclusivity, no CNAME at the apex (use ALIAS), syntax checks, Lua compile check, and so on |
| Writers | Humans, the API, and an MCP server. All of them go through the same API and validation. No permissions in v1. |
| Staleness | About 5 s target. **A node stops serving a zone (SERVFAIL) once it has gone past SOA EXPIRE without a successful sync.** SOA REFRESH and RETRY become the heartbeat check and backoff intervals. |
| Scripts | **LuaJIT** through `mlua` (luajit feature). One Lua state per worker thread, because LuaJIT states are not thread-safe. An instruction-count hook enforces the time budget. On an error or timeout, use the static answer if there is one, otherwise SERVFAIL. |
| TTL | Each record has a TTL, defaulting to a per-zone value. Negative TTL is min(SOA TTL, SOA MINIMUM), as RFC 2308 says. |
| Geo | **No GeoIP database in v1.** Scripts get the client subnet (ECS, otherwise the source IP) plus CIDR-match helpers, which covers "this network gets that answer". Add MaxMind only if you need rules written as country or region. |
| Ops | Anycast, response rate limiting (RRL), DNS cookies, Prometheus metrics for QPS, latency histograms, applier lag and script errors |
| Source of truth | **Postgres**. The API and MCP server write here. A changelog table with a sequence number feeds the nodes. |
| ALIAS | Targets must be in our own zones. Resolved by a local LMDB lookup at query time: no network, no caching. |
| Out of scope | Recursion, caching, DoT/DoH, zone transfers, permissions, **DNSSEC** (later, as its own stage) |

## Architecture
```
 Control plane                                Data plane (each node)
 ┌─────────────────────────────┐  changelog  ┌──────────────────────────────────┐
 │ REST API ◀── MCP server      │ ──────────▶ │ applier (single LMDB writer)     │
 │ validation, changesets       │  seq-numbered│ LMDB: zones, RRsets, scripts,    │
 │ source of truth: Postgres       │  + heartbeat │       per-zone sync state        │
 └─────────────────────────────┘             │ workers: parse → lookup → Lua?   │
                                             │          → encode → send          │
                                             └──────────────────────────────────┘
```
Query path: parse the packet, find the closest enclosing zone, and check that zone hasn't expired. If a script is attached, run it; otherwise do the static lookup. Then apply wildcard, CNAME and negative-answer logic, encode, and set the ECS scope.

## Stages
Each stage ends with something you can run and a test that fails if it breaks.

**Stage 0: Skeleton.** A Cargo workspace with `dns-server` and `control-plane` crates. A UDP+TCP listener returns a hard-coded A record. Done when `dig @127.0.0.1` gets the answer.

**Stage 1: LMDB data model and lookup engine.** Define the key layout: reversed-label name keys, so a zone's names sort together and finding the closest enclosing zone is a short range scan. Build the full RFC answer logic for the static record types. A CLI loads zones from a file.
- Done when a golden-file test suite passes: one `dig`-style case per edge case (wildcard, NODATA, NXDOMAIN, CNAME chain, delegation and glue, truncation with TCP retry).

**Stage 2: Control plane.**
- Schema for the source of truth.
- Validation rules.
- Atomic changesets with automatic SOA serial bumps.
- A REST API.
- A changelog with monotonically increasing sequence numbers.

Done when an invalid change is rejected and a valid one shows up in the changelog.

**Stage 3: Replication.**
- The node applier pulls or subscribes to the changelog and applies each change in one LMDB write transaction.
- Each zone tracks its last sequence number and last sync time.
- A new node bootstraps from a snapshot and then catches up.
- Zones expire according to SOA EXPIRE.

Done when a multi-node local test (docker compose) shows a write appearing on every node within 5 s, and a node cut off from the control plane SERVFAILs once a zone passes EXPIRE.

**Stage 4: Lua tailoring.**
- Scripts are attached to a name+type, or to a name pattern for generated answers.
- Scripts receive this context: qname, qtype, client subnet, source IP, node ID, and the zone's static RRset.
- Helpers: CIDR matching and building records.
- Instruction budget, fallback behaviour, and the ECS scope-prefix in responses.

Done with tests for override, error→fallback, error→SERVFAIL, budget exceeded, and pattern records, plus a benchmark showing script overhead under 1 ms at p99.

**Stage 5: ALIAS.** Resolve ALIAS at query time against our own zones only. Validation rejects targets outside them. Done when tests cover an apex ALIAS, a missing target (NODATA), and loop detection.

**Stage 6: Operations.**
- Prometheus metrics and RRL.
- DNS cookies.
- A health endpoint that drives anycast route withdrawal through BIRD or ExaBGP. The node withdraws when it's unhealthy or all its zones have expired.
- Load testing with `dnsperf` or `flamethrower`.

Done at 50k+ QPS per node with p99 under 1 ms.

**Stage 7: MCP server.** A thin layer over the REST API with tools for zones, records, changesets and scripts. It reuses the API's validation and has no logic of its own.

## Verification (across stages)
- Golden answer tests (Stage 1) run in CI on every change.
- Multi-node compose test for propagation and expiry (Stage 3).
- `dnsperf` load test with a latency budget (Stage 6).
- Spot checks against the RFCs using `dig +norec` and, optionally, `zonemaster` or `dnsviz` on a public test zone.

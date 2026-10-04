# dns_server_db

An authoritative DNS server, written in Rust, that answers queries straight from a database you can update while it runs: no restarts, no zone reloads. Responses can be tailored per query by in-process LuaJIT scripts (client subnet, name patterns, arbitrary logic).

See [PLAN.md](PLAN.md) for the full design, decisions, and staged roadmap.

## Status

**Stage 6 of 7: operations (done).** Prometheus metrics, a health check for anycast, response rate limiting, DNS cookies, and a load test. See [Operations](#operations). Stage 5 (ALIAS) was skipped and can be added later.

Already in place:
- **LuaJIT tailoring (Stage 4):** `LUA` records hold scripts that build answers per query. See [LUA records](#lua-records).
- **Replication (Stage 3):** DNS nodes follow the control plane's changelog, and a change reaches every node in about a second.
  - A new node replays the whole changelog to catch up.
  - Every SOA REFRESH seconds, a node compares each zone's serial with the control plane's. If they differ, it re-fetches the zone; a failed check is retried after RETRY seconds. This repairs drift the changelog can't see, and it makes the node an exact mirror of the control plane.
  - A node that can't sync returns SERVFAIL for a zone once its SOA EXPIRE has passed since the last sync.
- **Control plane (Stage 2):** Postgres with validated, atomic changesets and a REST API.
- **Answer engine (Stage 1):** RFC-correct lookups, EDNS0 and truncation.

| Stage | Scope | Status |
|---|---|---|
| 0 | Skeleton UDP/TCP server | ✅ Done |
| 1 | LMDB data model + RFC-correct lookup engine | ✅ Done |
| 2 | Control plane: Postgres, validation, REST API, changelog | ✅ Done |
| 3 | Replication to nodes, SOA REFRESH/RETRY/EXPIRE | ✅ Done |
| 4 | LuaJIT tailoring | ✅ Done |
| 5 | ALIAS (in-zone targets) | Skipped for now |
| 6 | Ops: metrics, RRL, cookies, anycast health | ✅ Done |
| 7 | MCP server over the API | Next |

## LUA records

A `LUA` record's data is `<TYPE> <script>`. The script answers queries of that type at that name, and it overrides any static records of the same type there:

```bash
curl -X POST localhost:8053/zones/example.com/changes -H 'content-type: application/json' -d @- <<'EOF'
{"changes":[{"action":"add","name":"www","type":"LUA","ttl":60,
  "data":"A if in_cidr(q.client, '10.0.0.0/8') then return '192.0.2.10' end return {'192.0.2.20', '192.0.2.21'}"}]}
EOF
```

**What a script sees**, in the table `q`:

| Field | Value |
|---|---|
| `q.name` | Query name (lowercase, absolute), even when the script is on a wildcard |
| `q.type` | Query type, e.g. `"A"` |
| `q.client` | The EDNS Client Subnet address if the resolver sent one, otherwise the source IP |
| `q.client_prefix` | ECS prefix length, or 32/128 for a plain IP |
| `q.source` | The packet's source IP (usually the resolver) |
| `q.node` | The node's ID (`--node-id`, default `$HOSTNAME`) |
| `q.static` | The static records being overridden, as text |

Helpers: `in_cidr(ip, "10.0.0.0/8")`, plus Lua's `math`, `string` and `table` libraries.

**What a script returns:** record data in zone-file syntax, as one string or a list of strings. The records it builds get the `LUA` record's TTL.

| Script result | Response |
|---|---|
| Valid data | The tailored answer. With ECS, the response's scope is the full client prefix, so resolvers cache it per subnet. |
| `nil` or `{}` | The static records, or NODATA if there are none |
| An error, data that doesn't parse, or the instruction budget exceeded | The static records, or SERVFAIL if there are none |

Answers that don't come from a script carry ECS scope 0, so resolvers can cache them for everyone.

**Name patterns:** put the script on a wildcard name and build the answer from `q.name`. For example, `*.ip LUA A` with a script that turns `1-2-3-4.ip.example.com` into `1.2.3.4`.

**Scripts can answer:** A, AAAA, TXT, MX or CAA, with at most one script per type at a name. A `LUA` record counts as a record for CNAME exclusivity. The control plane compiles each script with LuaJIT before accepting it.

**Sandbox:**
- There's one Lua state per worker thread, and each script has its own globals.
- The shared libraries are read-only.
- No `io`, `os`, `require`, `load`, `debug` or `ffi`.
- Each call has a budget of 200k instructions, and each state has a 64 MiB memory limit.
- LuaJIT's JIT compiler is off. The instruction budget can't interrupt JIT-compiled code, so a runaway loop could otherwise never be stopped.

`LUA` records themselves are never served, not even to ANY queries.

**Latency** in release builds, measuring complete `answer()` calls with ECS: static p99 2.7µs, script p99 9.2µs. Reproduce with:

```bash
cargo test --release -p dns-server -- --ignored --nocapture script_latency
```

## Operations

Node flags for running in production:

| Flag | Default | Purpose |
|---|---|---|
| `--http ADDR` | off | Serves `/metrics` (Prometheus) and `/health` |
| `--rrl-rps N` | off | Response rate limit: identical responses per second per client network |
| `--rrl-slip N` | 2 | Send every Nth rate-limited response truncated instead of dropping it (0 = drop all) |
| `--cookie-secret HEX` | random | 32 hex digits. Give every node behind one anycast address the same secret. |

**Health:** `GET /health` returns 200 while the node serves at least one zone that hasn't expired, and 503 otherwise. The JSON body includes zone counts, `applied_seq` and the time since the last sync.

An anycast speaker should withdraw the node's route while the check fails. That happens on its own when a node is cut off from the control plane for longer than its zones' EXPIRE. For example, with ExaBGP's health-check process:

```
process dns-health {
    run python3 -m exabgp healthcheck --cmd "curl -sf http://127.0.0.1:9153/health" --ip 192.0.2.53/32 --interval 1 --rise 3 --fall 2;
    encoder text;
}
```

**Metrics:**
- `dns_queries_total{transport,rcode}`
- `dns_query_duration_seconds`: a histogram of the time spent building each answer
- truncations, RRL drops and slips, valid cookies
- Lua runs and errors
- follower errors and REFRESH repairs
- gauges: `dns_zones`, `dns_zones_expired`, `dns_healthy`, `dns_follow_applied_seq`, `dns_follow_sync_age_seconds`

**Response rate limiting** works like BIND's RRL:
- Responses are counted per token bucket. A bucket covers one client network (IPv4 /24, IPv6 /56), one response name, one query type and one response code.
- Negative answers count against the zone rather than the name, so a flood of random subdomains shares one bucket.
- Over the limit, responses are dropped, except every `--rrl-slip`th one, which is sent truncated so a real client can retry over TCP.
- TCP queries and clients presenting a valid server cookie are never limited.

**DNS cookies** follow RFC 7873, with RFC 9018 server cookies (SipHash-2-4 with a timestamp, valid for an hour). Cookies are optional: a missing or invalid server cookie gets a fresh cookie and a normal answer. A malformed cookie option gets FORMERR.

**Load test** with `dns-server/examples/loadgen.rs`, a closed-loop UDP client. These numbers come from one 10-core Mac, with the client and the node sharing the machine:

| Answer type | Client threads | QPS | p50 | p99 | p99.9 |
|---|---|---|---|---|---|
| Static | 4 | 98,759 | 37µs | 82µs | 106µs |
| `LUA` script | 4 | 84,975 | 43µs | 91µs | 122µs |
| Static | 16 | 73,308 | 211µs | 400µs | 557µs |
| `LUA` script | 16 | 78,548 | 196µs | 386µs | 675µs |

With more client threads, throughput levels off around 71–78k QPS on macOS, because every worker shares one UDP socket. On Linux, one `SO_REUSEPORT` socket per core is the next step (marked in the code). On the server side, 99.98% of 1.55M queries took under 100µs to answer.

```bash
cargo run --release -p dns-server --example loadgen -- 127.0.0.1:5300 10 4 www.example.com/A
```

## Layout

A Cargo workspace with two crates:

- `dns-server/`: the authoritative DNS node
  - `src/main.rs`: CLI, UDP/TCP listeners, packet handling (EDNS, truncation)
  - `src/store.rs`: LMDB store: key layout, zone loading, lookups
  - `src/lookup.rs`: authoritative answer logic
  - `src/follow.rs`: changelog follower (polling, atomic apply, sync state) and SOA REFRESH/RETRY checks
  - `src/script.rs`: LuaJIT sandbox for `LUA` records
  - `src/metrics.rs`: Prometheus metrics, health check, HTTP endpoint
  - `src/rrl.rs`: response rate limiting
  - `src/cookie.rs`: DNS cookies (RFC 7873 / 9018)
  - `examples/loadgen.rs`: UDP load generator
  - `testdata/`: test zones and `cases.txt`, the golden answer file (a query followed by its expected response, checked by `cargo test`)
- `control-plane/`: the REST API over Postgres
  - `src/api.rs`: routes, transactions, serial bumps, changelog
  - `src/validate.rs`: record parsing, canonical forms, validation rules
  - `migrations/`: the schema, applied automatically at startup
  - `tests/api.rs`: end-to-end test against Postgres
- `scripts/multinode-test.sh`: Docker end-to-end test: propagation, expiry, recovery
- `Dockerfile`, `docker-compose.yml`: one image with both binaries; the `multinode` compose profile runs the control plane plus two DNS nodes

## Running

Requires Rust ([rustup](https://rustup.rs)) and Docker.

Start Postgres:

```bash
docker compose up -d
```

Run all tests (the control-plane test needs Postgres running):

```bash
cargo test
```

### Control plane

Listens on `127.0.0.1:8053`. Override with the `LISTEN` and `DATABASE_URL` environment variables.

```bash
cargo run -p control-plane
```

Create a zone (SOA fields are optional; mname defaults to the first NS):

```bash
curl -X POST localhost:8053/zones -H 'content-type: application/json' -d '{"name":"example.com","ns":["ns1.example.com."]}'
```

Apply a changeset (all-or-nothing):

```bash
curl -X POST localhost:8053/zones/example.com/changes -H 'content-type: application/json' -d '{"changes":[{"action":"add","name":"www","type":"A","data":"192.0.2.10"}]}'
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/zones` | List zones, plus `seq` (the changelog head in the same snapshot; nodes use it for REFRESH checks) |
| `POST` | `/zones` | Create: `name`, `ns[]`, optional `default_ttl`, `soa{mname,rname,refresh,retry,expire,minimum}` |
| `GET` | `/zones/{zone}` | Zone, SOA and all records |
| `PATCH` | `/zones/{zone}` | Change `default_ttl` or SOA fields |
| `DELETE` | `/zones/{zone}` | Delete the zone |
| `POST` | `/zones/{zone}/changes` | `{"changes":[...]}`, each `add` (name, type, data, optional ttl) or `delete` (name, type, optional data; without data, deletes the whole RRset) |
| `GET` | `/changelog?after=SEQ&limit=N` | Changelog entries after `SEQ`, oldest first |

Names may be `@` (the zone apex), relative (`www`), or absolute (`www.example.com.`). Names inside record data (CNAME, MX and NS targets) must be absolute.

If a record is added without a TTL, it takes its RRset's existing TTL, or else the zone default.

Validation covers:
- record syntax for each type;
- the name being inside the zone;
- CNAME exclusivity, and no CNAME at the apex;
- the apex keeping at least one NS;
- a single TTL per RRset;
- names that belong to a hosted child zone (those must be changed in that zone);
- for `LUA` records: an allowed answer type, a script that compiles, and one script per type.

Each changelog entry carries the complete new record set of every name it touches, so replaying an entry is safe.

### DNS server

Follow a control plane (the normal mode):

```bash
cargo run -p dns-server -- serve ./db --follow http://127.0.0.1:8053
```

Flags:
- `--listen ADDR`: default `127.0.0.1:5300`; port 53 needs root.
- `--poll-ms N`: changelog poll interval, default 1000.
- `--node-id ID`: the name scripts see as `q.node`, default `$HOSTNAME`.
- See [Operations](#operations) for `--http`, `--rrl-rps`, `--rrl-slip` and `--cookie-secret`.

```bash
dig @127.0.0.1 -p 5300 www.example.com A
```

Without `--follow`, the server serves whatever is in `./db` and never expires it. That's useful with zone files:

```bash
cargo run -p dns-server -- load ./db dns-server/testdata/example.com.zone
```

### Multi-node test

Builds the image, starts Postgres, the control plane (on host port 8054) and two DNS nodes (on host ports 5301 and 5302), then checks propagation, REFRESH repair, `LUA` scripts on each node, health, metrics, cross-node cookies, expiry and recovery. Node metrics are on host ports 9301 and 9302:

```bash
./scripts/multinode-test.sh
```

## License

MIT, see [LICENSE](LICENSE).

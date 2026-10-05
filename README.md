# dns_server_db

An authoritative DNS server, written in Rust, that answers queries straight from a database you can update while it runs: no restarts, no zone reloads. Responses can be tailored per query by in-process LuaJIT scripts (client subnet, name patterns, arbitrary logic).

See [PLAN.md](PLAN.md) for the full design, decisions, and staged roadmap.

## Status

**All planned stages are done (Stage 5, ALIAS, was skipped and can be added later).** The last one, Stage 7, added an MCP server so AI assistants can manage zones through the same validated API. See [MCP server](#mcp-server).

Already in place:
- **Managed SPF:** flattens a domain's allowed senders into TXT records that stay under SPF's 10-lookup limit. See [Managed SPF](#managed-spf).
- **Operations (Stage 6):** Prometheus metrics, a health check for anycast, response rate limiting, DNS cookies, and a load test. See [Operations](#operations).
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
| 7 | MCP server over the API | ✅ Done |

## LUA records

A `LUA` record's data is `<TYPE> <script>`. The script answers queries of that type at that name, and it overrides any static records of the same type there:

```bash
curl -X POST localhost:8053/zones/example.com/changes -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d @- <<'EOF'
{"changes":[{"action":"add","name":"www","type":"LUA","ttl":60,
  "data":"A if in_cidr(q.client, '198.51.100.0/24') then return '192.0.2.10' end return {'192.0.2.20', '192.0.2.21'}"}]}
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

**`q.client` is chosen by whoever sends the query.** Any client can put any address in an ECS option, so `q.client` is fine for tailoring answers (geography, load spreading) but never for deciding who may see something. Don't return internal addresses based on it. `q.source` is the address the answer is sent to.

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
- Each query thread runs its scripts on its own runner thread, which has one Lua state. Each script has its own globals.
- The shared libraries are read-only.
- No `io`, `os`, `require`, `load`, `debug`, `ffi` or `pcall`, and source text only (never precompiled bytecode).
- Scripts are at most 16 KiB, and `string.rep` builds at most 64 KiB.
- Each call has a budget of 200k instructions, and each state has a 64 MiB memory limit. Where LuaJIT won't use mlua's allocator (e.g. aarch64 Linux), the limit is checked every 100 instructions, so a single C call (such as a huge concatenation) can briefly overshoot it.
- Each call also has a 100 ms wall-clock limit, which covers time spent inside C functions such as pattern matching, where the instruction budget can't reach.
  - A script that exceeds it is disabled on that node until the node restarts or the script changes, and `dns_lua_timeouts_total` counts it.
  - The runner thread stuck in it is abandoned and replaced, so a query thread is never held longer than the limit.
- Scripts still run code on every node, so grant `scripts` only to tokens you'd trust with the nodes themselves.
- LuaJIT's JIT compiler is off. The instruction budget can't interrupt JIT-compiled code, so a runaway loop could otherwise never be stopped.

`LUA` records themselves are never served, not even to ANY queries.

**Latency** in release builds, measuring complete `answer()` calls with ECS: static p99 2.8µs, script p99 17.4µs. Handing each script call to the runner thread adds about 5–8µs. Reproduce with:

```bash
cargo test --release -p dns-server -- --ignored --nocapture script_latency
```

## Managed SPF

SPF lets a receiver follow at most 10 DNS lookups. A domain that sends through several providers (`include:_spf.google.com`, `include:sendgrid.net`, …) can exceed that and fail SPF. Managed SPF **flattens** the list instead: the control plane resolves each sender's SPF record, recursively, into `ip4:`/`ip6:` terms and publishes them as plain TXT records.

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  localhost:8053/zones/example.com/spf/@ \
  -d '{"senders": ["_spf.google.com", "sendgrid.net", "192.0.2.0/24"], "qualifier": "~all"}'
```

For a name `N`, that publishes:

```
N          TXT "v=spf1 include:_spf0.N include:_spf1.N ~all"
_spf0.N    TXT "v=spf1 ip4:… ip4:… ip6:…"
_spf1.N    TXT "v=spf1 …"
```

- **Senders** are domains to flatten, or literal `ip4:`/`ip6:` terms, bare IPs or CIDRs.
- **Qualifier** is `~all` (the default), `-all` or `?all`.
- **Lookups:** each chunk is at most 450 bytes, and there are at most 9 chunks, so receivers use 9 lookups or fewer.
- **Other TXT records** at `N` are kept. `N`'s own `v=spf1` record and the `_spf0`–`_spf8` names are managed, so hand edits to them get overwritten.
- **Refresh:** every `SPF_REFRESH_SECS` (default 900), the control plane re-resolves every policy and commits only when the records change (actor `spf-refresh`).
- **Failures:** if a refresh fails, the last good records stay and the policy's `last_error` is set. A `PUT` that can't be flattened is rejected and stores nothing.
- **What can't be flattened:** senders whose records use `exists:`, `ptr` or macros are rejected, because those depend on the individual message.
- **Exclusions:** `-`/`~`/`?` terms inside included records are dropped rather than kept as exclusions.
- **Permissions:** writing a policy needs editor on the zone; reading one needs viewer.
- **No per-message answers:** every receiver gets the same answer, and queries carry nothing about the sender. Answering SPF macro queries per sender was considered and left out, because it appears to be covered by Valimail's US patents (e.g. US 9,762,618 and its continuations, expiring around 2036).

## MCP server

`mcp-server` lets MCP clients (Claude Code, Claude Desktop and others) manage zones. It speaks MCP over stdio and calls the control plane's REST API over HTTP. It holds no logic of its own: every change goes through the API's validation and atomic changesets. When the API rejects a change, the tool returns the API's error messages, so the model can correct the request and retry.

| Tool | REST call | Effect |
|---|---|---|
| `list_zones` | `GET /zones` | Lists zones with their serial and SOA settings (read-only) |
| `get_zone` | `GET /zones/{zone}` | Returns a zone's SOA settings and records, including `LUA` scripts (read-only) |
| `create_zone` | `POST /zones` | Creates a zone with its name servers |
| `update_zone` | `PATCH /zones/{zone}` | Changes the default TTL or SOA fields |
| `delete_zone` | `DELETE /zones/{zone}` | Deletes a zone (marked destructive) |
| `apply_changes` | `POST /zones/{zone}/changes` | Applies an atomic changeset; its description explains `LUA` records (marked destructive) |
| `get_changelog` | `GET /changelog` | Reads changelog entries for zones the token can see, including who made each change (read-only) |
| `get_spf_policy` | `GET /zones/{zone}/spf/{name}` | Shows a managed SPF policy, its flattened terms and any refresh error (read-only) |
| `set_spf_policy` | `PUT /zones/{zone}/spf/{name}` | Creates or replaces a managed SPF policy; flattens its senders now (marked destructive) |
| `delete_spf_policy` | `DELETE /zones/{zone}/spf/{name}` | Deletes a policy and its TXT records (marked destructive) |
| `whoami` | `GET /whoami` | Shows the token's name and grants (read-only) |

Build it and register it with Claude Code:

```bash
cargo build --release -p mcp-server
```

```bash
claude mcp add dns -e CONTROL_PLANE_URL=http://127.0.0.1:8053 -e CONTROL_PLANE_TOKEN="$DNS_TOKEN" -- "$PWD/target/release/mcp-server"
```

Or, in a project's `.mcp.json`. Reference the token from your environment rather than pasting it in, because `.mcp.json` is usually committed:

```json
{
  "mcpServers": {
    "dns": {
      "command": "/absolute/path/to/target/release/mcp-server",
      "env": { "CONTROL_PLANE_URL": "http://127.0.0.1:8053", "CONTROL_PLANE_TOKEN": "${DNS_TOKEN}" }
    }
  }
}
```

`CONTROL_PLANE_URL` defaults to `http://127.0.0.1:8053`. Other hosts need `https://` (see [Control plane](#control-plane)).

The MCP server can do exactly what its token allows (see [Access control](#access-control)), and the `whoami` tool shows the model what that is. Give it a token scoped to the zones it should manage, and leave out `scripts` unless it should write `LUA` records.

Record data reaches the model as tool output, and other token holders can write it (a TXT record, say). Treat it like any untrusted text the model reads:
- For read-only use, give the MCP server a `viewer` token.
- Keep your client's approval prompt on for the tools marked destructive (`delete_zone`, `apply_changes` and the SPF writes).

## Access control

Every API call needs a bearer token: `Authorization: Bearer dnsdb_...`. Missing, invalid, expired or revoked tokens get 401.

A token has a **name**, which is recorded as the `actor` on every change it makes, plus **grants** (zone pattern, role, scripts) and an optional **admin** flag.

| Pattern | Matches |
|---|---|
| `example.com` | That zone |
| `*.example.com` | Zones below it, not `example.com` itself |
| `*` | Every zone |

| Role | Can |
|---|---|
| `viewer` | Read the zone, and see it in `/zones` and `/changelog` |
| `editor` | Everything a viewer can, plus apply record changes |
| `owner` | Everything an editor can, plus change zone settings and delete the zone. Can also create zones matching the pattern (so `*.team.example.com` lets a team create its own zones). Creating a zone that would take over records a parent zone already has at or below its apex also needs editor on that parent. |
| `scripts` (flag) | Add or delete `LUA` records, which run code on every DNS node. Needs editor or owner. |
| `admin` (token flag) | Owner with scripts on every zone, plus token management |

A token's role on a zone is the highest role among its matching grants:
- A zone the token can't see returns 404, so its existence doesn't leak.
- A zone it can see, but lacks the role for, returns 403.

**Minting the first admin token:** run the `create-token` subcommand against the database (`DATABASE_URL` must be set, see [Running](#running)). It prints the secret, which is shown only once:

```bash
TOKEN=$(cargo run -q -p control-plane -- create-token --name ops-admin --admin)
```

The same command creates scoped tokens, such as one for DNS nodes (read-only, every zone):

```bash
cargo run -q -p control-plane -- create-token --name dns-nodes --grant '*:viewer'
```

To register a value you already have, which suits configuration management, add `--secret-env VAR` to read it from an environment variable. (`--secret VALUE` also works, but the value shows up in `ps` and shell history.) Add `--if-missing` to make the command safe to re-run.

**Managing tokens over the API** (admin only):
- `POST /tokens` with `{"name", "admin", "grants": [{"pattern", "role", "scripts"}], "expires_in_days"}` returns the secret once.
- `GET /tokens` lists every token, without secrets.
- `DELETE /tokens/{name}` revokes a token. The row is kept, so its name stays reserved and changelog actors still make sense.
- `GET /whoami` shows any token its own grants.

**Clients** read their token from `CONTROL_PLANE_TOKEN`, an environment variable, so it never appears in a process list:
- DNS nodes need a `*:viewer` token.
- The MCP server needs whatever its users should be allowed to do.

The multi-node compose setup mints fixed dev tokens, which are public and dev-only.

**Upgrading from a version without access control:**
1. Start the new control plane; it adds the auth tables automatically.
2. Mint tokens.
3. Give nodes and the MCP server their tokens.

Until step 3, nodes log "rejected the token (401)" but keep serving their zones until EXPIRE (7 days by default).

## Operations

Node flags for running in production:

| Flag | Default | Purpose |
|---|---|---|
| `--http ADDR` | off | Serves `/metrics` (Prometheus) and `/health` |
| `--rrl-rps N` | off | Response rate limit: identical responses per second per client network |
| `--rrl-slip N` | 2 | Send every Nth rate-limited response truncated instead of dropping it (0 = drop all) |
| `COOKIE_SECRET` (env) | random | 32 hex digits. Give every node behind one anycast address the same secret. `--cookie-secret HEX` also works, but flags show up in `ps`. |
| `--map-size-mb N` | 1024 | LMDB map size. If the data outgrows it, writes fail and the node stops following, so watch `dns_follow_errors_total`. |

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
- Lua runs, errors and timeouts
- follower errors and REFRESH repairs
- gauges: `dns_zones`, `dns_zones_expired`, `dns_healthy`, `dns_follow_applied_seq`, `dns_follow_sync_age_seconds`

**Response rate limiting** works like BIND's RRL:
- Responses are counted per token bucket. A bucket covers one client network (IPv4 /24, IPv6 /56), one response name, one query type and one response code.
- Negative answers count against the zone rather than the name, so a flood of random subdomains shares one bucket.
- Over the limit, responses are dropped, except every `--rrl-slip`th one, which is sent truncated so a real client can retry over TCP.
- TCP queries and clients presenting a valid server cookie are never limited.
- ANY queries over UDP always get a truncated answer (RFC 8482), so they can't be used for amplification. Over TCP they're answered in full.

**TCP:** a connection that sends no complete query for 10 seconds is closed, and a node holds at most 1024 TCP connections.

**DNS cookies** follow RFC 7873, with RFC 9018 server cookies (SipHash-2-4 with a timestamp, valid for an hour). Cookies are optional: a missing or invalid server cookie gets a fresh cookie and a normal answer. A malformed cookie option gets FORMERR.

**Load test** with `dns-server/examples/loadgen.rs`, a closed-loop UDP client. These numbers come from one 10-core Mac, with the client and the node sharing the machine:

| Answer type | Client threads | QPS | p50 | p99 | p99.9 |
|---|---|---|---|---|---|
| Static | 4 | 98,759 | 37µs | 82µs | 106µs |
| `LUA` script | 4 | 84,975 | 43µs | 91µs | 122µs |
| Static | 16 | 73,308 | 211µs | 400µs | 557µs |
| `LUA` script | 16 | 78,548 | 196µs | 386µs | 675µs |

The `LUA` rows were measured before scripts moved to runner threads, which add about 5–8µs per script call.

With more client threads, throughput levels off around 71–78k QPS on macOS, because every worker shares one UDP socket. On Linux, one `SO_REUSEPORT` socket per core is the next step (marked in the code). On the server side, 99.98% of 1.55M queries took under 100µs to answer.

```bash
cargo run --release -p dns-server --example loadgen -- 127.0.0.1:5300 10 4 www.example.com/A
```

## Layout

A Cargo workspace with three crates:

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
  - `src/api.rs`: routes, transactions, serial bumps, changelog, token endpoints
  - `src/auth.rs`: tokens, grants, roles, request authentication
  - `src/spf.rs`: SPF flattening and chunked TXT rendering
  - `src/validate.rs`: record parsing, canonical forms, validation rules
  - `migrations/`: the schema, applied automatically at startup
  - `tests/api.rs`: end-to-end test against Postgres
- `mcp-server/`: MCP server (stdio) over the REST API
  - `src/main.rs`: JSON-RPC handling, tool definitions, HTTP calls
  - `tests/mcp.rs`: drives the binary over stdio against a real control plane
- `scripts/multinode-test.sh`: Docker end-to-end test: propagation, expiry, recovery
- `Dockerfile`, `docker-compose.yml`: one image with both binaries; the `multinode` compose profile runs the control plane plus two DNS nodes. Containers run as an unprivileged user, so nodes listen on 5300 inside the container; map host port 53 to it.

## Running

Requires Rust ([rustup](https://rustup.rs)) and Docker.

Start Postgres:

```bash
docker compose up -d
```

The control plane needs `DATABASE_URL`; it has no default, so a deployment can't silently fall back to these development credentials:

```bash
export DATABASE_URL=postgres://dns:dns@127.0.0.1:5432/dns
```

Run all tests (the control-plane test needs Postgres running):

```bash
cargo test
```

### Control plane

Listens on `127.0.0.1:8053`; override with the `LISTEN` environment variable. `DATABASE_URL` is required. Every request needs a token; mint the first one with `create-token` (see [Access control](#access-control)).

The API serves plain HTTP. Anywhere beyond localhost, put it behind a reverse proxy that terminates TLS and rate-limits clients, and point nodes and the MCP server at `https://`. Tokens, and the changelog with its `LUA` scripts, would otherwise cross the network in the clear.

DNS nodes (`--follow`) and the MCP server enforce this:
- They refuse a plain `http://` URL unless its host is `localhost` or a loopback address.
- On a trusted private network, `CONTROL_PLANE_ALLOW_HTTP=1` allows plain HTTP. The compose setup sets it for its nodes.
- Certificates are checked against the public web PKI roots, so the proxy needs a publicly trusted certificate.

**Limits:**
- 64 requests at once; beyond that, requests get 503.
- 30 seconds per request.
- 1000 changes per changeset.
- 20 seconds to resolve an SPF policy's senders.

```bash
cargo run -p control-plane
```

Create a zone (SOA fields are optional; mname defaults to the first NS):

```bash
curl -X POST localhost:8053/zones -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"name":"example.com","ns":["ns1.example.com."]}'
```

Apply a changeset (all-or-nothing):

```bash
curl -X POST localhost:8053/zones/example.com/changes -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"changes":[{"action":"add","name":"www","type":"A","data":"192.0.2.10"}]}'
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/zones` | List zones, plus `seq` (the changelog head in the same snapshot; nodes use it for REFRESH checks) |
| `POST` | `/zones` | Create: `name`, `ns[]`, optional `default_ttl`, `soa{mname,rname,refresh,retry,expire,minimum}` |
| `GET` | `/zones/{zone}` | Zone, SOA and all records |
| `PATCH` | `/zones/{zone}` | Change `default_ttl` or SOA fields |
| `DELETE` | `/zones/{zone}` | Delete the zone |
| `POST` | `/zones/{zone}/changes` | `{"changes":[...]}`, each `add` (name, type, data, optional ttl) or `delete` (name, type, optional data; without data, deletes the whole RRset) |
| `GET` | `/changelog?after=SEQ&limit=N` | Changelog entries after `SEQ`, oldest first, for zones the token can see. Each has an `actor`; continue from `next_after`. |
| `PUT`, `GET`, `DELETE` | `/zones/{zone}/spf/{name}` | Managed SPF policy: `{"senders": [...], "qualifier"}` (see [Managed SPF](#managed-spf)) |
| `GET` | `/whoami` | The calling token's name and grants |
| `POST`, `GET`, `DELETE` | `/tokens`, `/tokens/{name}` | Token management (admin) |

Names may be `@` (the zone apex), relative (`www`), or absolute (`www.example.com.`). Names inside record data (CNAME, MX and NS targets) must be absolute.

If a record is added without a TTL, it takes its RRset's existing TTL, or else the zone default.

Validation covers:
- record syntax for each type;
- the name being inside the zone;
- CNAME exclusivity, and no CNAME at the apex;
- the apex keeping at least one NS;
- a single TTL per RRset;
- names that belong to a hosted child zone (those must be changed in that zone);
- for `LUA` records: an allowed answer type, a script that compiles from source text, at most 16 KiB, and one script per type;
- that the data fits what nodes can store: TXT strings of at most 255 bytes, and at most 60,000 bytes of records at one name.

Each changelog entry carries the complete new record set of every name it touches, so replaying an entry is safe.

### DNS server

Follow a control plane (the normal mode):

```bash
CONTROL_PLANE_TOKEN=dnsdb_... cargo run -p dns-server -- serve ./db --follow http://127.0.0.1:8053
```

Flags:
- `--listen ADDR`: default `127.0.0.1:5300`; port 53 needs root.
- `--poll-ms N`: changelog poll interval, default 1000.
- `--node-id ID`: the name scripts see as `q.node`, default `$HOSTNAME`.
- See [Operations](#operations) for `--http`, `--rrl-rps`, `--rrl-slip`, `--map-size-mb` and `COOKIE_SECRET`.

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

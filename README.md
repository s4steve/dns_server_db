# dns_server_db

An authoritative DNS server, written in Rust, that answers queries straight from a database you can update while it runs: no restarts, no zone reloads. Responses can be tailored per query by in-process LuaJIT scripts (client subnet, name patterns, arbitrary logic).

See [PLAN.md](PLAN.md) for the full design, decisions, and staged roadmap.

## Status

**Stage 3 of 7: replication (done).** DNS nodes follow the control plane's changelog into their local LMDB.

- **Propagation:** a change made through the API reaches every node in about a second. Nodes poll every second, and each page of entries is applied in one LMDB transaction together with the node's position in the changelog, so a crash never leaves a node half-updated.
- **New nodes** start from changelog position 0 and replay everything. Each entry carries the complete record set of every name it touches, so the replay ends at the current state.
- **Expiry:** a node that can't reach the control plane keeps serving until a zone's SOA EXPIRE passes since its last successful sync. After that it returns SERVFAIL for the zone. When the control plane comes back, the node catches up and serves again.
- **Bad data:** an entry the node can't parse stops it from advancing; it never skips the entry. Its zones then expire safely rather than serve data it doesn't understand.

- **SOA REFRESH and RETRY:** every REFRESH seconds, a node compares each zone's serial with the control plane's. If they differ, it re-fetches the zone; a failed check is retried after RETRY seconds. This repairs drift the changelog can't see, like a local edit. It also makes the node an exact mirror: zones the control plane doesn't have are removed. The check only runs when the node is caught up with the changelog, so a change still on its way isn't mistaken for drift.

Differences from the plan:
- There's no snapshot endpoint yet: a new node replays the full changelog. A snapshot only becomes necessary once old changelog entries get pruned.

Earlier stages: the [control plane](https://github.com/s4steve/dns_server_db/commit/507e82a) (Postgres, validated atomic changesets, REST API) and the [DNS answer engine](https://github.com/s4steve/dns_server_db/commit/72c90b0) (RFC-correct lookups, EDNS0, truncation).

| Stage | Scope | Status |
|---|---|---|
| 0 | Skeleton UDP/TCP server | ✅ Done |
| 1 | LMDB data model + RFC-correct lookup engine | ✅ Done |
| 2 | Control plane: Postgres, validation, REST API, changelog | ✅ Done |
| 3 | Replication to nodes, SOA REFRESH/RETRY/EXPIRE | ✅ Done |
| 4 | LuaJIT tailoring | Next |
| 5 | ALIAS (in-zone targets) | |
| 6 | Ops: metrics, RRL, cookies, anycast health | |
| 7 | MCP server over the API | |

## Layout

A Cargo workspace with two crates:

- `dns-server/`: the authoritative DNS node
  - `src/main.rs`: CLI, UDP/TCP listeners, packet handling (EDNS, truncation)
  - `src/store.rs`: LMDB store: key layout, zone loading, lookups
  - `src/lookup.rs`: authoritative answer logic
  - `src/follow.rs`: changelog follower (polling, atomic apply, sync state) and SOA REFRESH/RETRY checks
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
- names that belong to a hosted child zone (those must be changed in that zone).

Each changelog entry carries the complete new record set of every name it touches, so replaying an entry is safe.

### DNS server

Follow a control plane (the normal mode):

```bash
cargo run -p dns-server -- serve ./db --follow http://127.0.0.1:8053
```

Flags: `--listen ADDR` (default `127.0.0.1:5300`; port 53 needs root) and `--poll-ms N` (default 1000).

```bash
dig @127.0.0.1 -p 5300 www.example.com A
```

Without `--follow`, the server serves whatever is in `./db` and never expires it. That's useful with zone files:

```bash
cargo run -p dns-server -- load ./db dns-server/testdata/example.com.zone
```

### Multi-node test

Builds the image, starts Postgres, the control plane (on host port 8054) and two DNS nodes (on host ports 5301 and 5302), then checks propagation, REFRESH repair, expiry and recovery:

```bash
./scripts/multinode-test.sh
```

## License

MIT, see [LICENSE](LICENSE).

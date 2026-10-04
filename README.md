# dns_server_db

An authoritative DNS server, written in Rust, that answers queries straight from a database you can update while it runs: no restarts, no zone reloads. Responses can be tailored per query by in-process LuaJIT scripts (client subnet, name patterns, arbitrary logic).

See [PLAN.md](PLAN.md) for the full design, decisions, and staged roadmap.

## Status

**Stage 2 of 7: control plane (done).** Postgres is the source of truth, and a REST API writes to it. Each write is one transaction that:

1. validates the result;
2. bumps the zone's SOA serial;
3. appends one entry to the changelog.

Invalid changesets are rejected whole, with every problem listed. The DNS nodes don't follow the changelog yet; that's Stage 3.

Already in place from Stage 1: the LMDB-backed DNS server, with RFC-correct answers (NODATA/NXDOMAIN, wildcards, CNAME chains, referrals with glue), EDNS0, and truncation with TCP retry. See the [Stage 1 commit](https://github.com/s4steve/dns_server_db/commit/72c90b0) for details.

| Stage | Scope | Status |
|---|---|---|
| 0 | Skeleton UDP/TCP server | ✅ Done |
| 1 | LMDB data model + RFC-correct lookup engine | ✅ Done |
| 2 | Control plane: Postgres, validation, REST API, changelog | ✅ Done |
| 3 | Replication to nodes, SOA-driven expiry | Next |
| 4 | LuaJIT tailoring | |
| 5 | ALIAS (in-zone targets) | |
| 6 | Ops: metrics, RRL, cookies, anycast health | |
| 7 | MCP server over the API | |

## Layout

A Cargo workspace with two crates:

- `dns-server/`: the authoritative DNS node
  - `src/main.rs`: CLI, UDP/TCP listeners, packet handling (EDNS, truncation)
  - `src/store.rs`: LMDB store: key layout, zone loading, lookups
  - `src/lookup.rs`: authoritative answer logic
  - `testdata/`: test zones and `cases.txt`, the golden answer file (a query followed by its expected response, checked by `cargo test`)
- `control-plane/`: the REST API over Postgres
  - `src/api.rs`: routes, transactions, serial bumps, changelog
  - `src/validate.rs`: record parsing, canonical forms, validation rules
  - `migrations/`: the schema, applied automatically at startup
  - `tests/api.rs`: end-to-end test against Postgres

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
| `GET` | `/zones` | List zones |
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

Load a zone file (repeat to replace it, even while the server is running):

```bash
cargo run -p dns-server -- load ./db dns-server/testdata/example.com.zone
```

Serve (listens on `127.0.0.1:5300` by default; port 53 needs root):

```bash
cargo run -p dns-server -- serve ./db
```

```bash
dig @127.0.0.1 -p 5300 www.example.com A
```

## License

MIT, see [LICENSE](LICENSE).

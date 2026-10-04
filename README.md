# dns_server_db

An authoritative DNS server, written in Rust, that answers queries straight from a database you can update while it runs: no restarts, no zone reloads. Responses can be tailored per query by in-process LuaJIT scripts (client subnet, name patterns, arbitrary logic).

See [PLAN.md](PLAN.md) for the full design, decisions, and staged roadmap.

## Status

**Stage 0 of 7: skeleton (done).** The server listens on UDP and TCP and returns a hard-coded answer:

- `A` queries for any name → `192.0.2.1`, TTL 300, authoritative (`aa`)
- Other record types → `NOERROR` with no answers (NODATA)
- Multiple questions → `FORMERR`; unparseable packets are dropped

Not yet implemented: EDNS (the OPT record isn't echoed), UDP truncation, real record storage. These start in Stage 1.

| Stage | Scope | Status |
|---|---|---|
| 0 | Skeleton UDP/TCP server | ✅ Done |
| 1 | LMDB data model + RFC-correct lookup engine | Next |
| 2 | Control plane: Postgres, validation, REST API, changelog | |
| 3 | Replication to nodes, SOA-driven expiry | |
| 4 | LuaJIT tailoring | |
| 5 | ALIAS (in-zone targets) | |
| 6 | Ops: metrics, RRL, cookies, anycast health | |
| 7 | MCP server over the API | |

## Running

Requires Rust ([rustup](https://rustup.rs)).

```bash
cargo test
```

```bash
cargo run
```

It listens on `127.0.0.1:5300` by default (port 53 needs root). Pass another address as the first argument:

```bash
cargo run -- 0.0.0.0:5300
```

Query it:

```bash
dig @127.0.0.1 -p 5300 example.com A
```

```bash
dig @127.0.0.1 -p 5300 example.com A +tcp
```

## License

MIT, see [LICENSE](LICENSE).

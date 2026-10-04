# dns_server_db

An authoritative DNS server, written in Rust, that answers queries straight from a database you can update while it runs: no restarts, no zone reloads. Responses can be tailored per query by in-process LuaJIT scripts (client subnet, name patterns, arbitrary logic).

See [PLAN.md](PLAN.md) for the full design, decisions, and staged roadmap.

## Status

**Stage 1 of 7: LMDB store and RFC-correct lookups (done).**

- Records live in LMDB. The `load` command atomically replaces a zone from an RFC 1035 zone file, and a running server sees the change on its next query, with no restart or signal. (In Stage 3, updates pulled from the changelog replace manual loads.)
- Record types: A, AAAA, CNAME, MX, TXT, NS, SOA, CAA
- Answer logic:
  - positive answers;
  - NODATA and NXDOMAIN with the SOA in the authority section, its TTL = min(SOA TTL, MINIMUM) per RFC 2308;
  - empty non-terminals return NODATA;
  - wildcards per RFC 4592;
  - CNAME chains followed across all zones we host, with loop detection;
  - referrals at zone cuts with in-zone glue, and data below a cut is never served;
  - hosted child zones are independent of their parent zone;
  - REFUSED for zones we don't host.
- EDNS0: the server advertises and honours a 1232-byte UDP payload, and returns BADVERS for unknown EDNS versions.
- Answers too large for UDP are truncated (TC flag set), so the client retries over TCP.

Not yet: additional-section records for MX/NS answers (optional per RFC 1034), DS at zone cuts (comes with DNSSEC), and a configurable LMDB map size (fixed at 1 GiB).

| Stage | Scope | Status |
|---|---|---|
| 0 | Skeleton UDP/TCP server | ✅ Done |
| 1 | LMDB data model + RFC-correct lookup engine | ✅ Done |
| 2 | Control plane: Postgres, validation, REST API, changelog | Next |
| 3 | Replication to nodes, SOA-driven expiry | |
| 4 | LuaJIT tailoring | |
| 5 | ALIAS (in-zone targets) | |
| 6 | Ops: metrics, RRL, cookies, anycast health | |
| 7 | MCP server over the API | |

## Layout

- `src/main.rs`: CLI, UDP/TCP listeners, packet handling (EDNS, truncation)
- `src/store.rs`: LMDB store: key layout, zone loading, lookups
- `src/lookup.rs`: authoritative answer logic
- `testdata/`: test zones and `cases.txt`, the golden answer file. Each case is a query followed by the expected response, and `cargo test` checks them all.

## Running

Requires Rust ([rustup](https://rustup.rs)).

```bash
cargo test
```

Load a zone (repeat to replace it, even while the server is running):

```bash
cargo run -- load ./db testdata/example.com.zone
```

Serve (listens on `127.0.0.1:5300` by default; port 53 needs root):

```bash
cargo run -- serve ./db
```

Query it:

```bash
dig @127.0.0.1 -p 5300 www.example.com A
```

## License

MIT, see [LICENSE](LICENSE).

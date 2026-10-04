-- Source of truth. Nodes never read these tables; they follow `changelog`.

CREATE TABLE zones (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,                 -- lowercase FQDN, e.g. 'example.com.'
    default_ttl INTEGER NOT NULL DEFAULT 300 CHECK (default_ttl >= 0),
    -- SOA fields live here, not in `records`: the serial is bumped on every change,
    -- and nodes use refresh/retry/expire to decide when to stop serving (Stage 3).
    mname       TEXT NOT NULL,
    rname       TEXT NOT NULL,
    serial      BIGINT NOT NULL DEFAULT 1 CHECK (serial BETWEEN 0 AND 4294967295),
    refresh     INTEGER NOT NULL DEFAULT 3600   CHECK (refresh > 0),
    retry       INTEGER NOT NULL DEFAULT 600    CHECK (retry > 0),
    expire      INTEGER NOT NULL DEFAULT 604800 CHECK (expire > 0),
    minimum     INTEGER NOT NULL DEFAULT 300    CHECK (minimum >= 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE records (
    id      BIGSERIAL PRIMARY KEY,
    zone_id BIGINT NOT NULL REFERENCES zones (id) ON DELETE CASCADE,
    name    TEXT NOT NULL,                            -- lowercase FQDN
    type    TEXT NOT NULL,                            -- 'A', 'AAAA', 'CNAME', ...
    ttl     INTEGER NOT NULL CHECK (ttl >= 0),
    data    TEXT NOT NULL,                            -- canonical presentation format
    UNIQUE (zone_id, name, type, data)
);
CREATE INDEX records_zone_name ON records (zone_id, name);

-- Append-only. Writers hold a global advisory lock from insert to commit, so seq order is
-- commit order: a node that has applied seq N can safely ask for everything after N.
-- (Rolled-back inserts leave gaps; that is harmless.)
CREATE TABLE changelog (
    seq        BIGSERIAL PRIMARY KEY,
    zone       TEXT NOT NULL,
    serial     BIGINT,                                -- zone serial after this change; NULL for deletes
    op         TEXT NOT NULL CHECK (op IN ('names', 'delete_zone')),
    -- op = 'names': {"<fqdn>": [{"type", "ttl", "data"}, ...]} -- each listed name's complete
    -- new record set; [] means the name now has no records. Replaying is idempotent.
    payload    JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

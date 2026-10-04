-- API tokens: bearer secrets, stored as SHA-256 hashes (secrets are 256-bit random, so a
-- fast hash is enough). Revoked tokens keep their row so changelog actors stay meaningful.
CREATE TABLE tokens (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    hash         BYTEA NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,          -- first characters of the secret, for recognizing it
    admin        BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

-- Per-zone permissions. pattern: 'example.com.' (that zone), '*.example.com.' (zones below
-- it, not the apex), or '*' (every zone).
CREATE TABLE grants (
    token_id BIGINT NOT NULL REFERENCES tokens (id) ON DELETE CASCADE,
    pattern  TEXT NOT NULL,
    role     TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'owner')),
    scripts  BOOLEAN NOT NULL DEFAULT false,  -- may add/delete LUA records (needs editor+)
    PRIMARY KEY (token_id, pattern)
);

-- Which token made each change. NULL for entries written before access control existed.
ALTER TABLE changelog ADD COLUMN actor TEXT;

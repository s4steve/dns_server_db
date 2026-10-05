-- Managed SPF: a sender list per name, flattened by the control plane into plain TXT
-- records (the name's v=spf1 record plus _spf0.._spf8 chunks). `terms` is the last good
-- result; `last_error` is set when a refresh fails, and the records are then left alone.
CREATE TABLE spf_policies (
    zone_id    BIGINT NOT NULL REFERENCES zones (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,                         -- lowercase FQDN
    senders    TEXT[] NOT NULL,
    qualifier  TEXT NOT NULL CHECK (qualifier IN ('~all', '-all', '?all')),
    terms      TEXT[] NOT NULL,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, name)
);

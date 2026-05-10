-- Federation: persistent server identity + operator-managed peer list.
--
-- `instance_identity` holds a single row containing this server's
-- Ed25519 keypair. It's generated on first boot if absent. The privkey
-- lives in DB to keep operations simple; operators who want HSM/file-
-- based keys can layer on top later without protocol changes.
--
-- `federation_peers` is the operator's manually-curated set of other
-- Lethe servers to pull from. `last_pulled_at` and `last_cursor` advance
-- as the pull worker makes progress; `enabled = false` means defederate
-- (existing replicated rows stay; new pulls stop).

CREATE TABLE instance_identity (
    server_pubkey  BYTEA PRIMARY KEY,
    server_privkey BYTEA NOT NULL,
    created_at     DATE NOT NULL DEFAULT CURRENT_DATE,
    CHECK (length(server_pubkey) = 32),
    CHECK (length(server_privkey) = 32)
);

CREATE TABLE federation_peers (
    server_pubkey  BYTEA PRIMARY KEY,
    endpoint       TEXT NOT NULL,
    label          TEXT,
    last_pulled_at TIMESTAMPTZ,
    last_cursor    BYTEA,
    added_at       DATE NOT NULL DEFAULT CURRENT_DATE,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (length(server_pubkey) = 32)
);

CREATE INDEX federation_peers_enabled_idx
    ON federation_peers(enabled) WHERE enabled = TRUE;

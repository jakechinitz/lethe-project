-- Multiple admin tokens with labels and revocation.
--
-- Replaces the single static `LETHE_ADMIN_TOKEN` env var as the only
-- credential. The env token still works as a bootstrap (so an
-- operator coming up cold can mint table-backed tokens for human
-- collaborators), but production peering should issue per-human
-- tokens through this table so revocation is granular.
--
-- Tokens are stored hashed (SHA-256) so a database snapshot doesn't
-- leak credentials. Lookup hashes the incoming bearer and compares.

CREATE TABLE admin_tokens (
    token_hash  BYTEA PRIMARY KEY,
    label       TEXT NOT NULL,
    created_at  DATE NOT NULL DEFAULT CURRENT_DATE,
    revoked_at  DATE,
    CHECK (length(token_hash) = 32),
    CHECK (length(label) <= 64)
);

CREATE INDEX admin_tokens_label_idx ON admin_tokens(label);

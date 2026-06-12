-- Server identity private key moves out of the database.
--
-- The 32-byte Ed25519 seed used to live in `instance_identity.server_privkey`
-- (migration 0013). A live DB compromise — SQL injection, a snapshot of an
-- unencrypted backup, a stolen postgres role — was enough to forge federated
-- events as this server. Moving the seed to a root-owned 0600 file outside
-- Postgres ends that exposure: ordinary DB queries can no longer reach it,
-- and routine DB backups don't carry a copy.
--
-- This migration relaxes the NOT NULL constraint so the app can:
--   1. Read the legacy seed from the row on first boot under the new code,
--   2. Persist it to the configured key file,
--   3. NULL the column so a future DB snapshot does not contain it.
--
-- The column itself is intentionally kept for one release so existing
-- deployments roll forward cleanly; a later migration can DROP it once
-- every operator has rotated through.

ALTER TABLE instance_identity
    ALTER COLUMN server_privkey DROP NOT NULL;

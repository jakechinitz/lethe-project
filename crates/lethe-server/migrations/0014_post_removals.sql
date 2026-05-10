-- Post-facto takedowns.
--
-- Today's moderation pipeline only rejects pre-insert. Federation
-- introduces the need to remove a post that was already accepted (an
-- origin server can issue a global takedown for content it originated;
-- locally an operator may take down content as well).
--
-- A removal substitutes the body with a tombstone in the read path
-- without deleting the row, so per-thread `seq` continuity stays intact
-- and the per-thread author signature chain is not broken.
--
-- scope = 'local'  → only this server's read path renders a tombstone.
-- scope = 'global' → originated as a signed RemovalEvent from the post's
--                    origin_server_id; propagates to peers via federation
--                    pull. The signature is verified at ingest against
--                    the originating server's pubkey.

CREATE TABLE post_removals (
    post_id          BYTEA PRIMARY KEY REFERENCES posts(id) ON DELETE CASCADE,
    removed_at       DATE NOT NULL DEFAULT CURRENT_DATE,
    reason           TEXT NOT NULL,
    scope            TEXT NOT NULL CHECK (scope IN ('local', 'global')),
    origin_server_id BYTEA,
    origin_signature BYTEA,
    CHECK (length(post_id) = 16),
    CHECK (origin_server_id IS NULL OR length(origin_server_id) = 32),
    CHECK (origin_signature IS NULL OR length(origin_signature) = 64)
);

CREATE INDEX post_removals_removed_at_idx ON post_removals(removed_at DESC);

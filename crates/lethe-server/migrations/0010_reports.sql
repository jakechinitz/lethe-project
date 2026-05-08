-- User-submitted reports against public posts.
--
-- No moderator UI or login exists yet, so this is purely a write-only
-- inbox at the schema level: clients submit a (post_id, reason?) tuple
-- gated by proof-of-work, the row lands here, and operators triage by
-- querying directly. A future moderation feature can read from this
-- table without a schema change.
--
-- Reports cascade-delete with their post so retention pruning doesn't
-- leave dangling rows. We do NOT store IP addresses, user agents, or
-- any reporter identity; reports are anonymous by construction.

CREATE TABLE reports (
    id           BYTEA PRIMARY KEY,
    post_id      BYTEA NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    reason_text  TEXT,
    reported_at  DATE NOT NULL DEFAULT CURRENT_DATE,
    CHECK (length(id) = 16),
    CHECK (length(post_id) = 16),
    CHECK (reason_text IS NULL OR length(reason_text) <= 500)
);

CREATE INDEX reports_post_id_idx     ON reports(post_id);
CREATE INDEX reports_reported_at_idx ON reports(reported_at);

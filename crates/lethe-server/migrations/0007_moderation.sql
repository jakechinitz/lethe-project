-- Public-content moderation log.
--
-- Rows are written when the moderation pipeline rejects a public post or
-- thread submission. The body content is NOT stored — only a SHA-256
-- hash so the log is auditable without re-publishing what was rejected.
-- `post_id` is null because moderation runs at submit time and rejected
-- submissions are never inserted into `posts`.
--
-- The retention worker can be configured to prune this log, but the
-- default is to keep it indefinitely; transparency is the point.

CREATE TABLE moderation_actions (
    id          BYTEA PRIMARY KEY,        -- 16-byte ULID
    board_id    TEXT,
    body_hash   BYTEA NOT NULL,           -- 32-byte SHA-256
    reason      TEXT  NOT NULL,           -- short reason code, see moderation::Verdict
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX moderation_actions_decided_at_idx
    ON moderation_actions(decided_at DESC);
CREATE INDEX moderation_actions_body_hash_idx
    ON moderation_actions(body_hash);

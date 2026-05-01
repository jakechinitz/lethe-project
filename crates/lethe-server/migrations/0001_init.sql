-- Public boards / threads / posts.
--
-- Things deliberately absent from this schema: users, accounts, sessions,
-- emails, phones, IP addresses, user-agents, edit/delete history, last-seen,
-- presence. Don't add columns from this list without changing the threat
-- model.

CREATE TABLE boards (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    pow_bits    SMALLINT NOT NULL DEFAULT 18,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO boards (id, title) VALUES ('general', 'general')
    ON CONFLICT (id) DO NOTHING;

CREATE TABLE threads (
    id          BYTEA PRIMARY KEY,         -- 16-byte ULID
    board_id    TEXT NOT NULL REFERENCES boards(id),
    title       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL       -- coarsened to 60s by the app
);

CREATE INDEX threads_board_created_idx ON threads(board_id, created_at DESC);

CREATE TABLE posts (
    id          BYTEA PRIMARY KEY,
    thread_id   BYTEA NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    body        TEXT NOT NULL,
    pow_nonce   BYTEA NOT NULL,
    pubkey      BYTEA,                     -- 32-byte Ed25519, NULL for anon
    signature   BYTEA,                     -- 64-byte detached sig
    created_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (thread_id, seq)
);

CREATE INDEX posts_thread_seq_idx ON posts(thread_id, seq);
CREATE INDEX posts_thread_pubkey_idx
    ON posts(thread_id, pubkey)
    WHERE pubkey IS NOT NULL;

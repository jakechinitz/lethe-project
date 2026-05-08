-- Federation: track which server each thread/post originated on.
--
-- A federated copy of a post carries the originating server's Ed25519
-- pubkey and the post id assigned on that server. Locally-authored rows
-- get their own server pubkey + a freshly-minted local id at write time
-- (logic::posts), so the same dedupe key works for both. Pre-existing
-- rows are left NULL; readers MUST treat NULL origin_server_id as "this
-- server" for backwards compatibility.

ALTER TABLE threads
    ADD COLUMN origin_server_id BYTEA;

ALTER TABLE posts
    ADD COLUMN origin_server_id BYTEA,
    ADD COLUMN origin_post_id   BYTEA;

CREATE UNIQUE INDEX posts_origin_idx
    ON posts(origin_server_id, origin_post_id)
    WHERE origin_server_id IS NOT NULL AND origin_post_id IS NOT NULL;

CREATE UNIQUE INDEX threads_origin_idx
    ON threads(origin_server_id, id)
    WHERE origin_server_id IS NOT NULL;

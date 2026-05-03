-- Per-room invitee allowlist (optional).
--
-- A room created from a public thread can restrict join to a specific
-- set of thread-signing pubkeys (each a 32-byte Ed25519 public key the
-- creator picked from the originating thread's signed posts).
--
-- NULL means open: anyone with the invite link can request to join,
-- exactly as before this column existed. A non-empty array activates
-- the allowlist; the join handler then requires the joiner to prove
-- ownership of one of these thread-signing keys with a fresh
-- signature over `b"lethe-join-v1\0" || invite_code || box_pubkey || ts_le8`.
--
-- The allowlist is only meaningful with `origin_thread` set, since
-- "this pubkey signed in that thread" is the property being proved.
-- The CREATE-room handler enforces that pairing.

ALTER TABLE rooms
    ADD COLUMN allowlist_thread_pubkeys BYTEA[];

-- Per-board / per-room retention policy.
--
-- Threads (and their cascading posts) are deleted by the background
-- retention worker once their `created_at` is older than the board's
-- `retention_days`. Room messages are deleted similarly per-room.
--
-- Encrypted ciphertext counts as data the user trusted us to retain;
-- the conservative defaults (7 days for room messages, 30 days for
-- public threads) are deliberately short so the server holds as little
-- as possible. Anyone running an instance can lengthen these by
-- updating the row.

ALTER TABLE boards
    ADD COLUMN retention_days SMALLINT NOT NULL DEFAULT 30;

ALTER TABLE rooms
    ADD COLUMN message_retention_days SMALLINT NOT NULL DEFAULT 7;

-- Member removal + room rekey.
--
-- `current_epoch` is bumped each time the room key is rotated. Clients
-- track their last-seen epoch and, on advance, look for an updated
-- `wrapped_key` on their own member row. The schema keeps a single row
-- per member and overwrites `wrapped_key` on rekey — old keys live in
-- the surviving members' localStorage for decrypting historical
-- messages, but the server only ever holds the current epoch's wrap.
--
-- `removed_at` is the soft-removal flag. Once set, the row is excluded
-- by all membership checks (post, list, wrap), but stays around so the
-- invite chain remains auditable in trust cards.

ALTER TABLE rooms
    ADD COLUMN current_epoch INTEGER NOT NULL DEFAULT 0;

ALTER TABLE room_members
    ADD COLUMN removed_at TIMESTAMPTZ;

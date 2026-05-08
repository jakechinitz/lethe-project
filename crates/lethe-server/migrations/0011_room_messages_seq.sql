-- Stable ordering for room messages.
--
-- Message ids became uniformly random in migration 0009 — they no
-- longer encode creation time, so ordering by id is no longer ordering
-- by insert time. Listing falls back on a server-side BIGSERIAL `seq`
-- per room: monotonically assigned at insert, used as the sole ordering
-- and cursor field. The serial number leaks "this message was inserted
-- after that one" but no absolute time, which matches the date-only
-- privacy contract.

ALTER TABLE room_messages
    ADD COLUMN seq BIGSERIAL;

CREATE INDEX room_messages_room_seq_idx ON room_messages(room_id, seq);

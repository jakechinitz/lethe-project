-- Public threads persist indefinitely by default; ephemerality becomes
-- an author-side choice instead of a server-imposed one.
--
-- Rationale: the anonymity properties of public posts (Tor transport,
-- no accounts, per-thread keys, date-only timestamps, random ids) do
-- not degrade with corpus age, while the product's trust primitives —
-- thread-local continuity ("same anon as #N"), room provenance, the
-- moderation audit log — all assume threads stay readable. A 30-day
-- blanket purge quietly destroyed the durable record the platform
-- exists to provide. Private-room ciphertext is unaffected and keeps
-- its short default (7 days): rooms have no forward secrecy, so
-- minimizing retained ciphertext is still the right call there.
--
-- Two knobs replace the old blanket default:
--   * boards.retention_days becomes NULLable; NULL = keep forever.
--     Operators may still set a number to re-enable board-wide pruning.
--   * threads.expires_at (DATE, NULL = never): set once by the author
--     at creation ("this thread should disappear after N days"). The
--     retention worker deletes the thread when current_date reaches it.
--
-- Existing boards are flipped to NULL so no deployed data starts
-- expiring (or stops being expired) in a surprising way: operators who
-- previously relied on the implicit 30 must now opt in explicitly.

ALTER TABLE boards
    ALTER COLUMN retention_days DROP NOT NULL,
    ALTER COLUMN retention_days DROP DEFAULT;

UPDATE boards SET retention_days = NULL;

ALTER TABLE threads
    ADD COLUMN expires_at DATE;

-- Partial index: the retention sweep scans only threads that can
-- actually expire.
CREATE INDEX threads_expires_at_idx
    ON threads(expires_at) WHERE expires_at IS NOT NULL;

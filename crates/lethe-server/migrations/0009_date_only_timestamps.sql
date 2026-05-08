-- Coarsen user-facing timestamps to DATE.
--
-- A database snapshot used to be able to reconstruct activity to the
-- minute (TIMESTAMPTZ + 60-second app-level coarsening) and to the
-- millisecond if you read the post id (ULIDs encode time). Both signals
-- are now removed: ids became random in `ids::new_id` (no time bytes)
-- and these columns are downgraded to DATE so the row itself only
-- reveals what day something happened.
--
-- `request_nonces.seen_at` deliberately keeps TIMESTAMPTZ: it's an
-- internal replay-protection field, never exposed in any API, and the
-- freshness check needs sub-day precision. The retention worker prunes
-- it on an hourly schedule.

ALTER TABLE boards
    ALTER COLUMN created_at TYPE DATE USING created_at::date,
    ALTER COLUMN created_at SET DEFAULT CURRENT_DATE;

ALTER TABLE threads
    ALTER COLUMN created_at TYPE DATE USING created_at::date,
    ALTER COLUMN last_post_at TYPE DATE USING last_post_at::date,
    ALTER COLUMN last_post_at SET DEFAULT CURRENT_DATE;

ALTER TABLE posts
    ALTER COLUMN created_at TYPE DATE USING created_at::date;

ALTER TABLE rooms
    ALTER COLUMN created_at TYPE DATE USING created_at::date;

ALTER TABLE room_members
    ALTER COLUMN joined_at  TYPE DATE USING joined_at::date,
    ALTER COLUMN removed_at TYPE DATE USING removed_at::date;

ALTER TABLE room_messages
    ALTER COLUMN created_at TYPE DATE USING created_at::date;

ALTER TABLE moderation_actions
    ALTER COLUMN decided_at TYPE DATE USING decided_at::date,
    ALTER COLUMN decided_at SET DEFAULT CURRENT_DATE;

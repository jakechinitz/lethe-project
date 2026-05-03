-- Categories: replace the single 'general' board with four discussion
-- categories. The original 'general' row is kept for backward
-- compatibility (existing test fixtures + threads keep working) but is
-- excluded from the front-page feed.
--
-- Threads gain `last_post_at` (timestamp of the most-recent post in the
-- thread) and `post_count`, so the feed can sort by activity without
-- aggregating on every read.

INSERT INTO boards (id, title) VALUES
    ('government',   'Government'),
    ('economy',      'Economy'),
    ('science_tech', 'Science & Tech'),
    ('all_other',    'All other')
    ON CONFLICT (id) DO NOTHING;

ALTER TABLE threads
    ADD COLUMN last_post_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN post_count   INTEGER     NOT NULL DEFAULT 0;

-- Backfill from existing posts. New rows start at 0 and rely on
-- `db::posts::insert` to bump them on every write.
UPDATE threads SET
    last_post_at = COALESCE(
        (SELECT MAX(created_at) FROM posts WHERE thread_id = threads.id),
        threads.created_at
    ),
    post_count = COALESCE(
        (SELECT COUNT(*)::int FROM posts WHERE thread_id = threads.id),
        0
    );

CREATE INDEX threads_last_post_at_idx ON threads(last_post_at DESC);

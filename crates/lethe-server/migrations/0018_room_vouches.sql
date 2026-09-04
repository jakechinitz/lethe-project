-- Room-vouched public posts.
--
-- A member of a room can attach a *vouch* to a public post: a linkable
-- ring signature over the room's accepted-member signing keys, proving
-- "someone in this room wrote this exact text" without revealing who.
-- The ring is pinned to a *creator-signed roster* so the server cannot
-- forge membership: readers verify the roster signature with the
-- creator's key, then verify the ring signature against that roster.
--
-- rooms.vouching_enabled  — opt-in. Only vouching rooms expose a public
--                           roster (signing pubkeys + count; nothing
--                           else). Set when the creator signs epoch 1.
-- rooms.roster_epoch      — the latest signed roster; 0 = none yet.
-- room_rosters            — every signed roster, keyed by epoch. A
--                           vouch cites its epoch so historical vouches
--                           stay verifiable after membership changes.
-- posts.vouch             — the vouch payload, opaque JSON, served
--                           verbatim; readers verify locally.
-- posts.vouch_room_id     — denormalised for cheap feed filtering.
--
-- Independently of vouching, /members is no longer public: the roster
-- of box keys, join dates and the invite tree is now member-only.

ALTER TABLE rooms
    ADD COLUMN vouching_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN roster_epoch     INTEGER NOT NULL DEFAULT 0;

CREATE TABLE room_rosters (
    room_id            BYTEA   NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    epoch              INTEGER NOT NULL,
    member_sig_pubkeys BYTEA[] NOT NULL,
    creator_sig        BYTEA   NOT NULL,
    signed_at          DATE    NOT NULL DEFAULT CURRENT_DATE,
    PRIMARY KEY (room_id, epoch),
    CHECK (epoch >= 1),
    CHECK (length(creator_sig) = 64)
);

ALTER TABLE posts
    ADD COLUMN vouch         TEXT,
    ADD COLUMN vouch_room_id BYTEA;

CREATE INDEX posts_vouch_room_idx
    ON posts(vouch_room_id) WHERE vouch_room_id IS NOT NULL;

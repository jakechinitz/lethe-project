-- Private rooms. Server stores opaque ciphertext only.
--
-- The server cannot decrypt `room_messages.ciphertext` and cannot read the
-- room key wrapped in `room_members.wrapped_key`. The trust layer (provenance,
-- invite chain, key continuity) lives in this schema; ceremony/attestation
-- tables are deferred to a future migration.

CREATE TABLE rooms (
    id                      BYTEA PRIMARY KEY,
    origin_thread           BYTEA REFERENCES threads(id),
    invite_code             TEXT NOT NULL UNIQUE,
    created_at              TIMESTAMPTZ NOT NULL,
    -- Provenance: optional Ed25519 attestation by the creator's thread key.
    creator_thread_pubkey   BYTEA,
    provenance_sig          BYTEA
);

CREATE INDEX rooms_invite_code_idx ON rooms(invite_code);

CREATE TABLE room_members (
    room_id                 BYTEA NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    member_box_pubkey       BYTEA NOT NULL,    -- X25519 (32 bytes)
    member_sig_pubkey       BYTEA NOT NULL,    -- Ed25519 (32 bytes)
    wrapped_key             BYTEA,             -- crypto_box_seal of the room key, NULL until granted
    joined_at               TIMESTAMPTZ NOT NULL,
    invited_by_box_pubkey   BYTEA,             -- forms the invite chain; NULL only for creator
    verification_state      TEXT NOT NULL DEFAULT 'unverified',
    PRIMARY KEY (room_id, member_box_pubkey)
);

CREATE INDEX room_members_sig_pubkey_idx ON room_members(room_id, member_sig_pubkey);

CREATE TABLE room_messages (
    id                  BYTEA PRIMARY KEY,
    room_id             BYTEA NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    sender_sig_pubkey   BYTEA NOT NULL,
    nonce               BYTEA NOT NULL,        -- 24 bytes (XChaCha20-Poly1305)
    ciphertext          BYTEA NOT NULL,
    sender_sig          BYTEA NOT NULL,        -- Ed25519 over canonical_message_payload
    created_at          TIMESTAMPTZ NOT NULL
);

CREATE INDEX room_messages_room_created_idx ON room_messages(room_id, created_at);

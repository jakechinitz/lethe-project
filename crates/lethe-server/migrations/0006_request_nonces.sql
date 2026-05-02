-- Replay protection for authenticated room requests.
--
-- The list-messages and remove-and-rekey endpoints are signed by a member
-- over a payload that includes a unix timestamp. The 60-second window in
-- the handler bounds how stale a signature can be, but within that window
-- a captured (sig, ts) could be replayed. We close that window by
-- recording every (kind, sig_pubkey, ts) we accept and rejecting any
-- duplicate.
--
-- Rows are pruned by the retention worker once they're older than the
-- handler's freshness window.

CREATE TABLE request_nonces (
    kind        TEXT        NOT NULL,
    sig_pubkey  BYTEA       NOT NULL,
    ts          BIGINT      NOT NULL,
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, sig_pubkey, ts)
);

CREATE INDEX request_nonces_seen_at_idx ON request_nonces(seen_at);

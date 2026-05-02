# Lethe

A Tor-native, anonymous public-to-private coordination platform. Public
boards are 4chan-style anonymous threads. Private rooms are end-to-end
encrypted text chat. There are no accounts, no global profiles, and the
server is treated as untrusted: it stores ciphertext only for private
rooms and never sees user plaintext or any unwrapped key.

This repository is a **thin end-to-end vertical slice** of the larger
design — anonymous board, thread-local Ed25519 continuity ("same anon as
#N"), and one-click E2EE rooms with provenance + invite-chain + key
continuity for the trust card. Forward secrecy, ceremonies, member
removal, attachments, voice/video, and Tor-deployment scripting are
intentionally out of scope here. See `/root/.claude/plans/give-this-a-shot-delegated-raven.md`
for the full plan.

## Repo layout

```
crates/lethe-types/    serde DTOs shared by the server and tests
crates/lethe-server/   axum + sqlx server (the binary)
  src/
    routes/  HTTP handlers — parse, call logic/, shape response
    logic/   business logic — no axum, no sqlx
    db/      sqlx queries — row types stay inside this module
    crypto.rs   Ed25519 verification (the only file using ed25519_dalek)
    pow.rs      SHA-256 hashcash check
    csp.rs      strict CSP and security headers
    config.rs / state.rs / error.rs / ids.rs / time.rs
  templates/   askama HTML pages (CSP-strict, no inline JS)
  static/      hand-written CSS + esbuild output
  migrations/  sqlx migrations
  tests/       integration tests + browser-mimic crypto helpers
client/                TypeScript page entries built by esbuild
  src/
    lib/       sodium, base64, pow, threadkey, roomkey, api, dom, strings
    pages/     one entry per HTML page; no SPA, no framework
```

The product is privacy-critical, so the codebase is laid out so any one
file is small enough to read top-to-bottom and reviewers (or LLMs) can
follow the call graph without holding the whole system in mind.
Layering rules: `routes/` calls into `logic/`, `logic/` calls into `db/`
and `crypto.rs`. No reverse imports. No SQL outside `db/`. No
`ed25519_dalek` types outside `crypto.rs`. On the client, only
`sodium.ts` imports libsodium and only `threadkey.ts` / `roomkey.ts`
touch `localStorage`.

## Running locally

Requires Rust (stable), Node (20+), and Postgres 14+.

```sh
# 1. Database
sudo service postgresql start
sudo -u postgres psql -c "CREATE DATABASE lethe;"
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'dev';"

# 2. Client bundles
cd client && npm install && node build.mjs && cd ..

# 3. Server
cp .env.example .env   # edit DATABASE_URL if needed
cargo run -p lethe-server
```

Then open <http://127.0.0.1:8080/>.

## Tests

Integration tests need a Postgres reachable at `127.0.0.1:5432` with
user `postgres`/password `dev`. Each test creates its own throwaway
database.

```sh
cargo test
(cd client && npx tsc --noEmit)
cargo clippy --all-targets -- -D warnings
```

The headline test is `tests/room_roundtrip.rs::room_e2ee_roundtrip_with_provenance`,
which drives two clients through the API, decrypts a message round-tripped
through the server, and asserts no plaintext was stored anywhere.

## Front-page feed

The home page (`/`) is a flat thread feed across four categories:
**Government**, **Economy**, **Science & Tech**, **All other**. Tabs at
the top filter to one category; the default merges all four. A "Sort"
toggle picks between **Last comment** (active threads first) and
**Newest** (most-recently created first). The feed is cursor-paginated
and infinite-scrolls via `IntersectionObserver`. The new-thread form
sits at the top in a collapsible `<details>`; pick a category from the
dropdown, write a title and body, and the browser computes the PoW
before posting. Once posted, the page redirects to the thread.

The welcome / rules / grounding-principles copy lives above the feed
in a collapsible block — open by default for first-time readers.

The legacy `general` board still exists for back-compat (existing tests
write to it) but is intentionally hidden from the front-page feed.

## Rooms

Private rooms are capped at **50 active members**. Removed members
don't count toward the cap; re-joining as the same box pubkey is
idempotent. The "My rooms" page (linked from the topbar) lists every
room this browser has keys for — built entirely from `localStorage`,
so the server never sees a per-user room list.

## Backup &amp; restore (keyfile)

Identities live entirely in `localStorage`. Tor Browser's "New Identity"
button and the Safer security level wipe site storage, which would
otherwise destroy every thread identity and room key on the device.

The "My rooms" page hosts an **Export keyfile** / **Import keyfile**
pair. Export prompts for a passphrase (≥ 8 chars), runs Argon2id over
it, encrypts every `lethe.*` localStorage entry with
XChaCha20-Poly1305, and downloads the result as `lethe-keys-YYYY-MM-DD.lethe`.
Import asks for the passphrase and restores the entries (with an
overwrite/keep-local prompt for any collisions). The file format is
documented at the top of `client/src/lib/keyfile.ts`. Lose the
passphrase and the file is unrecoverable.

## Replay protection

Authenticated room requests (`POST /messages/list`,
`POST /remove`) carry a Unix timestamp inside the signed payload. The
server rejects anything outside a ±60 s window AND inserts the
`(kind, sig_pubkey, ts)` tuple into a `request_nonces` table on accept;
a duplicate is rejected with 409. Old rows are pruned by the retention
worker every hour.

## Removing members and rotating room keys

The room creator (the only member with no inviter) can remove any other
member via `POST /api/rooms/:room_id/remove`. The request is signed
with the creator's per-room Ed25519 sig key over a canonical payload
containing the room id, a fresh timestamp (±60 s window), and the
target's box pubkey. Server checks the sig, verifies the signer is the
creator, and runs an atomic transaction:

1. Soft-remove the target (`removed_at = now()`); they immediately
   fail every `is_member` check, so they cannot post or list messages.
2. Overwrite each surviving member's `wrapped_key` with a fresh wrap of
   the new symmetric room key the caller supplies.
3. Bump `rooms.current_epoch`.

Surviving members detect the new epoch on their next member poll,
unwrap their fresh `wrapped_key`, and append it to a per-room key
history in `localStorage`. Sends always use the most recent key;
receives try each historical key (newest first), so messages from
before a rekey stay readable on still-present devices. The removed
member retains whatever they had locally — encryption can't take that
back — but every message after the rekey is opaque to them.

## Storage and retention

Public posts and private-room ciphertext both live in Postgres. Server
storage is automatic — every successful POST persists. The server has
no way to read room messages: each row stores opaque ciphertext, the
24-byte XChaCha20-Poly1305 nonce, and the sender's Ed25519 signature.

A background **retention worker** runs every hour and deletes:

- threads whose `created_at` exceeds the board's `retention_days`
  (default 30 days)
- room messages whose `created_at` exceeds the room's
  `message_retention_days` (default 7 days)

These columns are configurable per-board / per-room — operators pick
their own ceiling. The defaults are deliberately short so the server
holds as little as possible. There are no automated backups; if you
want them, point a sidecar at `pg_dump` with off-box encrypted storage.

There is no automatic data export and no user-facing "delete my
posts" — the retention sweep is the only deletion path.

## systemd

Minimal unit (`/etc/systemd/system/lethe.service`):

```
[Unit]
Description=Lethe
After=network.target postgresql.service

[Service]
Type=simple
User=lethe
EnvironmentFile=/etc/lethe.env
WorkingDirectory=/srv/lethe
ExecStart=/srv/lethe/lethe-server
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=

[Install]
WantedBy=multi-user.target
```

`/etc/lethe.env` holds `DATABASE_URL`, `BIND_ADDR=127.0.0.1:8080`, and
`RUST_LOG=lethe_server=info`. Logs land in `journalctl -u lethe`.

## Health check

`GET /healthz` returns `200 OK` with no body. Use it from your supervisor
or external monitor — it does not touch the database, log the request,
or expose anything else.

## Tor / onion deployment

The server binds to `127.0.0.1:8080` by default and serves no third-party
assets, so it works as a Tor hidden service with no application changes.

Add to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/lethe/
HiddenServicePort 80 127.0.0.1:8080
```

Then `systemctl restart tor` and read the `.onion` address from
`/var/lib/tor/lethe/hostname`. Do not put a reverse proxy or CDN in
front of the service — the whole point is that the operator runs as
little extra software as possible.

### Tor Browser security levels

| Level    | Works | Notes |
|----------|-------|-------|
| Standard | yes   | Full functionality (PoW, signing, encryption). |
| Safer    | yes   | JIT off; PoW is slower but still completes. |
| Safest   | no    | Disables JavaScript globally — there is nothing the app can do about this; it breaks PoW, signing, and the entire E2EE flow. The page still renders read-only public threads since those are server-rendered HTML, but posting and rooms are unavailable. |

## Mobile

The UI is designed mobile-first with a single-column layout that works
on a phone in portrait. There is no native app; use the system browser
or, on Tor, **Onion Browser** (iOS) or **Tor Browser for Android**. Both
default to the Standard security level, which is what we test against.

Tap targets are at least 44 px high and forms scale to full width below
480 px wide.

## What this slice deliberately does NOT promise

- It does **not** verify whether a room or member is safe. It can only
  show continuity, provenance, the invite path, and key continuity.
- Room messages are **not forward-secret**. Any compromised member's
  device exposes all past and future messages in that room.
- Browser keys live in `localStorage`. There is no recovery.
- Tor / network-layer anonymity is the deployment's responsibility.

These are not bugs; they are the boundary of the slice. The plan file
documents how each becomes a built feature in later phases.

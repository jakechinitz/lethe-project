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

## Tor / onion deployment

The server binds to `127.0.0.1:8080` by default. To expose it as a Tor
hidden service, point a `HiddenServicePort 80 127.0.0.1:8080` at it in
your `torrc`. No application changes are required; do not run any other
reverse proxy or CDN in front of it.

## What this slice deliberately does NOT promise

- It does **not** verify whether a room or member is safe. It can only
  show continuity, provenance, the invite path, and key continuity.
- Room messages are **not forward-secret**. Any compromised member's
  device exposes all past and future messages in that room.
- Browser keys live in `localStorage`. There is no recovery.
- Tor / network-layer anonymity is the deployment's responsibility.

These are not bugs; they are the boundary of the slice. The plan file
documents how each becomes a built feature in later phases.

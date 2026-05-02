#!/usr/bin/env bash
#
# infra/backup.sh — encrypted Postgres backup for Lethe.
#
# Reads its config from the environment (the systemd unit + cron pull
# /etc/lethe.env). Runs `pg_dump` against the configured DATABASE_URL,
# pipes the output through `age` so the key holder is the only entity
# that can decrypt, and writes a timestamped file to BACKUP_DIR.
#
# Encryption model:
#   - Generate the keypair OFFLINE, on a machine that is not the server.
#     `age-keygen -o lethe-backup-key.txt`
#   - Copy ONLY the public key (e.g. age1...) to /etc/lethe.env as
#     BACKUP_AGE_RECIPIENT=age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#   - Store the file with the private key (lethe-backup-key.txt) in a
#     secure offline location.  The server NEVER has the private key, so
#     a server compromise cannot decrypt past backups.
#
# Restore:
#   age --decrypt -i lethe-backup-key.txt lethe-2026-05-12.sql.age \
#     | psql "$DATABASE_URL"
#
# Required env:
#   DATABASE_URL          full Postgres URL (already in /etc/lethe.env)
#   BACKUP_AGE_RECIPIENT  age public key (age1...)
#
# Optional env:
#   BACKUP_DIR            default /var/backups/lethe
#   BACKUP_RETENTION_DAYS default 30
#
# Exit codes:
#   0 success
#   1 misconfiguration (missing env, no `age`, no `pg_dump`)
#   2 backup itself failed

set -euo pipefail

die() { echo "[lethe-backup] $*" >&2; exit "${2:-1}"; }
log() { echo "[lethe-backup] $*"; }

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_AGE_RECIPIENT:?BACKUP_AGE_RECIPIENT is required (run age-keygen offline; put the public key here)}"

BACKUP_DIR="${BACKUP_DIR:-/var/backups/lethe}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

command -v pg_dump >/dev/null 2>&1 || die "pg_dump not found"
command -v age     >/dev/null 2>&1 || die "age not found (apt install age)"

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

stamp="$(date -u +%Y-%m-%dT%H%M%SZ)"
out="$BACKUP_DIR/lethe-$stamp.sql.age"
tmp="$out.partial"

log "starting backup -> $out"
if pg_dump --no-owner --no-privileges --format=plain "$DATABASE_URL" \
   | age --recipient "$BACKUP_AGE_RECIPIENT" --output "$tmp"; then
    mv "$tmp" "$out"
    chmod 0600 "$out"
    log "wrote $(stat -c%s "$out") bytes to $out"
else
    rm -f "$tmp"
    die "pg_dump | age failed" 2
fi

# Prune old backups. find -mtime is whole days; we want strictly-older-than.
log "pruning files older than $RETENTION_DAYS days from $BACKUP_DIR"
find "$BACKUP_DIR" -maxdepth 1 -name 'lethe-*.sql.age' -type f \
    -mtime +"$RETENTION_DAYS" -print -delete || true

log "done."

#!/usr/bin/env bash
#
# infra/provision.sh — single-machine Lethe deploy on Debian/Ubuntu.
#
# What this does:
#   1. Installs build deps, postgres, tor.
#   2. Creates a `lethe` system user.
#   3. Builds the release binary from the current checkout.
#   4. Writes /etc/lethe.env, /etc/systemd/system/lethe.service.
#   5. Configures Postgres: creates the `lethe` role + `lethe` database.
#   6. Configures Tor: writes a HiddenServicePort line and prints the
#      .onion address.
#   7. Enables and starts the lethe systemd unit.
#
# Idempotent: re-running upgrades the binary and re-applies config.
#
# Run as root from the repo root: `sudo infra/provision.sh`.

set -euo pipefail

LETHE_USER=lethe
LETHE_HOME=/srv/lethe
LETHE_BIN="$LETHE_HOME/lethe-server"
LETHE_STATIC="$LETHE_HOME/static"
LETHE_TEMPLATES="$LETHE_HOME/templates"
LETHE_MIGRATIONS="$LETHE_HOME/migrations"
ENV_FILE=/etc/lethe.env
UNIT_FILE=/etc/systemd/system/lethe.service
TOR_CONFIG=/etc/tor/torrc.d/lethe.conf
TOR_HIDDEN_DIR=/var/lib/tor/lethe

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

die() { echo "[provision] error: $*" >&2; exit 1; }
log() { echo "[provision] $*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$REPO_ROOT/Cargo.toml" ]] || die "run from the Lethe repo (Cargo.toml not found)"

# ---------------------------------------------------------------- packages

log "installing apt packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev curl git cron \
    postgresql tor nodejs npm age

# ---------------------------------------------------------------- rust

if ! command -v cargo >/dev/null 2>&1; then
    log "installing rustup"
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

# ---------------------------------------------------------------- system user

if ! id -u "$LETHE_USER" >/dev/null 2>&1; then
    log "creating $LETHE_USER user"
    useradd --system --create-home --home-dir "$LETHE_HOME" --shell /usr/sbin/nologin "$LETHE_USER"
fi
install -d -m 0755 -o "$LETHE_USER" -g "$LETHE_USER" "$LETHE_HOME"

# ---------------------------------------------------------------- postgres

log "configuring postgres"
PG_PASSWORD="lethe-$(head -c 16 /dev/urandom | xxd -p)"
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lethe') THEN
        CREATE ROLE lethe LOGIN PASSWORD '$PG_PASSWORD';
    ELSE
        ALTER ROLE lethe WITH PASSWORD '$PG_PASSWORD';
    END IF;
END \$\$;
SELECT 'CREATE DATABASE lethe OWNER lethe' WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = 'lethe'
)\gexec
SQL

DATABASE_URL="postgres://lethe:${PG_PASSWORD}@127.0.0.1:5432/lethe"

# ---------------------------------------------------------------- build

log "building release binary"
cd "$REPO_ROOT"
cargo build --release --locked -p lethe-server

log "building client bundles"
( cd client && npm install --no-audit --no-fund && node build.mjs )

# ---------------------------------------------------------------- install

log "installing files into $LETHE_HOME"
install -m 0755 -o "$LETHE_USER" -g "$LETHE_USER" \
    "$REPO_ROOT/target/release/lethe-server" "$LETHE_BIN"
rm -rf "$LETHE_STATIC" "$LETHE_TEMPLATES" "$LETHE_MIGRATIONS"
cp -r "$REPO_ROOT/crates/lethe-server/static"     "$LETHE_STATIC"
cp -r "$REPO_ROOT/crates/lethe-server/templates"  "$LETHE_TEMPLATES"
cp -r "$REPO_ROOT/crates/lethe-server/migrations" "$LETHE_MIGRATIONS"
chown -R "$LETHE_USER:$LETHE_USER" "$LETHE_HOME"

# ---------------------------------------------------------------- env

log "writing $ENV_FILE"
install -m 0640 -o root -g "$LETHE_USER" /dev/null "$ENV_FILE"
cat > "$ENV_FILE" <<ENV
DATABASE_URL=$DATABASE_URL
BIND_ADDR=127.0.0.1:8080
DEFAULT_BOARD_POW_BITS=18
RUST_LOG=lethe_server=info,tower_http=warn
LETHE_STATIC_DIR=$LETHE_STATIC
ENV

# ---------------------------------------------------------------- systemd

log "writing $UNIT_FILE"
cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=Lethe
After=network.target postgresql.service

[Service]
Type=simple
User=$LETHE_USER
Group=$LETHE_USER
EnvironmentFile=$ENV_FILE
WorkingDirectory=$LETHE_HOME
ExecStart=$LETHE_BIN
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable lethe.service
systemctl restart lethe.service

# ---------------------------------------------------------------- backups

log "installing backup script"
install -m 0755 -o root -g root "$REPO_ROOT/infra/backup.sh" /usr/local/bin/lethe-backup
install -d -m 0700 -o "$LETHE_USER" -g "$LETHE_USER" /var/backups/lethe

# Daily backup at 03:17 UTC, jittered slightly to avoid neighbours.
cat > /etc/cron.d/lethe-backup <<CRON
17 3 * * * $LETHE_USER set -a; . $ENV_FILE; set +a; /usr/local/bin/lethe-backup >> /var/log/lethe-backup.log 2>&1
CRON
chmod 0644 /etc/cron.d/lethe-backup
touch /var/log/lethe-backup.log
chown "$LETHE_USER:$LETHE_USER" /var/log/lethe-backup.log
systemctl restart cron 2>/dev/null || true

if ! grep -q '^BACKUP_AGE_RECIPIENT=' "$ENV_FILE"; then
    echo "BACKUP_AGE_RECIPIENT=" >> "$ENV_FILE"
    log ""
    log "ACTION REQUIRED: backups will not run until you add an age recipient."
    log "  1. On a separate machine, run: age-keygen -o lethe-backup-key.txt"
    log "  2. Copy the public key (the line starting with age1...)"
    log "  3. Edit $ENV_FILE and set BACKUP_AGE_RECIPIENT=age1...."
    log "  4. Keep lethe-backup-key.txt OFFLINE. Without it, backups cannot be decrypted."
    log ""
fi

# ---------------------------------------------------------------- tor

log "configuring tor hidden service"
mkdir -p /etc/tor/torrc.d
cat > "$TOR_CONFIG" <<TOR
HiddenServiceDir $TOR_HIDDEN_DIR
HiddenServicePort 80 127.0.0.1:8080
TOR

# Ensure torrc includes the snippet (Debian default does %include /etc/tor/torrc.d).
if ! grep -q "torrc.d" /etc/tor/torrc 2>/dev/null; then
    echo "%include /etc/tor/torrc.d/" >> /etc/tor/torrc
fi
systemctl restart tor
sleep 2

if [[ -f "$TOR_HIDDEN_DIR/hostname" ]]; then
    log "onion address:"
    cat "$TOR_HIDDEN_DIR/hostname"
else
    log "tor hidden service hostname not yet generated; check $TOR_HIDDEN_DIR/hostname shortly"
fi

log "done."

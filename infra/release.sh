#!/usr/bin/env bash
#
# infra/release.sh — produce a reproducible release binary plus a
# signed JSON manifest.
#
# What this does:
#   1. Builds lethe-server in release mode with deterministic flags
#      (pinned toolchain via rust-toolchain.toml, locked dependencies,
#      no incremental, stripped symbols, sorted timestamps).
#   2. Computes SHA-256 of the resulting binary.
#   3. Writes a manifest JSON: { version, commit, target, sha256,
#      built_at_day }.
#   4. Optionally signs the manifest with one or more Ed25519 keys
#      (one signature per maintainer). The output is the manifest
#      JSON plus a .sigs file holding `<keyid> <base64-signature>`
#      lines.
#
# Multi-key signing is the point: no single maintainer can ship a
# release; verifiers require N-of-M signatures from a pre-published
# operator-council key set before treating a binary as "the canonical
# Lethe release at this commit."
#
# Usage:
#   infra/release.sh [--sign-with <ed25519_priv_b64>:<keyid> ...]
#
# The signing flag is intentionally awkward — operators rarely sign
# from a shell history, and this is the in-tree script for the rare
# case. Real release automation should be a private fork of this
# script that loads keys from an HSM / hardware token.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_TRIPLE="$(rustc -vV | awk '/host:/ {print $2}')"
COMMIT="$(git rev-parse HEAD)"
DIRTY="$(git status --porcelain | wc -l | tr -d ' ')"
if [[ "$DIRTY" != "0" ]]; then
    echo "[release] error: working tree has uncommitted changes; refusing to build a release" >&2
    exit 1
fi

VERSION="$(grep -m1 '^version' crates/lethe-server/Cargo.toml | cut -d '"' -f 2)"
BUILT_AT_DAY="$(date -u +%Y-%m-%d)"

echo "[release] toolchain: $(rustc -V)"
echo "[release] target: $TARGET_TRIPLE"
echo "[release] commit: $COMMIT"
echo "[release] version: $VERSION"

# Deterministic flags. SOURCE_DATE_EPOCH is the dominant knob; the
# Rust compiler honors it for some embedded timestamps. `--locked`
# refuses to update Cargo.lock at build time.
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export RUSTFLAGS="-C codegen-units=1 -C link-arg=-Wl,--build-id=none"
export CARGO_INCREMENTAL=0

cargo build --release -p lethe-server --locked --target "$TARGET_TRIPLE"

BIN="target/$TARGET_TRIPLE/release/lethe-server"
[[ -f "$BIN" ]] || { echo "[release] error: built binary missing" >&2; exit 1; }

SHA256="$(sha256sum "$BIN" | awk '{print $1}')"
echo "[release] sha256: $SHA256"

MANIFEST_DIR="target/release-manifest"
mkdir -p "$MANIFEST_DIR"
MANIFEST="$MANIFEST_DIR/manifest.json"
cat > "$MANIFEST" <<EOF
{
  "version": "$VERSION",
  "commit": "$COMMIT",
  "target": "$TARGET_TRIPLE",
  "sha256": "$SHA256",
  "built_at_day": "$BUILT_AT_DAY"
}
EOF
echo "[release] wrote $MANIFEST"

# Sign if --sign-with was passed. Multiple times = multiple signers.
SIGS="$MANIFEST_DIR/manifest.sigs"
: > "$SIGS"
shift_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sign-with)
            shift
            ARG="$1"; shift
            KEYID="${ARG#*:}"
            PRIV="${ARG%:*}"
            SIG="$(python3 -c '
import sys, base64, hashlib
import nacl.signing  # pip install pynacl
priv = base64.urlsafe_b64decode(sys.argv[1] + "==")
msg  = open(sys.argv[2], "rb").read()
sig  = nacl.signing.SigningKey(priv[:32]).sign(msg).signature
print(base64.urlsafe_b64encode(sig).rstrip(b"=").decode())
' "$PRIV" "$MANIFEST")"
            echo "$KEYID $SIG" >> "$SIGS"
            echo "[release] signed by $KEYID"
            ;;
        *)
            shift_args+=("$1"); shift
            ;;
    esac
done
echo "[release] manifest dir: $MANIFEST_DIR"
echo "[release] verify with: tools/verify-release.sh $BIN $MANIFEST $SIGS <keyid:pubkey_b64> ..."

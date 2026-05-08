#!/usr/bin/env bash
#
# tools/verify-release.sh — verify a downloaded Lethe binary against a
# multi-key signed manifest. End-user / operator script.
#
# Usage:
#   verify-release.sh <binary> <manifest.json> <manifest.sigs> \
#       <required_signatures> <keyid:pubkey_b64> [<keyid:pubkey_b64> ...]
#
# Exit 0 iff:
#   - the binary's SHA-256 matches `manifest.json.sha256`,
#   - at least `required_signatures` distinct keyids in `<keyid:pubkey>`
#     appear in `manifest.sigs` with valid Ed25519 signatures over the
#     manifest bytes.
#
# This is the verification half of the no-single-release-key property.
# The maintainer's machine alone can't ship a binary; you, the
# verifier, decide which key set you trust and how many of them must
# co-sign before you treat a build as canonical.

set -euo pipefail

if [[ $# -lt 5 ]]; then
    cat >&2 <<EOF
usage: $0 <binary> <manifest.json> <manifest.sigs> <required_sigs> <keyid:pubkey_b64> ...
EOF
    exit 2
fi

BIN="$1"; shift
MANIFEST="$1"; shift
SIGS="$1"; shift
REQUIRED="$1"; shift

EXPECTED_SHA="$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["sha256"])
' "$MANIFEST")"
ACTUAL_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
    echo "[verify] FAIL: sha256 mismatch (expected $EXPECTED_SHA, got $ACTUAL_SHA)" >&2
    exit 1
fi
echo "[verify] sha256 ok: $ACTUAL_SHA"

VALID=0
declare -A SEEN
for kp in "$@"; do
    KEYID="${kp%%:*}"
    PUB="${kp#*:}"
    SIG_LINE="$(awk -v k="$KEYID" '$1 == k {print $2}' "$SIGS" | head -n1)"
    [[ -n "$SIG_LINE" ]] || { echo "[verify] no signature for $KEYID"; continue; }
    if python3 -c '
import sys, base64
import nacl.signing, nacl.exceptions
pub = base64.urlsafe_b64decode(sys.argv[1] + "==")
sig = base64.urlsafe_b64decode(sys.argv[2] + "==")
msg = open(sys.argv[3], "rb").read()
vk = nacl.signing.VerifyKey(pub[:32])
try:
    vk.verify(msg, sig)
except nacl.exceptions.BadSignatureError:
    sys.exit(1)
' "$PUB" "$SIG_LINE" "$MANIFEST"; then
        if [[ -z "${SEEN[$KEYID]:-}" ]]; then
            VALID=$((VALID + 1))
            SEEN["$KEYID"]=1
            echo "[verify] signature ok: $KEYID"
        fi
    else
        echo "[verify] signature INVALID: $KEYID" >&2
    fi
done

if (( VALID < REQUIRED )); then
    echo "[verify] FAIL: $VALID valid signatures, need $REQUIRED" >&2
    exit 1
fi
echo "[verify] OK: $VALID-of-$# signatures verified (required $REQUIRED)"

# Releasing Lethe

The release process is built around two structural properties:

1. **Reproducible builds.** Anyone with the same source tree at the
   same commit produces a byte-identical `lethe-server` binary.
2. **Multi-key signatures.** No single maintainer's key alone can mark
   a release as canonical. End users / operators verify a build
   against a published key set and require N-of-M signatures.

Together these two properties mean the maintainer's machine being
seized, coerced, or compromised does not give an attacker the ability
to ship a backdoored release that anyone using the standard verifier
will accept.

## Reproducing a build

```bash
# Toolchain is pinned in rust-toolchain.toml; rustup picks it up
# automatically.
infra/release.sh
# → target/<triple>/release/lethe-server
# → target/release-manifest/manifest.json
```

The script enforces a clean working tree, sets `SOURCE_DATE_EPOCH`
from the commit time, sets `RUSTFLAGS` to disable timestamps and
non-deterministic codegen, and uses `--locked` so Cargo.lock is the
source of truth. Two operators on different machines running
`infra/release.sh` at the same commit should get the same SHA-256.

If they don't, the most likely cause is a system-library version
difference (libc, OpenSSL); record the failing target triples in an
issue. The long-term fix is to build inside a pinned container; that
is left to a future iteration.

## Signing a release

Each maintainer signs the manifest **separately** with their own
Ed25519 key. Signatures concatenate; no signer sees the others' keys.

```bash
# After infra/release.sh produces manifest.json, each maintainer runs:
infra/release.sh --sign-with "$MY_PRIV_B64:$MY_KEYID"
```

The result is `target/release-manifest/manifest.sigs` containing one
`<keyid> <base64_signature>` line per signer. Concatenate signatures
from all maintainers into the same file before publishing.

## Publishing

Publish three artifacts to a stable, mirrored location (project
website, multiple GitHub mirrors, or wherever the operator council
agrees on):

- `lethe-server-<version>-<triple>` (the binary)
- `manifest.json`
- `manifest.sigs`

The set of canonical signing keys lives in `keys/release-keys.txt`
in the repo (one `<keyid> <base64_pubkey>` line per active signer)
and is the input every verifier hard-codes.

## Verifying a downloaded binary

End users and operators who do not trust any single distribution
mirror run:

```bash
tools/verify-release.sh \
    lethe-server-0.1.0-x86_64-unknown-linux-gnu \
    manifest.json \
    manifest.sigs \
    2 \
    alice:<alice_pubkey_b64> \
    bob:<bob_pubkey_b64> \
    carol:<carol_pubkey_b64>
```

The `2` here is the operator's chosen quorum. `2-of-3` means: I trust
this build iff at least two of {alice, bob, carol} have signed it.
Different operators can pick different quorums and key sets; nothing
in the protocol forces consensus on those choices.

## What this does not solve yet

- **System-library reproducibility.** Two glibc versions can yield
  different binaries even at the same source commit. The intended fix
  is a pinned build container (`docker buildx` or nix). Tracked, not
  done.
- **Signing-key handling.** `--sign-with` takes a base64 private key
  as a CLI argument. That's fine for a one-off; production signing
  should load keys from an HSM / Yubikey / similar. Operators with
  better key handling should fork `infra/release.sh`.
- **In-band release distribution.** The signed manifest doesn't fix
  the fact that someone has to download it from somewhere. Multiple
  mirrors + a known-good key set + the verifier above is what makes
  any single mirror non-decisive.

The MVP federation work has shipped without this property; running
this release pipeline is what moves the project from "the maintainer
ships the canonical binary" to "the network's chosen council co-signs
the canonical binary." Worth doing before any institutional operator
takes the project on as infrastructure.

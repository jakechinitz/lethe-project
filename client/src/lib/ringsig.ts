// Linkable ring signatures (LSAG, Liu–Wei–Wong 2004) over Ed25519,
// built on the libsodium ed25519 group operations shipped in the sumo
// build. This is the browser half of room vouches; the server half is
// `crates/lethe-server/src/crypto.rs::verify_vouch`, and the two MUST
// produce byte-identical results — every constant and byte assembly
// here is mirrored from `lethe-types::posts` docs.
//
// Hash-to-point: libsodium `crypto_core_ed25519_from_uniform` on the
// first 32 bytes of SHA-512(x). Verified byte-compatible with
// curve25519-dalek's `nonspec_map_to_curve::<Sha512>(x)`.
//
// Nothing in this file touches the network or localStorage.

import { sodium } from "./sodium";
import { concat, utf8 } from "./b64";

const KI_DOMAIN = "lethe-vouch-ki-v1\x00";
const MSG_DOMAIN = "lethe-vouch-msg-v1\x00";
const CH_DOMAIN = "lethe-vouch-ch-v1\x00";

export interface RingSignature {
  keyImage: Uint8Array;
  c0: Uint8Array;
  s: Uint8Array[];
}

/// Ed25519 secret scalar from a libsodium 64-byte signing secret key
/// (seed || pubkey): SHA-512(seed)[0..32], clamped, reduced mod l.
export async function scalarFromSigningKey(sk: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  if (sk.length !== 64) throw new Error("signing key must be 64 bytes");
  const h = s.crypto_hash_sha512(sk.slice(0, 32));
  const clamped = h.slice(0, 32);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;
  const wide = new Uint8Array(64);
  wide.set(clamped, 0);
  return s.crypto_core_ed25519_scalar_reduce(wide);
}

async function hashToPoint(input: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  const h = s.crypto_hash_sha512(input);
  return s.crypto_core_ed25519_from_uniform(h.slice(0, 32));
}

export async function keyImageBase(
  roomId: Uint8Array,
  threadId: Uint8Array,
  memberPubkey: Uint8Array,
): Promise<Uint8Array> {
  return hashToPoint(concat(utf8(KI_DOMAIN), roomId, threadId, memberPubkey));
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

function u16le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
}

export async function messageDigest(
  roomId: Uint8Array,
  threadId: Uint8Array,
  body: string,
  rosterEpoch: number,
  ring: Uint8Array[],
  keyImage: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const bodyHash = s.crypto_hash_sha256(utf8(body));
  const input = concat(
    utf8(MSG_DOMAIN),
    roomId,
    threadId,
    bodyHash,
    u32le(rosterEpoch),
    u16le(ring.length),
    ...ring,
    keyImage,
  );
  return s.crypto_hash_sha512(input);
}

async function challenge(m: Uint8Array, L: Uint8Array, R: Uint8Array): Promise<Uint8Array> {
  const s = await sodium();
  const h = s.crypto_hash_sha512(concat(utf8(CH_DOMAIN), m, L, R));
  return s.crypto_core_ed25519_scalar_reduce(h);
}

/// Bytewise comparison used to canonically order ring members. The
/// server sorts identically (`Vec<Vec<u8>>::sort`).
export function comparePubkeys(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < 32; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

/// Signs `m` as ring member `signerIndex` (whose pubkey must equal
/// `ring[signerIndex]`). `ring` must already be sorted.
export async function ringSign(
  m: Uint8Array,
  ring: Uint8Array[],
  hpBases: Uint8Array[],
  signerIndex: number,
  signerScalar: Uint8Array,
  keyImage: Uint8Array,
): Promise<RingSignature> {
  const s = await sodium();
  const n = ring.length;
  if (n === 0 || n > 50) throw new Error("ring size out of range");
  if (signerIndex < 0 || signerIndex >= n) throw new Error("signer index out of range");

  const c: Array<Uint8Array | null> = new Array(n).fill(null);
  const sv: Array<Uint8Array | null> = new Array(n).fill(null);

  const alpha = s.crypto_core_ed25519_scalar_random();
  const Lpi = s.crypto_scalarmult_ed25519_base_noclamp(alpha);
  const Rpi = s.crypto_scalarmult_ed25519_noclamp(alpha, hpBases[signerIndex]);
  c[(signerIndex + 1) % n] = await challenge(m, Lpi, Rpi);

  for (let k = 1; k < n; k++) {
    const i = (signerIndex + k) % n;
    const si = s.crypto_core_ed25519_scalar_random();
    sv[i] = si;
    const ci = c[i]!;
    const L = s.crypto_core_ed25519_add(
      s.crypto_scalarmult_ed25519_base_noclamp(si),
      s.crypto_scalarmult_ed25519_noclamp(ci, ring[i]),
    );
    const R = s.crypto_core_ed25519_add(
      s.crypto_scalarmult_ed25519_noclamp(si, hpBases[i]),
      s.crypto_scalarmult_ed25519_noclamp(ci, keyImage),
    );
    c[(i + 1) % n] = await challenge(m, L, R);
  }

  // Close the ring: s_pi = alpha - c_pi * x.
  const cpi = c[signerIndex]!;
  sv[signerIndex] = s.crypto_core_ed25519_scalar_sub(
    alpha,
    s.crypto_core_ed25519_scalar_mul(cpi, signerScalar),
  );

  return { keyImage, c0: c[0]!, s: sv.map((v) => v!) };
}

/// Verifies a ring signature. Returns false (never throws) on any
/// malformed input, so callers can treat "invalid" uniformly.
export async function ringVerify(
  m: Uint8Array,
  ring: Uint8Array[],
  hpBases: Uint8Array[],
  sig: RingSignature,
): Promise<boolean> {
  const s = await sodium();
  const n = ring.length;
  if (n === 0 || n > 50 || sig.s.length !== n) return false;
  if (sig.keyImage.length !== 32 || sig.c0.length !== 32) return false;
  try {
    if (!s.crypto_core_ed25519_is_valid_point(sig.keyImage)) return false;
    for (const p of ring) {
      if (!s.crypto_core_ed25519_is_valid_point(p)) return false;
    }
    let c = sig.c0;
    for (let i = 0; i < n; i++) {
      const si = sig.s[i];
      if (si.length !== 32) return false;
      const L = s.crypto_core_ed25519_add(
        s.crypto_scalarmult_ed25519_base_noclamp(si),
        s.crypto_scalarmult_ed25519_noclamp(c, ring[i]),
      );
      const R = s.crypto_core_ed25519_add(
        s.crypto_scalarmult_ed25519_noclamp(si, hpBases[i]),
        s.crypto_scalarmult_ed25519_noclamp(c, sig.keyImage),
      );
      c = await challenge(m, L, R);
    }
    return s.memcmp(c, sig.c0);
  } catch {
    return false;
  }
}

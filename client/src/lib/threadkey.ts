// Per-thread Ed25519 signing keypair. Generates on first use, stores in
// localStorage, and signs canonical post payloads. This file is the only
// module that touches `localStorage` for thread keys.

import { sodium } from "./sodium";
import { b64decode, b64encode, concat, utf8 } from "./b64";

const PREFIX = "lethe.tkey.";

interface StoredKeypair {
  publicKey: string;
  privateKey: string;
}

function storageKey(threadIdB64: string): string {
  return PREFIX + threadIdB64;
}

export async function getOrCreateKeypair(
  threadIdB64: string,
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  const existing = localStorage.getItem(storageKey(threadIdB64));
  if (existing) {
    const parsed: StoredKeypair = JSON.parse(existing);
    return {
      publicKey: b64decode(parsed.publicKey),
      privateKey: b64decode(parsed.privateKey),
    };
  }
  const s = await sodium();
  const kp = s.crypto_sign_keypair();
  const stored: StoredKeypair = {
    publicKey: b64encode(kp.publicKey),
    privateKey: b64encode(kp.privateKey),
  };
  localStorage.setItem(storageKey(threadIdB64), JSON.stringify(stored));
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function hasKeypair(threadIdB64: string): boolean {
  return localStorage.getItem(storageKey(threadIdB64)) !== null;
}

/// Stores a keypair generated elsewhere — used by the new-thread form
/// when the OP claims identity, since the keypair is minted before the
/// thread id is known to the server.
export function persistKeypair(
  threadIdB64: string,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
): void {
  const stored: StoredKeypair = {
    publicKey: b64encode(publicKey),
    privateKey: b64encode(privateKey),
  };
  localStorage.setItem(storageKey(threadIdB64), JSON.stringify(stored));
}

export function forget(threadIdB64: string): void {
  localStorage.removeItem(storageKey(threadIdB64));
}

/// Signs the canonical post payload `b"lethe-post-v1" || thread_id || body`.
/// Server uses the same byte assembly in `lethe-types::posts::canonical_post_payload`.
export async function signPost(
  threadId: Uint8Array,
  body: string,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const payload = concat(utf8("lethe-post-v1"), threadId, utf8(body));
  return s.crypto_sign_detached(payload, privateKey);
}

/// Signs the canonical room provenance payload
/// `b"lethe-room-v1\x00" || origin_thread || creator_thread_pubkey`.
export async function signRoomProvenance(
  originThread: Uint8Array,
  creatorThreadPubkey: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const payload = concat(
    utf8("lethe-room-v1\x00"),
    originThread,
    creatorThreadPubkey,
  );
  return s.crypto_sign_detached(payload, privateKey);
}

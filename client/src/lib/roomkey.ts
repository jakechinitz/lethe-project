// Per-room key material: X25519 box keypair (used for sealed-box wrapping
// of the room key), Ed25519 sig keypair (used to authenticate messages),
// and the symmetric room key. This file is the only module that touches
// `localStorage` for room keys.

import { sodium } from "./sodium";
import { b64decode, b64encode, concat, utf8 } from "./b64";

const PREFIX = "lethe.room.";

interface StoredRoom {
  boxPub: string;
  boxPriv: string;
  sigPub: string;
  sigPriv: string;
  roomKey: string | null;
}

export interface RoomKeys {
  boxPub: Uint8Array;
  boxPriv: Uint8Array;
  sigPub: Uint8Array;
  sigPriv: Uint8Array;
  roomKey: Uint8Array | null;
}

function storageKey(roomIdB64: string): string {
  return PREFIX + roomIdB64;
}

function load(roomIdB64: string): StoredRoom | null {
  const raw = localStorage.getItem(storageKey(roomIdB64));
  return raw ? (JSON.parse(raw) as StoredRoom) : null;
}

function save(roomIdB64: string, s: StoredRoom): void {
  localStorage.setItem(storageKey(roomIdB64), JSON.stringify(s));
}

export async function generateForNewRoom(): Promise<RoomKeys> {
  const s = await sodium();
  const boxKp = s.crypto_box_keypair();
  const sigKp = s.crypto_sign_keypair();
  const roomKey = s.randombytes_buf(32);
  return {
    boxPub: boxKp.publicKey,
    boxPriv: boxKp.privateKey,
    sigPub: sigKp.publicKey,
    sigPriv: sigKp.privateKey,
    roomKey,
  };
}

export async function generateForJoin(): Promise<Omit<RoomKeys, "roomKey">> {
  const s = await sodium();
  const boxKp = s.crypto_box_keypair();
  const sigKp = s.crypto_sign_keypair();
  return {
    boxPub: boxKp.publicKey,
    boxPriv: boxKp.privateKey,
    sigPub: sigKp.publicKey,
    sigPriv: sigKp.privateKey,
  };
}

export function persist(roomIdB64: string, k: RoomKeys): void {
  save(roomIdB64, {
    boxPub: b64encode(k.boxPub),
    boxPriv: b64encode(k.boxPriv),
    sigPub: b64encode(k.sigPub),
    sigPriv: b64encode(k.sigPriv),
    roomKey: k.roomKey ? b64encode(k.roomKey) : null,
  });
}

export function read(roomIdB64: string): RoomKeys | null {
  const stored = load(roomIdB64);
  if (!stored) return null;
  return {
    boxPub: b64decode(stored.boxPub),
    boxPriv: b64decode(stored.boxPriv),
    sigPub: b64decode(stored.sigPub),
    sigPriv: b64decode(stored.sigPriv),
    roomKey: stored.roomKey ? b64decode(stored.roomKey) : null,
  };
}

export function persistRoomKey(roomIdB64: string, roomKey: Uint8Array): void {
  const stored = load(roomIdB64);
  if (!stored) throw new Error("no stored keys for room");
  stored.roomKey = b64encode(roomKey);
  save(roomIdB64, stored);
}

/// Wraps `roomKey` for a recipient using sealed-box (anonymous sender).
export async function wrapRoomKey(
  roomKey: Uint8Array,
  recipientBoxPub: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  return s.crypto_box_seal(roomKey, recipientBoxPub);
}

export async function unwrapRoomKey(
  wrapped: Uint8Array,
  myBoxPub: Uint8Array,
  myBoxPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  return s.crypto_box_seal_open(wrapped, myBoxPub, myBoxPriv);
}

export async function encryptMessage(
  plaintext: string,
  roomId: Uint8Array,
  roomKey: Uint8Array,
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const s = await sodium();
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    utf8(plaintext),
    roomId,
    null,
    nonce,
    roomKey,
  );
  return { nonce, ciphertext };
}

export async function decryptMessage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  roomId: Uint8Array,
  roomKey: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    roomId,
    nonce,
    roomKey,
  );
}

export async function signMessageEnvelope(
  roomId: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  sigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const payload = concat(utf8("lethe-msg-v1\x00"), roomId, nonce, ciphertext);
  return s.crypto_sign_detached(payload, sigPriv);
}

export async function verifyMessageEnvelope(
  roomId: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  sig: Uint8Array,
  senderSigPub: Uint8Array,
): Promise<boolean> {
  const s = await sodium();
  const payload = concat(utf8("lethe-msg-v1\x00"), roomId, nonce, ciphertext);
  return s.crypto_sign_verify_detached(sig, payload, senderSigPub);
}

/// Signs a canonical message-list request: `b"lethe-list-v1\x00" || room_id || ts_le8`.
/// Server verifies, checks membership, and gates history to created_at >= joined_at.
export async function signListRequest(
  roomId: Uint8Array,
  unixTs: number,
  sigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const tsBytes = new Uint8Array(8);
  let ts = BigInt(unixTs);
  for (let i = 0; i < 8; i++) {
    tsBytes[i] = Number(ts & 0xffn);
    ts >>= 8n;
  }
  const payload = concat(utf8("lethe-list-v1\x00"), roomId, tsBytes);
  return s.crypto_sign_detached(payload, sigPriv);
}

export async function verifyProvenance(
  originThread: Uint8Array,
  creatorThreadPubkey: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  const s = await sodium();
  const payload = concat(
    utf8("lethe-room-v1\x00"),
    originThread,
    creatorThreadPubkey,
  );
  return s.crypto_sign_verify_detached(sig, payload, creatorThreadPubkey);
}

// Per-room key material: X25519 box keypair (used for sealed-box wrapping
// of the room key), Ed25519 sig keypair (used to authenticate messages),
// and the symmetric room key — historicized so that after a rekey we can
// still decrypt messages from before the rotation.
//
// This file is the only module that touches `localStorage` for room keys.

import { sodium } from "./sodium";
import { b64decode, b64encode, concat, utf8 } from "./b64";

const PREFIX = "lethe.room.";

interface StoredRoomV2 {
  v: 2;
  boxPub: string;
  boxPriv: string;
  sigPub: string;
  sigPriv: string;
  /// Most-recent key is last. Send always uses the last; receive tries
  /// each (newest first) and accepts the first that decrypts.
  roomKeys: string[];
  /// Last `current_epoch` we observed from the server. Used to detect
  /// rekeys and pull in the new wrapped_key.
  lastEpoch: number;
}

interface StoredRoomV1 {
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
  /// Most recent last. Empty until at least one key has been received.
  roomKeys: Uint8Array[];
  lastEpoch: number;
}

function storageKey(roomIdB64: string): string {
  return PREFIX + roomIdB64;
}

function loadRaw(roomIdB64: string): StoredRoomV2 | null {
  const raw = localStorage.getItem(storageKey(roomIdB64));
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  if (parsed && parsed.v === 2) return parsed as StoredRoomV2;
  // Migrate v1 → v2 in place.
  const v1 = parsed as StoredRoomV1;
  const v2: StoredRoomV2 = {
    v: 2,
    boxPub: v1.boxPub,
    boxPriv: v1.boxPriv,
    sigPub: v1.sigPub,
    sigPriv: v1.sigPriv,
    roomKeys: v1.roomKey ? [v1.roomKey] : [],
    lastEpoch: 0,
  };
  localStorage.setItem(storageKey(roomIdB64), JSON.stringify(v2));
  return v2;
}

function save(roomIdB64: string, s: StoredRoomV2): void {
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
    roomKeys: [roomKey],
    lastEpoch: 0,
  };
}

export async function generateForJoin(): Promise<Omit<RoomKeys, "roomKeys" | "lastEpoch">> {
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
    v: 2,
    boxPub: b64encode(k.boxPub),
    boxPriv: b64encode(k.boxPriv),
    sigPub: b64encode(k.sigPub),
    sigPriv: b64encode(k.sigPriv),
    roomKeys: k.roomKeys.map(b64encode),
    lastEpoch: k.lastEpoch,
  });
}

/// Every room id this browser holds keys for. Built from localStorage
/// only; the server never sees a per-user room list.
export function listRoomIds(): string[] {
  const out: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(PREFIX)) out.push(key.slice(PREFIX.length));
  }
  return out;
}

export function read(roomIdB64: string): RoomKeys | null {
  const stored = loadRaw(roomIdB64);
  if (!stored) return null;
  return {
    boxPub: b64decode(stored.boxPub),
    boxPriv: b64decode(stored.boxPriv),
    sigPub: b64decode(stored.sigPub),
    sigPriv: b64decode(stored.sigPriv),
    roomKeys: stored.roomKeys.map(b64decode),
    lastEpoch: stored.lastEpoch,
  };
}

/// Appends a freshly-unwrapped room key, deduplicating by raw bytes so
/// repeated calls (e.g. on every poll) don't grow the array.
export function appendRoomKey(
  roomIdB64: string,
  newKey: Uint8Array,
  newEpoch: number,
): void {
  const stored = loadRaw(roomIdB64);
  if (!stored) throw new Error("no stored keys for room");
  const newKeyB64 = b64encode(newKey);
  if (!stored.roomKeys.includes(newKeyB64)) {
    stored.roomKeys.push(newKeyB64);
  }
  if (newEpoch > stored.lastEpoch) {
    stored.lastEpoch = newEpoch;
  }
  save(roomIdB64, stored);
}

export function setLastEpoch(roomIdB64: string, epoch: number): void {
  const stored = loadRaw(roomIdB64);
  if (!stored) return;
  stored.lastEpoch = epoch;
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

/// Encrypts under the most recent room key.
export async function encryptMessage(
  plaintext: string,
  roomId: Uint8Array,
  roomKeys: Uint8Array[],
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const s = await sodium();
  if (roomKeys.length === 0) throw new Error("no room keys available");
  const roomKey = roomKeys[roomKeys.length - 1];
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

/// Tries each historicized key (newest first); returns the plaintext from
/// the first that decrypts. Throws if none work.
///
/// We distinguish AEAD authentication failures (`Error: ...`) from
/// errors raised by sodium itself (sodium not ready, parameter type
/// mismatch). The AEAD path returns a plain `Error` whose message
/// starts with "wrong secret key" or similar; that's the only error we
/// suppress to "try the next key." Anything else — a string thrown by
/// libsodium, a TypeError, a sodium-not-ready promise rejection — is a
/// signal we should NOT silently treat as a wrong-key, since it could
/// be a tampered ciphertext field, a runtime mismatch, or a
/// supply-chain anomaly. Those propagate.
export async function decryptMessage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  roomId: Uint8Array,
  roomKeys: Uint8Array[],
): Promise<Uint8Array> {
  const s = await sodium();
  let lastAeadErr: Error | null = null;
  for (let i = roomKeys.length - 1; i >= 0; i--) {
    try {
      return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        roomId,
        nonce,
        roomKeys[i],
      );
    } catch (e) {
      if (isAeadAuthFailure(e)) {
        lastAeadErr = e as Error;
        continue;
      }
      throw e;
    }
  }
  throw lastAeadErr ?? new Error("no room keys to try");
}

/// libsodium-wrappers signals MAC failure by throwing an `Error` whose
/// message includes "wrong secret key for the given ciphertext" (or,
/// historically, "incorrect key pair for the given ciphertext"). All
/// other thrown values — strings, TypeErrors, unrelated `Error`s — are
/// real runtime bugs we don't want to hide.
function isAeadAuthFailure(e: unknown): boolean {
  if (!(e instanceof Error)) return false;
  return /wrong secret key|incorrect key|verification failed/i.test(e.message);
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
  const tsBytes = tsLeBytes(unixTs);
  const payload = concat(utf8("lethe-list-v1\x00"), roomId, tsBytes);
  return s.crypto_sign_detached(payload, sigPriv);
}

/// Signs an authenticated members-list request:
///   `b"lethe-members-v1\x00" || room_id || ts_le8`.
/// The member list is member-only; pending joiners may call it too.
export async function signMembersRequest(
  roomId: Uint8Array,
  unixTs: number,
  sigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const payload = concat(utf8("lethe-members-v1\x00"), roomId, tsLeBytes(unixTs));
  return s.crypto_sign_detached(payload, sigPriv);
}

/// Signs a self-leave request: `b"lethe-leave-v1\x00" || room_id || ts_le8`.
export async function signLeaveRequest(
  roomId: Uint8Array,
  unixTs: number,
  sigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const tsBytes = tsLeBytes(unixTs);
  const payload = concat(utf8("lethe-leave-v1\x00"), roomId, tsBytes);
  return s.crypto_sign_detached(payload, sigPriv);
}

/// Signs a join proof for a restricted invite:
///   `b"lethe-join-v1\x00" || invite_code || box_pubkey || ts_le8`.
/// Server checks the signer's pubkey is on the room's allowlist.
export async function signJoinProof(
  inviteCode: string,
  boxPub: Uint8Array,
  unixTs: number,
  threadSigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const tsBytes = tsLeBytes(unixTs);
  const payload = concat(
    utf8("lethe-join-v1\x00"),
    utf8(inviteCode),
    boxPub,
    tsBytes,
  );
  return s.crypto_sign_detached(payload, threadSigPriv);
}

/// Signs a remove-and-rekey request:
///   `b"lethe-remove-v1\x00" || room_id || ts_le8 || target_box_pubkey`.
/// Server additionally checks the signer is the creator.
export async function signRemoveRequest(
  roomId: Uint8Array,
  unixTs: number,
  targetBoxPubkey: Uint8Array,
  sigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const tsBytes = tsLeBytes(unixTs);
  const payload = concat(
    utf8("lethe-remove-v1\x00"),
    roomId,
    tsBytes,
    targetBoxPubkey,
  );
  return s.crypto_sign_detached(payload, sigPriv);
}

/// Signs a create-room request:
///   `b"lethe-create-v1\x00" || ts_le8 || creator_box_pubkey || creator_sig_pubkey || wrapped_key_for_creator`.
/// Proves the caller controls the creator's signing key and consented
/// to room creation under this box pubkey.
export async function signCreateRoom(
  creatorBoxPubkey: Uint8Array,
  creatorSigPubkey: Uint8Array,
  wrappedKeyForCreator: Uint8Array,
  unixTs: number,
  creatorSigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const payload = concat(
    utf8("lethe-create-v1\x00"),
    tsLeBytes(unixTs),
    creatorBoxPubkey,
    creatorSigPubkey,
    wrappedKeyForCreator,
  );
  return s.crypto_sign_detached(payload, creatorSigPriv);
}

/// Signs a wrap-key request:
///   `b"lethe-wrap-v1\x00" || ts_le8 || room_id || for_box_pubkey || wrapped_key`.
/// Server verifies the (sig, box) pubkey pair is an active member row
/// before applying the wrap.
export async function signWrapRequest(
  roomId: Uint8Array,
  forBoxPubkey: Uint8Array,
  wrappedKey: Uint8Array,
  unixTs: number,
  inviterSigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  const payload = concat(
    utf8("lethe-wrap-v1\x00"),
    tsLeBytes(unixTs),
    roomId,
    forBoxPubkey,
    wrappedKey,
  );
  return s.crypto_sign_detached(payload, inviterSigPriv);
}

function tsLeBytes(unixTs: number): Uint8Array {
  const out = new Uint8Array(8);
  let ts = BigInt(unixTs);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(ts & 0xffn);
    ts >>= 8n;
  }
  return out;
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


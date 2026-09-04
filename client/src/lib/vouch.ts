// Room vouches: build one as a member, verify one as a reader, and the
// reader's private "trusted rooms" list. This file and `ringsig.ts`
// are the only modules that know the vouch byte layout.
//
// Trusted rooms live in localStorage under `lethe.trust.<roomId>` and
// never leave the device. The server does not learn which rooms a
// reader trusts, nor that they filtered.

import { api, RosterResp, VouchPayload } from "./api";
import { b64decode, b64encode, bytesEqual, concat, utf8 } from "./b64";
import * as ringsig from "./ringsig";
import type { RoomKeys } from "./roomkey";
import { sodium } from "./sodium";

const TRUST_PREFIX = "lethe.trust.";

export interface TrustedRoom {
  roomId: string;
  label: string;
}

/// Alias so page scripts don't import the wire type from two places.
export type VouchPayloadLike = VouchPayload;

export function listTrusted(): TrustedRoom[] {
  const out: TrustedRoom[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith(TRUST_PREFIX)) continue;
    const roomId = key.slice(TRUST_PREFIX.length);
    try {
      const parsed = JSON.parse(localStorage.getItem(key) ?? "{}") as { label?: string };
      out.push({ roomId, label: parsed.label ?? `Room ${roomId.slice(0, 8)}` });
    } catch {
      out.push({ roomId, label: `Room ${roomId.slice(0, 8)}` });
    }
  }
  out.sort((a, b) => a.label.localeCompare(b.label));
  return out;
}

export function trustedLabel(roomId: string): string | null {
  const raw = localStorage.getItem(TRUST_PREFIX + roomId);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as { label?: string };
    return parsed.label ?? `Room ${roomId.slice(0, 8)}`;
  } catch {
    return `Room ${roomId.slice(0, 8)}`;
  }
}

export function setTrusted(roomId: string, label: string): void {
  localStorage.setItem(TRUST_PREFIX + roomId, JSON.stringify({ label }));
}

export function removeTrusted(roomId: string): void {
  localStorage.removeItem(TRUST_PREFIX + roomId);
}

/// Canonical roster bytes — mirrors `lethe_types::rooms::canonical_roster`.
export function canonicalRoster(
  roomId: Uint8Array,
  epoch: number,
  ring: Uint8Array[],
): Uint8Array {
  const epochLe = new Uint8Array([
    epoch & 0xff, (epoch >>> 8) & 0xff, (epoch >>> 16) & 0xff, (epoch >>> 24) & 0xff,
  ]);
  const nLe = new Uint8Array([ring.length & 0xff, (ring.length >>> 8) & 0xff]);
  return concat(utf8("lethe-roster-v1\x00"), roomId, epochLe, nLe, ...ring);
}

/// Sorts and deduplicates member pubkeys into canonical ring order.
export function canonicalRing(pubkeys: Uint8Array[]): Uint8Array[] {
  const sorted = [...pubkeys].sort(ringsig.comparePubkeys);
  const out: Uint8Array[] = [];
  for (const p of sorted) {
    if (out.length > 0 && bytesEqual(out[out.length - 1], p)) continue;
    out.push(p);
  }
  return out;
}

/// Creator-side: sign a roster snapshot for `epoch`.
export async function signRoster(
  roomId: Uint8Array,
  epoch: number,
  ring: Uint8Array[],
  creatorSigPriv: Uint8Array,
): Promise<Uint8Array> {
  const s = await sodium();
  return s.crypto_sign_detached(canonicalRoster(roomId, epoch, ring), creatorSigPriv);
}

async function verifyRosterSig(
  roster: { creator_sig_pubkey: string },
  roomId: Uint8Array,
  epoch: number,
  ring: Uint8Array[],
  creatorSig: Uint8Array,
): Promise<boolean> {
  const s = await sodium();
  try {
    return s.crypto_sign_verify_detached(
      creatorSig,
      canonicalRoster(roomId, epoch, ring),
      b64decode(roster.creator_sig_pubkey),
    );
  } catch {
    return false;
  }
}

/// Member-side: build a vouch for `body` in `threadId` as a member of
/// the room whose keys are `keys`. Fetches the room's current signed
/// roster; throws if vouching isn't enabled or we're not on the roster
/// (e.g. our wrap is still pending).
export async function buildVouch(
  roomIdB64: string,
  threadId: Uint8Array,
  body: string,
  keys: RoomKeys,
): Promise<VouchPayload> {
  const roster = await api.roster(roomIdB64);
  const roomId = b64decode(roomIdB64);
  const ring = canonicalRing(roster.member_sig_pubkeys.map(b64decode));
  const signerIndex = ring.findIndex((p) => bytesEqual(p, keys.sigPub));
  if (signerIndex < 0) {
    throw new Error("you are not on this room's signed roster yet (wrap pending, or roster not re-signed)");
  }
  const creatorSig = b64decode(roster.creator_sig);
  if (!(await verifyRosterSig(roster, roomId, roster.epoch, ring, creatorSig))) {
    throw new Error("room roster signature did not verify — refusing to vouch");
  }

  const hp = await Promise.all(ring.map((p) => ringsig.keyImageBase(roomId, threadId, p)));
  const x = await ringsig.scalarFromSigningKey(keys.sigPriv);
  const s = await sodium();
  const keyImage = s.crypto_scalarmult_ed25519_noclamp(x, hp[signerIndex]);
  const m = await ringsig.messageDigest(roomId, threadId, body, roster.epoch, ring, keyImage);
  const sig = await ringsig.ringSign(m, ring, hp, signerIndex, x, keyImage);

  return {
    room_id: roomIdB64,
    roster_epoch: roster.epoch,
    creator_sig: roster.creator_sig,
    ring: ring.map(b64encode),
    key_image: b64encode(sig.keyImage),
    c0: b64encode(sig.c0),
    s: sig.s.map(b64encode),
  };
}

export interface VouchVerdict {
  ok: boolean;
  roomId: string;
  /// Reader's local label if the room is trusted, else null.
  trustedLabel: string | null;
  /// Why it failed, for the UI. Empty when ok.
  reason: string;
}

const rosterCache = new Map<string, Promise<RosterResp | null>>();

async function rosterFor(roomIdB64: string): Promise<RosterResp | null> {
  let p = rosterCache.get(roomIdB64);
  if (!p) {
    p = api.roster(roomIdB64).catch(() => null);
    rosterCache.set(roomIdB64, p);
  }
  return p;
}

/// Reader-side verification. Never trusts the server: checks the
/// creator's roster signature, that the cited epoch isn't from the
/// future, and the ring signature itself — all locally.
export async function verifyVouch(
  vouch: VouchPayload,
  threadId: Uint8Array,
  body: string,
): Promise<VouchVerdict> {
  const roomIdB64 = vouch.room_id;
  const trusted = trustedLabel(roomIdB64);
  const fail = (reason: string): VouchVerdict => ({
    ok: false, roomId: roomIdB64, trustedLabel: trusted, reason,
  });
  let roomId: Uint8Array;
  let ring: Uint8Array[];
  let creatorSig: Uint8Array;
  let keyImage: Uint8Array;
  let c0: Uint8Array;
  let sVals: Uint8Array[];
  try {
    roomId = b64decode(roomIdB64);
    ring = vouch.ring.map(b64decode);
    creatorSig = b64decode(vouch.creator_sig);
    keyImage = b64decode(vouch.key_image);
    c0 = b64decode(vouch.c0);
    sVals = vouch.s.map(b64decode);
  } catch {
    return fail("malformed vouch");
  }
  if (roomId.length !== 16 || ring.length === 0 || ring.length > 50) return fail("malformed vouch");
  for (let i = 1; i < ring.length; i++) {
    if (ringsig.comparePubkeys(ring[i - 1], ring[i]) >= 0) return fail("ring not canonical");
  }

  const roster = await rosterFor(roomIdB64);
  if (!roster) return fail("room roster unavailable (vouching disabled or room gone)");
  if (vouch.roster_epoch < 1 || vouch.roster_epoch > roster.epoch) return fail("roster epoch out of range");
  if (!(await verifyRosterSig(roster, roomId, vouch.roster_epoch, ring, creatorSig))) {
    return fail("roster signature invalid");
  }

  const hp = await Promise.all(ring.map((p) => ringsig.keyImageBase(roomId, threadId, p)));
  const m = await ringsig.messageDigest(roomId, threadId, body, vouch.roster_epoch, ring, keyImage);
  const ok = await ringsig.ringVerify(m, ring, hp, { keyImage, c0, s: sVals });
  if (!ok) return fail("ring signature invalid");
  return { ok: true, roomId: roomIdB64, trustedLabel: trusted, reason: "" };
}

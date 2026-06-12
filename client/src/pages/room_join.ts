// Room join: generate keys, request access, then redirect to the room.
// For restricted invites, also signs a proof with the local thread key
// so the server can verify the joiner is on the room's allowlist.

import { api, InviteInfo } from "../lib/api";
import { $, meta, text } from "../lib/dom";
import { b64encode } from "../lib/b64";
import * as roomkey from "../lib/roomkey";
import * as tkey from "../lib/threadkey";

const inviteCode = meta("lethe-invite-code");

const btn = $<HTMLButtonElement>("#join-btn");
const status = $<HTMLParagraphElement>("#join-status");
const openLine = $<HTMLElement>("#open-room-line");
const openRoom = $<HTMLAnchorElement>("#open-room");

let info: InviteInfo | null = null;

main();

async function main(): Promise<void> {
  text(status, "Checking invite…");
  try {
    info = await api.inviteInfo(inviteCode);
  } catch (e) {
    text(status, `Could not load invite: ${(e as Error).message}`);
    btn.disabled = true;
    return;
  }
  // Tell the joiner up front how ephemeral this room's history is.
  const note = document.querySelector<HTMLElement>("#retention-note");
  if (note) {
    const d = info.message_retention_days;
    const span = d === 1 ? "1 day" : `${d} days`;
    note.textContent =
      `Heads up: messages in this room are automatically deleted from ` +
      `the server ${span} after they're sent. Chat history is ephemeral ` +
      `by design.`;
  }
  if (!info.restricted) {
    text(status, "This is an open invite. Click below to request access.");
    return;
  }
  // Restricted: only people who posted with a thread-local identity
  // matching one on the allowlist can join.
  if (!info.origin_thread) {
    text(status, "Restricted invite has no originating thread; cannot join.");
    btn.disabled = true;
    return;
  }
  if (!tkey.hasKeypair(info.origin_thread)) {
    text(
      status,
      "This invite is restricted to specific anons from a thread. " +
        "Your browser doesn't have a thread-local identity for that thread, " +
        "so you can't prove you're invited.",
    );
    btn.disabled = true;
    return;
  }
  // Confirm our local pubkey is actually on the allowlist before
  // bothering with PoW etc.
  const myKp = await tkey.getOrCreateKeypair(info.origin_thread);
  const myPub = b64encode(myKp.publicKey);
  if (!info.allowlist_thread_pubkeys?.includes(myPub)) {
    text(
      status,
      "You have an identity for the right thread, but it isn't one of the anons the room creator invited.",
    );
    btn.disabled = true;
    return;
  }
  text(status, "Restricted invite. You're on the list — click to join.");
}

btn.addEventListener("click", async () => {
  if (!info) return;
  btn.disabled = true;
  text(status, "Generating keys…");
  const k = await roomkey.generateForJoin();

  const body: Record<string, unknown> = {
    box_pubkey: b64encode(k.boxPub),
    sig_pubkey: b64encode(k.sigPub),
  };

  if (info.restricted && info.origin_thread) {
    const myKp = await tkey.getOrCreateKeypair(info.origin_thread);
    const ts = Math.floor(Date.now() / 1000);
    const proof = await roomkey.signJoinProof(
      inviteCode,
      k.boxPub,
      ts,
      myKp.privateKey,
    );
    body.proof_thread_pubkey = b64encode(myKp.publicKey);
    body.proof_ts = ts;
    body.proof_sig = b64encode(proof);
  }

  text(status, "Requesting access…");
  try {
    const resp = await api.joinRoom(inviteCode, body);
    roomkey.persist(resp.room_id, { ...k, roomKeys: [], lastEpoch: 0 });
    openRoom.href = `/r/${resp.room_id}`;
    openLine.hidden = false;
    text(
      status,
      "Access requested. Open the room — an existing member must grant you access.",
    );
  } catch (e) {
    text(status, `Error: ${(e as Error).message}`);
    btn.disabled = false;
  }
});

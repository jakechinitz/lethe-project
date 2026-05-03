// Room creation: generate keys + room key, optionally attach thread
// provenance signed by the user's existing thread identity.

import { api } from "../lib/api";
import { $, meta, text } from "../lib/dom";
import { b64decode, b64encode } from "../lib/b64";
import * as roomkey from "../lib/roomkey";
import * as tkey from "../lib/threadkey";

const fromThreadId = meta("lethe-from-thread");

const form = $<HTMLFormElement>("#create-form");
const status = $<HTMLParagraphElement>("#create-status");
const inviteSection = $<HTMLElement>("#invite-section");
const inviteLink = $<HTMLElement>("#invite-link");
const openRoom = $<HTMLAnchorElement>("#open-room");
const attachProvenance = $<HTMLInputElement>("#attach-provenance");

if (!fromThreadId) {
  attachProvenance.checked = false;
  attachProvenance.disabled = true;
}

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  text(status, "Generating keys…");
  const k = await roomkey.generateForNewRoom();
  const currentRoomKey = k.roomKeys[k.roomKeys.length - 1];
  const wrappedSelf = await roomkey.wrapRoomKey(currentRoomKey, k.boxPub);

  const body: Record<string, unknown> = {
    creator_box_pubkey: b64encode(k.boxPub),
    creator_sig_pubkey: b64encode(k.sigPub),
    wrapped_key_for_creator: b64encode(wrappedSelf),
  };

  if (fromThreadId && attachProvenance.checked) {
    if (!tkey.hasKeypair(fromThreadId)) {
      text(
        status,
        "You haven't claimed an identity in this thread yet. Open the thread, " +
          "post once with 'Claim thread-local identity' enabled, then come back.",
      );
      return;
    }
    const myThreadKp = await tkey.getOrCreateKeypair(fromThreadId);
    const sig = await tkey.signRoomProvenance(
      b64decode(fromThreadId),
      myThreadKp.publicKey,
      myThreadKp.privateKey,
    );
    body.origin_thread = fromThreadId;
    body.creator_thread_pubkey = b64encode(myThreadKp.publicKey);
    body.provenance_sig = b64encode(sig);
  }

  text(status, "Creating room…");
  try {
    const resp = await api.createRoom(body);
    roomkey.persist(resp.room_id, k);
    inviteSection.hidden = false;
    inviteLink.textContent = `${location.origin}/r/join/${resp.invite_code}`;
    openRoom.href = `/r/${resp.room_id}`;
    text(status, "Room created.");
  } catch (e) {
    text(status, `Error: ${(e as Error).message}`);
  }
});

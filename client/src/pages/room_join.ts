// Room join: generate keys, request access, then redirect to the room.
// The unwrap happens on the room page once an existing member grants us
// the room key.

import { api } from "../lib/api";
import { $, meta, text } from "../lib/dom";
import { b64encode } from "../lib/b64";
import * as roomkey from "../lib/roomkey";

const inviteCode = meta("lethe-invite-code");

const btn = $<HTMLButtonElement>("#join-btn");
const status = $<HTMLParagraphElement>("#join-status");
const openLine = $<HTMLElement>("#open-room-line");
const openRoom = $<HTMLAnchorElement>("#open-room");

btn.addEventListener("click", async () => {
  btn.disabled = true;
  text(status, "Generating keys…");
  const k = await roomkey.generateForJoin();
  text(status, "Requesting access…");
  try {
    const resp = await api.joinRoom(inviteCode, {
      box_pubkey: b64encode(k.boxPub),
      sig_pubkey: b64encode(k.sigPub),
    });
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

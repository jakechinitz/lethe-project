// Room page: provenance verification, member trust cards, send/receive
// E2EE messages. The creator-side grant loop runs here too — when a new
// member appears with `wrapped_key=null`, an existing member's tab wraps
// the room key for them.

import { api, MemberView, MessageView, ProvenanceView } from "../lib/api";
import { $, clear, durationSince, el, meta, text } from "../lib/dom";
import { b64decode, b64encode, fromUtf8 } from "../lib/b64";
import * as roomkey from "../lib/roomkey";
import { trust } from "../lib/strings";

const roomIdB64 = meta("lethe-room-id");
const roomIdBytes = b64decode(roomIdB64);

const provenanceText = $<HTMLElement>("#provenance-text");
const membersList = $<HTMLElement>("#members-list");
const messagesList = $<HTMLElement>("#messages-list");
const sendForm = $<HTMLFormElement>("#send-form");
const sendStatus = $<HTMLParagraphElement>("#send-status");

let lastMessageId: string | undefined;
let memberCache: MemberView[] = [];

main();

async function main(): Promise<void> {
  const stored = roomkey.read(roomIdB64);
  if (!stored) {
    text(provenanceText, "No keys stored for this room. Did you join from another browser?");
    return;
  }
  await renderProvenance();
  await tickMembers(stored);
  await tickMessages(stored);
  setInterval(() => tickMembers(stored), 4000);
  setInterval(() => tickMessages(stored), 3000);

  sendForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fresh = roomkey.read(roomIdB64);
    if (!fresh?.roomKey) {
      text(sendStatus, "Cannot send: room key not available yet.");
      return;
    }
    const body = String(new FormData(sendForm).get("body") ?? "");
    if (!body) return;
    text(sendStatus, "Sending…");
    const enc = await roomkey.encryptMessage(body, roomIdBytes, fresh.roomKey);
    const sig = await roomkey.signMessageEnvelope(
      roomIdBytes,
      enc.nonce,
      enc.ciphertext,
      fresh.sigPriv,
    );
    try {
      await api.sendMessage(roomIdB64, {
        sender_sig_pubkey: b64encode(fresh.sigPub),
        nonce: b64encode(enc.nonce),
        ciphertext: b64encode(enc.ciphertext),
        sender_sig: b64encode(sig),
      });
      sendForm.reset();
      text(sendStatus, "");
      await tickMessages(fresh);
    } catch (e) {
      text(sendStatus, `Error: ${(e as Error).message}`);
    }
  });
}

async function renderProvenance(): Promise<void> {
  let p: ProvenanceView;
  try {
    p = await api.provenance(roomIdB64);
  } catch (e) {
    text(provenanceText, `Could not load provenance: ${(e as Error).message}`);
    return;
  }
  if (!p.origin_thread || !p.creator_thread_pubkey || !p.provenance_sig) {
    text(provenanceText, trust.noProvenance);
    return;
  }
  const ok = await roomkey.verifyProvenance(
    b64decode(p.origin_thread),
    b64decode(p.creator_thread_pubkey),
    b64decode(p.provenance_sig),
  );
  text(
    provenanceText,
    ok
      ? `${trust.provenanceVerified} — created by an identity from thread ${p.origin_thread}`
      : trust.noProvenance,
  );
}

async function tickMembers(keys: roomkey.RoomKeys): Promise<void> {
  const { members } = await api.members(roomIdB64);
  memberCache = members;
  renderMembers(members);
  if (keys.roomKey) {
    await maybeGrantPending(keys, members);
  } else {
    await maybeUnwrap(keys, members);
  }
}

function renderMembers(members: MemberView[]): void {
  clear(membersList);
  for (const m of members) {
    const flagged = isFlagged(m, members);
    const card = el("div", { class: flagged ? "member flagged" : "member" });
    const inviter = m.invited_by_box_pubkey
      ? trust.invitedBy(shortId(m.invited_by_box_pubkey))
      : "Creator";
    card.appendChild(
      el("div", {}, [`${shortId(m.box_pubkey)} · ${inviter} · ${trust.joinedAgo(durationSince(m.joined_at))}`]),
    );
    const badges = el("div", { class: "badges" });
    badges.appendChild(el("span", { class: "badge" }, [trust.continuityVerified]));
    badges.appendChild(el("span", { class: "badge" }, [trust.unverified]));
    if (isNew(m.joined_at)) badges.appendChild(el("span", { class: "badge" }, [trust.newMember]));
    if (m.invited_by_box_pubkey) {
      const inviterRow = members.find((x) => x.box_pubkey === m.invited_by_box_pubkey);
      if (inviterRow && isNew(inviterRow.joined_at)) {
        badges.appendChild(el("span", { class: "badge" }, [trust.newInviter]));
      }
    }
    card.appendChild(badges);
    membersList.appendChild(card);
  }
}

function isNew(joinedAt: string): boolean {
  return Date.now() - new Date(joinedAt).getTime() < 60 * 60 * 1000;
}

function isFlagged(m: MemberView, all: MemberView[]): boolean {
  if (isNew(m.joined_at)) return true;
  if (m.invited_by_box_pubkey) {
    const inviter = all.find((x) => x.box_pubkey === m.invited_by_box_pubkey);
    if (inviter && isNew(inviter.joined_at)) return true;
  }
  return false;
}

function shortId(b64: string): string {
  return b64.slice(0, 8);
}

async function maybeGrantPending(keys: roomkey.RoomKeys, members: MemberView[]): Promise<void> {
  if (!keys.roomKey) return;
  for (const m of members) {
    if (m.wrapped_key) continue;
    if (m.box_pubkey === b64encode(keys.boxPub)) continue;
    const wrapped = await roomkey.wrapRoomKey(keys.roomKey, b64decode(m.box_pubkey));
    try {
      await api.wrap(roomIdB64, {
        for_box_pubkey: m.box_pubkey,
        wrapped_key: b64encode(wrapped),
        inviter_box_pubkey: b64encode(keys.boxPub),
      });
    } catch {
      // Another member may have raced us; ignore and re-poll.
    }
  }
}

async function maybeUnwrap(keys: roomkey.RoomKeys, members: MemberView[]): Promise<void> {
  const myB64 = b64encode(keys.boxPub);
  const me = members.find((m) => m.box_pubkey === myB64);
  if (!me?.wrapped_key) return;
  try {
    const roomKey = await roomkey.unwrapRoomKey(
      b64decode(me.wrapped_key),
      keys.boxPub,
      keys.boxPriv,
    );
    roomkey.persistRoomKey(roomIdB64, roomKey);
    location.reload();
  } catch (e) {
    text(provenanceText, `Failed to unwrap room key: ${(e as Error).message}`);
  }
}

async function tickMessages(keys: roomkey.RoomKeys): Promise<void> {
  if (!keys.roomKey) return;
  const fresh = roomkey.read(roomIdB64);
  if (!fresh?.roomKey) return;
  let resp: { messages: MessageView[] };
  try {
    resp = await api.listMessages(roomIdB64, lastMessageId);
  } catch {
    return;
  }
  for (const m of resp.messages) {
    await renderMessage(m, fresh.roomKey);
    lastMessageId = m.message_id;
  }
}

async function renderMessage(m: MessageView, roomKey: Uint8Array): Promise<void> {
  const senderPub = b64decode(m.sender_sig_pubkey);
  const member = memberCache.find((x) => x.sig_pubkey === m.sender_sig_pubkey);
  const fromLabel = member ? `from ${shortId(member.box_pubkey)}` : "from unknown member";

  const sigOk = await roomkey.verifyMessageEnvelope(
    roomIdBytes,
    b64decode(m.nonce),
    b64decode(m.ciphertext),
    b64decode(m.sender_sig),
    senderPub,
  );

  let bodyText: string;
  if (!sigOk) {
    bodyText = "[unverified — signature mismatch]";
  } else {
    try {
      const pt = await roomkey.decryptMessage(
        b64decode(m.ciphertext),
        b64decode(m.nonce),
        roomIdBytes,
        roomKey,
      );
      bodyText = fromUtf8(pt);
    } catch {
      bodyText = "[unreadable — decryption failed]";
    }
  }

  messagesList.appendChild(
    el("div", { class: "msg" }, [
      el("div", { class: "from" }, [`${fromLabel} · ${durationSince(m.created_at)} ago`]),
      el("div", { class: "body" }, [bodyText]),
    ]),
  );
}

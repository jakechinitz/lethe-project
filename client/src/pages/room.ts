// Room page: provenance verification, member trust cards, send/receive
// E2EE messages, and (creator only) a remove-and-rekey flow that
// rotates the room key to cut off a removed member from future
// messages while keeping historical messages decryptable for survivors.

import { api, MemberView, MessageView, ProvenanceView } from "../lib/api";
import { $, clear, el, formatPostTimestamp, meta, text } from "../lib/dom";
import { b64decode, b64encode, bytesEqual, fromUtf8 } from "../lib/b64";
import * as roomkey from "../lib/roomkey";
import { trust } from "../lib/strings";

const roomIdB64 = meta("lethe-room-id");
const roomIdBytes = b64decode(roomIdB64);

const provenanceText = $<HTMLElement>("#provenance-text");
const membersList = $<HTMLElement>("#members-list");
const messagesList = $<HTMLElement>("#messages-list");
const sendForm = $<HTMLFormElement>("#send-form");
const sendStatus = $<HTMLParagraphElement>("#send-status");

let lastMessageSeq: number | undefined;
let memberCache: MemberView[] = [];
let amCreator = false;
let currentEpoch = 0;

main();

async function main(): Promise<void> {
  const stored = roomkey.read(roomIdB64);
  if (!stored) {
    text(provenanceText, "No keys stored for this room. Did you join from another browser?");
    return;
  }
  await renderProvenance();
  await tickMembers();
  await tickMessages();
  setInterval(tickMembers, 4000);
  setInterval(tickMessages, 3000);

  const leaveBtn = document.querySelector<HTMLButtonElement>("#leave-btn");
  if (leaveBtn) {
    leaveBtn.addEventListener("click", onLeave);
  }

  sendForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fresh = roomkey.read(roomIdB64);
    if (!fresh || fresh.roomKeys.length === 0) {
      text(sendStatus, "Cannot send: room key not available yet.");
      return;
    }
    const body = String(new FormData(sendForm).get("body") ?? "");
    if (!body) return;
    text(sendStatus, "Sending…");
    const enc = await roomkey.encryptMessage(body, roomIdBytes, fresh.roomKeys);
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
      await tickMessages();
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

async function tickMembers(): Promise<void> {
  const keys = roomkey.read(roomIdB64);
  if (!keys) return;
  const resp = await api.members(roomIdB64);
  memberCache = resp.members;
  currentEpoch = resp.current_epoch;
  renderRetentionNote(resp.message_retention_days);

  // "I'm the creator" iff my box pubkey matches the member with no inviter.
  const creatorRow = resp.members.find((m) => !m.invited_by_box_pubkey);
  amCreator = !!creatorRow && bytesEqual(b64decode(creatorRow.box_pubkey), keys.boxPub);

  if (keys.roomKeys.length > 0) {
    await maybeGrantPending(keys, resp.members);
    await maybeAdoptNewEpoch(keys, resp.members);
  } else {
    await maybeUnwrap(keys, resp.members);
  }
  renderMembers(resp.members);
}

/// Replaces the template's placeholder with the room's actual
/// server-side message lifetime, so members aren't surprised when
/// history vanishes. Local copies in the browser are unaffected.
function renderRetentionNote(days: number): void {
  const note = document.querySelector<HTMLElement>("#retention-note");
  if (!note) return;
  const span = days === 1 ? "1 day" : `${days} days`;
  note.textContent =
    `Messages are automatically deleted from the server ${span} after ` +
    `they're sent. What you've already loaded stays visible until you ` +
    `close the page; nothing older than ${span} can be fetched again — ` +
    `by you, the server operator, or anyone who seizes the server.`;
}

function renderMembers(members: MemberView[]): void {
  const counts = members.reduce(
    (acc, m) => {
      if (m.removed_at) acc.removed += 1; else acc.active += 1;
      return acc;
    },
    { active: 0, removed: 0 },
  );
  const countEl = document.querySelector<HTMLElement>("#member-count");
  if (countEl) {
    countEl.textContent =
      counts.removed === 0
        ? `(${counts.active} active)`
        : `(${counts.active} active · ${counts.removed} removed)`;
  }
  clear(membersList);
  for (const m of members) {
    const removed = !!m.removed_at;
    const flagged = !removed && isFlagged(m, members);
    const card = el("div", {
      class: removed ? "member removed" : flagged ? "member flagged" : "member",
    });

    const inviter = m.invited_by_box_pubkey
      ? trust.invitedBy(shortId(m.invited_by_box_pubkey))
      : trust.creator;
    card.appendChild(
      el("div", {}, [
        `${shortId(m.box_pubkey)} · ${inviter} · ${trust.joinedOn(formatPostTimestamp(m.joined_at))}`,
      ]),
    );

    const badges = el("div", { class: "badges" });
    if (removed) {
      badges.appendChild(el("span", { class: "badge" }, [trust.removed]));
    } else {
      badges.appendChild(el("span", { class: "badge" }, [trust.continuityVerified]));
      badges.appendChild(el("span", { class: "badge" }, [trust.unverified]));
      if (isNew(m.joined_at)) {
        badges.appendChild(el("span", { class: "badge" }, [trust.newMember]));
      }
      if (m.invited_by_box_pubkey) {
        const inviterRow = members.find(
          (x) => x.box_pubkey === m.invited_by_box_pubkey,
        );
        if (inviterRow && isNew(inviterRow.joined_at)) {
          badges.appendChild(el("span", { class: "badge" }, [trust.newInviter]));
        }
      }
    }
    card.appendChild(badges);

    // Remove button: creator-only, not for self, not for already-removed.
    const meKeys = roomkey.read(roomIdB64);
    const isMe = meKeys && bytesEqual(b64decode(m.box_pubkey), meKeys.boxPub);
    if (amCreator && !removed && !isMe) {
      const btn = el("button", { type: "button", class: "remove-btn" }, ["Remove"]);
      btn.addEventListener("click", () => removeMember(m));
      card.appendChild(btn);
    }

    membersList.appendChild(card);
  }

  // Footer: epoch label so users can see when a key has been rotated.
  membersList.appendChild(
    el("p", { class: "muted epoch-label" }, [trust.keyEpoch(currentEpoch)]),
  );
}

async function onLeave(): Promise<void> {
  const keys = roomkey.read(roomIdB64);
  if (!keys) {
    alert("No keys for this room. Already gone.");
    return;
  }
  if (!confirm(
      "Leave this room? You'll be cut off from new messages and posts " +
        "immediately. The room key on this device will be wiped — old " +
        "messages stop being readable here too. There's no undo.",
    )) {
    return;
  }
  const ts = Math.floor(Date.now() / 1000);
  const sig = await roomkey.signLeaveRequest(roomIdBytes, ts, keys.sigPriv);
  try {
    await api.leaveRoom(roomIdB64, {
      sig_pubkey: b64encode(keys.sigPub),
      ts,
      sig: b64encode(sig),
    });
    localStorage.removeItem(`lethe.room.${roomIdB64}`);
    location.href = "/my-rooms";
  } catch (e) {
    alert(`Leave failed: ${(e as Error).message}`);
  }
}

async function removeMember(target: MemberView): Promise<void> {
  if (!confirm(
      `Remove ${shortId(target.box_pubkey)}? This will rotate the room key. They keep any messages they've already seen.`,
    )) {
    return;
  }
  const keys = roomkey.read(roomIdB64);
  if (!keys || keys.roomKeys.length === 0) {
    alert("Cannot rekey: no current room key on this device.");
    return;
  }

  // 1. Generate a fresh room key.
  const sodiumLib = await (await import("../lib/sodium")).sodium();
  const newKey = sodiumLib.randombytes_buf(32);

  // 2. Wrap for every surviving member (everyone except target and removed).
  const survivors = memberCache.filter(
    (m) => !m.removed_at && m.box_pubkey !== target.box_pubkey,
  );
  const wraps: Array<{ for_box_pubkey: string; wrapped_key: string }> = [];
  for (const m of survivors) {
    const wrapped = await roomkey.wrapRoomKey(newKey, b64decode(m.box_pubkey));
    wraps.push({
      for_box_pubkey: m.box_pubkey,
      wrapped_key: b64encode(wrapped),
    });
  }

  // 3. Authenticated remove-and-rekey request.
  const ts = Math.floor(Date.now() / 1000);
  const sig = await roomkey.signRemoveRequest(
    roomIdBytes,
    ts,
    b64decode(target.box_pubkey),
    keys.sigPriv,
  );
  try {
    const resp = await api.removeMember(roomIdB64, {
      remover_sig_pubkey: b64encode(keys.sigPub),
      ts,
      sig: b64encode(sig),
      target_box_pubkey: target.box_pubkey,
      new_wrapped_keys: wraps,
    });
    // 4. Append the new key locally. Future sends use it; old keys still
    //    decrypt historical messages.
    roomkey.appendRoomKey(roomIdB64, newKey, resp.current_epoch);
    await tickMembers();
  } catch (e) {
    alert(`Remove failed: ${(e as Error).message}`);
  }
}

function isNew(joinedAt: string): boolean {
  // Date-granularity input: a member counts as "new" if they joined today
  // (UTC), since that's the finest resolution the server stores.
  const todayUtc = new Date().toISOString().slice(0, 10);
  return joinedAt.slice(0, 10) === todayUtc;
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
  // Wrap for any pending (newly-joined) member with the current room key.
  if (keys.roomKeys.length === 0) return;
  const currentKey = keys.roomKeys[keys.roomKeys.length - 1];
  const myB64 = b64encode(keys.boxPub);
  for (const m of members) {
    if (m.removed_at) continue;
    if (m.wrapped_key) continue;
    if (m.box_pubkey === myB64) continue;
    const forBox = b64decode(m.box_pubkey);
    const wrapped = await roomkey.wrapRoomKey(currentKey, forBox);
    const ts = Math.floor(Date.now() / 1000);
    const sig = await roomkey.signWrapRequest(
      roomIdBytes,
      forBox,
      wrapped,
      ts,
      keys.sigPriv,
    );
    try {
      await api.wrap(roomIdB64, {
        for_box_pubkey: m.box_pubkey,
        wrapped_key: b64encode(wrapped),
        inviter_box_pubkey: b64encode(keys.boxPub),
        inviter_sig_pubkey: b64encode(keys.sigPub),
        inviter_ts: ts,
        inviter_sig: b64encode(sig),
      });
    } catch {
      // Race: another member granted first; ignore.
    }
  }
}

async function maybeAdoptNewEpoch(
  keys: roomkey.RoomKeys,
  members: MemberView[],
): Promise<void> {
  if (currentEpoch <= keys.lastEpoch) return;
  const myB64 = b64encode(keys.boxPub);
  const me = members.find((m) => m.box_pubkey === myB64);
  if (!me?.wrapped_key) return;
  try {
    const newKey = await roomkey.unwrapRoomKey(
      b64decode(me.wrapped_key),
      keys.boxPub,
      keys.boxPriv,
    );
    roomkey.appendRoomKey(roomIdB64, newKey, currentEpoch);
  } catch {
    // The wrapped key on the server may still be the old one for one
    // poll cycle if our row hasn't been updated yet. Nothing to do.
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
    roomkey.appendRoomKey(roomIdB64, roomKey, currentEpoch);
    location.reload();
  } catch (e) {
    text(provenanceText, `Failed to unwrap room key: ${(e as Error).message}`);
  }
}

async function tickMessages(): Promise<void> {
  const fresh = roomkey.read(roomIdB64);
  if (!fresh || fresh.roomKeys.length === 0) return;
  const ts = Math.floor(Date.now() / 1000);
  const sig = await roomkey.signListRequest(roomIdBytes, ts, fresh.sigPriv);
  let resp: { messages: MessageView[] };
  try {
    resp = await api.listMessages(roomIdB64, {
      requester_sig_pubkey: b64encode(fresh.sigPub),
      ts,
      sig: b64encode(sig),
      since_seq: lastMessageSeq,
    });
  } catch {
    return;
  }
  for (const m of resp.messages) {
    await renderMessage(m, fresh.roomKeys);
    lastMessageSeq = m.seq;
  }
}

async function renderMessage(m: MessageView, roomKeys: Uint8Array[]): Promise<void> {
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
        roomKeys,
      );
      bodyText = fromUtf8(pt);
    } catch {
      bodyText = "[unreadable — decryption failed]";
    }
  }

  messagesList.appendChild(
    el("div", { class: "msg" }, [
      el("div", { class: "from" }, [`${fromLabel} · ${formatPostTimestamp(m.created_at)}`]),
      el("div", { class: "body" }, [bodyText]),
    ]),
  );
}

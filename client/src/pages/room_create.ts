// Room creation: generate keys + room key, optionally restrict the
// invite to a hand-picked set of anons from the originating thread.

import { api } from "../lib/api";
import { $, clear, el, meta, text } from "../lib/dom";
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
const inviteesSection = $<HTMLElement>("#invitees-section");
const inviteesList = $<HTMLElement>("#invitees-list");
const inviteesStatus = $<HTMLParagraphElement>("#invitees-status");
const selectAll = $<HTMLInputElement>("#select-all-anons");

if (!fromThreadId) {
  attachProvenance.checked = false;
  attachProvenance.disabled = true;
  // Restricted mode requires an originating thread; hide it entirely.
  $<HTMLInputElement>("#invite-mode-allowlist").disabled = true;
}

let signerPubkeysInThread: { pubkey: string; firstSeq: number }[] = [];

form.addEventListener("change", (ev) => {
  const target = ev.target as HTMLElement | null;
  if (target instanceof HTMLInputElement && target.name === "invite_mode") {
    const showAllowlist = target.value === "allowlist" && !!fromThreadId;
    inviteesSection.hidden = !showAllowlist;
    if (showAllowlist && signerPubkeysInThread.length === 0) {
      void loadInviteeList();
    }
  }
});

selectAll.addEventListener("change", () => {
  const checked = selectAll.checked;
  for (const cb of inviteesList.querySelectorAll<HTMLInputElement>(
    "input[type=checkbox]",
  )) {
    cb.checked = checked;
  }
});

async function loadInviteeList(): Promise<void> {
  if (!fromThreadId) return;
  try {
    const { posts } = await api.listPosts(fromThreadId, 0);
    // De-duplicate signed pubkeys, preserving order of first appearance,
    // skipping the OP. Each entry shows up once with its earliest seq.
    const seen = new Set<string>();
    signerPubkeysInThread = [];
    for (const p of posts) {
      if (p.seq === 1) continue;
      if (!p.pubkey) continue;
      if (seen.has(p.pubkey)) continue;
      seen.add(p.pubkey);
      signerPubkeysInThread.push({
        pubkey: p.pubkey,
        firstSeq: p.signer_first_seq ?? p.seq,
      });
    }
    renderInvitees();
  } catch (e) {
    text(inviteesStatus, `Could not load thread: ${(e as Error).message}`);
  }
}

function renderInvitees(): void {
  clear(inviteesList);
  if (signerPubkeysInThread.length === 0) {
    text(
      inviteesStatus,
      "No signed posters in this thread yet. Only fully-anonymous posts so far — there's nobody specific to invite.",
    );
    return;
  }
  text(
    inviteesStatus,
    `${signerPubkeysInThread.length} signed anon${signerPubkeysInThread.length === 1 ? "" : "s"} in this thread:`,
  );
  for (let i = 0; i < signerPubkeysInThread.length; i++) {
    const entry = signerPubkeysInThread[i];
    const cb = el("input", {
      type: "checkbox",
      value: entry.pubkey,
      name: "invitee",
    }) as HTMLInputElement;
    const label = el("label", { class: "invitee" }, [
      cb,
      ` Anon ${i + 1} (first signed at #${entry.firstSeq})`,
    ]);
    inviteesList.appendChild(label);
  }
}

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const inviteMode = (
    form.querySelector<HTMLInputElement>('input[name="invite_mode"]:checked')?.value ?? "open"
  );

  let allowlist: string[] | undefined;
  if (inviteMode === "allowlist") {
    if (!fromThreadId) {
      text(status, "Restricted mode requires opening this page from a thread.");
      return;
    }
    allowlist = Array.from(
      inviteesList.querySelectorAll<HTMLInputElement>("input[type=checkbox]:checked"),
    ).map((cb) => cb.value);
    if (allowlist.length === 0) {
      text(status, "Pick at least one anon to invite, or switch to 'Anyone with the invite link'.");
      return;
    }
  }

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

  if (allowlist && allowlist.length > 0) {
    if (!body.origin_thread) {
      // Restricted mode hard-requires origin_thread. The provenance
      // attachment supplies it; if the user unchecked provenance,
      // attach it anyway just for the allowlist check.
      body.origin_thread = fromThreadId;
    }
    body.allowlist_thread_pubkeys = allowlist;
  }

  text(status, "Creating room…");
  try {
    const resp = await api.createRoom(body);
    roomkey.persist(resp.room_id, k);
    inviteSection.hidden = false;
    inviteLink.textContent = `${location.origin}/r/join/${resp.invite_code}`;
    openRoom.href = `/r/${resp.room_id}`;
    if (allowlist && allowlist.length > 0) {
      text(status, `Room created. Only your ${allowlist.length} selected anon${allowlist.length === 1 ? "" : "s"} can use this link.`);
    } else {
      text(status, "Room created.");
    }
  } catch (e) {
    text(status, `Error: ${(e as Error).message}`);
  }
});

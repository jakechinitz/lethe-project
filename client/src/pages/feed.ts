// Feed page: renders the cross-board thread list with a category filter
// and infinite scroll, and hosts the new-thread form.

import { $, clear, el, formatPostTimestamp, meta, text } from "../lib/dom";
import { b64encode, utf8 } from "../lib/b64";
import { findNonce } from "../lib/pow";
import { sodium } from "../lib/sodium";
import * as tkey from "../lib/threadkey";
import * as roomkey from "../lib/roomkey";
import * as vouch from "../lib/vouch";
import * as netview from "../lib/netview";

interface FeedItem {
  thread_id: string;
  board_id: string;
  title: string;
  created_at: string;
  last_post_at: string;
  post_count: number;
  /// Room the OP *claims* a vouch from. Not verified here — the thread
  /// page verifies. Enough to pre-filter by trusted rooms.
  op_vouch_room_id?: string;
}


interface FeedResp {
  items: FeedItem[];
  category?: string | null;
  sort: "last_comment" | "newest";
}

const selectedCat = meta("lethe-selected-cat") || null;
const selectedSort = meta("lethe-selected-sort") as "last_comment" | "newest";
const powBits = parseInt(meta("lethe-pow-bits"), 10);

const feedEl = $<HTMLElement>("#feed");
const feedEnd = $<HTMLElement>("#feed-end");
const form = $<HTMLFormElement>("#new-thread-form");
const status = $<HTMLParagraphElement>("#new-thread-status");
const vouchSelect = $<HTMLSelectElement>("#vouch-room");
const viewNote = $<HTMLParagraphElement>("#view-note");

for (const id of roomkey.listRoomIds()) {
  const keys = roomkey.read(id);
  if (!keys || keys.roomKeys.length === 0) continue;
  const label = vouch.trustedLabel(id) ?? `Room ${id.slice(0, 8)}`;
  vouchSelect.appendChild(el("option", { value: id }, [label]));
}

/// All / My network / Room X. The feed only knows which room the first
/// post *claims*; the thread page verifies on open.
let view: netview.View = netview.mount($<HTMLElement>("#view-switch"), (v) => {
  view = v;
  applyFeedFilter();
  renderViewNote();
});
renderViewNote();

function renderViewNote(): void {
  switch (view.kind) {
    case "all":
      text(viewNote, "");
      break;
    case "network":
      text(viewNote, "Threads whose first post claims a vouch from a room you belong to or trust. Verified when you open the thread.");
      break;
    case "room":
      text(viewNote, `Threads whose first post claims a vouch from ${vouch.networkLabel(view.roomId) ?? "that room"}. Verified when you open the thread.`);
      break;
  }
}

function applyFeedFilter(): void {
  for (const item of feedEl.querySelectorAll<HTMLElement>(".feed-item")) {
    const room = item.dataset.vouchRoom || null;
    item.classList.toggle("vouch-hidden", !netview.passes(view, room));
  }
}

const CATEGORY_LABELS: Record<string, string> = {
  government: "Government",
  economy: "Economy",
  science_tech: "Science & Tech",
  all_other: "All other",
};

let cursor: { ts: string; id: string } | null = null;
let exhausted = false;
let loading = false;

main();

async function main(): Promise<void> {
  await loadMore();
  setupInfiniteScroll();
  form.addEventListener("submit", onSubmit);
}

async function loadMore(): Promise<void> {
  if (loading || exhausted) return;
  loading = true;
  try {
    const params = new URLSearchParams();
    if (selectedCat) params.set("cat", selectedCat);
    params.set("sort", selectedSort);
    if (cursor) {
      params.set("cursor_ts", cursor.ts);
      params.set("cursor_id", cursor.id);
    }
    const resp = await fetch(`/api/feed?${params.toString()}`);
    if (!resp.ok) throw new Error(`feed ${resp.status}`);
    const body: FeedResp = await resp.json();
    if (cursor === null) {
      clear(feedEl);
      feedEl.removeAttribute("aria-busy");
      if (body.items.length === 0) {
        feedEl.appendChild(el("p", { class: "muted" }, ["No threads yet. Be the first."]));
      }
    }
    for (const item of body.items) {
      feedEl.appendChild(renderItem(item));
    }
    applyFeedFilter();
    if (body.items.length === 0) {
      exhausted = true;
      feedEnd.hidden = false;
    } else {
      const last = body.items[body.items.length - 1];
      cursor = {
        ts: selectedSort === "newest" ? last.created_at : last.last_post_at,
        id: last.thread_id,
      };
    }
  } catch (e) {
    feedEl.appendChild(el("p", { class: "muted" }, [`Error: ${(e as Error).message}`]));
  } finally {
    loading = false;
  }
}

function renderItem(item: FeedItem): HTMLElement {
  const article = el("article", { class: "feed-item" });
  const link = el("a", {}, [item.title]) as HTMLAnchorElement;
  link.href = `/b/${item.board_id}/t/${item.thread_id}`;
  link.className = "feed-title";
  article.appendChild(link);

  const label = CATEGORY_LABELS[item.board_id] ?? item.board_id;
  const replies = Math.max(0, item.post_count - 1);
  const metaChildren: Array<Node | string> = [
    el("span", { class: "badge cat" }, [label]),
    ` · `,
    `${replies} ${replies === 1 ? "reply" : "replies"}`,
    ` · last activity ${formatPostTimestamp(item.last_post_at)}`,
  ];
  if (item.op_vouch_room_id) {
    const label = vouch.networkLabel(item.op_vouch_room_id);
    article.dataset.vouchRoom = item.op_vouch_room_id;
    const tag = el(
      "span",
      { class: `vouch-badge feed-vouch ${label ? "trusted" : "untrusted"}` },
      [label ? `vouched: ${label}` : `vouched: room ${item.op_vouch_room_id.slice(0, 8)}…`],
    );
    tag.title = "Claimed by the first post; verified when you open the thread";
    metaChildren.push(" · ", tag);
  }
  article.appendChild(el("div", { class: "feed-meta" }, metaChildren));
  return article;
}

function setupInfiniteScroll(): void {
  const sentinel = el("div", { class: "feed-sentinel" });
  feedEl.appendChild(sentinel);
  const obs = new IntersectionObserver(
    async (entries) => {
      if (entries.some((e) => e.isIntersecting) && !loading && !exhausted) {
        await loadMore();
        // Reattach the sentinel at the new bottom so it keeps firing.
        feedEl.appendChild(sentinel);
      }
    },
    { rootMargin: "400px 0px" },
  );
  obs.observe(sentinel);
}

async function onSubmit(ev: SubmitEvent): Promise<void> {
  ev.preventDefault();
  const data = new FormData(form);
  const title = String(data.get("title") ?? "").trim();
  const body = String(data.get("body") ?? "");
  const boardId = String(data.get("board_id") ?? "");
  if (!title || !body || !boardId) return;

  const claimOp =
    document.querySelector<HTMLInputElement>("#claim-op-identity")?.checked ?? false;

  text(status, "Computing proof-of-work…");
  const nonce = await findNonce(utf8(boardId), body, powBits);

  // Mint a fresh thread_id locally so the OP signature can include it.
  // For unsigned posts we still mint it here for consistency; the server
  // accepts either a client-supplied or auto-generated id.
  const s = await sodium();
  const threadIdBytes = s.randombytes_buf(16);
  const threadIdB64 = b64encode(threadIdBytes);

  const reqBody: Record<string, unknown> = {
    board_id: boardId,
    title,
    body,
    pow_nonce: b64encode(nonce),
    thread_id: threadIdB64,
  };

  // Author-chosen expiry. Empty string = "Keep forever" = omit field.
  const expiresRaw = String(data.get("expires_in_days") ?? "");
  if (expiresRaw) {
    reqBody.expires_in_days = parseInt(expiresRaw, 10);
  }

  let pendingKey: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  if (claimOp) {
    const kp = s.crypto_sign_keypair();
    const sig = await tkey.signPost(threadIdBytes, body, kp.privateKey);
    reqBody.pubkey = b64encode(kp.publicKey);
    reqBody.signature = b64encode(sig);
    pendingKey = { publicKey: kp.publicKey, privateKey: kp.privateKey };
  }

  if (vouchSelect.value) {
    const keys = roomkey.read(vouchSelect.value);
    if (!keys) {
      text(status, "No keys for the selected room on this device.");
      return;
    }
    text(status, "Building room vouch…");
    try {
      reqBody.vouch = await vouch.buildVouch(vouchSelect.value, threadIdBytes, body, keys);
    } catch (e) {
      text(status, `Vouch failed: ${(e as Error).message}`);
      return;
    }
  }

  text(status, "Submitting…");
  try {
    const resp = await fetch("/api/threads", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(reqBody),
    });
    if (!resp.ok) {
      throw new Error(`server ${resp.status}: ${await resp.text()}`);
    }
    const created: { thread_id: string } = await resp.json();

    // Persist the thread key under the canonical localStorage slot so the
    // thread page picks it up and tags future replies as OP.
    if (pendingKey) {
      tkey.persistKeypair(created.thread_id, pendingKey.publicKey, pendingKey.privateKey);
    }

    location.href = `/b/${boardId}/t/${created.thread_id}`;
  } catch (e) {
    text(status, `Error: ${(e as Error).message}`);
  }
}

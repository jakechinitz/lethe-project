// Feed page: renders the cross-board thread list with a category filter
// and infinite scroll, and hosts the new-thread form.

import { $, clear, el, formatPostTimestamp, meta, text } from "../lib/dom";
import { b64encode, utf8 } from "../lib/b64";
import { findNonce } from "../lib/pow";
import { sodium } from "../lib/sodium";
import * as tkey from "../lib/threadkey";

interface FeedItem {
  thread_id: string;
  board_id: string;
  title: string;
  created_at: string;
  last_post_at: string;
  post_count: number;
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
  article.appendChild(
    el("div", { class: "feed-meta" }, [
      el("span", { class: "badge cat" }, [label]),
      ` · `,
      `${replies} ${replies === 1 ? "reply" : "replies"}`,
      ` · last activity ${formatPostTimestamp(item.last_post_at)}`,
    ]),
  );
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

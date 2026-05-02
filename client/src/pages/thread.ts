// Thread page: loads posts, lets the user reply anonymously or with a
// thread-local Ed25519 identity ("same anon as #N").

import { api, PostView } from "../lib/api";
import { $, clear, el, meta, text } from "../lib/dom";
import { b64decode, b64encode } from "../lib/b64";
import { findNonce } from "../lib/pow";
import * as tkey from "../lib/threadkey";
import { limitations } from "../lib/strings";

const threadIdB64 = meta("lethe-thread-id");
const threadIdBytes = b64decode(threadIdB64);
const powBits = parseInt(meta("lethe-pow-bits"), 10);

const postsEl = $<HTMLElement>("#posts");
const replyForm = $<HTMLFormElement>("#reply-form");
const replyStatus = $<HTMLParagraphElement>("#reply-status");
const claim = $<HTMLInputElement>("#claim-identity");
const forgetBtn = $<HTMLButtonElement>("#forget-identity");

claim.checked = tkey.hasKeypair(threadIdB64);
updateForgetVisibility();
claim.addEventListener("change", updateForgetVisibility);
forgetBtn.addEventListener("click", () => {
  if (!confirm(limitations.threadIdentity)) return;
  tkey.forget(threadIdB64);
  claim.checked = false;
  updateForgetVisibility();
});

replyForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = String(new FormData(replyForm).get("body") ?? "");
  if (!body) return;

  text(replyStatus, "Computing proof-of-work…");
  const nonce = await findNonce(threadIdBytes, body, powBits);

  let pubkey: string | undefined;
  let signature: string | undefined;
  if (claim.checked) {
    const kp = await tkey.getOrCreateKeypair(threadIdB64);
    const sig = await tkey.signPost(threadIdBytes, body, kp.privateKey);
    pubkey = b64encode(kp.publicKey);
    signature = b64encode(sig);
  }

  text(replyStatus, "Submitting…");
  try {
    await api.createPost(threadIdB64, {
      body,
      pow_nonce: b64encode(nonce),
      pubkey,
      signature,
    });
    replyForm.reset();
    text(replyStatus, "");
    await refresh();
    updateForgetVisibility();
  } catch (e) {
    text(replyStatus, `Error: ${(e as Error).message}`);
  }
});

async function refresh(): Promise<void> {
  try {
    const { posts } = await api.listPosts(threadIdB64, 0);
    render(posts);
  } catch (e) {
    text(postsEl, `Error: ${(e as Error).message}`);
  }
}

function render(posts: PostView[]): void {
  clear(postsEl);
  postsEl.removeAttribute("aria-busy");
  if (posts.length === 0) {
    postsEl.appendChild(el("p", { class: "muted" }, ["No posts yet."]));
    return;
  }
  for (const p of posts) {
    postsEl.appendChild(renderPost(p));
  }
  scrollToHashTarget();
}

function renderPost(p: PostView): HTMLElement {
  const isOp = p.seq === 1;
  const article = el("article", { class: isOp ? "post op" : "post" });
  article.id = `p${p.seq}`;

  const seqLink = el("a", {}, [`#${p.seq}`]) as HTMLAnchorElement;
  seqLink.href = `#p${p.seq}`;
  seqLink.className = "seq-link";
  seqLink.title = "Click to copy a deep link to this post";
  seqLink.addEventListener("click", (ev) => {
    ev.preventDefault();
    const url = `${location.origin}${location.pathname}#p${p.seq}`;
    history.replaceState(null, "", `#p${p.seq}`);
    if (navigator.clipboard) {
      void navigator.clipboard.writeText(url);
    }
    seqLink.classList.add("copied");
    setTimeout(() => seqLink.classList.remove("copied"), 1200);
  });

  const created = new Date(p.created_at);
  const ts = el("time", { title: created.toISOString(), dateTime: p.created_at }, [
    `${humanAgo(created)} ago`,
  ]);

  const identity = p.pubkey
    ? p.signer_first_seq && p.signer_first_seq !== p.seq
      ? `same anon as #${p.signer_first_seq}`
      : "same anon (first signed post)"
    : "anonymous";

  const meta_ = el("div", { class: "meta" }, [seqLink, " · ", ts, " · ", identity]);
  const body = el("div", { class: "body" }, [p.body]);

  article.appendChild(meta_);
  article.appendChild(body);
  return article;
}

function humanAgo(then: Date): string {
  const seconds = Math.max(0, Math.round((Date.now() - then.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h`;
  const days = Math.round(hours / 24);
  return `${days}d`;
}

function scrollToHashTarget(): void {
  if (!location.hash) return;
  const target = document.querySelector(location.hash);
  if (target instanceof HTMLElement) {
    target.scrollIntoView({ behavior: "instant", block: "start" });
    target.classList.add("flash");
    setTimeout(() => target.classList.remove("flash"), 1500);
  }
}

function updateForgetVisibility(): void {
  forgetBtn.hidden = !tkey.hasKeypair(threadIdB64);
}

refresh();

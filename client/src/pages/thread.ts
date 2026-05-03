// Thread page: loads posts, renders them in a Reddit-style nested view
// (OP card on top, replies indented with alternating shading up to two
// levels deep), and lets the user reply with or without a thread-local
// Ed25519 identity.

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

const MAX_DEPTH = 2;

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
  const labels = assignLabels(posts);
  const childrenOf = buildTree(posts);

  // OP card (always at the top, regardless of children).
  const op = posts.find((p) => p.seq === 1);
  if (op) {
    postsEl.appendChild(renderPost(op, labels, 0, /* isOp */ true));
  }

  // Direct replies to OP first, then DFS down to MAX_DEPTH.
  const opChildren = childrenOf.get(1) ?? [];
  for (const seq of opChildren) {
    renderSubtree(posts, childrenOf, labels, seq, 0);
  }
  scrollToHashTarget();
}

function renderSubtree(
  posts: PostView[],
  childrenOf: Map<number, number[]>,
  labels: Map<number, string>,
  seq: number,
  depth: number,
): void {
  const post = posts.find((p) => p.seq === seq);
  if (!post) return;
  postsEl.appendChild(renderPost(post, labels, depth, /* isOp */ false));
  const cs = childrenOf.get(seq) ?? [];
  for (const child of cs) {
    renderSubtree(posts, childrenOf, labels, child, Math.min(depth + 1, MAX_DEPTH));
  }
}

/// Builds the parent → children map. A post's parent is the first
/// `>>N` in its body where N refers to an existing earlier post.
/// Posts with no usable >>N reference are children of OP (#1).
function buildTree(posts: PostView[]): Map<number, number[]> {
  const seqs = new Set(posts.map((p) => p.seq));
  const childrenOf = new Map<number, number[]>();
  for (const p of posts) {
    if (p.seq === 1) continue;
    const m = />>(\d+)/.exec(p.body);
    let parent = 1;
    if (m) {
      const n = parseInt(m[1], 10);
      if (n !== p.seq && n < p.seq && seqs.has(n)) parent = n;
    }
    const arr = childrenOf.get(parent) ?? [];
    arr.push(p.seq);
    childrenOf.set(parent, arr);
  }
  return childrenOf;
}

/// Assigns display names. OP (post #1) is "OP". Any subsequent post
/// signed with the same key as OP is also "OP". Other posts get
/// "Anon N" — same key gets the same label, unsigned posts each get a
/// fresh number (because we have no continuity for them).
function assignLabels(posts: PostView[]): Map<number, string> {
  const labels = new Map<number, string>();
  const op = posts.find((p) => p.seq === 1);
  const opPubkey = op?.pubkey ?? null;
  labels.set(1, "OP");
  let nextAnon = 1;
  const keyToLabel = new Map<string, string>();
  for (const p of posts) {
    if (p.seq === 1) continue;
    if (opPubkey && p.pubkey === opPubkey) {
      labels.set(p.seq, "OP");
      continue;
    }
    if (p.pubkey) {
      const existing = keyToLabel.get(p.pubkey);
      if (existing) {
        labels.set(p.seq, existing);
        continue;
      }
      const label = `Anon ${nextAnon++}`;
      keyToLabel.set(p.pubkey, label);
      labels.set(p.seq, label);
    } else {
      labels.set(p.seq, `Anon ${nextAnon++}`);
    }
  }
  return labels;
}

function renderPost(
  p: PostView,
  labels: Map<number, string>,
  depth: number,
  isOp: boolean,
): HTMLElement {
  const cls =
    (isOp ? "post op" : `post comment depth-${depth}`) +
    ` ${depth % 2 === 0 ? "shade-a" : "shade-b"}`;
  const article = el("article", { class: cls });
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

  const author = el("span", { class: "author" }, [labels.get(p.seq) ?? "?"]);

  const replyBtn = el("button", { type: "button", class: "reply-btn" }, ["Reply"]);
  replyBtn.addEventListener("click", () => {
    const ta = document.querySelector<HTMLTextAreaElement>("#reply-form textarea");
    if (!ta) return;
    const prefix = `>>${p.seq}\n`;
    ta.value = ta.value.length === 0 ? prefix : `${ta.value}\n${prefix}`;
    ta.focus();
    ta.scrollIntoView({ behavior: "smooth", block: "center" });
    ta.setSelectionRange(ta.value.length, ta.value.length);
  });

  const meta_ = el("div", { class: "meta" }, [
    author, " · ", seqLink, " · ", ts, " · ", replyBtn,
  ]);
  const body = el("div", { class: "body" }, renderBody(p.body));

  article.appendChild(meta_);
  article.appendChild(body);
  return article;
}

/// Splits a post body into text nodes and `>>N` link elements.
function renderBody(text: string): Array<Node | string> {
  const out: Array<Node | string> = [];
  const re = />>(\d+)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    if (match.index > lastIndex) {
      out.push(text.slice(lastIndex, match.index));
    }
    const seq = match[1];
    const link = document.createElement("a");
    link.href = `#p${seq}`;
    link.className = "quote";
    link.textContent = `>>${seq}`;
    out.push(link);
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < text.length) {
    out.push(text.slice(lastIndex));
  }
  return out;
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

window.addEventListener("hashchange", () => {
  const target = location.hash ? document.querySelector(location.hash) : null;
  if (target instanceof HTMLElement) {
    target.classList.add("flash");
    setTimeout(() => target.classList.remove("flash"), 1500);
  }
});

function updateForgetVisibility(): void {
  forgetBtn.hidden = !tkey.hasKeypair(threadIdB64);
}

refresh();

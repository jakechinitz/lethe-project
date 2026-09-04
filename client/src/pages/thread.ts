// Thread page: loads posts, renders them in a Reddit-style nested view
// (OP card on top, replies indented with alternating shading up to two
// levels deep), and lets the user reply with or without a thread-local
// Ed25519 identity.

import { api, PostView } from "../lib/api";
import { $, clear, el, formatPostTimestamp, meta, text } from "../lib/dom";
import { b64decode, b64encode } from "../lib/b64";
import { findNonce } from "../lib/pow";
import * as tkey from "../lib/threadkey";
import * as roomkey from "../lib/roomkey";
import * as vouch from "../lib/vouch";
import * as netview from "../lib/netview";
import { limitations } from "../lib/strings";

const threadIdB64 = meta("lethe-thread-id");
const threadIdBytes = b64decode(threadIdB64);
const powBits = parseInt(meta("lethe-pow-bits"), 10);

const postsEl = $<HTMLElement>("#posts");
const replyForm = $<HTMLFormElement>("#reply-form");
const replyStatus = $<HTMLParagraphElement>("#reply-status");
const claim = $<HTMLInputElement>("#claim-identity");
const forgetBtn = $<HTMLButtonElement>("#forget-identity");
const vouchSelect = $<HTMLSelectElement>("#vouch-room");
const vouchHint = $<HTMLParagraphElement>("#vouch-hint");
const vouchSummary = $<HTMLParagraphElement>("#vouch-summary");
const viewNote = $<HTMLParagraphElement>("#view-note");

const MAX_DEPTH = 2;

/// Verified vouch verdicts by post seq, filled asynchronously after
/// each render. Drives badges, the view filter, and the
/// distinct-voucher summary.
const verdicts = new Map<number, vouch.VouchVerdict>();
let currentPosts: PostView[] = [];

/// All / My network / Room X — computed on the device, remembered.
let view: netview.View = netview.mount($<HTMLElement>("#view-switch"), (v) => {
  view = v;
  applyVouchFilter();
  renderViewNote();
});
renderViewNote();

function renderViewNote(): void {
  switch (view.kind) {
    case "all":
      text(viewNote, "");
      break;
    case "network":
      text(viewNote, "Showing posts whose authors proved membership in a room you belong to or trust. Verified on this device.");
      break;
    case "room":
      text(viewNote, `Showing posts vouched by ${vouch.networkLabel(view.roomId) ?? "that room"}. Verified on this device.`);
      break;
  }
}

populateVouchSelect();
vouchSelect.addEventListener("change", updateVouchHint);
claim.addEventListener("change", updateVouchHint);

function populateVouchSelect(): void {
  let n = 0;
  for (const id of roomkey.listRoomIds()) {
    const keys = roomkey.read(id);
    if (!keys || keys.roomKeys.length === 0) continue; // pending join: not on roster yet
    const label = vouch.trustedLabel(id) ?? `Room ${id.slice(0, 8)}`;
    vouchSelect.appendChild(el("option", { value: id }, [label]));
    n++;
  }
  // Nothing to vouch as: don't show an empty control.
  const toggle = document.querySelector<HTMLElement>(".vouch-toggle");
  if (toggle && n === 0) toggle.hidden = true;
}

function updateVouchHint(): void {
  if (vouchSelect.value && claim.checked) {
    text(
      vouchHint,
      "Heads-up: vouching while claiming a thread identity tells readers that " +
        "this thread persona is a member of that room (still not which member). " +
        "Uncheck \"Claim thread-local identity\" to vouch anonymously.",
    );
  } else {
    text(
      vouchHint,
      "A vouch proves \"someone in that room wrote this\" without revealing who. " +
        "Vouching without a thread identity is the most private option.",
    );
  }
}

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

  let vouchPayload: vouch.VouchPayloadLike | undefined;
  if (vouchSelect.value) {
    const keys = roomkey.read(vouchSelect.value);
    if (!keys) {
      text(replyStatus, "No keys for the selected room on this device.");
      return;
    }
    text(replyStatus, "Building room vouch…");
    try {
      vouchPayload = await vouch.buildVouch(vouchSelect.value, threadIdBytes, body, keys);
    } catch (e) {
      text(replyStatus, `Vouch failed: ${(e as Error).message}`);
      return;
    }
  }

  text(replyStatus, "Submitting…");
  try {
    await api.createPost(threadIdB64, {
      body,
      pow_nonce: b64encode(nonce),
      pubkey,
      signature,
      vouch: vouchPayload,
    });
    replyForm.reset();
    text(replyStatus, "");
    await refresh();
    updateForgetVisibility();
  } catch (e) {
    text(replyStatus, `Error: ${(e as Error).message}`);
  }
});

/// b64 pubkey of this browser's thread identity, or null when no
/// identity is claimed. Loaded once per refresh so renderPost can put
/// a Delete button on the user's own signed posts.
let myPubkeyB64: string | null = null;

async function refresh(): Promise<void> {
  try {
    if (tkey.hasKeypair(threadIdB64)) {
      const kp = await tkey.getOrCreateKeypair(threadIdB64);
      myPubkeyB64 = b64encode(kp.publicKey);
    } else {
      myPubkeyB64 = null;
    }
    const { posts } = await api.listPosts(threadIdB64, 0);
    render(posts);
  } catch (e) {
    text(postsEl, `Error: ${(e as Error).message}`);
  }
}

function render(posts: PostView[]): void {
  clear(postsEl);
  postsEl.removeAttribute("aria-busy");
  currentPosts = posts;
  verdicts.clear();
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
  applyVouchFilter();
  void verifyAllVouches(posts);
}

/// Verifies every vouch locally (never trusting the server's word),
/// then updates badges, the filter, and the summary line.
async function verifyAllVouches(posts: PostView[]): Promise<void> {
  const withVouch = posts.filter((p) => p.vouch);
  await Promise.all(
    withVouch.map(async (p) => {
      const verdict = await vouch.verifyVouch(p.vouch!, threadIdBytes, p.body);
      if (currentPosts !== posts) return; // a newer render superseded us
      verdicts.set(p.seq, verdict);
      renderVouchBadge(p.seq, verdict);
    }),
  );
  if (currentPosts !== posts) return;
  renderSameVoucherMarks();
  applyVouchFilter();
  renderVouchSummary();
}

function renderVouchBadge(seq: number, verdict: vouch.VouchVerdict): void {
  const badge = document.querySelector<HTMLElement>(`#p${seq} .vouch-badge`);
  if (!badge) return;
  badge.classList.remove("pending", "trusted", "untrusted", "invalid");
  if (!verdict.ok) {
    badge.classList.add("invalid");
    badge.textContent = "Vouch failed verification";
    badge.title = verdict.reason;
  } else if (verdict.trustedLabel) {
    badge.classList.add("trusted");
    badge.textContent = `Vouched by ${verdict.trustedLabel}`;
    badge.title = `Room ${verdict.roomId}`;
  } else {
    badge.classList.add("untrusted");
    badge.textContent = `Vouched by room ${verdict.roomId.slice(0, 8)}… (not in your trusted list)`;
    badge.title = `Room ${verdict.roomId} — add it under My rooms to trust it`;
  }
}

/// Thread-scoped linkability: posts whose vouches share a key image
/// came from the same (still anonymous) member. Mark the later ones.
function renderSameVoucherMarks(): void {
  const firstSeqByImage = new Map<string, number>();
  const sorted = [...currentPosts].sort((a, b) => a.seq - b.seq);
  for (const p of sorted) {
    const v = verdicts.get(p.seq);
    if (!p.vouch || !v?.ok) continue;
    const key = `${v.roomId}:${p.vouch.key_image}`;
    const first = firstSeqByImage.get(key);
    const badge = document.querySelector<HTMLElement>(`#p${p.seq} .vouch-badge`);
    if (first === undefined) {
      firstSeqByImage.set(key, p.seq);
    } else if (badge && !badge.nextElementSibling?.classList.contains("vouch-same")) {
      badge.insertAdjacentElement(
        "afterend",
        el("span", { class: "vouch-same" }, [` · same voucher as #${first}`]),
      );
    }
  }
}

function applyVouchFilter(): void {
  for (const p of currentPosts) {
    const article = document.querySelector<HTMLElement>(`#p${p.seq}`);
    if (!article) continue;
    const v = verdicts.get(p.seq);
    // Only a *verified* vouch counts toward a view; a pending or
    // failed one is treated as unvouched.
    const vouchedRoom = v && v.ok ? v.roomId : null;
    const passes = netview.passes(view, vouchedRoom);
    article.classList.toggle("vouch-hidden", !passes && p.seq !== 1);
    article.classList.toggle("vouch-dim", !passes && p.seq === 1);
  }
}

/// "N distinct members of <room> vouched in this thread" — the one
/// place a count is safe to show, because the set behind it is a
/// curated room, not the open board.
function renderVouchSummary(): void {
  const perRoom = new Map<string, { label: string; images: Set<string> }>();
  for (const p of currentPosts) {
    const v = verdicts.get(p.seq);
    if (!p.vouch || !v?.ok || !v.trustedLabel) continue;
    const entry = perRoom.get(v.roomId) ?? { label: v.trustedLabel, images: new Set<string>() };
    entry.images.add(p.vouch.key_image);
    perRoom.set(v.roomId, entry);
  }
  if (perRoom.size === 0) {
    text(vouchSummary, "");
    return;
  }
  const parts: string[] = [];
  for (const { label, images } of perRoom.values()) {
    const n = images.size;
    parts.push(`${n} distinct member${n === 1 ? "" : "s"} of ${label} vouched in this thread`);
  }
  text(vouchSummary, parts.join(" · "));
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

  const ts = el("time", { dateTime: p.created_at, title: p.created_at }, [
    formatPostTimestamp(p.created_at),
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

  const reportBtn = el("button", { type: "button", class: "report-btn" }, ["Report"]);
  reportBtn.addEventListener("click", () => openReportDialog(article, p.post_id));

  // If the post originated on a peer, surface a small badge so the
  // reader can attribute the content. Locally-authored posts have
  // `origin_server_id` omitted by the server.
  const metaChildren: Array<Node | string> = [
    author, " · ", seqLink, " · ", ts, " · ", replyBtn, " · ", reportBtn,
  ];

  // Delete button: only on posts signed by this browser's thread key.
  // Anonymous posts can't be deleted by anyone — there's no key that
  // can prove authorship.
  if (myPubkeyB64 && p.pubkey === myPubkeyB64) {
    const deleteBtn = el("button", { type: "button", class: "delete-btn" }, ["Delete"]);
    deleteBtn.addEventListener("click", () => void onDeletePost(p));
    metaChildren.push(" · ", deleteBtn);
  }
  if (p.origin_server_id) {
    const labelText =
      p.origin_server_label ?? `${p.origin_server_id.slice(0, 8)}…`;
    const fromBadge = el("span", { class: "origin-badge" }, [
      "from ", el("strong", {}, [labelText]),
    ]);
    fromBadge.title = `Origin server: ${p.origin_server_id}`;
    metaChildren.push(" · ", fromBadge);
  }
  if (p.vouch) {
    // Placeholder until local verification finishes; never shows
    // "verified" on the server's say-so.
    const badge = el("span", { class: "vouch-badge pending" }, ["Verifying vouch…"]);
    metaChildren.push(" · ", badge);
  }
  const meta_ = el("div", { class: "meta" }, metaChildren);
  const body = el("div", { class: "body" }, renderBody(p.body));

  article.appendChild(meta_);
  article.appendChild(body);
  return article;
}

/// Author self-delete: signs `lethe-delete-v1 || post_id || ts` with
/// the thread key and POSTs it. The server scrubs the body, signature,
/// and pubkey from the row and leaves a "[removed: deleted by author]"
/// tombstone; on a federated network the takedown propagates to peers.
async function onDeletePost(p: PostView): Promise<void> {
  if (!confirm(
      "Delete this post? The text is permanently removed from the server " +
        "and a “[removed: deleted by author]” placeholder is left in its " +
        "place. Copies that other people or other servers already made " +
        "cannot be recalled. There is no undo.",
    )) {
    return;
  }
  try {
    const kp = await tkey.getOrCreateKeypair(threadIdB64);
    const ts = Math.floor(Date.now() / 1000);
    const sig = await tkey.signPostDelete(b64decode(p.post_id), ts, kp.privateKey);
    await api.deletePost(p.post_id, {
      pubkey: b64encode(kp.publicKey),
      ts,
      sig: b64encode(sig),
    });
    await refresh();
  } catch (e) {
    alert(`Delete failed: ${(e as Error).message}`);
  }
}

/// Inline report form. Opens beneath the post, asks for an optional
/// reason, runs PoW bound to the post id, and submits. No login: a
/// successful submit is logged anonymously server-side and triaged by
/// operators directly.
function openReportDialog(article: HTMLElement, postIdB64: string): void {
  if (article.querySelector(".report-dialog")) return;
  const status = el("p", { class: "report-status muted" });
  const textarea = el("textarea", {
    name: "reason",
    rows: 2,
    placeholder: "Optional: why are you reporting this? (max 500 chars)",
    maxLength: 500,
  }) as HTMLTextAreaElement;
  const submit = el("button", { type: "submit", class: "report-submit" }, ["Submit report"]);
  const cancel = el("button", { type: "button", class: "report-cancel" }, ["Cancel"]);
  const dialog = el("form", { class: "report-dialog" }, [
    textarea,
    el("div", { class: "report-actions" }, [submit, " ", cancel, " ", status]),
  ]) as HTMLFormElement;
  cancel.addEventListener("click", () => dialog.remove());
  dialog.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    submit.disabled = true;
    const reason = textarea.value.trim();
    text(status, "Computing proof-of-work…");
    try {
      const postIdBytes = b64decode(postIdB64);
      const nonce = await findNonce(postIdBytes, reason, powBits);
      text(status, "Submitting…");
      await api.reportPost(postIdB64, {
        reason: reason ? reason : undefined,
        pow_nonce: b64encode(nonce),
      });
      text(status, "Report submitted. Thank you.");
      submit.disabled = true;
      cancel.textContent = "Close";
    } catch (e) {
      text(status, `Error: ${(e as Error).message}`);
      submit.disabled = false;
    }
  });
  article.appendChild(dialog);
  textarea.focus();
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

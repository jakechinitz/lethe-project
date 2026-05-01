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
    const meta_ = el("div", { class: "meta" }, [
      `#${p.seq}`,
      ...(p.pubkey
        ? [
            ` · `,
            p.signer_first_seq && p.signer_first_seq !== p.seq
              ? `same anon as #${p.signer_first_seq}`
              : `same anon (this is the first signed post)`,
          ]
        : [` · anonymous`]),
    ]);
    const body = el("div", { class: "body" }, [p.body]);
    postsEl.appendChild(el("article", { class: "post" }, [meta_, body]));
  }
}

function updateForgetVisibility(): void {
  forgetBtn.hidden = !tkey.hasKeypair(threadIdB64);
}

refresh();

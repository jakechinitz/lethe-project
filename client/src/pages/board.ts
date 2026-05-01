// Board page: posts a new thread (anonymous) using PoW over the board id.

import { api } from "../lib/api";
import { $, meta, text } from "../lib/dom";
import { b64encode, utf8 } from "../lib/b64";
import { findNonce } from "../lib/pow";

const boardId = meta("lethe-board-id");
const powBits = parseInt(meta("lethe-pow-bits"), 10);

const form = $<HTMLFormElement>("#new-thread-form");
const status = $<HTMLParagraphElement>("#new-thread-status");

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const data = new FormData(form);
  const title = String(data.get("title") ?? "").trim();
  const body = String(data.get("body") ?? "");
  if (!title || !body) return;

  text(status, "Computing proof-of-work…");
  const nonce = await findNonce(utf8(boardId), body, powBits);
  text(status, "Submitting…");
  try {
    const resp = await api.createThread({
      board_id: boardId,
      title,
      body,
      pow_nonce: b64encode(nonce),
    });
    location.href = `/b/${boardId}/t/${resp.thread_id}`;
  } catch (e) {
    text(status, `Error: ${(e as Error).message}`);
  }
});

// Main-thread API for proof-of-work. Spawns the worker, returns the
// winning nonce as raw bytes.

import { utf8 } from "./b64";

export function findNonce(
  threadIdBytes: Uint8Array,
  body: string,
  bits: number,
): Promise<Uint8Array> {
  const worker = new Worker("/static/js/pow.worker.js", { type: "module" });
  const bodyBytes = utf8(body);
  return new Promise((resolve, reject) => {
    worker.addEventListener(
      "message",
      (ev: MessageEvent<{ type: "found"; nonce: Uint8Array }>) => {
        worker.terminate();
        resolve(ev.data.nonce);
      },
      { once: true },
    );
    worker.addEventListener("error", (e) => {
      worker.terminate();
      reject(e);
    });
    worker.postMessage({ type: "start", threadIdBytes, bodyBytes, bits });
  });
}

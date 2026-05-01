// Off-main-thread proof-of-work search. Hashes
//   thread_id || body || nonce_u64_LE
// with SHA-256 until the digest has `bits` leading zero bits, then posts
// the winning nonce back to the page.

interface StartMsg {
  type: "start";
  threadIdBytes: Uint8Array;
  bodyBytes: Uint8Array;
  bits: number;
}

self.addEventListener("message", async (ev: MessageEvent<StartMsg>) => {
  const { threadIdBytes, bodyBytes, bits } = ev.data;
  const buf = new Uint8Array(threadIdBytes.length + bodyBytes.length + 8);
  buf.set(threadIdBytes, 0);
  buf.set(bodyBytes, threadIdBytes.length);
  const nonceOffset = threadIdBytes.length + bodyBytes.length;

  let nonce = 0n;
  while (true) {
    writeU64LE(buf, nonceOffset, nonce);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
    if (leadingZeroBits(digest) >= bits) {
      const out = new Uint8Array(8);
      writeU64LE(out, 0, nonce);
      (self as unknown as Worker).postMessage({ type: "found", nonce: out });
      return;
    }
    nonce++;
  }
});

function writeU64LE(buf: Uint8Array, off: number, value: bigint): void {
  for (let i = 0; i < 8; i++) {
    buf[off + i] = Number((value >> BigInt(i * 8)) & 0xffn);
  }
}

function leadingZeroBits(digest: Uint8Array): number {
  let n = 0;
  for (let i = 0; i < digest.length; i++) {
    const byte = digest[i];
    if (byte === 0) {
      n += 8;
      continue;
    }
    n += Math.clz32(byte) - 24;
    return n;
  }
  return n;
}

// urlsafe-base64 (no padding) encode/decode. Mirrors the server's
// `crates/lethe-server/src/ids.rs` exactly.

const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64encode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    out += ALPHABET[a >> 2];
    out += ALPHABET[((a & 3) << 4) | (b >> 4)];
    out += ALPHABET[((b & 15) << 2) | (c >> 6)];
    out += ALPHABET[c & 63];
  }
  if (i < bytes.length) {
    const a = bytes[i];
    out += ALPHABET[a >> 2];
    if (i + 1 < bytes.length) {
      const b = bytes[i + 1];
      out += ALPHABET[((a & 3) << 4) | (b >> 4)];
      out += ALPHABET[(b & 15) << 2];
    } else {
      out += ALPHABET[(a & 3) << 4];
    }
  }
  return out;
}

export function b64decode(s: string): Uint8Array {
  const lookup = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) lookup[ALPHABET.charCodeAt(i)] = i;
  const len = s.length;
  const padded = (len % 4 === 0 ? len : len + (4 - (len % 4)));
  const bytes = new Uint8Array(((padded * 3) >> 2) - (padded - len));
  let bi = 0;
  for (let i = 0; i < len; i += 4) {
    const a = lookup[s.charCodeAt(i)] ?? -1;
    const b = lookup[s.charCodeAt(i + 1)] ?? -1;
    if (a < 0 || b < 0) throw new Error("invalid base64");
    bytes[bi++] = (a << 2) | (b >> 4);
    if (i + 2 < len) {
      const c = lookup[s.charCodeAt(i + 2)] ?? -1;
      if (c < 0) throw new Error("invalid base64");
      bytes[bi++] = ((b & 15) << 4) | (c >> 2);
      if (i + 3 < len) {
        const d = lookup[s.charCodeAt(i + 3)] ?? -1;
        if (d < 0) throw new Error("invalid base64");
        bytes[bi++] = ((c & 3) << 6) | d;
      }
    }
  }
  return bytes;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

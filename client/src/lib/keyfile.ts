// Identity-key export/import.
//
// Saves every lethe.* localStorage entry into a single passphrase-encrypted
// file the user can keep on disk (USB, password manager, etc.) and restore
// later — useful when Tor Browser's "New Identity" or the Safer security
// level wipes site storage.
//
// File layout (all big-endian network order is irrelevant; everything is
// fixed-size or length-prefixed by libsodium):
//
//   bytes 0..8   magic "LETHEv1\x00"
//   bytes 8..24  Argon2id salt (16 bytes)
//   bytes 24..48 XChaCha20-Poly1305 nonce (24 bytes)
//   bytes 48..   ciphertext (libsodium AEAD output)
//
// The plaintext under encryption is a UTF-8 JSON object:
//   { "v": 1, "entries": { "<localStorage-key>": "<stringified-value>", ... } }
//
// Passphrase KDF: crypto_pwhash with INTERACTIVE limits — strong enough for
// offline brute-force resistance, fast enough to run on a phone.

import { sodium } from "./sodium";

const MAGIC = new Uint8Array([0x4c, 0x45, 0x54, 0x48, 0x45, 0x76, 0x31, 0x00]); // "LETHEv1\0"
const SALT_LEN = 16;
const NONCE_LEN = 24;
const KEY_LEN = 32;

interface KeyfilePlaintext {
  v: 1;
  entries: Record<string, string>;
}

/// Returns the keys this device knows about, ready to be encrypted. Only
/// pulls localStorage entries with the `lethe.` prefix so the file never
/// inadvertently snapshots unrelated site data.
export function snapshotEntries(): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (k && k.startsWith("lethe.")) {
      const v = localStorage.getItem(k);
      if (v !== null) out[k] = v;
    }
  }
  return out;
}

export async function encryptKeyfile(
  passphrase: string,
  entries: Record<string, string>,
): Promise<Uint8Array> {
  if (passphrase.length < 8) {
    throw new Error("passphrase must be at least 8 characters");
  }
  const s = await sodium();
  const salt = s.randombytes_buf(SALT_LEN);
  const key = s.crypto_pwhash(
    KEY_LEN,
    passphrase,
    salt,
    s.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    s.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  const nonce = s.randombytes_buf(NONCE_LEN);
  const plaintext: KeyfilePlaintext = { v: 1, entries };
  const ptBytes = new TextEncoder().encode(JSON.stringify(plaintext));
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ptBytes,
    MAGIC,
    null,
    nonce,
    key,
  );
  const out = new Uint8Array(MAGIC.length + salt.length + nonce.length + ciphertext.length);
  out.set(MAGIC, 0);
  out.set(salt, MAGIC.length);
  out.set(nonce, MAGIC.length + salt.length);
  out.set(ciphertext, MAGIC.length + salt.length + nonce.length);
  return out;
}

export async function decryptKeyfile(
  passphrase: string,
  file: Uint8Array,
): Promise<Record<string, string>> {
  if (file.length < MAGIC.length + SALT_LEN + NONCE_LEN + 16) {
    throw new Error("file is too short to be a Lethe keyfile");
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (file[i] !== MAGIC[i]) {
      throw new Error("not a Lethe keyfile (magic mismatch)");
    }
  }
  const s = await sodium();
  const salt = file.subarray(MAGIC.length, MAGIC.length + SALT_LEN);
  const nonce = file.subarray(MAGIC.length + SALT_LEN, MAGIC.length + SALT_LEN + NONCE_LEN);
  const ciphertext = file.subarray(MAGIC.length + SALT_LEN + NONCE_LEN);
  const key = s.crypto_pwhash(
    KEY_LEN,
    passphrase,
    salt,
    s.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    s.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
  let pt: Uint8Array;
  try {
    pt = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      MAGIC,
      nonce,
      key,
    );
  } catch {
    throw new Error("wrong passphrase or corrupted file");
  }
  const parsed = JSON.parse(new TextDecoder().decode(pt)) as KeyfilePlaintext;
  if (parsed.v !== 1 || typeof parsed.entries !== "object") {
    throw new Error("unsupported keyfile version");
  }
  return parsed.entries;
}

/// Writes every entry from a decrypted keyfile back into localStorage,
/// preserving any existing entries unless they collide. Returns counts
/// so the UI can report what happened.
export function applyEntries(
  entries: Record<string, string>,
  options: { overwrite: boolean },
): { added: number; overwrote: number; skipped: number } {
  let added = 0;
  let overwrote = 0;
  let skipped = 0;
  for (const [k, v] of Object.entries(entries)) {
    if (!k.startsWith("lethe.")) continue; // be conservative
    const existing = localStorage.getItem(k);
    if (existing === null) {
      localStorage.setItem(k, v);
      added += 1;
    } else if (existing === v) {
      skipped += 1;
    } else if (options.overwrite) {
      localStorage.setItem(k, v);
      overwrote += 1;
    } else {
      skipped += 1;
    }
  }
  return { added, overwrote, skipped };
}

export function downloadBytes(bytes: Uint8Array, filename: string): void {
  // Copy into a fresh ArrayBuffer so the Blob constructor accepts it.
  // (Recent TS lib defs allow ArrayBuffer but not the generic
  // ArrayBufferLike that Uint8Array.buffer can be typed as.)
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  const blob = new Blob([buf], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function readFileAsBytes(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

export function suggestedFilename(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `lethe-keys-${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}.lethe`;
}

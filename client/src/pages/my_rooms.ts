// "My rooms": pure-client page that lists every room this browser has
// keys for. Reads localStorage, fetches a small server snapshot per
// room (current epoch + active member count) so the list reflects
// reality, and links back into each room. Also hosts the keyfile
// export/import UI for backing up identities against Tor Browser
// session resets.

import { $, clear, durationSince, el, text } from "../lib/dom";
import * as keyfile from "../lib/keyfile";

interface StoredRoomV2 {
  v: 2;
  roomKeys: string[];
  lastEpoch: number;
}

interface Snapshot {
  current_epoch: number;
  active_members: number;
  unlocked: boolean;
}

const root = $<HTMLElement>("#my-rooms-list");
const exportBtn = $<HTMLButtonElement>("#export-btn");
const importInput = $<HTMLInputElement>("#import-input");
const keyfileStatus = $<HTMLParagraphElement>("#keyfile-status");

exportBtn.addEventListener("click", onExport);
importInput.addEventListener("change", onImport);

main();

async function main(): Promise<void> {
  const ids = roomIdsFromStorage();
  if (ids.length === 0) {
    clear(root);
    root.removeAttribute("aria-busy");
    root.appendChild(
      el("p", { class: "muted" }, [
        "No rooms on this device. Create one from a thread or open an invite link.",
      ]),
    );
    return;
  }
  const rows = await Promise.all(ids.map(async (id) => ({ id, snap: await snapshot(id) })));
  clear(root);
  root.removeAttribute("aria-busy");
  for (const row of rows) {
    root.appendChild(renderRow(row.id, row.snap));
  }
}

function roomIdsFromStorage(): string[] {
  const out: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key || !key.startsWith("lethe.room.")) continue;
    out.push(key.slice("lethe.room.".length));
  }
  return out;
}

async function snapshot(roomId: string): Promise<Snapshot | null> {
  try {
    const resp = await fetch(`/api/rooms/${roomId}/members`);
    if (!resp.ok) return null;
    const body: { current_epoch: number; members: Array<{ removed_at?: string | null }> } =
      await resp.json();
    const active = body.members.filter((m) => !m.removed_at).length;
    const stored = JSON.parse(
      localStorage.getItem(`lethe.room.${roomId}`) ?? "null",
    ) as StoredRoomV2 | null;
    const unlocked = !!stored && stored.roomKeys.length > 0;
    return { current_epoch: body.current_epoch, active_members: active, unlocked };
  } catch {
    return null;
  }
}

function renderRow(roomId: string, snap: Snapshot | null): HTMLElement {
  const card = el("article", { class: "room-row" });
  const link = el("a", {}, [`Room ${roomId.slice(0, 8)}`]) as HTMLAnchorElement;
  link.href = `/r/${roomId}`;
  link.className = "room-row-title";
  card.appendChild(link);

  let metaText: string;
  if (!snap) {
    metaText = "could not reach server";
  } else if (!snap.unlocked) {
    metaText = `awaiting key · ${snap.active_members} active member${snap.active_members === 1 ? "" : "s"}`;
  } else {
    metaText =
      `${snap.active_members} active member${snap.active_members === 1 ? "" : "s"}` +
      ` · ${snap.current_epoch === 0 ? "original key" : `key rotated ${snap.current_epoch} time${snap.current_epoch === 1 ? "" : "s"}`}`;
  }
  card.appendChild(el("div", { class: "room-row-meta muted" }, [metaText]));

  const forget = el("button", { type: "button", class: "remove-btn" }, ["Forget on this device"]);
  forget.addEventListener("click", () => {
    if (!confirm("This wipes the keys for this room from this browser. There is no recovery.")) return;
    localStorage.removeItem(`lethe.room.${roomId}`);
    card.remove();
  });
  card.appendChild(forget);

  return card;
}

// Touch the import so the unused-imports rule stays happy if the helper
// gets removed in a refactor; durationSince is intentionally available
// here for future "last visited" labels.
void durationSince;

async function onExport(): Promise<void> {
  const entries = keyfile.snapshotEntries();
  const count = Object.keys(entries).length;
  if (count === 0) {
    text(keyfileStatus, "No keys to export. Post once or join a room first.");
    return;
  }
  const passphrase = prompt(
    `You're about to export ${count} key entr${count === 1 ? "y" : "ies"} to an encrypted file.\n` +
      "Pick a passphrase (at least 8 characters). There is no recovery if you forget it.",
  );
  if (!passphrase) return;
  if (passphrase.length < 8) {
    text(keyfileStatus, "Passphrase must be at least 8 characters.");
    return;
  }
  const confirm_ = prompt("Confirm passphrase:");
  if (confirm_ !== passphrase) {
    text(keyfileStatus, "Passphrases didn't match. Nothing exported.");
    return;
  }
  text(keyfileStatus, "Encrypting…");
  try {
    const bytes = await keyfile.encryptKeyfile(passphrase, entries);
    keyfile.downloadBytes(bytes, keyfile.suggestedFilename());
    text(keyfileStatus, `Exported ${count} entr${count === 1 ? "y" : "ies"}.`);
  } catch (e) {
    text(keyfileStatus, `Export failed: ${(e as Error).message}`);
  }
}

async function onImport(ev: Event): Promise<void> {
  const input = ev.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = ""; // allow re-selecting the same file later
  if (!file) return;
  const passphrase = prompt("Enter the passphrase for this keyfile:");
  if (!passphrase) return;
  text(keyfileStatus, "Decrypting…");
  try {
    const bytes = await keyfile.readFileAsBytes(file);
    const entries = await keyfile.decryptKeyfile(passphrase, bytes);
    const overwrite = confirm(
      "If this keyfile contains entries that already exist locally, overwrite them?\n" +
        "OK = overwrite (use the imported version)\n" +
        "Cancel = keep local versions",
    );
    const result = keyfile.applyEntries(entries, { overwrite });
    text(
      keyfileStatus,
      `Imported. Added ${result.added}, overwrote ${result.overwrote}, skipped ${result.skipped}.`,
    );
    // Refresh the room list so the imported rooms show up immediately.
    await main();
  } catch (e) {
    text(keyfileStatus, `Import failed: ${(e as Error).message}`);
  }
}

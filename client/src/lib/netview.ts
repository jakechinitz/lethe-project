// The three ways to look at the public forum:
//
//   All        — everything, the anonymous public commons.
//   My network — posts whose authors chose to prove membership in a
//                room you belong to or trust.
//   Room X     — posts vouched by that one room.
//
// Everything here is computed on the device. The server never receives
// "show me rooms A, D, F" — it serves the same public posts and public
// proofs to everyone, and each browser decides which proofs it cares
// about. Two people can look at the same forum and see different
// versions of it, and the forum can't tell why.
//
// Once you have any network rooms, "My network" becomes your remembered
// default; "All" is always one tap away and is never removed.

import { el } from "./dom";
import * as vouch from "./vouch";

export type View = { kind: "all" } | { kind: "network" } | { kind: "room"; roomId: string };

const PREF = "lethe.pref.view";

export function getView(): View {
  let raw: string | null = null;
  try { raw = localStorage.getItem(PREF); } catch { /* storage unavailable */ }
  const rooms = vouch.networkRooms();
  if (raw === "all") return { kind: "all" };
  if (raw === "network") return rooms.length > 0 ? { kind: "network" } : { kind: "all" };
  if (raw && raw.startsWith("room:")) {
    const roomId = raw.slice(5);
    if (rooms.some((r) => r.roomId === roomId)) return { kind: "room", roomId };
  }
  // No stored choice: default to the network once the user has one.
  return rooms.length > 0 ? { kind: "network" } : { kind: "all" };
}

export function setView(v: View): void {
  const raw = v.kind === "room" ? `room:${v.roomId}` : v.kind;
  try { localStorage.setItem(PREF, raw); } catch { /* ignore */ }
}

export function sameView(a: View, b: View): boolean {
  if (a.kind !== b.kind) return false;
  return a.kind === "room" && b.kind === "room" ? a.roomId === b.roomId : true;
}

/// Does a post vouched by `roomId` (or unvouched, `null`) belong in `view`?
export function passes(view: View, vouchedRoomId: string | null): boolean {
  switch (view.kind) {
    case "all":
      return true;
    case "network":
      return vouchedRoomId !== null && vouch.networkLabel(vouchedRoomId) !== null;
    case "room":
      return vouchedRoomId === view.roomId;
  }
}

/// Renders the segmented control into `container` and calls `onChange`
/// whenever the user picks a view. Returns the initial view.
export function mount(container: HTMLElement, onChange: (v: View) => void): View {
  let current = getView();
  const rooms = vouch.networkRooms();

  const render = (): void => {
    while (container.firstChild) container.removeChild(container.firstChild);
    const add = (label: string, v: View, count?: number): void => {
      const btn = el("button", { type: "button", class: sameView(v, current) ? "active" : "" }, [label]);
      if (count !== undefined) btn.appendChild(el("span", { class: "count" }, [String(count)]));
      btn.addEventListener("click", () => {
        current = v;
        setView(v);
        render();
        onChange(v);
      });
      container.appendChild(btn);
    };
    add("All", { kind: "all" });
    if (rooms.length > 0) {
      add("My network", { kind: "network" }, rooms.length);
      for (const r of rooms) add(r.label, { kind: "room", roomId: r.roomId });
    }
  };
  render();
  return current;
}

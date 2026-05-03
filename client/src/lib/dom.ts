// Tiny DOM helpers used by page entries. No framework, no virtual DOM.

export function $<T extends HTMLElement = HTMLElement>(sel: string): T {
  const el = document.querySelector(sel);
  if (!el) throw new Error(`missing element: ${sel}`);
  return el as T;
}

export function meta(name: string): string {
  const el = document.querySelector(`meta[name="${name}"]`);
  if (!el) throw new Error(`missing meta: ${name}`);
  return el.getAttribute("content") ?? "";
}

export function text(el: HTMLElement, s: string): void {
  el.textContent = s;
}

export function clear(el: HTMLElement): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  children: Array<Node | string> = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.class) {
    node.className = props.class;
    delete props.class;
  }
  Object.assign(node, props);
  for (const c of children) {
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

export function durationSince(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const seconds = Math.max(0, Math.round((now - then) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h`;
  const days = Math.round(hours / 24);
  return `${days}d`;
}

/// Renders an ISO timestamp as a date+time the user can read at a glance:
///   - within today       → "2:23 PM"
///   - within this year   → "Aug 15, 2:23 PM"
///   - older              → "Aug 15, 2024, 2:23 PM"
/// Always uses the visitor's local timezone.
export function formatPostTimestamp(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  if (sameDay) {
    return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  }
  const sameYear = d.getFullYear() === now.getFullYear();
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
    hour: "numeric",
    minute: "2-digit",
  });
}

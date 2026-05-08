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

/// Renders an ISO-8601 date ("YYYY-MM-DD") at day granularity:
///   - today                → "Today"
///   - yesterday            → "Yesterday"
///   - earlier this year    → "Aug 15"
///   - older                → "Aug 15, 2024"
/// Always rendered in the visitor's local locale, no timezone conversion
/// (the input is a calendar date, not an instant).
export function formatPostTimestamp(date_iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(date_iso);
  if (!m) return date_iso;
  const year = parseInt(m[1], 10);
  const month = parseInt(m[2], 10);
  const day = parseInt(m[3], 10);
  const d = new Date(year, month - 1, day);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const diffDays = Math.round((today.getTime() - d.getTime()) / 86_400_000);
  if (diffDays === 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  const sameYear = year === now.getFullYear();
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

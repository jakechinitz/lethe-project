// /federation page — fetches /api/federation/info and
// /api/federation/peers/public, renders them as plain prose. Strict
// CSP forbids inline JS, so the page template just provides the
// scaffold and this module fills in the rest.

import { $, clear, el } from "../lib/dom";

interface InfoResp {
  server_pubkey: string;
  protocol_version: string;
  constitution_version: string;
  constitution_hash: string;
  code_version: string;
  code_commit: string;
  local_moderation_summary: string;
  operator_label?: string;
  release_manifest_sha256?: string;
}

interface PeerView {
  server_pubkey: string;
  endpoint: string;
  label?: string;
  enabled: boolean;
}

interface PeersList {
  peers: PeerView[];
}

async function loadInfo(): Promise<void> {
  const section = $<HTMLElement>("#info");
  try {
    const r = await fetch("/api/federation/info");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const info = (await r.json()) as InfoResp;
    clear(section);
    section.appendChild(el("h2", {}, ["This server"]));
    const dl = el("dl", { class: "kv" });
    appendRow(dl, "Operator", info.operator_label ?? "(none)");
    appendRow(dl, "Server pubkey", info.server_pubkey);
    appendRow(dl, "Protocol", info.protocol_version);
    appendRow(
      dl,
      "Constitution",
      `${info.constitution_version} (sha256 ${info.constitution_hash.slice(0, 12)}…)`,
    );
    appendRow(
      dl,
      "Code",
      `${info.code_version} (${info.code_commit.slice(0, 8)})`,
    );
    appendRow(
      dl,
      "Release manifest",
      info.release_manifest_sha256
        ? `sha256 ${info.release_manifest_sha256.slice(0, 12)}…`
        : "(none — running unattested build)",
    );
    appendRow(dl, "Local moderation", info.local_moderation_summary);
    section.appendChild(dl);
  } catch (e) {
    clear(section);
    section.appendChild(el("h2", {}, ["This server"]));
    section.appendChild(el("p", { class: "muted" }, [`Failed to load: ${e}`]));
  }
}

async function loadPeers(): Promise<void> {
  const section = $<HTMLElement>("#peers");
  try {
    const r = await fetch("/api/federation/peers/public");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const list = (await r.json()) as PeersList;
    clear(section);
    section.appendChild(el("h2", {}, ["Peered servers"]));
    if (list.peers.length === 0) {
      section.appendChild(
        el("p", { class: "muted" }, [
          "No peers configured. This instance is not federating with " +
            "any other Lethe server right now.",
        ]),
      );
      return;
    }
    section.appendChild(
      el("p", { class: "muted" }, [
        "Public posts authored on these servers may appear in this " +
          "instance's threads. Each post carries the originating " +
          "server's pubkey for attribution.",
      ]),
    );
    const ul = el("ul", { class: "peer-list" });
    for (const p of list.peers) {
      const a = el("a", {}, [p.endpoint]);
      a.setAttribute("href", p.endpoint);
      a.setAttribute("rel", "noopener");
      const li = el("li", {}, [
        el("strong", {}, [p.label ?? "(unlabelled)"]),
        " — ",
        a,
        el("code", {}, [` ${p.server_pubkey.slice(0, 12)}…`]),
      ]);
      ul.appendChild(li);
    }
    section.appendChild(ul);
  } catch (e) {
    clear(section);
    section.appendChild(el("h2", {}, ["Peered servers"]));
    section.appendChild(el("p", { class: "muted" }, [`Failed to load: ${e}`]));
  }
}

function appendRow(dl: HTMLElement, k: string, v: string): void {
  dl.appendChild(el("dt", {}, [k]));
  dl.appendChild(el("dd", {}, [v]));
}

void loadInfo();
void loadPeers();

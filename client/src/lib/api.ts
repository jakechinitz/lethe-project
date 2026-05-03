// Single source of truth for fetch URLs and request shapes. Pages import
// only named functions from here — no string URLs anywhere else.

interface JsonInit {
  method: "GET" | "POST";
  body?: unknown;
}

async function call<T>(path: string, init: JsonInit): Promise<T> {
  const res = await fetch(path, {
    method: init.method,
    headers: init.body ? { "content-type": "application/json" } : {},
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${path} ${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  createThread: (body: unknown) =>
    call<{ thread_id: string; seq: number }>("/api/threads", { method: "POST", body }),
  createPost: (threadId: string, body: unknown) =>
    call<{ post_id: string; seq: number; signer_first_seq?: number }>(
      `/api/threads/${threadId}/posts`,
      { method: "POST", body },
    ),
  listPosts: (threadId: string, sinceSeq: number) =>
    call<{ posts: Array<PostView> }>(
      `/api/threads/${threadId}/posts?since_seq=${sinceSeq}`,
      { method: "GET" },
    ),
  createRoom: (body: unknown) =>
    call<{ room_id: string; invite_code: string }>("/api/rooms", { method: "POST", body }),
  joinRoom: (inviteCode: string, body: unknown) =>
    call<{ room_id: string; members: Array<MemberView> }>(
      `/api/rooms/by-invite/${inviteCode}/join`,
      { method: "POST", body },
    ),
  wrap: (roomId: string, body: unknown) =>
    call<void>(`/api/rooms/${roomId}/wrap`, { method: "POST", body }),
  members: (roomId: string) =>
    call<MembersResp>(`/api/rooms/${roomId}/members`, { method: "GET" }),
  provenance: (roomId: string) =>
    call<ProvenanceView>(`/api/rooms/${roomId}/provenance`, { method: "GET" }),
  sendMessage: (roomId: string, body: unknown) =>
    call<{ message_id: string; created_at: string }>(
      `/api/rooms/${roomId}/messages`,
      { method: "POST", body },
    ),
  listMessages: (roomId: string, body: unknown) =>
    call<{ messages: Array<MessageView> }>(
      `/api/rooms/${roomId}/messages/list`,
      { method: "POST", body },
    ),
  removeMember: (roomId: string, body: unknown) =>
    call<{ current_epoch: number }>(
      `/api/rooms/${roomId}/remove`,
      { method: "POST", body },
    ),
};

export interface PostView {
  post_id: string;
  seq: number;
  body: string;
  created_at: string;
  pubkey?: string;
  signer_first_seq?: number;
}

export interface MemberView {
  box_pubkey: string;
  sig_pubkey: string;
  wrapped_key?: string | null;
  joined_at: string;
  invited_by_box_pubkey?: string | null;
  removed_at?: string | null;
}

export interface MembersResp {
  members: MemberView[];
  current_epoch: number;
}

export interface ProvenanceView {
  origin_thread?: string | null;
  creator_thread_pubkey?: string | null;
  provenance_sig?: string | null;
  created_at: string;
}

export interface MessageView {
  message_id: string;
  sender_sig_pubkey: string;
  nonce: string;
  ciphertext: string;
  sender_sig: string;
  created_at: string;
}

// The only labels the trust UI may use. See plan §"User-facing Limitations".
//
// This file is intentionally tiny. All trust-card text comes from here so a
// reviewer can read one file to audit the entire vocabulary surface.

export const trust = {
  continuityVerified: "Continuity verified",
  provenanceVerified: "Provenance verified",
  noProvenance: "No thread provenance",
  invitedBy: (name: string) => `Invited by ${name}`,
  joinedAgo: (duration: string) => `Joined ${duration} ago`,
  unverified: "Unverified",
  newMember: "New member",
  newInviter: "New inviter",
  removed: "Removed",
  creator: "Creator",
  keyEpoch: (n: number) =>
    n === 0 ? "Original key" : `Key rotated ${n} time${n === 1 ? "" : "s"}`,
} as const;

export const limitations = {
  roomBanner:
    "Messages are encrypted on your device. Anyone you let into this room can copy or leak messages. " +
    "This room has no forward secrecy: any compromised member's device exposes all past and future messages here. " +
    "Closing or clearing this browser deletes your keys; there is no recovery. " +
    "This product cannot tell you whether a room or member is safe.",
  threadIdentity:
    "This identity exists only in this browser. Clearing browser data destroys it. There is no recovery.",
} as const;

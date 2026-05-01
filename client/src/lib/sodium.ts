// Single libsodium import point. All other client files import named
// functions from here so libsodium-specific types stay contained.

import _sodium from "libsodium-wrappers-sumo";

let ready: Promise<typeof _sodium> | null = null;

export function sodium(): Promise<typeof _sodium> {
  if (!ready) {
    ready = (async () => {
      await _sodium.ready;
      return _sodium;
    })();
  }
  return ready;
}

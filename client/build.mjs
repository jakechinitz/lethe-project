// Builds each page entry into a self-contained ESM bundle in
// ../crates/lethe-server/static/js. The PoW worker is built separately.

import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const outdir = resolve(here, "../crates/lethe-server/static/js");
const require_ = createRequire(import.meta.url);

// libsodium-wrappers-sumo's ESM bundle imports `./libsodium-sumo.mjs`
// from a path that doesn't exist next to it; the inner module ships as a
// separate `libsodium-sumo` package. Patch the resolution.
const libsodiumPlugin = {
  name: "libsodium-sumo-resolver",
  setup(b) {
    b.onResolve({ filter: /libsodium-sumo\.mjs$/ }, () => ({
      path: require_.resolve("libsodium-sumo"),
    }));
  },
};

const common = {
  bundle: true,
  format: "esm",
  target: "es2022",
  platform: "browser",
  minify: process.env.LETHE_BUILD_DEBUG ? false : true,
  sourcemap: process.env.LETHE_BUILD_DEBUG ? "inline" : false,
  logLevel: "info",
  plugins: [libsodiumPlugin],
};

const pages = ["board", "thread", "room_create", "room_join", "room"];

await build({
  ...common,
  splitting: true,
  entryPoints: pages.map((p) => resolve(here, `src/pages/${p}.ts`)),
  outdir,
});

await build({
  ...common,
  entryPoints: [resolve(here, "src/lib/pow.worker.ts")],
  outfile: resolve(outdir, "pow.worker.js"),
});

console.log("client built into", outdir);

// `node --test webapp/test/` with Node 24 runs this folder as one module,
// which resolves to this file: it loads every test file of the web app, each
// *.test.mjs in this folder, so a new test file runs without being listed
// here. The tests in e2e/ need a real node and are run on their own.
// An ES module, as the web app's package.json sets.

import { readdirSync } from "node:fs";

const here = new URL("./", import.meta.url);
const files = readdirSync(here)
  .filter((name) => name.endsWith(".test.mjs"))
  .sort();
for (const name of files) {
  await import(new URL(name, here).href);
}

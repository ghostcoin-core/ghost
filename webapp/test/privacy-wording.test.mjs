// The app's wording on cover and on a block holding a transaction: the tree
// count is a count of commitments, not of people or a promise of anonymity,
// and one block is neither final settlement nor privacy. app.mjs needs a
// page to load, so the test takes the pieces that build the text from its
// source and runs them on their own.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const source = readFileSync(new URL("../src/app.mjs", import.meta.url), "utf8");

// The text of a top-level `const NAME = ...;` or `function name(...) {...}`.
function piece(start) {
  const at = source.indexOf(start);
  assert.notEqual(at, -1, `app.mjs has ${start}`);
  const end = start.startsWith("function") ? source.indexOf("\n}\n", at) + 2 : source.indexOf(";\n", at) + 1;
  return source.slice(at, end);
}

const formatGhost = (wei) => String(wei);
const { describeCover, describeSummon, IN_A_BLOCK } = new Function(
  "formatGhost",
  [
    piece("const SEAL_TRUST ="),
    piece("const IN_A_BLOCK ="),
    piece("function describeSummon("),
    piece("function describeCover("),
    "return { describeCover, describeSummon, IN_A_BLOCK };",
  ].join("\n"),
)(formatGhost);

const unclaimed = { status: "unclaimed", current: { amount: 5n }, fee: 1n, available: 4n, tip: 40 };

test("the cover text states the tree's coin count, not who it hides among", () => {
  const cover = describeCover({ ...unclaimed, cover: { height: 38, covers: 7, total: 9 } });
  assert.equal(cover.warning, false);
  assert.match(cover.text, /The tree holds 7 coins as of block 38\./);
  assert.match(cover.text, /count of commitments, not of people/);
  assert.match(cover.text, /not a promise of anonymity/);
  assert.match(cover.text, /2 more are in newer blocks/);
  assert.doesNotMatch(cover.text, /hides|among/);
  // The holder still chooses; the app forces no wait.
  assert.match(cover.text, /reveal now, or wait for more coins and press Refresh\. The choice is yours\./);
});

test("a sent reveal says one block is not final settlement and not privacy", () => {
  const text = describeSummon({
    ...unclaimed,
    lastReveal: { stage: "sent", out: 3n, recipient: "0xabc", txHash: "0x01" },
  });
  assert.ok(text.includes(`transaction 0x01. ${IN_A_BLOCK}`));
  assert.match(IN_A_BLOCK, /Done when a block holds it/);
  assert.match(IN_A_BLOCK, /One block is not final/);
  assert.match(IN_A_BLOCK, /harder to undo/);
  assert.match(IN_A_BLOCK, /no privacy/);
  assert.doesNotMatch(text, /Done once/);
});

test("the Vanish and Claim sent messages use the same block wording", () => {
  const lines = source.split("\n");
  for (const start of ["Sent: a commit of", "Sent: a claim of"]) {
    const line = lines.find((l) => l.includes(start));
    assert.ok(line, `app.mjs has ${start}`);
    assert.ok(line.includes("${IN_A_BLOCK}"), line);
    assert.doesNotMatch(line, /Done once/);
  }
  assert.doesNotMatch(source, /hides this coin|Done once a block/);
});

test("Done is still shown when the block holds the reveal", () => {
  const text = describeSummon({
    ...unclaimed,
    lastReveal: { stage: "done", out: 3n, recipient: "0xabc", block: 41 },
  });
  assert.match(text, /Done: revealed 3 GHOST to 0xabc in block 41\./);
});

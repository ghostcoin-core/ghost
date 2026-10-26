// The receipts of a coin's own block (spec 05, section 8, item 5 "Notes are
// authenticated separately"): the scan (flow.mjs,
// scanKey) checks the leaf, note and salt of the key's highest-numbered coin
// against the coin tree record at its tree index and position in the receipts
// of the block that appended it. That block is asked for together with
// decoys, RECEIPT_BLOCKS blocks in all, so the request does not say which
// one holds the coin. The node serves receipts per block (eth_getBlockReceipts
// by block hash), so the blocks are asked one after another in block order.

import { toHex } from "./bytes.mjs";

// The blocks one receipts request asks for: the real block and 7 decoys.
export const RECEIPT_BLOCKS = 8;

// The index of the block that appended position `position` of coin tree
// `treeIndex`: the first of `places` (one `{ treeIndex, count }` per block in
// chain order, the tree and leaf count its coin root is of) whose place is
// past the position, a later tree or the same tree with more than `position`
// leaves. Null when no block holds the position yet.
export function blockOfPosition(places, treeIndex, position) {
  const at = places.findIndex((place) => place.treeIndex > treeIndex || (place.treeIndex === treeIndex && place.count > position));
  return at < 0 ? null : at;
}

// A uniform index below `total` from 4 random bytes a draw: a value at or
// above the largest multiple of `total` that fits in 32 bits is drawn again,
// so no index is favoured.
function drawIndex(random, total) {
  const limit = Math.floor(2 ** 32 / total) * total;
  for (;;) {
    const bytes = random(4);
    const value = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    if (value < limit) return value % total;
  }
}

// Draws indexes below `total` not in `taken` (a Set, which gains each one)
// until it holds `count`, uniform without replacement.
function drawInto(random, total, taken, count) {
  while (taken.size < count) taken.add(drawIndex(random, total));
}

// `min(RECEIPT_BLOCKS, total)` distinct block indexes below `total`, in
// ascending order: `real` among them unless it is null, the others drawn
// uniform without replacement (`random(n)` gives n random bytes).
export function drawBlocks({ random, total, real }) {
  if (!Number.isInteger(total) || total < 0) throw new Error(`cannot draw blocks among ${total}`);
  if (real !== null && !(Number.isInteger(real) && real >= 0 && real < total)) {
    throw new Error(`block ${real} is not among the ${total} blocks`);
  }
  const taken = new Set(real === null ? [] : [real]);
  drawInto(random, total, taken, Math.min(RECEIPT_BLOCKS, total));
  return [...taken].sort((a, b) => a - b);
}

// The blocks each coin's receipts are asked for, kept in memory for the page
// session only. `blocksFor(id, { first, last, real })` gives the ascending
// block numbers to ask for between `first` and `last`: `real` (a block
// number, or null) and decoys, drawn once per `id` and reused on every later
// call, so a repeat scan asks the same blocks. A stored decoy no longer
// between `first` and `last`, or that is now `real`, is drawn again, as are
// the decoys a longer chain now has room for.
export function createBlockSets({ random }) {
  const decoysOf = new Map();
  return {
    blocksFor(id, { first, last, real }) {
      const total = last - first + 1;
      if (!(Number.isInteger(first) && Number.isInteger(last) && total >= 1)) throw new Error(`no blocks from ${first} to ${last}`);
      if (real !== null && !(Number.isInteger(real) && real >= first && real <= last)) {
        throw new Error(`block ${real} is not between blocks ${first} and ${last}`);
      }
      const wanted = Math.min(RECEIPT_BLOCKS, total) - (real === null ? 0 : 1);
      const kept = (decoysOf.get(id) ?? []).filter((n) => n >= first && n <= last && n !== real).slice(0, wanted);
      const taken = new Set(kept.map((n) => n - first));
      if (real !== null) taken.add(real - first);
      drawInto(random, total, taken, Math.min(RECEIPT_BLOCKS, total));
      const blocks = [...taken].map((i) => i + first).sort((a, b) => a - b);
      decoysOf.set(id, blocks.filter((n) => n !== real));
      return blocks;
    },
  };
}

// The one record of `records` (coinRecord's, of one block's receipts) at
// position `position` of coin tree `treeIndex`; throws when none or more
// than one is.
export function findRecord(records, treeIndex, position) {
  const here = records.filter((record) => record.treeIndex === treeIndex && record.position === position);
  const where = `position ${position} of coin tree ${treeIndex}`;
  if (here.length === 0) throw new Error(`the receipts of the coin's block hold no record at ${where}`);
  if (here.length > 1) throw new Error(`the receipts of the coin's block hold ${here.length} records at ${where}`);
  return here[0];
}

// Checks a coin's `leaf`, `note` and `salt` (null for a leaf with none)
// against its receipt record; throws naming the first that differs.
export function checkRecord(record, { leaf, note, salt }) {
  const where = `position ${record.position} of coin tree ${record.treeIndex}`;
  if (toHex(record.leaf) !== toHex(leaf)) throw new Error(`the leaf at ${where} differs from its receipt`);
  if (toHex(record.note) !== toHex(note)) throw new Error(`the note at ${where} differs from its receipt`);
  const theirs = record.salt ?? null;
  const ours = salt ?? null;
  if ((theirs === null) !== (ours === null) || (ours !== null && toHex(theirs) !== toHex(ours))) {
    throw new Error(`the salt at ${where} differs from its receipt`);
  }
}

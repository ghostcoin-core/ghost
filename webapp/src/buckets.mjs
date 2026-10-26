// Restore by note buckets (spec 01, sections 8 and 9; spec 05, section 8):
// the web app's twin of the client library's restore_coins_by_tags.
//
// Every note's nonce starts with the 3-byte lookup tag of its commitment
// number under the key's note key, so only the key knows where its notes
// are. A bucket is the set of notes of one coin tree whose tag starts with
// the same `bits` bits, where bits = clamp(floor(log2(n / 4096)), 0, 24) for
// the tree's leaf count n at the anchor; the node serves one by
// ghost_getNoteBucket (ghost-node docs/note-buckets.md). A restore asks for
// the buckets of the tags of numbers 0 to 15, always 16, then of 16 to 31
// only if number 15 was found, and so on, each distinct prefix once.
//
// A bucket is a hint, not completeness: the node can withhold a note, and no
// header root covers a bucket. So the scan (flow.mjs, scanKey) still reads
// every page, checks it against the header root and the block receipts, and
// takes a bucket restore only when every entry read equals the page-read
// record at its position; otherwise, or when the node does not serve buckets,
// the full page scan restores the key.

import { equalBytes, fromHex, quantity, toHex, toQuantity } from "./bytes.mjs";

// Commitment numbers one batch of lookup tags asks for.
export const TAG_BATCH = 16;
// The most prefix bits of a bucket: every bit of the 3-byte tag.
export const MAX_BUCKET_BITS = 24;
const NOTE_BYTES = 156;
const SALT_BYTES = 16;
const LEAF_RECORD_BYTES = 32 + NOTE_BYTES;

// A bucket the node served that is malformed, or one that disagrees with the
// pages the scan read: the scan drops the bucket restore for the page one.
export class BucketRefused extends Error {}

// The bucket a lookup tag (3 bytes, its first in a note) falls in: its first
// `bits` bits, big-endian, as an integer.
export function tagPrefix(tag, bits) {
  if (!Number.isInteger(bits) || bits < 0 || bits > MAX_BUCKET_BITS) throw new Error(`bucket bits are 0 to ${MAX_BUCKET_BITS}`);
  return ((tag[0] << 16) | (tag[1] << 8) | tag[2]) >>> (MAX_BUCKET_BITS - bits);
}

// Restores the key's coins in coin tree `treeIndex` of `count` leaves at
// the anchor from the buckets of the key's own lookup tags, as
// restore_coins_by_tags does. `readBucket(treeIndex, bits, prefix)` gives a
// bucket's entries [{ position, leaf, note, salt }]; `spent` holds the spent
// markers (32 bytes each). Returns the coins `found` (restoreAt's, in
// position order), the `entries` read (in position order, each once), the
// `bucketReads` (one per distinct prefix) and the `notesTried` (the sum of
// the lengths of the buckets read).
export async function restoreByBuckets({ prover, readBucket, key, chainId, treeIndex, count, spent }) {
  const { bits } = await prover.request("bucketBits", { count });
  const read = new Set();
  const byContent = new Map();
  let notesTried = 0;
  for (let first = 0; ; first += TAG_BATCH) {
    const { tags } = await prover.request("noteTags", { key, first, count: TAG_BATCH });
    for (const tag of tags) {
      const prefix = tagPrefix(tag, bits);
      if (read.has(prefix)) continue;
      read.add(prefix);
      const bucket = await readBucket(treeIndex, bits, prefix);
      notesTried += bucket.length;
      // A note served twice is tried once.
      for (const entry of bucket) byContent.set(entryId(entry), entry);
    }
    const entries = [...byContent.values()].sort((a, b) => a.position - b.position);
    const { found } = await prover.request("restoreAt", { chainId, key, treeIndex, entries, markers: spent });
    const last = BigInt(first + TAG_BATCH - 1);
    if (!found.some((coin) => BigInt(coin.number) === last)) {
      return { found, entries, bucketReads: read.size, notesTried };
    }
  }
}

function entryId({ position, leaf, note, salt }) {
  return `${position}:${toHex(leaf)}:${toHex(note)}:${salt ? toHex(salt) : ""}`;
}

// The bucket reads of one scan, as of `anchorHash` (the anchor header's hash,
// bytes or hex). `readBucket(treeIndex, bits, prefix)` asks the node for the
// coin bucket and gives its entries [{ position, leaf, note, salt }], salt
// null for a leaf served without one. A reply that is not the bucket asked
// for (its kind, tree index, bits, prefix or count), whose positions do not
// strictly increase, whose leaf, note or salt is of the wrong length, or that
// holds a note whose tag does not start with the prefix is refused
// (BucketRefused). An error the node answers is thrown as the rpc throws it.
export function createBucketReader({ rpc, anchorHash }) {
  const anchor = typeof anchorHash === "string" ? anchorHash : toHex(anchorHash);
  return {
    async readBucket(treeIndex, bits, prefix) {
      const reply = await rpc.call("ghost_getNoteBucket", ["coin", toQuantity(treeIndex), toQuantity(bits), toQuantity(prefix), anchor]);
      const which = `note bucket ${prefix} of ${bits} bits of coin tree ${treeIndex}`;
      const refuse = (why) => new BucketRefused(`${which} from the endpoint is malformed: ${why}`);
      if (!reply || typeof reply !== "object" || !Array.isArray(reply.entries)) throw refuse("it is not a bucket");
      if (reply.kind !== "coin" || !sameQuantity(reply.treeIndex, treeIndex) || !sameQuantity(reply.bits, bits) || !sameQuantity(reply.prefix, prefix)) {
        throw refuse("it is not the bucket asked for");
      }
      if (!sameQuantity(reply.count, reply.entries.length)) throw refuse("its count is not its number of entries");
      const entries = [];
      let previous = -1;
      for (const entry of reply.entries) {
        let position;
        let leaf;
        let note;
        let salt;
        try {
          position = Number(quantity(entry?.position));
          leaf = fromHex(entry.leaf, 32);
          note = fromHex(entry.note, NOTE_BYTES);
          salt = entry.salt === undefined ? null : fromHex(entry.salt, SALT_BYTES);
        } catch (err) {
          throw refuse(err.message);
        }
        if (!(position > previous && position <= 0xffffffff)) throw refuse("its positions do not strictly increase");
        if (tagPrefix(note, bits) !== prefix) throw refuse(`the note at position ${position} is not of the bucket`);
        previous = position;
        entries.push({ position, leaf, note, salt });
      }
      return entries;
    },
  };
}

// Whether `text` is a hex quantity of value `n`.
function sameQuantity(text, n) {
  return typeof text === "string" && /^0x[0-9a-fA-F]+$/.test(text) && BigInt(text) === BigInt(n);
}

// A scan's restore by buckets over every coin tree it read (flow.mjs,
// scanKey): `trees` [{ treeIndex, count, records, salts }] as read in whole
// pages, `anchorHash` the hash of the header they were read at. Each tree is
// restored by restoreByBuckets with its page-read leaf count, and every
// entry a bucket holds must be the page-read leaf, note and salt at its
// position, checked as the bucket arrives, before the key is tried on it,
// or the whole restore is refused (BucketRefused). Returns the coins found,
// tree by tree.
export async function restoreTreesByBuckets({ prover, rpc, anchorHash, key, chainId, trees, spent }) {
  const reader = createBucketReader({ rpc, anchorHash });
  const found = [];
  for (const t of trees) {
    const readBucket = async (treeIndex, bits, prefix) => {
      const entries = await reader.readBucket(treeIndex, bits, prefix);
      for (const entry of entries) {
        if (!samePageRecord(t, entry)) {
          throw new BucketRefused(`the note bucket entry at position ${entry.position} of coin tree ${treeIndex} is not the leaf the pages hold there`);
        }
      }
      return entries;
    };
    const restored = await restoreByBuckets({ prover, readBucket, key, chainId, treeIndex: t.treeIndex, count: t.count, spent });
    found.push(...restored.found);
  }
  return found;
}

// Whether `entry` is the record the pages of tree `t` hold at its position.
function samePageRecord(t, { position, leaf, note, salt }) {
  if (position >= t.count) return false;
  const record = t.records.subarray(position * LEAF_RECORD_BYTES, (position + 1) * LEAF_RECORD_BYTES);
  if (!equalBytes(record.subarray(0, 32), leaf) || !equalBytes(record.subarray(32), note)) return false;
  const pageSalt = t.salts[position];
  return pageSalt == null ? salt == null : salt != null && equalBytes(pageSalt, salt);
}

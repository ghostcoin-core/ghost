// The WebAssembly module against the golden vectors of spec 01 and spec 05,
// and its refusals.

import assert from "node:assert/strict";
import test from "node:test";

import { concat, fromHex, toHex, word } from "../src/bytes.mjs";
import { receiptBytes } from "../src/flow.mjs";
import { readHeader } from "../src/header.mjs";
import { loadModule } from "./support/env.mjs";

const ghost = await loadModule();

// The example words key of spec 01, as its digit view.
const VECTOR_KEY = "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812";
// The retired twelve-group key of spec 01's vectors, refused now.
const OLD_KEY = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417";
// The two leaves of spec 05, section 11's tree vectors.
const LEAF_A = "562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458";
const LEAF_B = "93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15";

test("tree roots match spec 05, section 11", () => {
  assert.equal(toHex(ghost.treeRoots(new Uint8Array(0)).root), "0x8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8");
  const two = fromHex(LEAF_A + LEAF_B);
  const { root, pageRoots } = ghost.treeRoots(two);
  assert.equal(toHex(root), "0x142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5");
  assert.deepEqual(pageRoots.map(toHex), ["0x06d032e35a1f30a5773c38d9631f5e4ec069786f4d22131ef0bbba75acf2b717"]);
  const prefixes = ghost.prefixRoots(two, 0, 2).map(toHex);
  assert.equal(prefixes[0], "0x8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8");
  assert.equal(prefixes[2], toHex(root));
  assert.equal(prefixes[1], toHex(ghost.treeRoots(fromHex(LEAF_A)).root));
});

// Spec 05, vector header-block-one-example, as the JSON-RPC names its fields.
const BLOCK_ONE = {
  parentHash: "0xffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7",
  sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
  miner: "0x00000000000000000000000000000000000004d2",
  stateRoot: `0x${"11".repeat(32)}`,
  transactionsRoot: `0x${"22".repeat(32)}`,
  receiptsRoot: `0x${"33".repeat(32)}`,
  logsBloom: `0x${"00".repeat(256)}`,
  difficulty: "0x1000000",
  number: "0x1",
  gasLimit: "0x1c9c380",
  gasUsed: "0x1ec30",
  timestamp: "0x6b37040e",
  extraData: "0x",
  mixHash: `0x${"44".repeat(32)}`,
  nonce: "0x0102030405060708",
  baseFeePerGas: "0x342770c0",
  coinTreeRoot: "0x142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5",
  dataTreeRoot: "0xdfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a",
};

test("a header's RLP and hash match spec 05, section 11", () => {
  const { rlp, values } = readHeader(BLOCK_ONE);
  assert.equal(values.number, 1n);
  assert.equal(values.baseFeePerGas, 875_000_000n);
  assert.match(toHex(rlp), /^0xf90243a0ffc501cc/);
  assert.match(toHex(rlp), /84342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a$/);
  assert.equal(toHex(ghost.keccak256(rlp)), "0x943182f201b34dae77dc5c8efb5c84083dda907eac51f8ac3fc6f6c36a791c23");
  // Any changed field changes the hash: a coin root, a base fee.
  const otherRoot = { ...BLOCK_ONE, coinTreeRoot: BLOCK_ONE.coinTreeRoot.replace(/5$/, "4") };
  assert.notEqual(toHex(ghost.keccak256(readHeader(otherRoot).rlp)), "0x943182f201b34dae77dc5c8efb5c84083dda907eac51f8ac3fc6f6c36a791c23");
  assert.throws(() => readHeader({ ...BLOCK_ONE, dataTreeRoot: undefined }), /no dataTreeRoot/);
  assert.throws(() => readHeader({ ...BLOCK_ONE, coinTreeRoot: BLOCK_ONE.coinTreeRoot.slice(0, -2) }), /expected 32 bytes/);
  assert.throws(() => readHeader({ ...BLOCK_ONE, extraData: `0x${"00".repeat(33)}` }), /longer than 32/);
  assert.throws(() => readHeader({ ...BLOCK_ONE, number: `0x1${"0".repeat(16)}` }), /out of range/);
});

test("the tree check accepts matching data and refuses a changed leaf or root", () => {
  const two = fromHex(LEAF_A + LEAF_B);
  const { root, pageRoots } = ghost.treeRoots(two);
  ghost.treeCheck({ pageRoots: pageRoots[0], leaves: two, root });
  const changed = Uint8Array.from(two);
  changed[40] ^= 1;
  assert.throws(() => ghost.treeCheck({ pageRoots: pageRoots[0], leaves: changed, root }), /page 0 does not match/);
  const otherRoot = Uint8Array.from(root);
  otherRoot[0] ^= 1;
  assert.throws(() => ghost.treeCheck({ pageRoots: pageRoots[0], leaves: two, root: otherRoot }), /header's coin root/);
  assert.throws(() => ghost.treeCheck({ pageRoots: new Uint8Array(0), leaves: two, root }), /do not fill/);
});

const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const u64 = (n) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
};
const u32 = (n) => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
};
const text = (t) => {
  const b = new TextEncoder().encode(t);
  return concat([u32(b.length), b]);
};

test("a version 1 commit is refused", () => {
  const amount = 10n ** 18n;
  for (const version of [1, 3]) {
    assert.throws(() => ghost.commit({ version, chainId: 7n, amount, seed: random(32), key: VECTOR_KEY }), /unknown commit version/);
  }
  // The module itself refuses version 1, whatever the JavaScript side passes.
  const input = concat([Uint8Array.of(1), u64(7n), word(amount), random(32), text(VECTOR_KEY)]);
  assert.throws(() => ghost.call("ghost_commit", input), /unknown commit version/);
  assert.equal(ghost.constants().commitPayloadBytes, 206);
  assert.equal(Object.keys(ghost.constants()).length, 2, "no version 1 payload length");

  const commit = ghost.commit({ chainId: 7n, amount, seed: random(32), key: VECTOR_KEY });
  const fingerprint = commit.payload.slice(2, 34);
  assert.equal(toHex(ghost.coinCommitment(fingerprint, amount, 2)), toHex(commit.commitment));
  assert.throws(() => ghost.coinCommitment(fingerprint, amount, 1), /unknown commit version/);
  const raw = concat([fingerprint, word(amount), Uint8Array.of(1)]);
  assert.throws(() => ghost.call("ghost_coin_commitment", raw), /unknown commit version/);
});

test("a coin without a salt is refused by the prover", () => {
  const chainId = 7n;
  const amount = 10n ** 18n;
  const commit = ghost.commit({ chainId, amount, seed: random(32), key: VECTOR_KEY });
  const leaves = commit.commitment;
  const { root } = ghost.treeRoots(leaves);
  const args = {
    chainId,
    domain: new Uint8Array(32),
    root,
    recipient: new Uint8Array(20).fill(1),
    out: 1n,
    fee: 1n,
    number: 0n,
    amount,
    position: 0,
    leaves,
    seed: random(32),
    zk: random(32),
    key: VECTOR_KEY,
    newKey: ghost.newKey(random(32)),
  };
  // A partial reveal, a full one (nothing left) and a claim of the coin,
  // its salt left out.
  for (const change of [{ kind: "partial" }, { kind: "partial", out: amount - 1n }, { kind: "claim", out: 0n }]) {
    assert.throws(() => ghost.prove({ ...args, ...change, salt: null }), /a coin without a salt cannot be revealed/);
  }
  // A decoy (kind 2 and 3) whose salt record says "no salt" is refused too,
  // before any proof work.
  for (const kind of [2, 3]) {
    const input = concat([
      u64(chainId),
      new Uint8Array(32),
      Uint8Array.of(kind),
      root,
      new Uint8Array(20).fill(1),
      word(kind === 3 ? 0n : 1n),
      word(1n),
      u64(0n),
      word(3n),
      u32(0),
      new Uint8Array(17),
      u32(1),
      leaves,
      random(32),
      random(32),
      text(VECTOR_KEY),
      ...(kind === 3 ? [text(args.newKey)] : []),
    ]);
    assert.throws(() => ghost.call("ghost_prove", input), /a coin without a salt cannot be revealed/);
  }
});

test("a commit is version 2 by default, its salt fresh each time", () => {
  const seed = () => crypto.getRandomValues(new Uint8Array(32));
  const a = ghost.commit({ chainId: 7n, amount: 10n ** 18n, seed: seed(), key: VECTOR_KEY });
  const b = ghost.commit({ chainId: 7n, amount: 10n ** 18n, seed: seed(), key: VECTOR_KEY });
  assert.equal(a.payload.length, ghost.constants().commitPayloadBytes);
  assert.equal(a.payload.length, 206);
  assert.equal(toHex(a.payload.slice(0, 2)), "0x0002");
  assert.notEqual(toHex(a.payload.slice(34, 50)), toHex(b.payload.slice(34, 50)), "a fresh salt");
  assert.notEqual(toHex(a.commitment), toHex(b.commitment), "so a fresh commitment from the same key");
  assert.notEqual(toHex(a.marker), toHex(b.marker));
  assert.equal(toHex(ghost.coinCommitment(a.payload.slice(2, 34), 10n ** 18n, 2)), toHex(a.commitment));
});

test("restore finds the committed coin from its note and passes over others", () => {
  const chainId = 7n;
  const commit = ghost.commit({ chainId, amount: 10n ** 18n, seed: random(32), key: VECTOR_KEY });
  const salt = commit.payload.slice(34, 50);
  const stranger = new Uint8Array(188).fill(3);
  const records = new Uint8Array([...stranger, ...commit.commitment, ...commit.payload.slice(50)]);
  const salts = [null, salt];
  let found = ghost.restore({ chainId, key: VECTOR_KEY, records, salts, markers: new Uint8Array(0) });
  assert.equal(found.length, 1);
  assert.equal(found[0].position, 1);
  assert.equal(found[0].amount, 10n ** 18n);
  assert.equal(found[0].spent, false);
  assert.equal(toHex(found[0].salt), toHex(salt), "the coin's salt as served beside its leaf");
  found = ghost.restore({ chainId, key: VECTOR_KEY, records, salts, markers: commit.marker });
  assert.equal(found[0].spent, true);
  // Another chain's note does not open.
  assert.equal(ghost.restore({ chainId: 8n, key: VECTOR_KEY, records, salts, markers: new Uint8Array(0) }).length, 0);
  // One salt (or none) per leaf.
  assert.throws(() => ghost.restore({ chainId, key: VECTOR_KEY, records, salts: [null], markers: new Uint8Array(0) }), /one salt/);
});

test("restore reports the coin tree it was asked about and refuses nothing it could read", () => {
  const chainId = 7n;
  const commit = ghost.commit({ chainId, amount: 10n ** 18n, seed: random(32), key: VECTOR_KEY });
  const salt = commit.payload.slice(34, 50);
  const stranger = new Uint8Array(188).fill(3);
  const records = new Uint8Array([...stranger, ...commit.commitment, ...commit.payload.slice(50)]);
  const ask = (more) => ghost.restore({ chainId, key: VECTOR_KEY, records, salts: [null, salt], markers: new Uint8Array(0), ...more });
  // Not named, the tree is tree 0.
  let found = ask({});
  assert.equal(found.length, 1);
  assert.deepEqual([found[0].treeIndex, found[0].position], [0, 1]);
  // Named, the coin reports that tree, at its position in it.
  found = ask({ treeIndex: 2 });
  assert.equal(found.length, 1);
  assert.deepEqual([found[0].treeIndex, found[0].position], [2, 1]);
  assert.equal(found[0].amount, 10n ** 18n);
  assert.equal(toHex(found[0].salt), toHex(salt));
  // The last index a u32 holds is read as itself.
  assert.equal(ask({ treeIndex: 0xffffffff })[0].treeIndex, 0xffffffff);
  // An index that is not a u32 is refused before the module is called.
  for (const treeIndex of [-1, 2 ** 32, 1.5]) {
    assert.throws(() => ask({ treeIndex }), /32-bit unsigned/);
  }
  // The module reads the tree index right after the chain id: its own
  // output names the tree, between the amount and the position.
  const input = concat([
    u64(chainId),
    u32(5),
    text(VECTOR_KEY),
    u32(2),
    records,
    u32(2),
    new Uint8Array(17),
    Uint8Array.of(1),
    salt,
    u32(0),
  ]);
  const out = ghost.call("ghost_restore", input);
  const view = new DataView(out.buffer);
  assert.equal(view.getUint32(0), 1, "one coin");
  assert.equal(view.getUint32(4 + 8 + 32), 5, "its tree index");
  assert.equal(view.getUint32(4 + 8 + 32 + 4), 1, "its position");
  assert.equal(out.length, 4 + 8 + 32 + 4 + 4 + 32 + 32 + 1 + 17);
});

test("keys: new keys are 24 words, typed keys are checked, errors hold no word or digit", () => {
  const key = ghost.newKey(crypto.getRandomValues(new Uint8Array(32)));
  assert.match(key, /^[a-z]+( [a-z]+){23}$/);
  assert.deepEqual(ghost.checkKey(key), { format: "words", groups: 21 });
  assert.deepEqual(ghost.checkKey(VECTOR_KEY.replaceAll(" ", "-")), { format: "words", groups: 21 });
  const bad = VECTOR_KEY.slice(0, -1) + "8";
  assert.throws(() => ghost.checkKey(bad), (err) => /group 21/.test(err.message) && !/\d{4}/.test(err.message));
  assert.throws(() => ghost.checkKey("1234"), /has 84 digits, not 4/);
  // The digit keys of twelve and twenty-four groups are refused, and nothing
  // is derived from them.
  assert.throws(() => ghost.checkKey(OLD_KEY), /has 84 digits, not 48/);
  assert.throws(() => ghost.checkKey(`${OLD_KEY} ${OLD_KEY}`), /has 84 digits, not 96/);
  assert.throws(() => ghost.keyDigits(OLD_KEY), /not a valid Phantom Key/);
  assert.throws(() => ghost.commit({ chainId: 7n, amount: 1n, seed: new Uint8Array(32), key: OLD_KEY }), /not 48/);
  assert.notEqual(ghost.newKey(crypto.getRandomValues(new Uint8Array(32))), key);
  // The digit view of a words key: 21 groups, which open the same key.
  const digits = ghost.keyDigits(key);
  assert.match(digits, /^\d{4}( \d{4}){20}$/);
  assert.deepEqual(ghost.checkKey(digits), { format: "words", groups: 21 });
  assert.equal(ghost.keyDigits(VECTOR_KEY), VECTOR_KEY);
});

test("the tree-state rule takes a settled candidate at or above the leaf's block, its own root included", () => {
  const a = new Uint8Array(32).fill(1);
  const b = new Uint8Array(32).fill(2);
  // Two blocks deep is enough, at any height: no epoch block.
  assert.equal(ghost.chooseTreeState({ tip: 7, leafHeight: 4, leafRoot: a, height: 5, root: b }), true);
  // A root equal to the leaf block's, or the leaf's own block, counts too:
  // nobody else has to commit first.
  assert.equal(ghost.chooseTreeState({ tip: 7, leafHeight: 4, leafRoot: a, height: 5, root: a }), true);
  assert.equal(ghost.chooseTreeState({ tip: 7, leafHeight: 5, leafRoot: a, height: 5, root: a }), true);
  // Not yet 2 deep, or below the leaf's block: wait.
  assert.equal(ghost.chooseTreeState({ tip: 6, leafHeight: 4, leafRoot: a, height: 5, root: b }), false);
  assert.equal(ghost.chooseTreeState({ tip: 6, leafHeight: 5, leafRoot: a, height: 5, root: a }), false);
  assert.equal(ghost.chooseTreeState({ tip: 7, leafHeight: 6, leafRoot: a, height: 5, root: b }), false);
});

test("a malformed envelope is refused before any proof work", () => {
  const { envelopeBytes } = ghost.constants();
  assert.equal(envelopeBytes, 1 + 190 + 1_310_720 + 156);
  const domain = new Uint8Array(32);
  assert.throws(() => ghost.decodeEnvelope({ chainId: 7n, domain, envelope: new Uint8Array(100) }), /expected size/);
  const envelope = new Uint8Array(envelopeBytes);
  envelope[0] = 0x50;
  envelope[2] = 0x02;
  assert.throws(() => ghost.decodeEnvelope({ chainId: 7n, domain, envelope }), /version/);
  envelope[2] = 0x01;
  assert.throws(() => ghost.decodeEnvelope({ chainId: 7n, domain, envelope }), /chain/);
});

// --- Block receipts ---

const EMPTY_TRIE = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
const COIN_TREE_ACCOUNT = "0x67686f7374000000000000000000000000000001";
const tagTopic = (tag) => toHex(ghost.keccak256(concat([Uint8Array.of(tag.length), new TextEncoder().encode(tag)])));
const be32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

test("a receipt from eth_getBlockReceipts is encoded as its block's receiptsRoot covers it", () => {
  // A legacy receipt with no log: 0xf90108, status 0x01, gas 0x825208, the
  // bloom (0xb90100 and 256 bytes) and the empty log list 0xc0.
  const plain = { type: "0x0", status: "0x1", cumulativeGasUsed: "0x5208", logsBloom: `0x${"00".repeat(256)}`, logs: [] };
  assert.equal(toHex(receiptBytes(plain)), `0xf9010801825208b90100${"00".repeat(256)}c0`);
  // Typed: the type byte first. A failed receipt's status is empty (0x80).
  assert.equal(toHex(receiptBytes({ ...plain, type: "0x52" })), `0x52f9010801825208b90100${"00".repeat(256)}c0`);
  assert.equal(toHex(receiptBytes({ ...plain, status: "0x0" })), `0xf9010880825208b90100${"00".repeat(256)}c0`);
  // A log: [address, [topics], data].
  const log = { address: COIN_TREE_ACCOUNT, topics: [`0x${"ab".repeat(32)}`], data: "0x0102" };
  const withLog = toHex(receiptBytes({ ...plain, logs: [log] }));
  assert.ok(withLog.endsWith(`f83a94${COIN_TREE_ACCOUNT.slice(2)}e1a0${"ab".repeat(32)}820102`), withLog);
  for (const bad of [
    { ...plain, type: undefined },
    { ...plain, type: "0x80" },
    { ...plain, status: "0x2" },
    { ...plain, logsBloom: "0x00" },
    { ...plain, logs: null },
    { ...plain, logs: [{ ...log, address: "0x01" }] },
    { ...plain, logs: [{ ...log, topics: ["0x01"] }] },
    null,
  ]) {
    assert.throws(() => receiptBytes(bad), Error, JSON.stringify(bad));
  }
  assert.equal(toHex(ghost.receiptsRoot([])), EMPTY_TRIE, "no receipts: the empty trie");
  const one = ghost.receiptsRoot([receiptBytes(plain)]);
  assert.notEqual(toHex(one), toHex(ghost.receiptsRoot([receiptBytes({ ...plain, cumulativeGasUsed: "0x5209" })])));
  assert.notEqual(toHex(one), toHex(ghost.receiptsRoot([receiptBytes(plain), receiptBytes(plain)])));
});

// Genesis and block 1, which holds a salted commit (position 0) and a reveal
// (its remainder at position 1, spending `marker`), with their receipts in
// the node's log layout.
function receiptsChain() {
  const leaf = new Uint8Array(32).fill(0xa1);
  const note = new Uint8Array(156).fill(0xa2);
  const salt = new Uint8Array(16).fill(0xa3);
  const remainder = new Uint8Array(32).fill(0xb1);
  const remainderNote = new Uint8Array(156).fill(0xb2);
  const marker = new Uint8Array(32).fill(0xc1);
  const receipt = (topics, data, gas) => ({
    type: "0x50",
    status: "0x1",
    cumulativeGasUsed: gas,
    logsBloom: `0x${"00".repeat(256)}`,
    logs: [
      { address: `0x${"11".repeat(20)}`, topics: [], data: "0x" },
      { address: COIN_TREE_ACCOUNT, topics, data: toHex(data) },
    ],
  });
  const commit = receipt([tagTopic("ghost/commit-receipt/v1")], concat([be32(0), be32(0), leaf, word(5n), note, salt]), "0x1");
  const reveal = receipt(
    [tagTopic("ghost/reveal-receipt/v1"), toHex(marker)],
    concat([be32(0), be32(1), remainder, remainderNote, new Uint8Array(20).fill(0x22), word(1n)]),
    "0x2",
  );
  const receipts = [commit, reveal].map(receiptBytes);
  const draft = (number, parentHash, receiptsRoot) =>
    readHeader({
      ...BLOCK_ONE,
      parentHash: toHex(parentHash),
      number: `0x${number.toString(16)}`,
      receiptsRoot: toHex(receiptsRoot),
    }).rlp;
  const genesis = draft(0, new Uint8Array(32), fromHex(EMPTY_TRIE));
  const block = draft(1, ghost.keccak256(genesis), ghost.receiptsRoot(receipts));
  return {
    genesis,
    block,
    receipts,
    hashes: [ghost.keccak256(genesis), ghost.keccak256(block)],
    records: concat([leaf, note, remainder, remainderNote]),
    salts: [salt, null],
    marker,
  };
}

test("block receipts check against their header's receiptsRoot, and the leaves, notes, salts and markers against them", () => {
  const c = receiptsChain();
  ghost.receiptsAdd([
    { header: c.genesis, receipts: [] },
    { header: c.block, receipts: c.receipts },
  ]);
  const scan = { hashes: c.hashes, fromGenesis: true, start: 0, records: c.records, salts: c.salts, markerBlocks: 2, markers: c.marker };
  ghost.receiptsCheck(scan);

  // A receipt dropped, reordered or changed gives another root.
  for (const receipts of [c.receipts.slice(1), [...c.receipts].reverse(), [c.receipts[0], Uint8Array.from(c.receipts[1], (b, i) => (i === 300 ? b ^ 1 : b))]]) {
    assert.throws(() => ghost.receiptsAdd([{ header: c.block, receipts }]), /the receipts of block 1: the receipts do not match the header's receipts root/);
  }

  const changed = (bytes, at) => Uint8Array.from(bytes, (b, i) => (i === at ? b ^ 1 : b));
  const refusals = [
    [{ records: changed(c.records, 100) }, /the note at position 0 differs from its receipt/],
    [{ records: changed(c.records, 188 + 5) }, /the leaf at position 1 differs from its receipt/],
    [{ salts: [null, null] }, /the salt at position 0 differs from its receipt/],
    [{ salts: [c.salts[0], c.salts[0]] }, /the salt at position 1 differs from its receipt/],
    [{ records: c.records.slice(0, 188), salts: [c.salts[0]] }, /the leaf at position 1 is missing/],
    [{ records: concat([c.records, c.records.slice(0, 188)]), salts: [...c.salts, null] }, /position 2 is not in the receipts/],
    [{ records: concat([c.records.slice(188), c.records.slice(0, 188)]), salts: [null, c.salts[0]] }, /position 0 differs/],
    [{ markers: new Uint8Array(0) }, /spent marker 0 is missing/],
    [{ markers: concat([c.marker, c.marker]) }, /spent marker 1 is not in the receipts/],
    [{ markers: new Uint8Array(32) }, /spent marker 0 differs from its receipt/],
    // The markers read at genesis cannot hold block 1's.
    [{ markerBlocks: 1 }, /spent marker 0 is not in the receipts/],
    // Blocks out of order, a block whose receipts were not checked, none.
    [{ hashes: [...c.hashes].reverse() }, /does not follow/],
    [{ hashes: [c.hashes[0], new Uint8Array(32)] }, /have not been checked/],
    [{ hashes: [] }, /do not cover the scan/],
  ];
  for (const [change, refusal] of refusals) assert.throws(() => ghost.receiptsCheck({ ...scan, ...change }), refusal, String(refusal));

  // From a pinned block 1 with one leaf before it: the run starts at
  // position 1, and the markers before the start are not the receipts' to
  // say, only the last ones are.
  const pinned = { ...scan, hashes: [c.hashes[1]], fromGenesis: false, start: 1, records: c.records.slice(188), salts: [null], markerBlocks: 1 };
  ghost.receiptsCheck({ ...pinned, markers: concat([new Uint8Array(32).fill(9), c.marker]) });
  assert.throws(() => ghost.receiptsCheck({ ...pinned, markers: new Uint8Array(0) }), /spent marker 0 is missing/);
  assert.throws(() => ghost.receiptsCheck({ ...pinned, markers: concat([c.marker, new Uint8Array(32)]) }), /differs from its receipt/);
});

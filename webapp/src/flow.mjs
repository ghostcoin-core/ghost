// The app's flow controller: Vanish with the save check, Summon and Claim.
// It touches no DOM, so the headless test drives exactly what the page
// drives; app.mjs only renders its state and forwards the user's input.
//
// What it talks to:
//
// - the chosen node endpoint, by JSON-RPC: headers, the coin tree in whole
//   pages, the spent markers in whole pages, receipts, and the reveal
//   transaction. No request names a key, a commitment, a position or a
//   marker; the reveal itself carries only public fields;
// - the injected EIP-1193 wallet, only to send the commit;
// - the background worker (prover.mjs), which holds the WebAssembly module
//   and receives a key's digits for the length of one request.
//
// A key lives only in this object's memory: it is never written to browser
// storage, a file, a cookie or a server, and it is dropped as soon as the
// step that needs it is done.

import { concat, equalBytes, fromHex, quantity, toHex, toQuantity } from "./bytes.mjs";
import {
  CONFIRMATIONS,
  EPOCH_BLOCKS,
  epochHeight,
  feeForNextBlock,
  formatGhost,
  parseAddress,
  parseGhost,
} from "./chain.mjs";
import { readHeader } from "./header.mjs";
import { DEFAULT_ENDPOINT, createRpc } from "./rpc.mjs";

// The commit entry address of the local internal network. The transaction
// format work fixes it; until then it is a setting next to the endpoint.
export const DEFAULT_COMMIT_ENTRY = "0x0000000000000000000000000000000000001000";
export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// Leaves (or markers) per page of wallet tree data (spec 05, section 8).
export const PAGE_LEAVES = 4096;
const NOTE_BYTES = 156;
// Groups the user re-types before a key is used, out of a key's twelve.
export const SAVE_CHECK_GROUPS = 3;
const KEY_GROUPS = 12;
// Times a reveal is proved again when the fee window changes meanwhile.
const FEE_ATTEMPTS = 3;

// The reveal cannot be made yet; the message says what it waits for.
export class WaitError extends Error {}

// Three distinct group positions (1 to 12), drawn without bias from the
// secure random source and returned in order.
export function pickGroups(random, total = KEY_GROUPS, count = SAVE_CHECK_GROUPS) {
  const limit = 256 - (256 % total);
  const chosen = new Set();
  while (chosen.size < count) {
    for (const byte of random(16)) {
      if (byte >= limit) continue;
      chosen.add((byte % total) + 1);
      if (chosen.size === count) break;
    }
  }
  return [...chosen].sort((a, b) => a - b);
}

// The positions whose typed group does not match the key.
export function wrongGroups(keyText, positions, answers) {
  const groups = keyText.trim().split(/[\s-]+/);
  return positions.filter((position, i) => String(answers[i] ?? "").replace(/[\s-]/g, "") !== groups[position - 1]);
}

// The key's state from what restore found: no coin yet, a coin to claim,
// or nothing left unspent.
export function keyStatus(found) {
  if (found.length === 0) return { status: "not-found", current: null };
  const unspent = found.filter((coin) => !coin.spent).sort((a, b) => b.position - a.position);
  if (unspent.length === 0) return { status: "claimed", current: null };
  return { status: "unclaimed", current: unspent[0] };
}

export function createFlow({
  prover,
  wallet = null,
  fetch = globalThis.fetch,
  random = (n) => crypto.getRandomValues(new Uint8Array(n)),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
  pollMs = 3000,
  maxPolls = 600,
  endpoint = DEFAULT_ENDPOINT,
  commitEntry = DEFAULT_COMMIT_ENTRY,
  onChange = () => {},
} = {}) {
  let rpc = createRpc(endpoint, { fetch });
  const state = {
    endpoint: rpc.url,
    commitEntry,
    wallet: null,
    busy: null,
    progress: null,
    error: null,
    vanish: null,
    summon: null,
  };

  const emit = () => onChange(state);
  const progress = (stage) => {
    state.progress = { stage, since: now() };
    emit();
  };

  async function run(label, task) {
    if (state.busy) throw new Error(`wait until "${state.busy}" is done`);
    state.busy = label;
    state.error = null;
    emit();
    try {
      return await task();
    } catch (err) {
      state.error = err.message;
      throw err;
    } finally {
      state.busy = null;
      state.progress = null;
      emit();
    }
  }

  // --- The chain, from the endpoint ---

  async function blockNumber() {
    return Number(quantity(await rpc.call("eth_blockNumber")));
  }

  // Block `number`'s header, kept only if keccak256 of its 18-field RLP
  // (spec 05, section 10) is the hash the endpoint returned with it, so no
  // field, a coin root included, can be changed under a real hash. The
  // proof-of-work seal is not checked: the endpoint is trusted for it.
  async function headerAt(number) {
    const raw = await rpc.call("eth_getBlockByNumber", [toQuantity(number), false]);
    if (!raw) throw new Error(`the endpoint has no block ${number}`);
    const { values, rlp } = readHeader(raw);
    const hash = fromHex(raw.hash, 32);
    const { hash: computed } = await prover.request("keccak256", { bytes: rlp });
    if (!equalBytes(computed, hash)) {
      throw new Error(`the endpoint's header of block ${number} does not hash to the block hash it returned`);
    }
    const header = {
      number: Number(values.number),
      hash,
      parentHash: values.parentHash,
      baseFee: values.baseFeePerGas,
      gasUsed: values.gasUsed,
      gasLimit: values.gasLimit,
      coinTreeRoot: values.coinTreeRoot,
    };
    if (header.number !== number) throw new Error(`the endpoint returned block ${header.number} for ${number}`);
    return header;
  }

  // The chain as of its tip: verified headers, each the parent of the next,
  // from 32 blocks below the epoch block (or from genesis) up to the tip,
  // which covers the epoch window, the fee window and the block 6 below the
  // tip. Which blocks are asked for depends on the tip alone.
  async function readChain() {
    const chainId = quantity(await rpc.call("eth_chainId"));
    const top = await blockNumber();
    const epoch = epochHeight(top);
    const low = epoch === null || epoch < EPOCH_BLOCKS ? 0 : epoch - EPOCH_BLOCKS;
    const headers = await headerRange(low, top);
    const at = (n) => {
      if (n < low || n > top) throw new Error(`block ${n} is outside the headers read`);
      return headers[n - low];
    };
    const genesis = low === 0 ? headers[0] : await headerAt(0);
    return { chainId, epoch, headers, at, tip: headers[headers.length - 1], genesis };
  }

  // Consecutive verified headers, each the parent of the next.
  async function headerRange(from, to) {
    const headers = [];
    for (let n = from; n <= to; n += 1) {
      const header = await headerAt(n);
      const parent = headers[headers.length - 1];
      if (parent && toHex(header.parentHash) !== toHex(parent.hash)) {
        throw new Error(`block ${n} does not follow block ${n - 1}`);
      }
      headers.push(header);
    }
    return headers;
  }

  // Every leaf and note of coin tree 0 as of `anchor`: the page-root list,
  // then every page in order, checked against the anchor's coin root.
  async function fetchTree(anchor) {
    const anchorHash = toHex(anchor.hash);
    const list = await rpc.call("ghost_getPageRoots", ["coin", "0x0", anchorHash]);
    const pageRoots = list.pageRoots.map((root) => fromHex(root, 32));
    const leaves = [];
    const records = [];
    for (let p = 0; p < pageRoots.length; p += 1) {
      const page = await rpc.call("ghost_getTreePage", ["coin", "0x0", toQuantity(p), anchorHash]);
      const count = Number(quantity(page.count));
      const whole = p === pageRoots.length - 1 ? count >= 1 && count <= PAGE_LEAVES : count === PAGE_LEAVES;
      if (!whole || page.leaves.length !== count || page.notes.length !== count) {
        throw new Error(`page ${p} from the endpoint is not a whole page`);
      }
      for (let i = 0; i < count; i += 1) {
        const leaf = fromHex(page.leaves[i], 32);
        leaves.push(leaf);
        records.push(leaf, fromHex(page.notes[i], NOTE_BYTES));
      }
    }
    const leafBytes = concat(leaves);
    await prover.request("treeCheck", { pageRoots: concat(pageRoots), leaves: leafBytes, root: anchor.coinTreeRoot });
    return { count: leaves.length, leaves: leafBytes, records: concat(records) };
  }

  // Every spent coin marker as of `anchor`, in whole marker pages. They are
  // hints, not checked against a header (spec 05, section 8).
  async function fetchSpent(anchor) {
    const markers = [];
    for (let p = 0; ; p += 1) {
      const page = await rpc.call("ghost_getTreePage", ["coin-markers", "0x0", toQuantity(p), toHex(anchor.hash)]);
      const count = Number(quantity(page.count));
      if (count > PAGE_LEAVES || page.markers.length !== count) throw new Error(`marker page ${p} is malformed`);
      for (const marker of page.markers) markers.push(fromHex(marker, 32));
      if (count < PAGE_LEAVES) return concat(markers);
    }
  }

  // Everything the endpoint is asked for a key is asked before the key is
  // tried on a note: the headers, the tree and the markers, all fixed by the
  // tip alone. Notes are not checked against the tree (an endpoint can alter
  // them), so no request may follow from what restore found; on every path,
  // found or not, the requests are the same.
  //
  // The markers are those as of 6 blocks below the tip, so a key shows
  // claimed only once its coin's spend has 6 blocks on top.
  //
  // The work in the worker is the same whatever the key finds too: the leaf
  // count of each epoch header, read from the roots of every prefix of the
  // fetched leaves, is computed here for every key, not only for one with a
  // coin to reveal.
  async function scanKey(key) {
    const chain = await readChain();
    progress("reading the coin tree");
    const tree = await fetchTree(chain.tip);
    const spent = await fetchSpent(chain.at(Math.max(0, chain.tip.number - CONFIRMATIONS)));
    const { epoch } = chain;
    const epochHeaders = epoch === null || epoch < EPOCH_BLOCKS ? null : chain.headers.slice(0, EPOCH_BLOCKS + 1);
    const fee = (await feeForNextBlock(chain.tip, async (n) => chain.at(n))).fee;
    let epochCounts = null;
    if (epochHeaders) {
      const { roots } = await prover.request("prefixRoots", { leaves: tree.leaves, from: 0, to: tree.count });
      const countOf = new Map(roots.map((root, count) => [toHex(root), count]));
      epochCounts = epochHeaders.map((header) => {
        const count = countOf.get(toHex(header.coinTreeRoot));
        if (count === undefined) throw new Error(`the endpoint's tree does not match the header of block ${header.number}`);
        return count;
      });
    }
    const epochLeaves = epochCounts ? tree.leaves.slice(0, epochCounts[epochCounts.length - 1] * 32) : tree.leaves;
    progress("looking for the key's coins");
    const { found } = await prover.request("restore", {
      chainId: chain.chainId,
      key,
      records: tree.records,
      markers: spent,
    });
    return { chain, tree, epochHeaders, epochCounts, epochLeaves, fee, found };
  }

  // The tree state to prove `coin` against (spec 02, section 8): the epoch
  // root E of the tip, if the shared epoch rule picks it. It sends no
  // request: the scan fetched everything it reads.
  //
  // The headers are always blocks E - 32 to E, verified and linked to the
  // tip, whatever the coin, so the requests say nothing about where the
  // coin is. The leaf's block is the first of those headers whose tree
  // holds the leaf; for a leaf older than E - 32 that is block E - 32
  // itself, which only makes the rule stricter, never looser.
  async function planReveal(scan, coin) {
    const { chain, epochHeaders: headers, epochCounts: counts, epochLeaves } = scan;
    const { epoch } = chain;
    if (!headers) {
      throw new WaitError(`the first epoch block is block ${EPOCH_BLOCKS}; wait until the chain passes block ${EPOCH_BLOCKS + 12}`);
    }
    progress("choosing the tree state");
    const epochHeader = headers[headers.length - 1];
    const epochCount = counts[counts.length - 1];
    const nextEpoch = epoch + EPOCH_BLOCKS + 12;
    if (epochCount <= coin.position) {
      throw new WaitError(`the coin is newer than epoch block ${epoch}; it can be revealed after block ${nextEpoch}`);
    }
    const leafHeader = headers[counts.findIndex((count) => count > coin.position)];
    scan.askedEpochRule = true;
    const { chosen } = await prover.request("chooseTreeState", {
      tip: chain.tip.number,
      leafHeight: leafHeader.number,
      leafRoot: leafHeader.coinTreeRoot,
      height: epoch,
      root: epochHeader.coinTreeRoot,
    });
    if (!chosen) {
      throw new WaitError(`no commitment followed the coin before epoch block ${epoch}; wait until after block ${nextEpoch}`);
    }
    return {
      root: epochHeader.coinTreeRoot,
      leaves: epochLeaves,
      fee: scan.fee,
      domain: chain.genesis.hash,
    };
  }

  async function waitReceipt(hash) {
    for (let i = 0; i < maxPolls; i += 1) {
      const receipt = await rpc.call("eth_getTransactionReceipt", [hash]);
      if (receipt) {
        if (receipt.transactionHash != null && String(receipt.transactionHash).toLowerCase() !== String(hash).toLowerCase()) {
          throw new Error("the endpoint returned the receipt of another transaction");
        }
        if (quantity(receipt.status) !== 1n) throw new Error("the transaction failed in its block");
        return {
          blockNumber: Number(quantity(receipt.blockNumber)),
          blockHash: receipt.blockHash == null ? null : fromHex(receipt.blockHash, 32),
        };
      }
      await sleep(pollMs);
    }
    throw new Error("no block holds the transaction yet; refresh later");
  }

  // A receipt is the endpoint's word only. A transaction sent when the
  // endpoint's tip was block `sentAfter` can only be in a later block. It
  // counts as settled when the chain shows what it did, with 6 blocks on
  // top: the coin tree as
  // of the tip, checked against the tip's coin root, holds `commitment` (the
  // new leaf every commit, reveal and claim appends) at a position the
  // receipt's block added, read from the coin roots of that block and its
  // parent in the verified header chain that leads to the tip.
  async function waitSettled(hash, commitment, sentAfter) {
    const receipt = await waitReceipt(hash);
    progress("checking the block");
    let top = await blockNumber();
    if (receipt.blockNumber <= sentAfter) {
      throw new Error(`the receipt names block ${receipt.blockNumber}, which was in the chain before the transaction was sent`);
    }
    if (receipt.blockNumber > top) {
      throw new Error(`the receipt names block ${receipt.blockNumber}, not a block of the chain`);
    }
    if (top < receipt.blockNumber + CONFIRMATIONS) progress(`waiting for ${CONFIRMATIONS} blocks on top`);
    for (let i = 0; top < receipt.blockNumber + CONFIRMATIONS; i += 1) {
      if (i >= maxPolls) {
        throw new Error(
          `block ${receipt.blockNumber} has ${top - receipt.blockNumber} of the ${CONFIRMATIONS} blocks on top it needs; refresh later`,
        );
      }
      await sleep(pollMs);
      top = await blockNumber();
    }
    const headers = await headerRange(receipt.blockNumber - 1, top);
    const [parent, block] = headers;
    const tip = headers[headers.length - 1];
    if (receipt.blockHash && toHex(receipt.blockHash) !== toHex(block.hash)) {
      throw new Error(`the receipt's block is not block ${block.number} of the chain`);
    }
    const tree = await fetchTree(tip);
    const { roots } = await prover.request("prefixRoots", { leaves: tree.leaves, from: 0, to: tree.count });
    const countOf = new Map(roots.map((root, count) => [toHex(root), count]));
    const before = countOf.get(toHex(parent.coinTreeRoot));
    const after = countOf.get(toHex(block.coinTreeRoot));
    if (before === undefined || after === undefined) {
      throw new Error(`the endpoint's tree does not match the header of block ${block.number}`);
    }
    const leaf = toHex(commitment);
    for (let position = before; position < after; position += 1) {
      if (toHex(tree.leaves.slice(position * 32, position * 32 + 32)) === leaf) {
        return { blockNumber: block.number, position };
      }
    }
    throw new Error(`block ${block.number} does not hold the transaction's new coin; it has not settled`);
  }

  // The worker's input for a reveal of the key's current coin; throws when
  // there is nothing to prove.
  async function revealArgs(scan, { key, kind, out, recipient, newKey }) {
    const { current } = keyStatus(scan.found);
    if (!current) throw new Error("this key holds no unspent coin");
    const plan = await planReveal(scan, current);
    const paid = (kind === "claim" ? 0n : out) + plan.fee;
    if (paid > current.amount) {
      throw new Error(
        `the coin holds ${formatGhost(current.amount)} GHOST; with the fee of ${formatGhost(plan.fee)} GHOST at most ${formatGhost(current.amount > plan.fee ? current.amount - plan.fee : 0n)} can go out`,
      );
    }
    return {
      chainId: scan.chain.chainId,
      domain: plan.domain,
      kind,
      root: plan.root,
      recipient: fromHex(kind === "claim" ? ZERO_ADDRESS : recipient, 20),
      out: kind === "claim" ? 0n : out,
      fee: plan.fee,
      number: current.number,
      amount: current.amount,
      position: current.position,
      leaves: plan.leaves,
      key,
      newKey,
    };
  }

  // The worker's input for a decoy of the same kind over the same leaves
  // (lib.rs, ghost_prove): a throwaway key's coin of the fee plus 1 wei at
  // the last position, proved as a real reveal would be. The epoch rule is
  // asked once too, as it is for a coin, whenever the scan has epoch headers.
  async function decoyArgs(scan, { kind, recipient }) {
    const { chain, epochHeaders: headers, epochLeaves } = scan;
    if (headers && !scan.askedEpochRule) {
      const epochHeader = headers[headers.length - 1];
      await prover.request("chooseTreeState", {
        tip: chain.tip.number,
        leafHeight: headers[0].number,
        leafRoot: headers[0].coinTreeRoot,
        height: epochHeader.number,
        root: epochHeader.coinTreeRoot,
      });
    }
    const claim = kind === "claim";
    return {
      decoy: true,
      chainId: chain.chainId,
      domain: chain.genesis.hash,
      kind: claim ? "claim" : "partial",
      root: new Uint8Array(32),
      recipient: fromHex(claim ? ZERO_ADDRESS : recipient, 20),
      out: claim ? 0n : 1n,
      fee: scan.fee,
      number: 0n,
      amount: scan.fee + (claim ? 1n : 2n),
      position: Math.max(epochLeaves.length / 32 - 1, 0),
      leaves: epochLeaves,
      key: "",
      newKey: "",
    };
  }

  // Proves a reveal of the key's current coin and sends it. A proof whose
  // fee window lapsed while it was being made is made again.
  //
  // After restore, every path, the one where the key holds no coin
  // included, does the same work and then asks the endpoint the same thing
  // in the same order before anything depends on the outcome. The work is a
  // proof: of the coin when there is one to reveal, otherwise of a decoy
  // (`decoyArgs`), so the time before the next request is a proof's time on
  // every path, the fee retries included. A coin's proof the worker refuses
  // takes a proof's time too: the worker proves a decoy before it answers
  // with the refusal (lib.rs, ghost_prove). The requests are eth_blockNumber,
  // the tip's header and the fee for the next block. Only then does a
  // failure surface, or the reveal go out; sending the reveal is what links
  // the connection to the coin.
  async function revealAndSend(request) {
    for (let attempt = 0; attempt < FEE_ATTEMPTS; attempt += 1) {
      const scan = await scanKey(request.key);
      let args = null;
      let failure = null;
      try {
        args = await revealArgs(scan, request);
      } catch (err) {
        failure = err;
      }
      let proved = null;
      progress("proving in the background worker");
      try {
        const result = await prover.request("prove", args ?? (await decoyArgs(scan, request)), (stage) =>
          progress(stage === "proving" ? "proving in the background worker" : stage),
        );
        if (args) proved = result;
      } catch (err) {
        failure ??= err;
      }
      const tip = await headerAt(await blockNumber());
      const { fee } = await feeForNextBlock(tip, headerAt);
      if (fee !== scan.fee) continue;
      if (failure) throw failure;
      progress("sending the reveal");
      const hash = await rpc.call("eth_sendRawTransaction", [toHex(proved.envelope)]);
      if (String(hash).toLowerCase() !== toHex(proved.txHash)) {
        throw new Error("the endpoint returned another transaction hash");
      }
      return { hash, fee: scan.fee, remainder: proved.remainder, sentAfter: tip.number };
    }
    throw new Error("the fee changed every time a proof was ready; try again");
  }

  async function connect() {
    if (!wallet) throw new Error("no browser wallet found: the app needs one that injects window.ethereum");
    const accounts = await wallet.request({ method: "eth_requestAccounts" });
    if (!Array.isArray(accounts) || accounts.length === 0) throw new Error("the wallet shared no account");
    const chainId = quantity(await wallet.request({ method: "eth_chainId" }));
    state.wallet = { account: String(accounts[0]).toLowerCase(), chainId };
    emit();
    return state.wallet;
  }

  async function refreshSummon() {
    const s = state.summon;
    const scan = await scanKey(s.key);
    const { status, current } = keyStatus(scan.found);
    const { fee } = scan;
    s.coins = scan.found.map(({ number, amount, position, spent }) => ({ number, amount, position, spent }));
    s.status = status;
    s.current = current ? { number: current.number, amount: current.amount, position: current.position } : null;
    s.fee = fee;
    s.available = current && current.amount > fee ? current.amount - fee : 0n;
    s.tip = scan.chain.tip.number;
    emit();
    return s;
  }

  function saveCheckStep(holder) {
    if (!holder || holder.stage !== "shown") throw new Error("show the key first");
    holder.groups = pickGroups(random);
    holder.wrong = [];
    holder.stage = "check";
    emit();
    return holder.groups;
  }

  function requireCheck(holder, answers) {
    if (!holder || holder.stage !== "check") throw new Error("the save check has not started");
    const wrong = wrongGroups(holder.key, holder.groups, answers);
    holder.wrong = wrong;
    emit();
    return wrong;
  }

  return {
    state,

    setEndpoint(text) {
      if (state.busy) throw new Error("wait until the current step is done");
      rpc = createRpc(text, { fetch });
      state.endpoint = rpc.url;
      emit();
      return state.endpoint;
    },

    setCommitEntry(text) {
      const address = parseAddress(text);
      if (address === ZERO_ADDRESS) throw new Error("the commit entry cannot be the zero address: the value would be burned");
      state.commitEntry = address;
      emit();
      return state.commitEntry;
    },

    connectWallet() {
      return run("connecting the wallet", connect);
    },

    // Vanish, step 1: a new standard key for `amountText` GHOST, shown to
    // the user to copy, write down or download.
    vanishStart(amountText) {
      return run("creating a key", async () => {
        const amount = parseGhost(amountText);
        if (amount === 0n) throw new Error("enter an amount above zero");
        const { key } = await prover.request("newKey");
        state.vanish = { stage: "shown", key, amount, groups: null, wrong: [], txHash: null, block: null };
        return key;
      });
    },

    // Vanish, step 2: the user says the key is saved; three groups to re-type.
    vanishSaved() {
      return saveCheckStep(state.vanish);
    },

    // Vanish, step 3: the re-typed groups. Nothing is sent unless all match.
    vanishCheck(answers) {
      return run("sending the commit", async () => {
        const v = state.vanish;
        const wrong = requireCheck(v, answers);
        if (wrong.length > 0) return { ok: false, wrong };
        const account = state.wallet ? state.wallet.account : (await connect()).account;
        const chainId = quantity(await rpc.call("eth_chainId"));
        const walletChain = quantity(await wallet.request({ method: "eth_chainId" }));
        if (walletChain !== chainId) {
          throw new Error(`the wallet is on chain ${walletChain}, the endpoint on chain ${chainId}`);
        }
        progress("building the commit");
        const sentAfter = await blockNumber();
        const commit = await prover.request("commit", { chainId, amount: v.amount, key: v.key });
        progress("waiting for the wallet");
        const txHash = await wallet.request({
          method: "eth_sendTransaction",
          params: [{ from: account, to: state.commitEntry, value: toQuantity(v.amount), data: toHex(commit.payload) }],
        });
        // The user has the key; the app no longer needs it.
        v.key = null;
        v.stage = "pending";
        v.txHash = txHash;
        progress("waiting for a block");
        const receipt = await waitSettled(txHash, commit.commitment, sentAfter);
        v.stage = "confirmed";
        v.block = receipt.blockNumber;
        return { ok: true, txHash, block: receipt.blockNumber };
      });
    },

    vanishCancel() {
      state.vanish = null;
      emit();
    },

    // Summon: enter any valid standard or long key.
    summonOpen(keyText) {
      return run("opening the key", async () => {
        const key = String(keyText).trim();
        const { groups } = await prover.request("checkKey", { key });
        state.summon = { key, groups, status: "scanning", coins: [], current: null, claim: null, lastReveal: null };
        return refreshSummon();
      });
    },

    summonRefresh() {
      return run("reading the key's coins", async () => {
        if (!state.summon) throw new Error("enter a key first");
        return refreshSummon();
      });
    },

    // Summon: reveal `amount` GHOST of the current coin to `recipient`; the
    // rest, minus the fee, stays under the same key.
    summonReveal({ amount, recipient }) {
      return run("revealing", async () => {
        const s = state.summon;
        if (!s || !s.current) throw new Error("this key holds no coin to reveal");
        const out = parseGhost(amount);
        if (out === 0n) throw new Error("enter an amount above zero");
        const to = parseAddress(recipient);
        // A reveal credits its recipient, and nobody can spend what the zero
        // address is credited.
        if (to === ZERO_ADDRESS) throw new Error("the zero address cannot receive a reveal: the amount would be lost");
        const sent = await revealAndSend({ key: s.key, kind: "partial", out, recipient: to });
        s.status = "pending";
        s.lastReveal = { txHash: sent.hash, out, recipient: to, fee: sent.fee, block: null };
        progress("waiting for a block");
        const receipt = await waitSettled(sent.hash, sent.remainder.commitment, sent.sentAfter);
        s.lastReveal.block = receipt.blockNumber;
        await refreshSummon();
        return s.lastReveal;
      });
    },

    // Claim, step 1: a new key for the remaining value, to be saved first.
    claimStart() {
      return run("creating a key", async () => {
        const s = state.summon;
        if (!s || !s.current) throw new Error("this key holds no coin to claim");
        const { key } = await prover.request("newKey");
        s.claim = { stage: "shown", key, groups: null, wrong: [], txHash: null, block: null, amount: null };
        return key;
      });
    },

    claimSaved() {
      return saveCheckStep(state.summon && state.summon.claim);
    },

    // Claim, step 3: with the new key's groups re-typed, move the coin's
    // value minus the fee to the new key, and wait for its block. The old
    // key stays unclaimed until the chain shows the new key's coin.
    claimCheck(answers) {
      return run("claiming", async () => {
        const s = state.summon;
        const c = s && s.claim;
        const wrong = requireCheck(c, answers);
        if (wrong.length > 0) return { ok: false, wrong };
        const sent = await revealAndSend({ key: s.key, kind: "claim", out: 0n, newKey: c.key });
        c.key = null;
        c.stage = "pending";
        c.txHash = sent.hash;
        c.amount = sent.remainder.amount;
        progress("waiting for a block");
        const receipt = await waitSettled(sent.hash, sent.remainder.commitment, sent.sentAfter);
        c.stage = "confirmed";
        c.block = receipt.blockNumber;
        await refreshSummon();
        return { ok: true, txHash: sent.hash, block: receipt.blockNumber, amount: sent.remainder.amount };
      });
    },

    summonClose() {
      state.summon = null;
      emit();
    },
  };
}

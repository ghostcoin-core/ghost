// The pop-up wallet's logic, apart from the page: the requests it answers
// (the four account requests and the four of Ghost Guard) and their strict
// checks, the encrypted vault, the count of issued
// receive addresses, the scheme of each account, and the order of the
// screens. main.mjs gives it the browser's objects; the tests give fakes.
//
// New accounts are rescue-key accounts (spec 09, section 5, scheme 0x0003),
// signed with their ML-DSA-44 key; ghost_rescue signs with their SLH-DSA key
// alone (scheme 0x0004) and calls nothing of ML-DSA signing. Accounts a
// wallet issued before rescue keys stay scheme 0x0001 and have no rescue key.
//
// The words of the wallet seed are the only secret. They are stored only
// encrypted (AES-256-GCM, under a key from a passkey's PRF output or from a
// password), and decrypted for one request at a time into a byte array
// that is overwritten with zeros once used. No JavaScript string of them is
// made after the backup screens.
//
// Ghost Guard (spec 10, sections 3.1, 12 and 13): ghost_guardCommit makes a
// new Phantom Key in the wallet, commits to it under a Guard rule and signs
// the commit; ghost_guardSpend is the normal spend with the override;
// ghost_guardWordsOnlySpend sweeps a Guard coin into Guard's escrow slot with
// the Phantom Key's words alone; ghost_guardRestore lists the coins of typed
// Phantom Key words. The guard secret is derived by the module from the
// wallet seed's words (number GUARD_INDEX); the stop root is what the user
// types from the stop card on the approval screen. Neither comes from a
// Phantom Key, and neither is stored. The Phantom Key is typed (or, for a
// commit, shown) in the wallet, never taken from the app.

import { concat, toHex, toQuantity, word } from "../../webapp/src/bytes.mjs";
import { LEAF_RECORD_BYTES, SALT_BYTES } from "../../webapp/src/wasm.mjs";
import { CHAIN_IDS, COMMIT_ENTRIES, GUARD_POLICIES } from "./config.mjs";

export const GET_ACCOUNT = "ghost_getAccount";
export const SIGN_TRANSACTION = "ghost_signTransaction";
export const NEW_RECEIVE_ADDRESS = "ghost_newReceiveAddress";
export const RESCUE = "ghost_rescue";
export const GUARD_COMMIT = "ghost_guardCommit";
export const GUARD_SPEND = "ghost_guardSpend";
export const GUARD_WORDS_ONLY_SPEND = "ghost_guardWordsOnlySpend";
export const GUARD_RESTORE = "ghost_guardRestore";
// The guard secret of every Guard coin of this wallet: number 0 of its seed.
// Each coin's own fresh action salt keeps the coins' rules apart.
export const GUARD_INDEX = 0;

// The two warnings of spec 10, section 12, and the third case of the second.
export const WARN_HANDED_OVER =
  "A Guard coin handed over as its words alone stays under the giver's stop key: the giver's stop card can cancel the receiver's words-only spend. Hand a Guard coin over with a transfer instead.";
export const WARN_SLOT_TOO_SMALL =
  "This coin is not larger than the cost of a cancel at this base fee: a words-only spend of it puts less in Guard's slot than a cancel costs, so the stop card could not stop it.";
export const WARN_COST_UNKNOWN = "The cost of a cancel is unknown at a base fee of zero, so this coin's size against it cannot be checked.";
export const USER_REJECTED = 4001;
// The status line once a request is refused at its first check.
export const REFUSED_STATUS = "This request was refused. Nothing was signed.";
// The window's and tab's title while a request waits for the user.
export const ASKING_TITLE = "Ghost app is asking: approve below";
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;

export const PBKDF2_ITERATIONS = 600_000;
const MIN_PASSWORD = 8;
const ACCOUNT_INDEX = 0;
const U32_MAX = 0xffffffff;
const HKDF_INFO = "ghost wallet vault";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// An answer with an error code and a message that names what is wrong.
class Refused extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const refuse = (message) => new Refused(INVALID_PARAMS, message);

// The fields of ghost_signTransaction, each 0x hex, as the web app's
// snapTransaction writes them, and `from`, which may be left out (account 0).
const SIGN_FIELDS = ["chainId", "genesisHash", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit", "to", "value", "data"];
const SIGN_OPTIONAL = ["from"];
// The fields of ghost_rescue: those of ghost_signTransaction without `to`,
// `value` and `data`, and `balance`, the account's balance in wei as the app
// read it from the node. The destination is typed in the wallet, never
// taken from the request.
const RESCUE_FIELDS = ["chainId", "genesisHash", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit", "balance"];
// Ghost Guard. The Guard policy (address and code hash) and the commit entry
// are the wallet's own, by chain (config.mjs), never the app's: a request
// that names a policy is refused as an unknown field. The tree data is what
// the app read from its node: the leaves with their notes (412 bytes each,
// from position 0, 0x hex), the salt beside each (16 bytes of 0x hex, or
// null), the spent markers (32 bytes each).
const TREE_FIELDS = ["leaves", "salts", "markers"];
const ROOM_FIELDS = ["filledLeaves", "leavesPerBlock"];
// A Guard commit: the fields of ghost_signTransaction without `data`, which
// the wallet makes (`to` must be the chain's trusted commit entry, `value` is
// the amount), the tree room and the base fee of the cost of a cancel.
const GUARD_COMMIT_FIELDS = ["chainId", "genesisHash", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit", "to", "value", ...ROOM_FIELDS, "baseFee"];
const GUARD_SPEND_FIELDS = ["chainId", "genesisHash", ...TREE_FIELDS, "recipient", "out", "fee", "remainder", ...ROOM_FIELDS];
const GUARD_WORDS_ONLY_FIELDS = ["chainId", "genesisHash", ...TREE_FIELDS, "recipient", "fee", "baseFee"];
const GUARD_RESTORE_FIELDS = ["chainId", "treeIndex", ...TREE_FIELDS];

// What the wallet trusts for Guard, by chain id (decimal string): the coin
// commit entry and the Guard policy { address, codehash } (0x hex). The
// defaults are config.mjs's; only the tests give others.
export const TRUSTED_GUARD = Object.freeze({ commitEntries: COMMIT_ENTRIES, policies: GUARD_POLICIES });
const REMAINDER_RULES = ["plain", "guard"];

// The account schemes (spec 09, section 5): plain ML-DSA-44, the rescue-key
// account every new account is, and the rescue signature of the latter.
export const SCHEME_PLAIN = "0x0001";
export const SCHEME_RESCUE_KEY = "0x0003";
export const SCHEME_RESCUE = "0x0004";
const U64_MAX = (1n << 64n) - 1n;
const U256_MAX = (1n << 256n) - 1n;

function exactKeys(object, keys, what, optional = []) {
  if (!object || typeof object !== "object" || Array.isArray(object)) throw refuse(`${what} is not an object`);
  for (const key of Object.keys(object)) if (!keys.includes(key) && !optional.includes(key)) throw refuse(`unknown field ${key}`);
  for (const key of keys) if (!Object.hasOwn(object, key)) throw refuse(`missing field ${key}`);
}

function quantityField(params, name, max) {
  const text = params[name];
  if (typeof text !== "string" || !/^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(text)) {
    throw refuse(`${name} is not a 0x quantity without leading zeros`);
  }
  const value = BigInt(text);
  if (value > max) throw refuse(`${name} is too large`);
  return value;
}

// 0x hex bytes; exactly `length` bytes when given.
function bytesField(params, name, length) {
  const text = params[name];
  if (typeof text !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(text) || (length !== undefined && text.length !== 2 + 2 * length)) {
    throw refuse(length === undefined ? `${name} is not 0x hex bytes` : `${name} is not ${length} bytes of 0x hex`);
  }
  const out = new Uint8Array((text.length - 2) / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(2 + 2 * i, 4 + 2 * i), 16);
  return out;
}

// A request as posted by the web app, checked before the user sees
// anything: { id, method } or { id, method, params }. Returns { id, method,
// fields }, or throws a Refused naming the field. `trust`: the wallet's own
// Guard settings (TRUSTED_GUARD).
export function checkRequest(message, trust = TRUSTED_GUARD) {
  if (!message || typeof message !== "object" || Array.isArray(message)) throw refuse("the request is not an object");
  if (!Number.isSafeInteger(message.id) || message.id < 0) throw refuse("id is not a whole number");
  if (message.method === GET_ACCOUNT) {
    exactKeys(message, ["id", "method"], "the request");
    return { id: message.id, method: GET_ACCOUNT, fields: null };
  }
  if (message.method === NEW_RECEIVE_ADDRESS) {
    exactKeys(message, ["id", "method"], "the request");
    return { id: message.id, method: NEW_RECEIVE_ADDRESS, fields: null };
  }
  if (message.method === RESCUE) return { id: message.id, method: RESCUE, fields: checkRescue(message) };
  const guard = GUARD_CHECKS[message.method];
  if (guard) {
    exactKeys(message, ["id", "method", "params"], "the request");
    return { id: message.id, method: message.method, fields: guard(message.params, trust) };
  }
  if (message.method !== SIGN_TRANSACTION) throw new Refused(METHOD_NOT_FOUND, `unknown method ${String(message.method)}`);
  exactKeys(message, ["id", "method", "params"], "the request");
  const p = message.params;
  exactKeys(p, SIGN_FIELDS, "params", SIGN_OPTIONAL);
  const fields = {
    // The address that signs: account 0 when left out.
    from: Object.hasOwn(p, "from") ? bytesField(p, "from", 20) : null,
    chainId: quantityField(p, "chainId", U64_MAX),
    genesis: bytesField(p, "genesisHash", 32),
    nonce: quantityField(p, "nonce", U64_MAX),
    maxPriorityFeePerGas: quantityField(p, "maxPriorityFeePerGas", U256_MAX),
    maxFeePerGas: quantityField(p, "maxFeePerGas", U256_MAX),
    gasLimit: quantityField(p, "gasLimit", U64_MAX),
    // Always an address: the wallet signs no contract creation.
    to: bytesField(p, "to", 20),
    value: quantityField(p, "value", U256_MAX),
    data: bytesField(p, "data"),
  };
  if (!CHAIN_IDS.includes(fields.chainId)) throw refuse(`chainId ${fields.chainId} is not a network this wallet signs for`);
  if (fields.maxPriorityFeePerGas > fields.maxFeePerGas) throw refuse("maxPriorityFeePerGas is above maxFeePerGas");
  return { id: message.id, method: SIGN_TRANSACTION, fields };
}

// The params of ghost_rescue: a `to`, `value` or `data` is an unknown field,
// and the balance must pay the most the gas can cost with something left
// to move.
function checkRescue(message) {
  exactKeys(message, ["id", "method", "params"], "the request");
  const p = message.params;
  exactKeys(p, RESCUE_FIELDS, "params", SIGN_OPTIONAL);
  const fields = {
    from: Object.hasOwn(p, "from") ? bytesField(p, "from", 20) : null,
    chainId: quantityField(p, "chainId", U64_MAX),
    genesis: bytesField(p, "genesisHash", 32),
    nonce: quantityField(p, "nonce", U64_MAX),
    maxPriorityFeePerGas: quantityField(p, "maxPriorityFeePerGas", U256_MAX),
    maxFeePerGas: quantityField(p, "maxFeePerGas", U256_MAX),
    gasLimit: quantityField(p, "gasLimit", U64_MAX),
    balance: quantityField(p, "balance", U256_MAX),
  };
  if (!CHAIN_IDS.includes(fields.chainId)) throw refuse(`chainId ${fields.chainId} is not a network this wallet signs for`);
  if (fields.maxPriorityFeePerGas > fields.maxFeePerGas) throw refuse("maxPriorityFeePerGas is above maxFeePerGas");
  fields.maxFee = fields.gasLimit * fields.maxFeePerGas;
  if (fields.balance <= fields.maxFee) throw refuse("balance does not cover gasLimit * maxFeePerGas with anything left to move");
  fields.value = fields.balance - fields.maxFee;
  return fields;
}

function chainIdField(p) {
  const chainId = quantityField(p, "chainId", U64_MAX);
  if (!CHAIN_IDS.includes(chainId)) throw refuse(`chainId ${chainId} is not a network this wallet signs for`);
  return chainId;
}

// The trusted value of chain `chainId` in `table`, or undefined.
const trustedFor = (table, chainId) => (Object.hasOwn(table, String(chainId)) ? table[String(chainId)] : undefined);

// The Guard policy this wallet trusts on `chainId`: never one an app names.
// A chain with none is refused, so no Guard coin is made, spent or named
// under a policy the wallet has not checked.
function trustedPolicy(chainId, trust) {
  const policy = trustedFor(trust.policies, chainId);
  if (!policy) throw refuse(`this wallet has no trusted Guard policy for chainId ${chainId}`);
  return {
    address: bytesField({ address: policy.address }, "address", 20),
    codehash: bytesField({ codehash: policy.codehash }, "codehash", 32),
  };
}

// A Guard commit's `to`, which must be the chain's trusted coin commit entry:
// anything else would credit the amount to that account and make no coin.
function commitEntryField(p, chainId, trust) {
  const to = bytesField(p, "to", 20);
  const entry = trustedFor(trust.commitEntries, chainId);
  if (!entry) throw refuse(`this wallet has no trusted commit entry for chainId ${chainId}`);
  if (toHex(to) !== entry.toLowerCase()) throw refuse(`to is not the commit entry of chainId ${chainId}`);
  return to;
}

function roomField(p) {
  return { filledLeaves: quantityField(p, "filledLeaves", U64_MAX), leavesPerBlock: quantityField(p, "leavesPerBlock", U64_MAX) };
}

// The tree data: whole leaf records, one salt (or null) per leaf, whole
// markers.
function treeField(p) {
  const records = bytesField(p, "leaves");
  if (records.length % LEAF_RECORD_BYTES !== 0) throw refuse(`leaves is not whole records of a leaf and its note (${LEAF_RECORD_BYTES} bytes each)`);
  const count = records.length / LEAF_RECORD_BYTES;
  if (!Array.isArray(p.salts) || p.salts.length !== count) throw refuse("salts is not one entry per leaf");
  const salts = p.salts.map((salt, i) => (salt === null ? null : bytesField({ [`salts[${i}]`]: salt }, `salts[${i}]`, SALT_BYTES)));
  const markers = bytesField(p, "markers");
  if (markers.length % 32 !== 0) throw refuse("markers is not whole 32-byte markers");
  return { records, salts, markers };
}

// The params of each Guard request, checked before any screen.
const GUARD_CHECKS = {
  [GUARD_COMMIT](p, trust) {
    exactKeys(p, GUARD_COMMIT_FIELDS, "params", SIGN_OPTIONAL);
    const chainId = chainIdField(p);
    const policy = trustedPolicy(chainId, trust);
    const fields = {
      from: Object.hasOwn(p, "from") ? bytesField(p, "from", 20) : null,
      chainId,
      genesis: bytesField(p, "genesisHash", 32),
      nonce: quantityField(p, "nonce", U64_MAX),
      maxPriorityFeePerGas: quantityField(p, "maxPriorityFeePerGas", U256_MAX),
      maxFeePerGas: quantityField(p, "maxFeePerGas", U256_MAX),
      gasLimit: quantityField(p, "gasLimit", U64_MAX),
      to: commitEntryField(p, chainId, trust),
      value: quantityField(p, "value", U256_MAX),
      policy,
      room: roomField(p),
      baseFee: quantityField(p, "baseFee", U256_MAX),
    };
    if (fields.maxPriorityFeePerGas > fields.maxFeePerGas) throw refuse("maxPriorityFeePerGas is above maxFeePerGas");
    if (fields.value === 0n) throw refuse("value is zero: a Guard coin holds at least 1 wei");
    return fields;
  },
  [GUARD_SPEND](p, trust) {
    exactKeys(p, GUARD_SPEND_FIELDS, "params");
    if (!REMAINDER_RULES.includes(p.remainder)) throw refuse('remainder is not "plain" or "guard"');
    const chainId = chainIdField(p);
    return {
      chainId,
      domain: bytesField(p, "genesisHash", 32),
      policy: trustedPolicy(chainId, trust),
      ...treeField(p),
      recipient: bytesField(p, "recipient", 20),
      out: quantityField(p, "out", U256_MAX),
      fee: quantityField(p, "fee", U256_MAX),
      remainder: p.remainder,
      room: roomField(p),
    };
  },
  [GUARD_WORDS_ONLY_SPEND](p, trust) {
    exactKeys(p, GUARD_WORDS_ONLY_FIELDS, "params");
    const chainId = chainIdField(p);
    return {
      chainId,
      domain: bytesField(p, "genesisHash", 32),
      policy: trustedPolicy(chainId, trust),
      ...treeField(p),
      recipient: bytesField(p, "recipient", 20),
      fee: quantityField(p, "fee", U256_MAX),
      baseFee: quantityField(p, "baseFee", U256_MAX),
    };
  },
  [GUARD_RESTORE](p, trust) {
    exactKeys(p, GUARD_RESTORE_FIELDS, "params");
    const chainId = chainIdField(p);
    return { chainId, policy: trustedPolicy(chainId, trust), treeIndex: Number(quantityField(p, "treeIndex", 0xffffffffn)), ...treeField(p) };
  },
};

// The warnings to show, from the module's flags.
function warningTexts(warnings) {
  const out = [];
  if (warnings.handedOverAsWords) out.push(WARN_HANDED_OVER);
  if (warnings.slotNotAboveActionCost) out.push(WARN_SLOT_TOO_SMALL);
  if (warnings.actionCostUnknown) out.push(WARN_COST_UNKNOWN);
  return out;
}

// A stop root as typed from the stop card: 32 bytes of hex, with or without
// 0x, spaces around ignored. Checked after the approval, before anything is
// built; the module refuses 32 zero bytes.
function stopRootField(typed) {
  const text = typeof typed === "string" ? typed.trim() : "";
  const hex = text.startsWith("0x") || text.startsWith("0X") ? text.slice(2) : text;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw refuse("the stop root is not 32 bytes of hex");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// An amount in wei as GHOST (18 decimals), every digit kept.
export function formatGhost(wei) {
  const whole = wei / 10n ** 18n;
  const fraction = (wei % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

function u32(n) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

function u64(n) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

// The scheme of account `index` of a wallet whose rescue-key accounts start
// at `rescueFrom` (the "accounts" record): 0x0001 below it, 0x0003 from it.
const schemeOf = (index, rescueFrom) => (index < rescueFrom ? SCHEME_PLAIN : SCHEME_RESCUE_KEY);

// The wasm calls with the words as bytes, in the input layout of
// webapp/src/wasm.mjs (walletAccount, walletRescueAccount, walletSign and
// the rescue signing calls): Ghost.call overwrites its input with zeros, and
// the module its own copy.
function account(ghost, words, index, scheme = SCHEME_PLAIN) {
  const name = scheme === SCHEME_PLAIN ? "ghost_wallet_account" : "ghost_wallet_rescue_account";
  const out = ghost.call(name, concat([u32(words.length), words, u32(index)]));
  return { address: out.slice(0, 20), publicKey: out.slice(20), scheme };
}

// An account as a reply carries it.
function shown({ address, publicKey, scheme }) {
  return { address: toHex(address), publicKey: toHex(publicKey), scheme, rescueKey: scheme === SCHEME_RESCUE_KEY };
}

// The module call that signs with `scheme`: 0x0004 is the rescue signature,
// with the SLH-DSA key alone.
const SIGN_CALLS = {
  [SCHEME_PLAIN]: "ghost_wallet_sign",
  [SCHEME_RESCUE_KEY]: "ghost_wallet_sign_rescue_key",
  [SCHEME_RESCUE]: "ghost_wallet_sign_rescue",
};

function sign(ghost, words, index, f, randomness, scheme) {
  const input = concat([
    u32(words.length),
    words,
    u32(index),
    u64(f.chainId),
    f.genesis,
    u64(f.nonce),
    word(f.maxPriorityFeePerGas),
    word(f.maxFeePerGas),
    u64(f.gasLimit),
    Uint8Array.of(1),
    f.to,
    word(f.value),
    u32(f.data.length),
    f.data,
    randomness,
  ]);
  randomness.fill(0);
  const out = ghost.call(SIGN_CALLS[scheme], input);
  return { txHash: out.slice(0, 32), sender: out.slice(32, 52), envelope: out.slice(52) };
}

// The vault in IndexedDB on the wallet's origin: one record, written once
// (add refuses to replace it), read for every request. Beside it, under the
// key "issued", `{ count }`: how many receive addresses (accounts 1 to
// count) ghost_newReceiveAddress has handed out. Public data only, replaced
// on each new address. Under the key "accounts", `{ rescueFrom }`: accounts
// below that index are scheme 0x0001, from it up scheme 0x0003. A new vault
// is written with `{ rescueFrom: 0 }` in the same transaction; a vault from
// before rescue keys has none until the wallet's first request writes it.
export function vaultStore(indexedDB) {
  function open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open("ghost-wallet", 1);
      req.onupgradeneeded = () => req.result.createObjectStore("vault");
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function run(mode, act) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("vault", mode);
      const req = act(tx.objectStore("vault"));
      tx.oncomplete = () => {
        db.close();
        resolve(req.result);
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  }
  return {
    get: () => run("readonly", (s) => s.get("vault")),
    add: (record) => run("readwrite", (s) => s.add(record, "vault")),
    // A new vault and its "accounts" record, every account scheme 0x0003.
    create: (record) =>
      run("readwrite", (s) => {
        const req = s.add(record, "vault");
        s.add({ rescueFrom: 0 }, "accounts");
        return req;
      }),
    // The first rescue-key account index, or undefined for a vault stored
    // before rescue keys.
    async getRescueFrom() {
      const record = await run("readonly", (s) => s.get("accounts"));
      if (record === undefined) return undefined;
      if (!Number.isSafeInteger(record?.rescueFrom) || record.rescueFrom < 0 || record.rescueFrom > U32_MAX) {
        throw new Error("the accounts record is damaged");
      }
      return record.rescueFrom;
    },
    putRescueFrom: (rescueFrom) => run("readwrite", (s) => s.put({ rescueFrom }, "accounts")),
    async getIssued() {
      const record = await run("readonly", (s) => s.get("issued"));
      if (record === undefined) return 0;
      if (!Number.isSafeInteger(record?.count) || record.count < 0 || record.count >= U32_MAX) throw new Error("the issued count is damaged");
      return record.count;
    },
    putIssued: (count) => run("readwrite", (s) => s.put({ count }, "issued")),
  };
}

// The AES-256-GCM key of a vault record from its secret: password bytes
// through PBKDF2-SHA-256, or a passkey's PRF output through HKDF-SHA-256.
// The key cannot be read back out of WebCrypto.
async function vaultKey(subtle, record, secret) {
  const password = record.kind === "password";
  const base = await subtle.importKey("raw", secret, password ? "PBKDF2" : "HKDF", false, ["deriveKey"]);
  secret.fill(0);
  const params = password
    ? { name: "PBKDF2", hash: "SHA-256", salt: record.salt, iterations: record.iterations }
    : { name: "HKDF", hash: "SHA-256", salt: record.salt, info: encoder.encode(HKDF_INFO) };
  return subtle.deriveKey(params, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

// The wallet behind the page. `ghost`: the loaded module (wasm.mjs);
// `store`: vaultStore; `ui`: the screens (main.mjs), whose optional
// `attention(title)` focuses the window and sets its title for a request
// (null: the request is answered, the title goes back); `subtle`: WebCrypto;
// `credentials`: navigator.credentials, or null without passkeys; `random(n)`:
// n bytes from crypto.getRandomValues; `origins`: the web app origins;
// `opener`: the window that opened the pop-up. `guard`: the trusted Guard
// settings, config.mjs's unless a test gives others; never from a request.
export function createWallet({ ghost, store, ui, subtle, credentials, random, origins, opener, guard = TRUSTED_GUARD }) {
  let queue = Promise.resolve();

  // The passkey's PRF output for the record's salt; the user touches the
  // passkey. Only its PRF is used, never its signature.
  async function passkeySecret(record) {
    const credential = await credentials.get({
      publicKey: {
        challenge: random(32),
        allowCredentials: [{ type: "public-key", id: record.credentialId }],
        userVerification: "required",
        extensions: { prf: { eval: { first: record.salt } } },
      },
    });
    const first = credential && credential.getClientExtensionResults().prf?.results?.first;
    if (!first) throw new Error("the passkey gave no secret");
    return new Uint8Array(first);
  }

  async function createPasskey() {
    const credential = await credentials.create({
      publicKey: {
        rp: { name: "Ghost wallet" },
        user: { id: random(16), name: "Ghost wallet", displayName: "Ghost wallet" },
        challenge: random(32),
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: { userVerification: "required" },
        extensions: { prf: {} },
      },
    });
    if (!credential || !credential.getClientExtensionResults().prf?.enabled) {
      throw new Error("this passkey cannot protect a wallet");
    }
    return new Uint8Array(credential.rawId);
  }

  // Encrypts `words` under `lock` and stores only the ciphertext, its salt,
  // IV and parameters.
  async function seal(words, lock) {
    const salt = random(16);
    const record =
      lock.kind === "password"
        ? { version: 1, kind: "password", salt, iterations: PBKDF2_ITERATIONS }
        : { version: 1, kind: "passkey", salt, credentialId: await createPasskey() };
    const secret = lock.kind === "password" ? encoder.encode(lock.password) : await passkeySecret(record);
    const key = await vaultKey(subtle, record, secret);
    const iv = random(12);
    const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, words));
    await store.create({ ...record, iv, ciphertext });
  }

  // The words of a stored record; throws on a wrong password or passkey.
  async function unseal(record, password) {
    if (record.version !== 1) throw new Error("unknown vault version");
    if (record.kind === "password" && !(record.iterations >= PBKDF2_ITERATIONS)) throw new Error("too few PBKDF2 iterations");
    const secret = record.kind === "password" ? encoder.encode(String(password)) : await passkeySecret(record);
    const key = await vaultKey(subtle, record, secret);
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: record.iv }, key, record.ciphertext));
  }

  // Three distinct word positions, 1 to 24, uniformly at random.
  function positions() {
    const picked = [];
    while (picked.length < 3) {
      const [b] = random(1);
      const p = (b % 24) + 1;
      if (b < 240 && !picked.includes(p)) picked.push(p);
    }
    return picked.sort((a, b) => a - b);
  }

  // The words shown once, then three of them typed back; nothing is stored
  // until they match.
  async function backup(words) {
    const list = decoder.decode(words).split(" ");
    for (;;) {
      await ui.showWords(list);
      const asked = positions();
      const typed = await ui.checkWords(asked);
      if (asked.every((p, i) => String(typed[i] ?? "").trim().toLowerCase() === list[p - 1])) return;
      ui.error("Those words do not match your backup. Look at your words again.");
    }
  }

  async function restore() {
    for (;;) {
      const text = String(await ui.restoreWords()).trim().toLowerCase().split(/\s+/).join(" ");
      const words = encoder.encode(text);
      try {
        account(ghost, words, ACCOUNT_INDEX);
        return words;
      } catch {
        words.fill(0);
        ui.error("These are not the 24 words of a Ghost wallet. Check each word.");
      }
    }
  }

  async function chooseLock() {
    for (;;) {
      const lock = await ui.chooseLock(Boolean(credentials));
      if (lock.kind === "passkey" && credentials) return lock;
      if (lock.kind === "password" && lock.password.length >= MIN_PASSWORD && lock.password === lock.again) return lock;
      ui.error(lock.kind === "password" && lock.password !== lock.again ? "The two passwords differ." : `Use a password of ${MIN_PASSWORD} characters or more.`);
    }
  }

  // A new wallet (32 random bytes made words by the module, and the backup
  // check) or one restored from its words, sealed and stored.
  async function setup() {
    const creating = (await ui.start()) === "create";
    // Ghost.call overwrites the 32 random bytes with zeros.
    const words = creating ? ghost.call("ghost_wallet_new", random(32)) : await restore();
    try {
      if (creating) await backup(words);
      for (;;) {
        try {
          await seal(words, await chooseLock());
          return;
        } catch (err) {
          ui.error(`The wallet could not be protected: ${err.message}. Try again.`);
        }
      }
    } finally {
      words.fill(0);
    }
  }

  async function vault() {
    const record = await store.get();
    if (record) return record;
    await setup();
    return store.get();
  }

  // The first rescue-key account index. A vault stored before rescue keys
  // gets it now: its issued accounts stay 0x0001, the next ones are 0x0003.
  // Before any vault, 0: setup stores that with the vault.
  async function rescueFrom() {
    const stored = await store.getRescueFrom();
    if (stored !== undefined) return stored;
    if (!(await store.get())) return 0;
    const from = (await store.getIssued()) + 1;
    await store.putRescueFrom(from);
    return from;
  }

  // Shows `summary`, waits for Approve and the unlock, and runs `use` on
  // the decrypted words and the screen's answer, the words overwritten with
  // zeros after. Reject signs nothing.
  async function approved(summary, use) {
    const record = await vault();
    for (;;) {
      const answer = await ui.approve(summary, record.kind);
      if (!answer) throw new Refused(USER_REJECTED, "the request was rejected in the wallet");
      let words;
      try {
        words = await unseal(record, answer.password);
      } catch {
        ui.error(record.kind === "password" ? "Wrong password." : "The passkey did not unlock the wallet.");
        continue;
      }
      try {
        // Awaited, so the words are zeroed only once `use` has finished.
        return await use(words, answer);
      } finally {
        words.fill(0);
      }
    }
  }

  // The 0x addresses of account 0 and the issued accounts, by index, as
  // derived while this window was unlocked: public data, kept in memory
  // only, so a `from` can be checked before any screen.
  const addresses = new Map();

  // Derives the accounts 0 to `count` not yet known, each with its scheme.
  function learn(words, count, first) {
    for (let index = 0; index <= count; index += 1) {
      if (!addresses.has(index)) addresses.set(index, toHex(account(ghost, words, index, schemeOf(index, first)).address));
    }
  }

  // The index of `from` among accounts 0 to `count`: a number, null when it
  // is none of them, or undefined while some are not yet known.
  function indexOf(from, count) {
    let complete = true;
    for (let index = 0; index <= count; index += 1) {
      if (!addresses.has(index)) complete = false;
      else if (addresses.get(index) === from) return index;
    }
    return complete ? null : undefined;
  }

  const notIssued = () => refuse("from is not an address this wallet issued");

  const noRescueKey = () => refuse("this account has no rescue key");

  // A typed rescue destination: 20 bytes of 0x hex, and not the account
  // itself. Checked after the approval, before anything is signed.
  function destination(typed, sender) {
    const text = typeof typed === "string" ? typed.trim() : typed;
    const to = bytesField({ destination: text }, "destination", 20);
    if (toHex(to) === sender) throw refuse("the destination is the account itself");
    return to;
  }

  const rejected = () => new Refused(USER_REJECTED, "the request was rejected in the wallet");

  // A module call whose refusal is the request's: its message names why.
  function guarded(call) {
    try {
      return call();
    } catch (err) {
      throw err instanceof Refused ? err : refuse(err.message);
    }
  }

  // The Phantom Key of a Guard request, typed in the wallet (words or
  // digits), checked by the module before anything is derived from it; asked
  // again until it is one. Reject refuses the request.
  async function typedKey(summary) {
    for (;;) {
      const typed = await ui.guardKey(summary);
      if (typed === null || typed === undefined) throw rejected();
      const text = String(typed).trim();
      try {
        ghost.checkKey(text);
        return text;
      } catch {
        ui.error("These are not the words or digits of a Phantom Key. Check each word.");
      }
    }
  }

  // The coins of `key` in the tree the app gave, each named by its rule.
  const guardCoins = (f, key) =>
    guarded(() =>
      ghost.guardRestore({ chainId: f.chainId, treeIndex: f.treeIndex ?? 0, policy: f.policy, key, records: f.records, salts: f.salts, markers: f.markers }),
    );

  // The key's latest unspent Guard coin of the policy.
  function unspentGuardCoin(f, key) {
    const coin = guardCoins(f, key)
      .filter((c) => c.rule === "guard" && !c.spent)
      .at(-1);
    if (!coin) throw refuse("these words hold no unspent Guard coin of this policy in the tree given");
    return coin;
  }

  // The new Phantom Key of a Guard commit, shown once with the warnings, and
  // three of its words typed back before the commit is signed.
  async function keyBackup(key, warnings) {
    const list = key.split(" ");
    for (;;) {
      await ui.showKey(list, warnings);
      const asked = positions();
      const typed = await ui.checkKey(asked);
      if (asked.every((p, i) => String(typed[i] ?? "").trim().toLowerCase() === list[p - 1])) return;
      ui.error("Those words do not match your Phantom Key. Look at it again.");
    }
  }

  // ghost_guardRestore: the coins of the typed words, listed in the wallet
  // with the warning of each coin that has a rule. Nothing is unlocked: the
  // words alone restore.
  async function guardRestore(f, origin) {
    const key = await typedKey({ kind: "guardRestore", origin });
    const coins = guardCoins(f, key);
    await ui.showCoins(
      coins.map((c) => ({
        number: String(c.number),
        amount: formatGhost(c.amount),
        position: c.position,
        spent: c.spent,
        rule: c.rule,
        warnings: c.handedOverAsWords ? [WARN_HANDED_OVER] : [],
      })),
    );
    return {
      coins: coins.map((c) => ({
        number: toQuantity(c.number),
        amount: toQuantity(c.amount),
        position: c.position,
        marker: toHex(c.marker),
        spent: c.spent,
        rule: c.rule,
      })),
    };
  }

  // ghost_guardSpend: the normal spend of the typed key's Guard coin, with
  // the override opened by this wallet's guard secret; the remainder is
  // plain or under a new Guard rule of the stop root typed on approval.
  async function guardSpend(f, origin) {
    const key = await typedKey({ kind: "guardSpend", origin });
    const coin = unspentGuardCoin(f, key);
    if (coin.amount < f.out + f.fee) throw refuse("out and fee are more than the coin holds");
    const summary = {
      kind: "guardSpend",
      origin,
      amount: formatGhost(coin.amount),
      out: formatGhost(f.out),
      fee: formatGhost(f.fee),
      recipient: toHex(f.recipient),
      remainder: formatGhost(coin.amount - f.out - f.fee),
      remainderRule: f.remainder,
      chainId: String(f.chainId),
    };
    return approved(summary, (words, approval) => {
      const stopRoot = f.remainder === "guard" ? stopRootField(approval.stopRoot) : null;
      try {
        const built = guarded(() =>
          ghost.guardSpend({
            chainId: f.chainId,
            domain: f.domain,
            policy: f.policy,
            walletWords: words,
            guardIndex: GUARD_INDEX,
            key,
            records: f.records,
            salts: f.salts,
            position: coin.position,
            recipient: f.recipient,
            out: f.out,
            fee: f.fee,
            remainder: stopRoot ? { stopRoot, room: f.room } : null,
            seed: random(32),
            zk: random(32),
          }),
        );
        return {
          txHash: toHex(built.txHash),
          marker: toHex(built.marker),
          envelope: toHex(built.envelope),
          remainder: { commitment: toHex(built.remainder.commitment), number: toQuantity(built.remainder.number), amount: toQuantity(built.remainder.amount) },
        };
      } finally {
        stopRoot?.fill(0);
      }
    });
  }

  // ghost_guardWordsOnlySpend: the typed key's Guard coin, less the fee,
  // into Guard's escrow slot for the recipient after the hold. It needs the
  // words alone: nothing is unlocked, no guard secret and no stop root.
  async function guardWordsOnlySpend(f, origin) {
    const key = await typedKey({ kind: "guardWordsOnly", origin });
    const coin = unspentGuardCoin(f, key);
    if (coin.amount <= f.fee) throw refuse("the fee is not less than the coin holds: nothing would go to the slot");
    const slot = coin.amount - f.fee;
    const check = guarded(() => ghost.guardCheck({ policy: f.policy, amount: slot, baseFee: f.baseFee }));
    const summary = {
      kind: "guardWordsOnly",
      origin,
      amount: formatGhost(coin.amount),
      slot: formatGhost(slot),
      fee: formatGhost(f.fee),
      recipient: toHex(f.recipient),
      actionCost: formatGhost(check.actionCost),
      chainId: String(f.chainId),
      warnings: warningTexts(check.warnings),
    };
    if (!(await ui.approve(summary, "none"))) throw rejected();
    const built = guarded(() =>
      ghost.guardWordsOnlySpend({
        chainId: f.chainId,
        domain: f.domain,
        policy: f.policy,
        key,
        records: f.records,
        salts: f.salts,
        position: coin.position,
        fee: f.fee,
        recipient: f.recipient,
        seed: random(32),
        zk: random(32),
      }),
    );
    return {
      txHash: toHex(built.txHash),
      marker: toHex(built.marker),
      envelope: toHex(built.envelope),
      slotAmount: toQuantity(built.slotAmount),
      remainder: { commitment: toHex(built.remainder.commitment), number: toQuantity(built.remainder.number), amount: toQuantity(built.remainder.amount) },
    };
  }

  async function answer(request, origin) {
    if (request.method === GUARD_RESTORE) return guardRestore(request.fields, origin);
    if (request.method === GUARD_SPEND) return guardSpend(request.fields, origin);
    if (request.method === GUARD_WORDS_ONLY_SPEND) return guardWordsOnlySpend(request.fields, origin);
    const first = await rescueFrom();
    if (request.method === GET_ACCOUNT) {
      const count = await store.getIssued();
      return approved({ kind: "connect", origin }, (words) => {
        const derived = account(ghost, words, ACCOUNT_INDEX, schemeOf(ACCOUNT_INDEX, first));
        addresses.set(ACCOUNT_INDEX, toHex(derived.address));
        learn(words, count, first);
        return shown(derived);
      });
    }
    if (request.method === NEW_RECEIVE_ADDRESS) {
      return approved({ kind: "receive", origin }, async (words) => {
        // Read after the approval, so a count raised meanwhile is not reused.
        const index = (await store.getIssued()) + 1;
        const derived = account(ghost, words, index, schemeOf(index, first));
        // Stored before the answer: the address is never handed out twice.
        await store.putIssued(index);
        addresses.set(index, toHex(derived.address));
        return shown(derived);
      });
    }
    const f = request.fields;
    const count = await store.getIssued();
    const from = f.from ? toHex(f.from) : null;
    // Refused before any screen when every account is known; otherwise
    // checked once unlocked, still before anything is signed.
    const known = from ? indexOf(from, count) : ACCOUNT_INDEX;
    if (known === null) throw notIssued();
    // The account's scheme, when its index is known before the unlock.
    const scheme = known === undefined ? null : schemeOf(known, first);
    const named = from ?? addresses.get(ACCOUNT_INDEX) ?? null;
    // The index of the account that signs, checked once unlocked.
    const signer = (words) => {
      if (!from) return ACCOUNT_INDEX;
      learn(words, count, first);
      const index = indexOf(from, count);
      if (index === null) throw notIssued();
      return index;
    };

    if (request.method === GUARD_COMMIT) {
      // Checked before any screen: the policy, the amount and the tree room.
      const check = guarded(() => ghost.guardCheck({ policy: f.policy, amount: f.value, baseFee: f.baseFee, room: f.room }));
      const warnings = warningTexts(check.warnings);
      const summary = {
        kind: "guardCommit",
        origin,
        from: named,
        scheme,
        amount: formatGhost(f.value),
        maxFee: formatGhost(f.gasLimit * f.maxFeePerGas),
        to: toHex(f.to),
        chainId: String(f.chainId),
        guardAddress: toHex(f.policy.address),
        actionCost: formatGhost(check.actionCost),
        warnings,
      };
      return approved(summary, async (words, approval) => {
        const index = signer(words);
        // The stop root from the stop card, typed on the approval screen.
        const stopRoot = stopRootField(approval.stopRoot);
        const keySeed = random(32);
        let key;
        let made;
        try {
          key = guarded(() => ghost.newKey(keySeed));
          made = guarded(() =>
            ghost.guardCommit({
              chainId: f.chainId,
              policy: f.policy,
              walletWords: words,
              guardIndex: GUARD_INDEX,
              stopRoot,
              amount: f.value,
              room: f.room,
              seed: random(32),
              key,
            }),
          );
        } finally {
          stopRoot.fill(0);
          keySeed.fill(0);
        }
        await keyBackup(key, warnings);
        const signedScheme = schemeOf(index, first);
        const signed = sign(ghost, words, index, { ...f, data: made.payload }, random(32), signedScheme);
        addresses.set(index, toHex(signed.sender));
        return {
          sender: toHex(signed.sender),
          txHash: toHex(signed.txHash),
          envelope: toHex(signed.envelope),
          scheme: signedScheme,
          commitment: toHex(made.commitment),
          marker: toHex(made.marker),
        };
      });
    }

    if (request.method === RESCUE) {
      if (scheme === SCHEME_PLAIN) throw noRescueKey();
      const summary = {
        kind: "rescue",
        origin,
        from: named,
        balance: formatGhost(f.balance),
        amount: formatGhost(f.value),
        maxFee: formatGhost(f.maxFee),
        chainId: String(f.chainId),
      };
      return approved(summary, (words, approval) => {
        const index = signer(words);
        if (schemeOf(index, first) === SCHEME_PLAIN) throw noRescueKey();
        const sender = addresses.get(index) ?? toHex(account(ghost, words, index, SCHEME_RESCUE_KEY).address);
        const to = destination(approval.destination, sender);
        const signed = sign(ghost, words, index, { ...f, to, data: new Uint8Array(0) }, random(32), SCHEME_RESCUE);
        addresses.set(index, toHex(signed.sender));
        return { sender: toHex(signed.sender), txHash: toHex(signed.txHash), envelope: toHex(signed.envelope), scheme: SCHEME_RESCUE };
      });
    }

    const summary = {
      kind: "sign",
      origin,
      from: named,
      scheme,
      rescueKey: scheme === null ? null : scheme === SCHEME_RESCUE_KEY,
      amount: formatGhost(f.value),
      maxFee: formatGhost(f.gasLimit * f.maxFeePerGas),
      to: toHex(f.to),
      chainId: String(f.chainId),
      dataBytes: f.data.length,
    };
    return approved(summary, (words) => {
      const index = signer(words);
      const signedScheme = schemeOf(index, first);
      const signed = sign(ghost, words, index, f, random(32), signedScheme);
      addresses.set(index, toHex(signed.sender));
      return { sender: toHex(signed.sender), txHash: toHex(signed.txHash), envelope: toHex(signed.envelope), scheme: signedScheme };
    });
  }

  // One request, checked first: a refusal never reaches a screen, but the
  // status line says it was refused instead of still waiting.
  async function handle(message, origin) {
    let request;
    try {
      request = checkRequest(message, guard);
    } catch (err) {
      ui.status(REFUSED_STATUS);
      const id = message && Number.isSafeInteger(message.id) ? message.id : null;
      return { id, error: { code: err.code ?? INVALID_PARAMS, message: err.message } };
    }
    // The window comes to the front and its title says it is waiting, so
    // the approval is not missed behind the app; the title goes back once
    // the request is answered.
    ui.attention?.(ASKING_TITLE);
    try {
      const result = await answer(request, origin);
      ui.status("Done. Keep this window open for the app's next request, or close it.");
      return { id: request.id, result };
    } catch (err) {
      ui.status(err.code === USER_REJECTED ? "Rejected. Nothing was signed." : "Something failed. Nothing was signed.");
      return { id: request.id, error: { code: err.code ?? INTERNAL_ERROR, message: String(err.message) } };
    } finally {
      ui.attention?.(null);
    }
  }

  return {
    // Tells the opener the wallet is listening, posted to each web app
    // origin: the browser delivers it only if the opener is one of them.
    announce() {
      for (const origin of origins) opener.postMessage({ ready: true }, origin);
      ui.status("Waiting for the Ghost app.");
    },

    // A message: answered only from a web app origin and from the opener,
    // and only to that origin; anything else is ignored. One at a time.
    onMessage(event) {
      if (!opener || event.source !== opener || !origins.includes(event.origin)) return;
      const { data, origin } = event;
      queue = queue.then(async () => opener.postMessage(await handle(data, origin), origin)).catch(() => {});
    },
  };
}

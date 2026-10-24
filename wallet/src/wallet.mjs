// The pop-up wallet's logic, apart from the page: the two requests it
// answers and their strict checks, the encrypted vault, and the order of
// the screens. main.mjs gives it the browser's objects; the tests give
// fakes.
//
// The words of the wallet seed are the only secret. They are stored only
// encrypted (AES-256-GCM, under a key from a passkey's PRF output or from a
// password), and decrypted for one request at a time into a byte array
// that is overwritten with zeros once used. No JavaScript string of them is
// made after the backup screens.

import { concat, toHex, word } from "../../webapp/src/bytes.mjs";
import { CHAIN_IDS } from "./config.mjs";

export const GET_ACCOUNT = "ghost_getAccount";
export const SIGN_TRANSACTION = "ghost_signTransaction";
export const USER_REJECTED = 4001;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;

export const PBKDF2_ITERATIONS = 600_000;
const MIN_PASSWORD = 12;
const ACCOUNT_INDEX = 0;
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
// snapTransaction writes them.
const SIGN_FIELDS = ["chainId", "genesisHash", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit", "to", "value", "data"];
const U64_MAX = (1n << 64n) - 1n;
const U256_MAX = (1n << 256n) - 1n;

function exactKeys(object, keys, what) {
  if (!object || typeof object !== "object" || Array.isArray(object)) throw refuse(`${what} is not an object`);
  for (const key of Object.keys(object)) if (!keys.includes(key)) throw refuse(`unknown field ${key}`);
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
// fields }, or throws a Refused naming the field.
export function checkRequest(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) throw refuse("the request is not an object");
  if (!Number.isSafeInteger(message.id) || message.id < 0) throw refuse("id is not a whole number");
  if (message.method === GET_ACCOUNT) {
    exactKeys(message, ["id", "method"], "the request");
    return { id: message.id, method: GET_ACCOUNT, fields: null };
  }
  if (message.method !== SIGN_TRANSACTION) throw new Refused(METHOD_NOT_FOUND, `unknown method ${String(message.method)}`);
  exactKeys(message, ["id", "method", "params"], "the request");
  const p = message.params;
  exactKeys(p, SIGN_FIELDS, "params");
  const fields = {
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

// The wasm calls with the words as bytes, in the input layout of
// webapp/src/wasm.mjs (walletAccount, walletSign): Ghost.call overwrites its
// input with zeros, and the module its own copy.
function account(ghost, words) {
  const out = ghost.call("ghost_wallet_account", concat([u32(words.length), words, u32(ACCOUNT_INDEX)]));
  return { address: out.slice(0, 20), publicKey: out.slice(20) };
}

function sign(ghost, words, f, randomness) {
  const input = concat([
    u32(words.length),
    words,
    u32(ACCOUNT_INDEX),
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
  const out = ghost.call("ghost_wallet_sign", input);
  return { txHash: out.slice(0, 32), sender: out.slice(32, 52), envelope: out.slice(52) };
}

// The vault in IndexedDB on the wallet's origin: one record, written once
// (add refuses to replace it), read for every request.
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
// `store`: vaultStore; `ui`: the screens (main.mjs); `subtle`: WebCrypto;
// `credentials`: navigator.credentials, or null without passkeys; `random(n)`:
// n bytes from crypto.getRandomValues; `origins`: the web app origins;
// `opener`: the window that opened the pop-up.
export function createWallet({ ghost, store, ui, subtle, credentials, random, origins, opener }) {
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
    await store.add({ ...record, iv, ciphertext });
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
        account(ghost, words);
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

  // Shows `summary`, waits for Approve and the unlock, and runs `use` on
  // the decrypted words, overwritten with zeros after. Reject signs nothing.
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
        return use(words);
      } finally {
        words.fill(0);
      }
    }
  }

  async function answer(request, origin) {
    if (request.method === GET_ACCOUNT) {
      return approved({ kind: "connect", origin }, (words) => {
        const { address, publicKey } = account(ghost, words);
        return { address: toHex(address), publicKey: toHex(publicKey) };
      });
    }
    const f = request.fields;
    const summary = {
      kind: "sign",
      origin,
      amount: formatGhost(f.value),
      maxFee: formatGhost(f.gasLimit * f.maxFeePerGas),
      to: toHex(f.to),
      chainId: String(f.chainId),
      dataBytes: f.data.length,
    };
    return approved(summary, (words) => {
      const signed = sign(ghost, words, f, random(32));
      return { sender: toHex(signed.sender), txHash: toHex(signed.txHash), envelope: toHex(signed.envelope) };
    });
  }

  // One request, checked first: a refusal never reaches a screen.
  async function handle(message, origin) {
    let request;
    try {
      request = checkRequest(message);
    } catch (err) {
      const id = message && Number.isSafeInteger(message.id) ? message.id : null;
      return { id, error: { code: err.code ?? INVALID_PARAMS, message: err.message } };
    }
    try {
      const result = await answer(request, origin);
      ui.status("Done. Keep this window open for the app's next request, or close it.");
      return { id: request.id, result };
    } catch (err) {
      ui.status(err.code === USER_REJECTED ? "Rejected. Nothing was signed." : "Something failed. Nothing was signed.");
      return { id: request.id, error: { code: err.code ?? INTERNAL_ERROR, message: String(err.message) } };
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

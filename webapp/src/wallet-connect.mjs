// The wallets the page connects to. The page holds no seed and no key: a
// connected wallet keeps the Ghost account's quantum-safe key (ML-DSA-44)
// and signs its account transactions (type 0x52) itself. Only wallets that
// hold such a key are listed; a wallet that signs with an elliptic curve
// cannot sign a Ghost transaction and is never offered.
//
// A connector is
//
//   { id, name, connect() -> { address }, signTransaction(fields) ->
//     { sender, txHash, envelope }, disconnect() }
//
// where `fields` is { chainId, genesis, nonce, maxPriorityFeePerGas,
// maxFeePerGas, gasLimit, to, value, data }: bigints, and byte arrays for
// the genesis hash (32), `to` (20, or null for a contract creation) and the
// data. The answer's sender (20), txHash (32) and envelope are byte arrays.
// The flow (flow.mjs, walletConnect) checks the sender against the connected
// address and the hash against the envelope before it sends anything.
//
// The connection is not remembered: nothing is written to browser storage
// or a cookie, and the user connects again on the next page load.

import { fromHex, quantity, toHex, toQuantity } from "./bytes.mjs";

// The MetaMask Snap that holds the Ghost account key inside MetaMask, and
// the two requests it answers.
export const GHOST_SNAP = "npm:@ghostcoin/ghost-snap";
export const SNAP_WALLET = { id: "metamask-ghost-snap", name: "MetaMask (Ghost Snap)" };

// The EIP-1193 code of a request the user turned down in the wallet.
export const USER_REJECTED = 4001;
// The JSON-RPC code of a method the provider does not have: a wallet that
// cannot run Snaps.
const METHOD_NOT_FOUND = -32601;

// A request the user turned down in the wallet; nothing was signed or sent.
export class WalletRejected extends Error {
  constructor(what) {
    super(`${what} was rejected in your wallet; nothing was sent`);
    this.name = "WalletRejected";
  }
}

// MetaMask's provider in this browser (window.ethereum), or null when there
// is none.
export function injectedProvider(win = globalThis) {
  const provider = win && win.ethereum;
  return provider && typeof provider.request === "function" ? provider : null;
}

// The Ghost Snap connector over an EIP-1193 `provider`. It asks the provider
// for wallet_requestSnaps and wallet_invokeSnap only: no account of the
// wallet's own and no other signing method.
export function snapConnector(provider) {
  let address = null;

  async function ask(what, method, params) {
    if (!provider) throw new Error("MetaMask is not installed in this browser: install MetaMask, then reload the page");
    try {
      return await provider.request({ method, params });
    } catch (err) {
      const code = err && err.code;
      if (code === USER_REJECTED) throw new WalletRejected(what);
      if (code === METHOD_NOT_FOUND) throw new Error("this wallet cannot run MetaMask Snaps: install MetaMask");
      throw new Error(`the wallet refused ${what}: ${(err && err.message) || err}`);
    }
  }

  const invoke = (what, method, params) =>
    ask(what, "wallet_invokeSnap", { snapId: GHOST_SNAP, request: params === undefined ? { method } : { method, params } });

  return {
    ...SNAP_WALLET,
    available: Boolean(provider),

    // Installs the Snap (MetaMask asks the user the first time) and reads
    // its Ghost account.
    async connect() {
      const snaps = await ask("the connection", "wallet_requestSnaps", { [GHOST_SNAP]: {} });
      if (!snaps || typeof snaps !== "object" || !snaps[GHOST_SNAP] || snaps[GHOST_SNAP].error) {
        throw new Error("the wallet did not install the Ghost Snap");
      }
      const account = await invoke("the connection", "ghost_getAccount");
      if (!account || typeof account.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(account.address)) {
        throw new Error("the Ghost Snap answered without a Ghost account address");
      }
      address = account.address.toLowerCase();
      return { address };
    },

    // The Snap shows the transaction in MetaMask and signs it once the user
    // approves it there.
    async signTransaction(fields) {
      if (!address) throw new Error("connect the wallet first");
      const answer = await invoke("the transaction", "ghost_signTransaction", snapTransaction(fields));
      return signedFromSnap(answer);
    },

    // Forgets the account; MetaMask keeps the Snap and its key.
    disconnect() {
      address = null;
    },
  };
}

// The params of ghost_signTransaction: every field as 0x hex, quantities
// without leading zeros, `to` null for a contract creation.
export function snapTransaction(fields) {
  return {
    chainId: toQuantity(fields.chainId),
    genesisHash: toHex(fields.genesis),
    nonce: toQuantity(fields.nonce),
    maxPriorityFeePerGas: toQuantity(fields.maxPriorityFeePerGas),
    maxFeePerGas: toQuantity(fields.maxFeePerGas),
    gasLimit: toQuantity(fields.gasLimit),
    to: fields.to === null ? null : toHex(fields.to),
    value: toQuantity(fields.value),
    data: toHex(fields.data),
  };
}

// The fields of ghost_signTransaction's params, as snapTransaction wrote
// them: what a Snap (or a test standing in for one) reads.
export function fieldsFromSnap(params) {
  return {
    chainId: quantity(params.chainId),
    genesis: fromHex(params.genesisHash, 32),
    nonce: quantity(params.nonce),
    maxPriorityFeePerGas: quantity(params.maxPriorityFeePerGas),
    maxFeePerGas: quantity(params.maxFeePerGas),
    gasLimit: quantity(params.gasLimit),
    to: params.to === null ? null : fromHex(params.to, 20),
    value: quantity(params.value),
    data: fromHex(params.data),
  };
}

// The Snap's answer, { sender, txHash, envelope } as 0x hex, as bytes.
function signedFromSnap(answer) {
  try {
    const signed = {
      sender: fromHex(answer.sender, 20),
      txHash: fromHex(answer.txHash, 32),
      envelope: fromHex(answer.envelope),
    };
    if (!answer.sender.startsWith("0x") || !answer.txHash.startsWith("0x") || !answer.envelope.startsWith("0x")) {
      throw new Error("not 0x hex");
    }
    if (signed.envelope.length === 0) throw new Error("an empty envelope");
    return signed;
  } catch {
    throw new Error("the Ghost Snap answered without a signed transaction");
  }
}

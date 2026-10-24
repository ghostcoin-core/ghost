// The wallets the page connects to. The page holds no seed and no key: a
// connected wallet keeps the Ghost account's quantum-safe key (ML-DSA-44)
// and signs its account transactions (type 0x52) itself. Only wallets that
// hold such a key are listed; a wallet that signs with an elliptic curve
// cannot sign a Ghost transaction and is never offered. Today that is the
// Ghost pop-up wallet (popup-wallet.mjs).
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

// The EIP-1193 code of a request the user turned down in the wallet.
export const USER_REJECTED = 4001;

// A request the user turned down in the wallet; nothing was signed or sent.
export class WalletRejected extends Error {
  constructor(what) {
    super(`${what} was rejected in your wallet; nothing was sent`);
    this.name = "WalletRejected";
  }
}

// A wallet that failed to sign for a reason other than the user turning it
// down; nothing was signed or sent.
export class WalletSignFailed extends Error {
  constructor(cause) {
    super(`the wallet could not sign the transaction: ${(cause && cause.message) || cause}; nothing was sent`, { cause });
    this.name = "WalletSignFailed";
  }
}

// Whether `err` is the user turning a request down in the wallet: the
// EIP-1193 code, or a WalletRejected.
export function isWalletRejection(err) {
  return Boolean(err) && (err.code === USER_REJECTED || err.name === "WalletRejected");
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
// them: what a wallet (or a test standing in for one) reads.
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

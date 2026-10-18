# The web app

Status: first version, 2026-10-18. Experimental and unaudited. How to build,
check and run it is in [webapp/README.md](../webapp/README.md).

The web app is the first product on the client library: a user connects a
supported EVM wallet and uses GHOST privately. It does three things.

- **Vanish.** It creates a standard Phantom Key, shows it (blurred until
  asked), and lets the user copy it, write it down or download it as an
  image. Before the commit is sent, the **save check** asks for three of the
  key's twelve groups, chosen at random with `crypto.getRandomValues`, shown by
  position and asked in order. The commit goes to the wallet only when all
  three match; a wrong group sends nothing. Once the wallet has the commit,
  the app forgets the key.
- **Summon.** The user types any valid standard or long key. The app finds
  the key's coin on the chain and reveals any available amount to any address;
  the rest, minus the fee, stays under the same key as the next commitment.
- **Claim.** The app creates a new key, shows it and runs the same save
  check on it, then moves the coin's value minus the fee to the new key. A
  received key shows **unclaimed** until the claim is in a block; then it
  shows **claimed**, and the new key holds the coin.

## Layout

| Path | What it is |
|---|---|
| `webapp/index.html`, `style.css` | The page; loads one same-origin module and names no external URL |
| `webapp/src/flow.mjs` | The flow controller: every step above, with no DOM |
| `webapp/src/app.mjs`, `keyimage.mjs` | The thin DOM layer and the key image drawn on a canvas |
| `webapp/src/chain.mjs` | The fee of spec 07, the base fee rule, the epoch height, amounts |
| `webapp/src/rpc.mjs` | JSON-RPC to the chosen endpoint |
| `webapp/src/prover.mjs`, `worker.mjs`, `worker-core.mjs` | The background worker and its message interface |
| `webapp/src/wasm.mjs` | The WebAssembly module's plain exports, with no bindings generator |
| `webapp/wasm/` | The client library built for `wasm32-unknown-unknown`: its own workspace and lock file, path dependencies on `client` and `proofs` |
| `webapp/build.sh` | The verifiable build |
| `webapp/test/` | The headless tests and the scripted node stand-in |

The worker answers `{ id, op, args }` with progress stages and then one
result or error. The page and the Node test use the same interface; only the
way the module's bytes are loaded differs.

## Node endpoint

The user types the endpoint's JSON-RPC URL; the default is the local internal
network, `http://127.0.0.1:8545`. The app sends only these requests:

| Method | Parameters | Result |
|---|---|---|
| `eth_chainId` | none | The chain identifier |
| `eth_blockNumber` | none | The tip |
| `eth_getBlockByNumber` | height, `false` | A header with `hash`, `parentHash`, `baseFeePerGas`, `gasUsed`, `gasLimit` and `coinTreeRoot` |
| `ghost_getPageRoots` | `"coin"`, tree index, anchor block hash | `{ pageRoots }`: the page roots of pages 0 to the last page with a leaf |
| `ghost_getTreePage` | `"coin"`, tree index, page, anchor block hash | `{ count, leaves, notes }`: every filled position of the page, in order |
| `ghost_getTreePage` | `"coin-markers"`, tree index, page, anchor block hash | `{ count, markers }`: a page of 4,096 spent coin markers in inclusion order |
| `eth_sendRawTransaction` | the reveal envelope | The transaction hash |
| `eth_getTransactionReceipt` | a transaction hash | `null` until the transaction is in a block |

The page and marker requests follow [spec 05](spec/05-trees-and-headers.md),
section 8: whole pages from page 0, as of a block hash, whatever the wallet
expects to find. The headers asked for depend only on the tip: genesis, the
tip, the first block of the fee window, and blocks `E - 32` to `E` for the
epoch block `E`. No request names a key, a commitment, a position or a
marker, and the app never asks for a witness; it computes its own from the
pages. The only request that carries a coin's data is the reveal itself,
whose fields are public.

## Wallet

Only the injected EIP-1193 provider (`window.ethereum`) is used:
`eth_requestAccounts`, `eth_chainId` (it must equal the endpoint's) and
`eth_sendTransaction` for the commit. The commit is a normal transaction to
the commit entry address whose value is the amount and whose data is the
commit payload of [spec 03](spec/03-coin-rules.md), section 6: the commit
format version `0x01`, the fingerprint `F` and the encrypted note of
commitment number 0 (189 bytes). A reveal is a native transaction with no
account, so it needs no wallet.

## Summon and Claim

1. **Restore.** The app reads the coin tree as of the tip in whole pages and
   checks each page against the page-root list and the list against the tip's
   `coinTreeRoot`. It reads the spent markers the same way. The worker tries
   the key's note key on every note and recomputes each found commitment
   (spec 01, section 8). The current coin is the found commitment whose
   marker is not spent.
2. **Tree state.** The proof uses the epoch root of
   [spec 02](spec/02-proof-statements.md), section 8, through the client
   library's `choose_tree_state`. The epoch block is `E`, the highest
   multiple of 32 at least 12 blocks below the tip. The app fetches blocks
   `E - 32` to `E`, reads each one's leaf count from the roots of every prefix
   of the leaves it already has, and takes as the leaf's block the first of
   them whose tree holds the leaf. For a leaf older than `E - 32` that is
   block `E - 32`, which makes the rule stricter, never looser: if no leaf was
   added between it and `E`, the app waits for the next epoch. A coin newer
   than `E` waits too.
3. **Fee.** The fee is the formula of [spec 07](spec/07-private-transaction.md),
   section 4, for the window of the next block, from headers alone. If the
   window's fee changes while the proof is made, the app proves again.
4. **Proof.** The worker computes the witness from the leaves under the
   epoch root, proves with the client library (partial reveal or claim to a
   new key), verifies the proof itself, and builds the envelope of spec 07,
   section 3. A claim sends nothing out and names the zero address.
5. **Status.** The app polls the receipt. After a claim's block the old key
   shows claimed; opened again later, it shows claimed because its marker is
   spent.

## Limits of this version

- **The node's own documents.** The request and result shapes above follow
  this repository's specifications; the node's documentation of its tree
  page methods was not at hand when the app was written. The node does not
  accept a reveal yet, so `eth_sendRawTransaction` of a reveal works only
  against the test's stand-in.
- **Proof field width (conflict with spec 07).** Spec 07 sets the proof field
  to 1,028,144 bytes from decision 0003, but the real prover's proofs measure
  about 1.19 MB ([reveal results](benchmarks/reveal-results.md)), so none fits.
  The app uses a field of 1,310,720 bytes (1.25 MiB) and otherwise the layout
  of spec 07, section 3, until the founder settles the width.
- **Commit entry address.** No specification fixes it yet. It is a setting
  next to the endpoint, with a placeholder default.
- **Headers are taken from the endpoint.** The app checks parent links over
  the headers it fetches but not the proof-of-work seal; there is no header
  chain in the page. A wrong header can make a reveal fail at the node or a
  status wrong, never move a coin.
- **Notes and markers are not checked against receipts** (spec 05, section 8,
  item 5): the page says so next to the status. Marker pages are hints.
- **One tree.** Only coin tree 0 is read; a rollover is 2^32 leaves away.
- **No reorganisation handling** beyond rereading everything on each step.

## Tests

`node --test webapp/test/` runs, after the module is built:

- `flow.test.mjs`: Vanish with a wrong and then a right save check, a
  partial Summon and a Claim, with the real prover in a `worker_threads`
  worker, against a scripted stand-in for the node's JSON-RPC
  (`test/support/fake-node.mjs`). The stand-in verifies every reveal's proof
  with the real verifier, checks the fee, the root and the marker as a node
  admits a reveal, and records every request. The test checks that no run of
  a key's digits and no commitment of the key reached the endpoint or the
  wallet, and that `index.html` loads only same-origin scripts.
- `wasm.test.mjs`: the module against the golden vectors of spec 01 and
  spec 05.
- `units.test.mjs`: the fee against the worked examples of spec 07, the
  base fee rule, the epoch height, amounts and the save check.

The key image download is drawn on a canvas in the page and is not covered
by the headless tests.

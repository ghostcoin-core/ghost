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
  received key shows **unclaimed** until the claim is in a block with 6
  verified blocks on top; then it shows **claimed**, and the new key holds the
  coin. Confirmation trusts the chosen endpoint for the proof-of-work seal of
  each block, which the app does not verify.

## Layout

| Path | What it is |
|---|---|
| `webapp/index.html`, `style.css` | The page; loads one same-origin module and names no external URL |
| `webapp/src/flow.mjs` | The flow controller: every step above, with no DOM |
| `webapp/src/app.mjs`, `keyimage.mjs` | The thin DOM layer and the key image drawn on a canvas |
| `webapp/src/chain.mjs` | The fee of spec 07, the base fee rule, the settled height, amounts |
| `webapp/src/header.mjs` | The header's 18-field RLP of spec 05, section 10, to recompute a block hash |
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
| `eth_getBlockByNumber` | height, `false` | A header with its `hash` and the 18 fields of spec 05, section 10, by their base client names (`parentHash` to `nonce`, `baseFeePerGas`, `coinTreeRoot`, `dataTreeRoot`) |
| `ghost_getPageRoots` | `"coin"`, tree index, anchor block hash | An array of 32-byte page roots, of pages 0 to the last page with a leaf (`[]` for an empty tree) |
| `ghost_getTreePage` | `"coin"`, tree index, page, anchor block hash | `{ kind, treeIndex, page, filled, entries }`: `filled` positions of the page, and `entries`, one `{ leaf, note }` (32 and 156 bytes of hex) per filled position, in order |
| `ghost_getTreePage` | `"coin-markers"`, tree index, page, anchor block hash | `{ count, markers }`: a page of 4,096 spent coin markers in inclusion order |
| `eth_sendRawTransaction` | the reveal envelope | The transaction hash |
| `eth_getTransactionReceipt` | a transaction hash | `null` until the transaction is in a block |

The page and marker requests follow [spec 05](spec/05-trees-and-headers.md),
section 8: whole pages from page 0, as of a block hash, whatever the wallet
expects to find. The headers asked for depend only on the tip: every block
from `S - 32` to the tip for the settled block `S`, 2 below the tip (from
genesis while `S` is below 32), and genesis. No request names a key, a commitment, a position or
a marker, and the app never asks for a witness; it computes its own from the
pages. The only request that carries a coin's data is the reveal itself,
whose fields are public; sending it, though, links the connection to the
coin it spends.

The tree answers are read in the node's shape (ghost-node
`docs/trees-and-headers.md`, "Wallet tree pages") and in no other. The app
refuses page roots that are not an array, and a coin page whose `filled` is
not the number of its `entries`, or that is not whole: every page but the
last holds 4,096 leaves and the last 1 to 4,096. The page roots and leaves
must then give the anchor header's coin root.

## Headers

The app keeps a header only if keccak256 of its RLP, the list of the 18
fields of [spec 05](spec/05-trees-and-headers.md), section 10 (fields 0 to
14 of the base header, the base fee, `coinTreeRoot`, `dataTreeRoot`), is the
hash the endpoint returned with it, and only if each header's `parentHash` is
the hash of the one before it, up to the tip. The worker computes the hash
with the client library's keccak256; `webapp/src/header.mjs` builds the RLP.
Every coin root the app uses comes from such a header. The app does not
check the proof-of-work seal or the difficulty, so it trusts the chosen
endpoint for the seal: an endpoint can still serve a whole chain of
well-formed headers no miner sealed.

## Wallet

Only the injected EIP-1193 provider (`window.ethereum`) is used:
`eth_requestAccounts`, `eth_chainId` (it must equal the endpoint's) and
`eth_sendTransaction` for the commit. The commit is a normal transaction to
the commit entry address whose value is the amount and whose data is the
commit payload of [spec 03](spec/03-coin-rules.md), section 6, in the layout
of [spec 07](spec/07-private-transaction.md) that the node reads as
`ghostpriv.CommitData`: the 2-byte version `0x0001` (`TX_VERSION`), the
fingerprint `F` (32 bytes) and the encrypted note of commitment number 0
(156 bytes), 190 bytes in all. The node refuses any other length or version
(`commit data is not 190 bytes of version 1`).
`webapp/test/vectors/commit-payload.json` holds one such payload, built from
spec 01, vector coin-commit. A reveal is a native transaction with no
account, so it needs no wallet.

The commit entry address defaults to the internal network's coin commit
entry, `0x67686f7374000000000000000000000000000005` ("ghost" in ASCII, then
5; `params/ghost/privaccounts.go` in ghost-node). The data commit entry of
that network, `0x67686f7374000000000000000000000000000007`, is not used: the
app makes no data commitments.

## Summon and Claim

1. **Restore.** The app reads the coin tree as of the tip in whole pages and
   checks each page against the page-root list and the list against the tip's
   `coinTreeRoot`. It reads the spent markers the same way, as of the block
   6 below the tip, so a key shows claimed only once its spend has 6 blocks
   on top. The worker tries the key's note key on every note and recomputes
   each found commitment (spec 01, section 8). The current coin is the found
   commitment whose marker is not spent. Notes are not checked against the
   tree, so an endpoint can alter them; the app therefore asks for everything
   a reveal needs (the headers, the tree and the markers, all fixed by the
   tip) before the key is tried.
2. **Same requests after restore.** On a reveal or claim, every path after
   restore, the one where the key holds no unspent coin included, then asks
   the endpoint the same thing in the same order before anything depends on
   what restore found: `eth_blockNumber`, the tip's header and the fee
   headers for the next block. Before these requests the worker always
   makes a proof and sends nothing: of the coin when it can be revealed,
   otherwise of a decoy, a throwaway key's coin placed at the last position
   of the same leaves, of the same kind. A coin's proof that the worker
   refuses before proving (its coin not under the root, amounts that do not
   balance) proves a decoy in its place and only then returns the refusal.
   So the time before them is a proof's on every path, refusals and fee
   retries included. The worker's other work
   (the leaf count of every header read, restore, the tree-state rule) is the
   same on every path too. Only after these requests does a failure surface
   or the reveal go out. Found or not, failing or not, the endpoint sees the
   same requests at the same pace up to the reveal; the reveal itself tells
   it the connection holds a coin.
3. **Tree state.** There is no forced wait (founder decision, 2026-10-20).
   The proof uses the settled root of
   [spec 02](spec/02-proof-statements.md), section 8, through the client
   library's `choose_tree_state`: the root of block `S`, 2 blocks below the
   tip (`SETTLE_DEPTH`), if its tree holds a leaf added after the coin's
   block. The app takes the verified headers of blocks `S - 32` to the tip,
   reads each one's leaf count from the roots of every prefix of the leaves
   it already has, and takes as the leaf's block the first of them whose tree
   holds the leaf. For a leaf older than `S - 32` it takes block `S - 32` and
   the tree that ends at the leaf, so a leaf added before `S - 32` still
   counts as following it. So a coin can be revealed 2 blocks after anyone
   else commits.
   - **Holder's choice.** Opening a key shows, for its coin, the block whose
     root a reveal or claim made now would use and how many coins that tree
     covers (its leaf count), and how many newer coins are not settled yet.
     Fewer coins make the reveal easier to link to the commit; the holder
     reveals now or waits and presses Refresh. The app never makes them wait.
   - **Nobody committed since.** When no leaf follows the coin, the only tree
     that holds it ends with the coin's own block, and a reveal against that
     root would tie it to its commit. The app says so plainly, keeps Reveal
     and Claim off, and waits; it never proves against the coin's own block
     root. When a later leaf exists but is not yet 2 blocks deep, the app
     names the block from which the coin can be revealed.
4. **Fee.** The fee is the formula of [spec 07](spec/07-private-transaction.md),
   section 4, for the window of the next block, from headers alone. If the
   window's fee changes while the proof is made, the app proves again; on
   every path, so the abort path also scans again.
5. **Proof.** The worker computes the witness from the leaves under the
   settled root, proves with the client library (partial reveal or claim to a
   new key), verifies the proof itself, and builds the envelope of spec 07,
   section 3. A claim sends nothing out and names the zero address.
6. **Send.** A node that mines fast can refuse the reveal with `chain head
   kept moving while the reveal was checked`: its pool checks a reveal on a
   snapshot of the head, checks again a bounded number of times when the
   head moves, and then gives up. That refusal is a transient, so the app
   treats exactly it as retryable. It is told by its JSON-RPC shape, as geth
   answers it over HTTP: error code -32000 and those words, whatever the
   class of the error object. After it the app waits 250 ms, asks for the
   tip once and for the fee headers for the next block; it never waits for
   the tip to hold still, since a node that seals a block every few
   milliseconds never does. If the fee is no longer the proof's, it proves
   again as for a fee change. If the block whose root the proof uses is
   more than 34 blocks below the tip by then (the settled block's 2 plus the
   32 headers a scan reads), it proves again against the settled root of
   the tip by then rather than send an envelope whose root is far behind.
   Otherwise it sends the same envelope again. It sends one proof at most
   5 times and then proves again. A node sealing a block every 20 ms can
   refuse dozens of sends in a row and still take a later one, so the app
   keeps going like this for up to 10 minutes from the first proof and at
   most 200 proofs (the last sent 5 times whatever its root); only then does
   the refusal surface, with nothing asked after it. A new proof is only ever of the first proof's
   input coin: an endpoint can take a send and still answer with this
   refusal, so once that coin is spent or no longer the key's current coin
   the app stops with an error instead of spending the remainder on the
   same reveal again. Any other
   refusal surfaces at once. Only a send refused this way is followed by
   more requests, so the requests before the first send stay as in step 2.
   The node can also take a send and let it go before any block holds it:
   its pool checks every reveal it holds again on each new head and drops
   one that fails. So after a send the node took, the app polls its
   receipt, and once the tip is 2 blocks past the send with no receipt it
   also asks `eth_getTransactionByHash`. When the node no longer knows the
   reveal and no block holds it, nothing was spent, and the send counts as
   refused as above: the same envelope again while the fee is the proof's,
   otherwise a new proof of the same coin. Every such envelope spends the
   same marker, so at most one of them can ever be executed. A reveal the
   node still holds is waited for as before.
7. **Status.** The app polls the receipt, but a receipt is only the
   endpoint's word. A receipt naming a block that was already in the chain
   when the transaction was sent, or one past the tip, is refused before any
   header is read for it. The app then waits until the receipt's block has 6 blocks on
   top. A commit, reveal or claim counts as confirmed only when the coin tree
   as of the tip, checked against the tip's coin root, holds the new leaf the
   transaction appends, at a position added by the receipt's block, read
   from the coin roots of that block and its parent in the verified header
   chain leading to the tip. Until then a claim stays pending and the old key
   unclaimed. After that the old key shows claimed because its marker is
   spent 6 or more blocks below the tip. Confirmation trusts the chosen
   endpoint for the proof-of-work seal, which the app does not verify.

## Limits of this version

- **The node's own documents.** The request and result shapes above follow
  this repository's specifications; the node's documentation of its tree
  page methods was not at hand when the app was written. The real-node test
  (see Tests) runs the whole flow against a release `geth` of ghost-node.
- **Proof field width.** The app uses the settled proof field of spec 07,
  section 3 ("Proof field"): 1,310,720 bytes (1.25 MiB) for every reveal kind,
  in the layout of that section. The real prover's proofs measure about
  1.19 MB ([reveal results](benchmarks/reveal-results.md)), below the field.
- **Commit entry address.** It is a setting next to the endpoint, with the
  internal network's coin commit entry as its default; another network
  needs its own.
- **The seal is the endpoint's word.** The app recomputes each header's hash
  and checks parent links up to the tip, but not the proof-of-work seal, and
  there is no header chain kept in the page. An endpoint that fabricates
  sealless headers can make a reveal fail at the node or a status wrong,
  never move a coin.
- **Notes and markers are not checked against receipts** (spec 05, section 8,
  item 5): the page says so next to the status. Marker pages are hints.
- **An endpoint can test for a coin, one bit at a time.** An altered note
  fails to decrypt exactly as a stranger's note does, so the app cannot tell
  it was altered. An endpoint that spoils the notes of some positions sees
  whether a reveal follows; over several reveals that can narrow down which
  commitment the connection holds. The requests and the proof work before
  them are the same either way; whether a reveal is sent is not. Use an
  endpoint you run or trust.
- **The zero address.** The app refuses it as a reveal's recipient and as
  the commit entry address, because what it is credited cannot be spent.
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
  wallet, and that `index.html` loads only same-origin scripts. Playing a
  dishonest endpoint, it also checks that altered notes leave the requests,
  and where the worker's proof falls among them, the same whether the key
  owns the targeted coin or not, up to the reveal itself; that a fabricated receipt for a withheld claim confirms nothing;
  that headers whose `coinTreeRoot` was changed under their real hash are
  refused; and that a claim is not confirmed, nor the old key claimed,
  before 6 blocks are on top. It also summons a coin 2 blocks after a
  stranger's later commit, against that commit's block root, after the same
  coin, with nobody committed since, was shown the plain warning and refused.
- `wasm.test.mjs`: the module against the golden vectors of spec 01 and
  spec 05, the header's RLP and hash included.
- `commit-layout.test.mjs`: the commit payload against spec 07's layout and
  the shared vector `test/vectors/commit-payload.json`, and the default
  commit entry address.
- `reveal-fast-node.test.mjs`: a Summon reveal against the stand-in playing
  the CI node: a block about every 20 ms, a send refused because the head
  moved, a fee that changes before the resend so the reveal is proved
  again, and a taken send the node drops before any block holds it. The
  reveal must land within a bound, the recipient paid once, every proof of
  the same coin and every envelope of the same marker.
- `reveal-reprove.test.mjs`, with nothing built: a Summon reveal against an
  in-process stand-in whose tip moves on every poll and that refuses every
  send of the first proof's envelope, with a stub prover. With a proof as
  slow as the real one the reveal is proved again after one refusal, with a
  quick one after 5; either way it goes through, paid once, every proof of
  the first proof's coin and of one marker.
- `reveal-moving-head.test.mjs`, with nothing built: an in-process stand-in
  whose tip moves on every poll and a stub prover. A reveal refused there is
  sent again after one look at the tip, never after waiting for a still tip,
  and goes through; a refused proof whose root has fallen more than 34
  blocks below the tip is proved again for the tip instead of sent again;
  a node that refuses 40 sends in a row with the head-moving error over
  minutes of proving still gets the reveal, paid once; and a node that
  refuses every send stops the reveal after 10 minutes, or at 200 proofs, of
  at most 5 sends each.
- `stand-in.test.mjs`: the stand-in refuses what the node refuses for a
  commit (not to the commit entry address, data not 190 bytes, a version
  other than `0x0001`, among them the old 189-byte layout) and accepts the
  190-byte payload.
- `units.test.mjs`: the fee against the worked examples of spec 07, the
  base fee rule, the settled height, amounts and the save check.
- `early-reveal.test.mjs`, with nothing built: the tree-state choice with a
  stub prover. A coin is revealed against the root 2 blocks below the tip
  right after a later commit, the plan reports the leaf count that root
  covers, and a coin nobody followed waits with the plain warning and is
  never proved against its own block root.

The key image download is drawn on a canvas in the page and is not covered
by the headless tests.

### Against a real node

`test/e2e/real-node.test.mjs` is not loaded from `test/index.js`. It starts
the release `geth` named by `GHOST_NODE_GETH` as a one-node internal network
(network 6777971, mining, the internal network's genesis, JSON-RPC
`eth,net,web3,ghost` over HTTP on a port the system picks) and runs Vanish, a
partial Summon and a Claim with the real prover. The wallet is the node's
unlocked miner account. It checks on chain the commit's 190 bytes and its
leaf, the spent marker, the remainder's leaf, the recipient's balance and the
claimed coin. It also checks the tree-state rule: opened before anyone else
commits, the coin waits with the plain warning and its reveal is refused;
once a stranger's commit is 2 blocks deep the Summon goes out with no
further wait, and so does the Claim after another stranger's commit follows
the remainder. Without `GHOST_NODE_GETH` it prints
`SKIP: GHOST_NODE_GETH is not set` and runs nothing.
`webapp/scripts/build-node.sh` clones ghost-node at the commit in
`test/e2e/NODE_COMMIT`, builds it and prints the path to its `geth`:

```sh
GHOST_NODE_GETH="$(webapp/scripts/build-node.sh)" \
  node --test --test-timeout=3600000 webapp/test/e2e/real-node.test.mjs
```

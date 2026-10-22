# The web app

Status: first version, 2026-10-18. Experimental and unaudited. How to build,
check and run it is in [webapp/README.md](../webapp/README.md).

The web app is the first product on the client library: a user opens the
app's own quantum-safe wallet and uses GHOST privately, with Phantom Keys of
24 words over salted coins (see Phantom Keys). It does three things.

- **Vanish.** It creates a new Phantom Key of 24 words, shows it (blurred
  until asked) for the user to write down, and offers its digit view, the
  same key as 21 groups of four digits, beside the words. Copying the key
  and downloading it as an image are conveniences, never the only backup:
  before the commit is sent, the **save check** asks for three of the key's
  24 words, chosen at random with `crypto.getRandomValues`, shown by
  position and asked in order, whichever view is shown. A word is compared
  in any case and only whole; the commit is signed and sent only when all
  three match, and a wrong word sends nothing. Once the node has the
  commit, the app forgets the key and its digit view.
- **Summon.** The user types any valid key: its 24 words, or its digits.
  Keys issued before the words, twelve (or twenty-four) groups of digits,
  still open, restore, reveal and claim. The app finds the key's coin on the
  chain and reveals any available amount to any address; the rest, minus the
  fee, stays under the same key as the next commitment.
- **Claim.** The app creates a new key of 24 words, shows it and runs the
  same save check on it, then moves the coin's value minus the fee to the
  new key. A
  received key shows **unclaimed** until a verified block holds the claim;
  from that block on it shows **claimed**, and the new key holds the coin.
  Every block the app counts is one the page checked itself, its
  proof-of-work seal and difficulty included (see Headers).

A commit, reveal or claim shows **Sent**, with its amount and transaction
hash, as soon as the node takes it, and **Done** at the first
block that holds it, with no block on top waited for (founder decision,
2026-10-20: at 30-second blocks a wait for more blocks kept the holder
waiting minutes). If a later reorganisation drops that block, the app says
so plainly and the holder can send again (see Status below).

## The page

One full-size page in one dark theme ("Midnight violet": its colors, glow,
motion and font stack are CSS variables at the top of `webapp/style.css`;
the font stack names Inter first, then the system UI font, and no font
file ships yet). It fits a phone's width with no sideways scroll.

- **Top bar.** The ghost icon and "Ghost" top left; the wallet button top
  right. With no wallet open the button reads "Open wallet" and opens a
  small panel holding the create-wallet flow (the 24 words, then their save
  check) and the restore-wallet flow. With a wallet open the button shows
  the short address (`0x3a…91c`), and the panel the full address, the
  balance, Refresh and "Close wallet".
- **The card.** One centered card, about 420px wide, with two filing-folder
  tabs, **Vanish** and **Summon** (a tab list: click, or the arrow keys,
  Home and End). The selected tab joins the card; the other sits behind it
  in a darker shade.
- **Vanish tab.** One rounded amount box: a large input (`0.00`) with the
  ghost icon and "GHOST" inside it on the right. Under it, right-aligned:
  `Balance:` and the open wallet's balance (`—` with no wallet open), and
  Max, which fills in the balance less the most the commit's gas can cost
  (0.01 GHOST). The main button reads "Vanish", or "Open wallet" with no
  wallet open, when it opens the wallet panel instead. Vanish runs the
  flow above: the key, its save check, then Sent and Done.
- **Summon tab.** The Summon controls: the key field, the coin's status and
  cover, Refresh, Close the key, and Reveal (amount and address).
- **Claim** has no tab and no visible control. Its markup stays in the
  page, inside a container with the `hidden` attribute, so the app's
  wiring and the tests that drive the flow keep working.
- **Footer.** One short line: experimental and unaudited. Under it,
  **Network** opens a small panel with the node endpoint, the commit entry
  address and the chain status (the Network link carries a red dot while
  the endpoint's chain is refused), and **About** opens the wording on
  what the app stores, where proofs are made and what still links a reveal
  to its commit.

The icons are inline SVG in `index.html`; no font, script, style or image
comes from anywhere but the page's own origin. The CSP stays
`default-src 'none'`, with `font-src 'self'` for a later self-hosted font.

## Phantom Keys

A new key comes from the client library's default (`KeyFormat::Words`,
[spec 01](spec/01-commitments-and-keys.md), section 5): a 256-bit secret
from `crypto.getRandomValues` and an 8-bit check, written as 24 words of the
BIP-39 English list. `ghost_new_key` returns the words separated by single
spaces; `ghost_key_digits` writes the digit view, 21 groups of four digits,
the last the check group. With the per-coin salt (see Wallet), so that one
guess at a key checks one leaf rather than every leaf, such a key keeps
about 128 bits of strength even against a quantum search. A key of twelve
digit groups holds about 146 bits of secret and was made before the salt:
its coins are version 1 and unsalted, and the app does not call it
quantum-safe. Such keys still work; new keys are always words.

A typed key is read only by the client library's `PhantomKey::parse`, in
the worker:

- **Words**: 24 whole words of the list, in any case, separated by any mix
  of spaces and hyphens (the flow makes any other white space, a line break
  of a pasted key, one space). A word cut short, run on or misspelled is
  refused and named by its position (`word 5 is not in the word list`),
  never corrected to a near word; 23 or 25 words is its own error.
- **Digits**: 84 digits (the digit view of a words key), 48 (twelve groups)
  or 96 (twenty-four groups), with spaces or hyphens between them.
- **The check first.** The words' check, or the digit view's check groups,
  is verified before anything is derived from the key. A wrong word of the
  list, or two words swapped, fails it (`the words do not pass the check`).

Anything uncertain about a typed key is refused, never guessed, and no
refusal holds a word or a digit of the key: it names at most a position or
a count.

## Layout

| Path | What it is |
|---|---|
| `webapp/index.html`, `style.css` | The page; loads one same-origin module and names no external URL |
| `webapp/src/flow.mjs` | The flow controller: every step above, with no DOM |
| `webapp/src/app.mjs`, `keyimage.mjs` | The thin DOM layer and the key image drawn on a canvas |
| `webapp/src/chain.mjs` | The fee of spec 07, the base fee rule, the settled height, amounts |
| `webapp/src/header.mjs` | The header's 18-field RLP of spec 05, section 10, and the table of networks this build knows, with the start of each one's header chain |
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
| `ghost_getTreePage` | `"coin"`, tree index, page, anchor block hash | `{ kind, treeIndex, page, filled, entries }`: `filled` positions of the page, and `entries`, one `{ leaf, note, salt }` (32, 156 and 16 bytes of hex) per filled position, in order; `salt` only beside the leaf of a version 2 commit, left out for a version 1 commit and for a reveal's remainder |
| `ghost_getTreePage` | `"coin-markers"`, tree index, page, anchor block hash | `{ count, markers }`: a page of 4,096 spent coin markers in inclusion order |
| `eth_getBlockReceipts` | a block hash | The block's receipts in transaction order, each with `type`, `status`, `cumulativeGasUsed`, `logsBloom` and `logs` (`address`, `topics`, `data`) |
| `eth_sendRawTransaction` | the reveal envelope, or the commit's account transaction | The transaction hash |
| `eth_getBalance` | the wallet's address, `"latest"` | The account's balance |
| `eth_getTransactionCount` | the wallet's address, `"pending"` | The account's next nonce |
| `eth_maxPriorityFeePerGas` | none | The priority fee of the commit |
| `eth_estimateGas` | the commit as a call from the wallet's address | The commit's gas, without the account transaction's extra 62,744 |
| `eth_getTransactionReceipt` | a transaction hash | `null` until the transaction is in a block |

The page and marker requests follow [spec 05](spec/05-trees-and-headers.md),
section 8: whole pages from page 0, as of a block hash, whatever the wallet
expects to find. The headers asked for depend only on the tip and on the
headers the page already holds: from the tip down to the first block its
header chain holds (see Headers), so the first time every block from the
pinned start (genesis on a network with no pin). The block receipts are
asked for the same way: by block hash, once for every block of the page's
header chain from its start to the tip, in chain order, whatever the key
(see Block receipts). No request names a key, a commitment, a position or
a marker, and the app never asks for a witness; it computes its own from the
pages. The wallet's requests name its address, which the commit transaction
shows anyway. The only request that carries a coin's data is the reveal itself,
whose fields are public; sending it, though, links the connection to the
coin it spends.

The tree answers are read in the node's shape (ghost-node
`docs/trees-and-headers.md`, "Wallet tree pages") and in no other. The app
refuses page roots that are not an array, and a coin page whose `filled` is
not the number of its `entries`, that is not whole (every page but the
last holds 4,096 leaves and the last 1 to 4,096), or that is not the page
asked for (its `kind` `"coin"`, its `treeIndex` the tree index asked and
its `page` the number asked), so no page is missing, repeated or out of
order. An entry's `salt`, when
present, must be 16 bytes of hex, or the page is refused as malformed. The
page roots and leaves must then give the root of their tree, as Coin trees
says.

### Coin trees

A coin tree holds 2^32 leaves; once it is full the next leaf goes to
position 0 of the next tree index, and the full tree is final (spec 05,
section 3). Headers carry only the current tree's root, so the app reads
every coin tree index as of the tip, from tree 0 up to the tip's own
(`fetchTrees` in `webapp/src/flow.mjs`; spec 05, section 8, RT-5), in
whole pages, and asks for tree k + 1 only once tree k is shown full and is
not the tip's tree, so it never asks for an index past the tip's:

- A tree with fewer leaves than a full one is the tip's: its page roots and
  leaves must give the tip's coin root.
- A full tree's root, computed from its leaves and checked against its page
  roots, is either the tip's coin root (nothing is in the next tree yet, and
  the read ends there) or that tree's final root, which must be the coin
  root of a header of the page's best chain from its start to the tip, and
  differ from every earlier tree's.

A tree with more leaves than a tree holds, a full tree whose final root no
header of the page's chain carries (for instance on a network whose pin is
above the block that filled it), a tree served twice, or a page of another
tree index is refused. A commit or a reveal's new leaf is looked for in the
tree its block appended to: the block's coin root is a prefix root of that
tree, and its parent's one of the same tree, or the final root of the tree
before when the block started it.

The worker's receipts check (`ghost_receipts_check`) covers coin tree 0
alone and takes a rollover only at 2^32 leaves. A scan whose tip is past
tree 0 therefore makes the same checks in the page, over every tree
(`checkTreesAgainstReceipts`): from the coin tree logs of the receipts the
worker has just checked against each header's `receiptsRoot`, read in the
client library's layout (`coinRecord`), every record must follow the one
before (the next position, or position 0 of the next tree once a tree
holds `treeLeaves`), each tree's leaves, notes and salts from the chain's
start on must be exactly those the records appended to it, no record may be
of a tree not read, and the markers must be those of the reveal records.
Anything else is refused before the key is tried on any note. The key is
then tried on each tree's notes, one restore per tree, and each coin found
carries its tree index; the current coin is the unspent one in the latest
tree, at its highest position.

A coin of a full earlier tree is proven against that tree's final root,
which every leaf of the tree shares and the header of the block that filled
it carries (spec 05, section 5, item 5, and section 13, item 4): no root of
the next tree holds it, so there is no wait, and Summon shows that block as
the tree state. A coin of the tip's tree follows the tree-state rule of
Summon and Claim, with
each header's leaf count taken in the tip's tree (none for a header of an
earlier tree). `createFlow`'s `treeLeaves` sets a smaller tree for a test
node; the release never sets it.

A test node built with trees of fewer levels (spec 05, RT-1 Part B: 14
levels, 16,384 leaves) carries roots of that depth in its headers.
`createFlow`'s `treeDepth` (12 to 32, 32 by default, with `treeLeaves` then
2^treeDepth unless set lower) tells the app so. The worker hashes only 32
levels, so at any other depth the page checks each tree and computes its
prefix roots itself (`treeCheckAt`, `prefixRootsAt`), with the same hash:
Keccak-256 of the node tag, the level and the two children, written in
`flow.mjs` and checked against the module's in the tests. At 32 levels the
worker's check is used, as before. The worker proves a coin only against a
32-level root, so with the module the page ships a reveal at a smaller depth
is refused before it is proved (`SMALL_TREE_REVEAL`).

Part B's node takes such reveals with a stub verifier (spec 05, RT-8 Part B),
which accepts exactly `K("ghost/test-proof/v1", binding digest)` in the first
32 bytes of the proof field and zeros after. For it, `webapp/wasm` has a
Cargo feature, `test-tree-depth`, off by default and never in the module the
page ships. Built with it (into a target directory of its own, as the tests
and `scripts/recovery-blackout.sh` do), the module also exports
`ghost_prove_test_depth` and `ghost_test_depth_levels`: the reveal of a coin of
a 14-level tree, built as a real one (the same marker, remainder, note and
envelope) against the page's 14-level root, with that stub of its binding
digest (`coin_reveal_binding`, or `salted_coin_reveal_binding` for a salted
coin) in place of a STARK, never a proof that claims to be real. It also
exports `ghost_decode_envelope_test_depth`, the envelope decoder that takes
that stub as the test node does, for the tests' stand-in node; its
`ghost_decode_envelope` still takes real proofs only. All of it is the last
item of `lib.rs`, behind the feature, so the module the page ships is built
from the same source as before. At a depth below 32 the flow asks the worker
`testDepthProver` for the depth the module's reveal is made for; when that is
the flow's depth it asks `proveTestDepth` for the coin, and otherwise refuses
with `SMALL_TREE_REVEAL`. A decoy is always proved at 32 levels, and a flow of
32 levels asks for neither.

## Headers

The page keeps its own header chain, in the background worker's memory for
the length of the page session: the client library's
`client/src/header_chain.rs`, exported by `webapp/wasm` (`ghost_chain_start`,
`ghost_chain_add`, `ghost_chain_view`). It holds public headers only. The app
adopts a header only through it:

- **Start.** The released build holds a table of networks in
  `webapp/src/header.mjs`, keyed by chain identifier. An entry has the chain
  constants of [spec 06](spec/06-consensus-and-emission.md), section 4.2
  (block time, half-life, start and minimum difficulty, future drift), the
  genesis timestamp, the genesis hash and the start: genesis for a network
  with no pin, or a pinned header (its hash, height, total work and the key
  blocks below it). The page fetches the start header from the endpoint and
  keeps it only if its hash is the pinned one. **The table is empty today**:
  no launch network or pinned start exists yet, so on any network this build
  shows no confirmations and says, in plain words, that it has no pinned
  start for the network. `createFlow` takes another table; the stand-in tests
  and the real-node test add their own entry (the real-node test reads the
  genesis hash from the node it started).
- **Every header after it.** The endpoint's headers are read from its tip
  down to the first one the chain holds, then added from there up, with the
  page's clock in Unix seconds. A header is adopted only if keccak256 of its
  RLP, the list of the 18 fields of
  [spec 05](spec/05-trees-and-headers.md), section 10 (`webapp/src/header.mjs`
  builds it), is the hash the endpoint returned with it; its parent is a
  header the chain holds and its number the parent's plus one; its
  timestamp is after the parent's and at most the future drift ahead of the
  clock; its difficulty is the one the ASERT rule of spec 06, section 4.3,
  requires; and its RandomX seal is valid under the key block on its own
  branch ([spec 08](spec/08-randomx-seal.md)). No seal after the start is
  skipped. A header that is only ahead of the clock is offered again after a
  short wait, three times at most.
- **Most work.** The best chain is the one with the most total work. The
  endpoint's tip must be on it: a tip on a lighter branch is refused, with
  the heavier chain kept, and a reorganisation is followed as soon as the
  endpoint's branch is the heavier one. Every height, coin root, fee input,
  settled height and confirmation count the app uses comes from headers on
  the best chain, up to the endpoint's tip.
- **Uncertain means refused.** A start whose hash is not the pinned one, a
  header the chain cannot place, a seal that is not valid, a wrong
  difficulty or any other failure of the check: the app shows no
  confirmation, takes no step that depends on the headers (it signs no
  commit and proves no reveal on them), and says that the endpoint's chain
  failed the proof-of-work check.

Each RandomX cache takes 256 MiB of the worker's memory; the chain holds at
most two. Checking a seal takes about a quarter of a second in the
WebAssembly module on a desktop, so the first visit to a long chain reads
and checks every header since the start, and a node that seals blocks
faster than that cannot be followed.

Querying more than one endpoint and refusing on conflict is not built
(front-desk decision, 2026-10-20): agreement between endpoints would be extra
evidence, never a substitute for the checks above.

## Block receipts

No header root covers the notes stored with the leaves, the salts beside
them or the spent markers, so the app checks them against the block
receipts ([spec 05](spec/05-trees-and-headers.md), section 8, item 5 and
"Marker status"), through the client library's receipt checks
(`check_block_receipts_against_header`, `check_leaves`, `check_markers`),
exported by `webapp/wasm` (`ghost_receipts_add`, `ghost_receipts_check`, and
`ghost_receipts_root` for the stand-ins). Every scan does this before the key
is tried on any note:

- **Fetch.** The app takes the blocks of the page's header chain from its
  start (genesis, or the pinned header) to the tip, each the parent of the
  next, and asks `eth_getBlockReceipts` for each by its hash, in chain
  order, for every key alike. It encodes each receipt as its block's
  `receiptsRoot` covers it (the type byte for a typed receipt, then the RLP
  of status, cumulative gas, bloom and logs). A block's receipts are fixed
  by its header, so the worker keeps the coin tree records of each block it
  checked for the page session, and a later scan asks only for the blocks
  added since. No request names a commitment, a marker, a note or a
  transaction.
- **Receipts.** The worker checks each block's receipts against the
  `receiptsRoot` of the header the page's chain holds for that hash, and
  reads the commit and reveal logs of the coin tree account in the node's
  layout, as the client library documents it.
- **Leaves, notes and salts.** From the leaf count of the chain's start
  (found by matching its coin root to a prefix root of the downloaded
  leaves, 0 at genesis) to the tip, every downloaded leaf, note and salt
  must be exactly the one the receipts appended at that position, none
  missing, repeated, reordered or invented.
- **Markers.** The spent markers, read as of the tip, must be exactly those
  of the reveal receipts of the blocks up to that block, in order: the
  whole list from genesis, or from a pinned start the markers its blocks
  spent, which must end the list.
- **Uncertain means refused.** A leaf, note, salt or marker the receipts do
  not show, a missing, repeated or reordered page or block, a receipts root
  that differs, a block whose receipts cannot be fetched, a receipt not in
  that shape or a start the app cannot place: the scan stops with a plain
  message (`the endpoint's coin tree or spent markers do not match the
  block receipts`), shows no coin, and the key is used for nothing, so no
  restore, marker lookup, proof or reveal follows. Every request of the
  scan comes before this check, so the endpoint sees the same requests
  whether the data it altered is the key's or another's, and nothing it
  sees afterwards depends on the key.

## Wallet

The wallet is built in (spec 09, section 9); no browser wallet and no
elliptic-curve key is used. Its seed is 32 bytes from
`crypto.getRandomValues`, shown as 24 words of the BIP-39 English list (the
256 bits and an 8-bit SHA-256 checksum; no PBKDF2 and no passphrase). A new
wallet shows its words (blurred until asked) and opens only after the same
save check as a key, on three of the 24 words. A saved wallet is restored by
typing its words. The words are kept in the flow controller's memory while
the wallet is open, never in its rendered state, browser storage, a file or a
server, and are dropped when it is closed. Digits are refused as a seed. The
seed's words and a Phantom Key's words come from the same list, with checks
of their own, and derive nothing in common: each derives its values under
its own tags, so a seed typed as a key finds no coin of the wallet's, and a
key typed as a seed opens no account of the key's.

The account is index 0 of the seed:

```text
key_seed = X("ghost/wallet-account/v1", 32, seed, 0x0001, 0 as 4 bytes)
(sk, pk) = ML-DSA-44.KeyGen_internal(key_seed)
address  = first 20 bytes of K("ghost/account-address/v1", 0x0001, pk)
```

The page shows the address and its balance. The commit is an account
transaction, type `0x52` in ghost-node (`docs/account-transactions.md` there;
spec 09 proposes `0x51`, which is the node's data reveal), to the commit
entry address, whose value is the amount and whose data is the commit
payload of [spec 03](spec/03-coin-rules.md), section 6, as the node reads
it (ghost-node `core/ghostpriv/commit.go`). The app sends version 2, a
salted commit (`SaltedCommitDataSize`): the 2-byte version `0x0002`, the
fingerprint `F` (32 bytes), the coin's salt (16 bytes) and the encrypted
note of commitment number 0 (156 bytes), 206 bytes in all. The salt is
fresh for every coin, drawn in the worker from `crypto.getRandomValues`
through the client library's `salted_coin_commit`; it goes into `F` and
the marker, travels in the clear beside `F`, and is in the note too (note
version 2). The node computes the leaf as `K(tag, COIN_V2, F, v)`, keeps the
salt beside it and serves it back as the page entry's `salt`. The flow
checks the payload is 206 bytes of version 2 before it signs anything.

The node still takes version 1 (`CommitDataSize`): `0x0001`, `F` and the
note, 190 bytes, the commits made before the salt; the app never sends one.
It refuses any other length or version (`commit data is not 190 bytes of
version 1 or 206 bytes of version 2: N bytes`).
`webapp/test/vectors/commit-payload.json` holds a version 1 payload, built
from spec 01, vector coin-commit, for the coins made before the salt.

The worker signs it with the client library (`client/src/account.rs`,
RustCrypto's `ml-dsa` 0.1.1): hedged ML-DSA-44 in pure mode with the context
`ghost/tx/v1`, over `K("ghost/account-tx/v1", 0x52, genesis_hash,
keccak256(unsigned))`. The genesis hash is the one this build's table holds
for the network (see Headers), and the base fee is read from the tip the
page's header chain adopted. The nonce is `eth_getTransactionCount` of the
pending block, the priority fee `eth_maxPriorityFeePerGas` held at 2 gwei at
most, the fee cap twice the next block's base fee plus the priority fee, and
the gas limit `eth_estimateGas` plus 62,744, the gas the node adds for the
scheme, key and signature bytes and the check. Those answers come from the
endpoint, so the app bounds what they can make it sign: it refuses a gas
limit above 500,000 and a commit whose gas could cost more than 0.01 GHOST
(`maxCommitFee`, a setting of the flow controller). A commit the balance
cannot pay for is not signed either. When `eth_sendRawTransaction` answers the commit with an error, the
app asks `eth_getTransactionByHash` and counts the commit as sent only if the
node holds it: ghost-node at the pinned commit takes a type `0x52`
transaction into its pool and still answers `transaction type not supported`,
and its JSON shows such a transaction's `from` as the zero address until its
RPC derives it from the public key. A reveal is a native transaction with no account, so Summon and
Claim need no wallet, and Summon pays to any 20-byte address as before.

The commit entry address defaults to the internal network's coin commit
entry, `0x67686f7374000000000000000000000000000005` ("ghost" in ASCII, then
5; `params/ghost/privaccounts.go` in ghost-node). The data commit entry of
that network, `0x67686f7374000000000000000000000000000007`, is not used: the
app makes no data commitments.

## Summon and Claim

1. **Restore.** The app reads the coin tree as of the tip in whole pages and
   checks each page against the page-root list and the list against the tip's
   `coinTreeRoot`. It reads the spent markers the same way, as of the tip
   (the depth of Done, the block itself), so a key shows claimed as soon as
   a block holds its spend. With each leaf and its note the app reads the
   salt served beside it, if any, and hands restore one salt (or none) per
   leaf, beside the leaf (the records stay leaf and note, 188 bytes each).
   The worker tries the key's note key on every note and recomputes
   each found commitment (spec 01, section 8): a version 2 note carries its
   coin's salt, which goes into `F`, `C` and the marker; a version 2 coin
   whose salt beside the leaf is not its note's is not trusted. Restore
   returns each found coin's salt (none for version 1). The current coin is
   the found commitment whose marker is not spent. The app asks for
   everything a reveal needs (the headers, the tree, the markers and the
   block receipts, fixed by the tip and by what the page already holds)
   before the key is tried, and restore runs only once the leaves, notes,
   salts and markers have passed the check of Block receipts.
2. **Same requests after restore.** On a reveal or claim, every path after
   restore, the one where the key holds no unspent coin included, then asks
   the endpoint the same thing in the same order before anything depends on
   what restore found: `eth_blockNumber`, the tip's header and the fee
   headers for the next block. Before these requests the worker always
   makes a proof and sends nothing: of the coin when it can be revealed,
   otherwise of a decoy, a throwaway key's coin placed at the last position
   of the same leaves, of the same kind. The decoy mirrors the version of
   the key's coin (salted, as a new coin is, unless the key's current coin
   is of version 1), so the work does not depend on the coin. A coin's proof that the worker
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
   section 3. The reveal and the claim pass the coin's salt, from restore,
   to the prover as a private witness: a salted coin is proved as salted and
   its remainder is salted under a fresh salt, carried only in the
   remainder's note; a version 1 coin is proved as before, with a version 1
   remainder. The worker verifies a salted proof as salted; the stand-in,
   like the node, verifies a reveal as salted first, then as version 1. A
   claim sends nothing out and names the zero address.
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
7. **Status.** As soon as the node takes the commit, a reveal or a claim, the page shows it **Sent**, with the amount and
   the transaction hash; nothing is waited for first. The app then polls the
   receipt, but a receipt is only the endpoint's word. A receipt naming a
   block that was already in the chain when the transaction was sent, or one
   past the tip, is refused before any header is read for it. The first
   block that holds the transaction is enough (`CONFIRMATIONS` is 1, the
   transaction's own block): no block on top is waited for. A commit,
   reveal or claim shows **Done** only when the coin tree as of the tip,
   checked against the tip's coin root, holds the new leaf the transaction
   appends, at a position added by the receipt's block, read from the coin
   roots of that block and its parent on the page's header chain leading
   to the tip, the one with the most work. Until then a claim stays Sent and
   the old key unclaimed. From that block on the old key shows claimed,
   because the markers are read at the tip. An endpoint whose chain fails
   the check of Headers gets no step past Sent.
8. **Reorganisation.** Done comes at the first block, so a reorganisation
   can still replace that block. A receipt, or a missing one, is never the
   evidence that a transaction is gone: an endpoint can answer null for a
   transaction that went through. The chain is. If the receipt names a
   block that is no longer the chain's block of that number while the app
   checks it, the app reads the coin tree as of the tip, checked against
   the tip's verified header: when it holds the transaction's new coin the
   receipt is read again to find its block, and only when it does not does
   the step show dropped. After Done, Refresh (Summon and Claim) and "Check
   the commit is still in the chain" (Vanish) look again: while the chain's
   verified header at the Done block is still that block, the step stays
   Done; otherwise it shows dropped only when the tip's verified coin tree
   no longer holds its new coin, and Done again, in its new block, when it
   does. Then the page says plainly that the chain was reorganised, that
   the block no longer holds it and that nothing it did stands, and the
   holder can send again: the coin shows unspent, so Reveal and Claim are
   open again, and Vanish can start again. From the moment the node takes a
   reveal or claim until it is Done, its input coin stays pinned for the
   open key, across a drop and the sends after it: a send again may only
   spend that same coin, whose marker is the one dropped, so at most one of
   them is ever executed. If the dropped reveal comes back before the send
   again, that coin is spent and the app stops with an error instead of
   paying again from the remainder; a Refresh that finds it Done again
   releases the pin. The pinned-coin guard of step 6 is unchanged.

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
- **The pinned start is the one assumption left.** Every header after it
  is checked in the page, seal and difficulty included (see Headers), so an
  endpoint cannot show confirmations no miner sealed; it can still withhold
  blocks, or serve a chain that real miners sealed and outworked. What the
  chain rests on is the start header in this build's table (genesis, or a
  pinned header with its total work and key blocks): a build with a wrong
  pin would follow the wrong chain. The table is empty today, so the
  released build shows no confirmations on any network until a launch
  network and its start are added.
- **One endpoint.** The page asks one endpoint. Asking several and refusing
  on conflict is not built; agreement between endpoints would be extra
  evidence, never a substitute for the checks of Headers.
- **The chain lives as long as the page.** The header chain is held in the
  worker's memory only, so each new page session reads and checks every
  header from the start again.
- **Before a pinned start.** The receipts start at the chain's start, so on
  a network whose build pins a header above genesis, the notes and salts of
  the leaves before it, and the spent markers its earlier blocks hold, rest
  on the pin as its coin root does: no header of the page's chain covers
  their receipts. From genesis, every one is checked. (Closed: the notes and
  markers are checked against block receipts, and an endpoint can no longer
  test for a coin one bit at a time by spoiling notes or markers and
  watching whether a reveal follows; see Block receipts.)
- **The zero address.** The app refuses it as a reveal's recipient and as
  the commit entry address, because what it is credited cannot be spent.
- **Later trees are checked in the page.** Once the coin tree has rolled
  over, 2^32 leaves away, the receipts check of every tree is the page's own
  (Coin trees), not the worker's, which covers tree 0 alone: the two read the
  same log layout and must agree. The worker still checks every block's
  receipts against its header's `receiptsRoot` first. Trees of fewer levels
  than 32, on a test node, are likewise hashed by the page, and no reveal is
  proved on them (Coin trees).
- **Reorganisations are found when asked.** A step shown Done is checked
  again only on Refresh or "Check the commit is still in the chain"; the
  page does not watch the chain on its own.

## Tests

`node --test webapp/test/` runs, after the module is built:

- `flow.test.mjs`: Vanish with a wrong and then a right save check, a
  partial Summon and a Claim, with the real prover in a `worker_threads`
  worker, against a scripted stand-in for the node's JSON-RPC
  (`test/support/fake-node.mjs`). The stand-in verifies every reveal's proof
  with the real verifier, checks the fee, the root and the marker as a node
  admits a reveal, and records every request. The test checks that no run of
  a key's words, no seed word and no commitment of the key reached the
  endpoint, that the block receipts were asked for by hash alone, every
  block once and in order, and that `index.html` loads only same-origin
  scripts. It checks that the requests, and where the worker's proof falls
  among them, are the same whether the key owns a coin or its coin was
  claimed from another device, up to the reveal itself. Playing a
  dishonest endpoint, it also checks that a fabricated receipt for a withheld claim confirms nothing;
  that headers whose `coinTreeRoot` was changed under their real hash are
  refused; and that a claim is Done, and the old key claimed, at the first
  block that holds it, with no block on top. It also summons a coin 2 blocks after a
  stranger's later commit, against that commit's block root, after the same
  coin, with nobody committed since, was shown the plain warning and refused.
  The stand-in's headers follow the internal network's test constants
  (difficulty 1 on the 30-second schedule, an all-zero mix digest), so the
  page's header chain checks the seal of every one of them.
- `block-receipts.test.mjs`: against the stand-in, which serves real
  receipts for every block in the node's log layout, with the real module in
  a worker. An honest scan passes, asking for the receipts of every block
  from genesis to the tip once, by hash, in chain order, before restore, and
  a later scan only for the blocks added since. An altered note, an altered
  or missing salt, a dropped, repeated or reordered page, a hidden, invented
  or replaced spent marker, receipts that do not give the header's
  `receiptsRoot`, a block whose receipts are not returned and a malformed
  receipt are each refused before restore, marker lookup, proving or any
  reveal, with no coin shown. The requests (method and parameters) of a scan
  whose altered note is the key's are those of one whose altered note is
  another's, and of an honest scan.
- `header-chain.test.mjs`: the module's chain exports directly (sealed
  headers adopted; a wrong hash, a wrong difficulty, an unmined seal above a
  pinned start stamped ahead of the schedule and a header ahead of the clock
  refused; the heavier of two branches kept and the reorganisation to it
  reported), then the app against the stand-in. A chain whose seals are not
  valid (every block 32 half-lives ahead of the schedule, carrying the 2^32
  that requires, with an unmined nonce, above a pinned block 1) and a chain
  whose headers carry a wrong difficulty are both refused: no coin, tip or
  Done is shown, the page says the endpoint's chain failed the proof-of-work
  check, and no commit is signed on them. A lighter competing chain is
  refused and the heavier one kept, the commit shown Done staying Done,
  until the competing chain outweighs it and the page follows the
  reorganisation. An empty table, and a start whose hash is not the pinned
  one, show no confirmations either. From a pinned start, the receipts of
  every block from the pin to the tip, and none below it, are checked.
- `words-key.test.mjs`: a new key is 24 words of the list, its digit view
  21 groups that open the same key; words round-trip through the save
  check; a typed key is taken in any case with spaces or hyphens, whole
  words only; a word cut short or run on is refused and named by position,
  a swapped or wrong word fails the check, and no refusal holds a word or
  digit of the key, nor is anything derived from it; an old 12-group key
  still restores, in the module and through the app against the stand-in.
- `earlier-trees.test.mjs`: against the stand-in given trees of three
  leaves, so that it rolls over: every coin tree from 0 up to the tip's is
  read in whole pages, each full one against its final root in a header and
  the last against the tip's, and no index past the tip's tree is asked for;
  a page of another tree index, a changed page root, a tree cut short at an
  earlier block's tree, a tree of too many leaves, a full tree whose final
  root no header carries and a tree served twice are refused. A commit is
  followed into the full tree 0 after the tip has moved to tree 1, and to
  tree 1's first position, where a scan of both trees finds it, while one
  whose tree 0 is just full still finds the coin that filled it. A coin of
  the full tree 0 is revealed against tree 0's final root with no wait, a
  clean device restores it spent and its remainder in tree 1, and that
  remainder is revealed against a settled root of tree 1. A note of either
  tree, a salt or a spent marker that the receipts do not show is refused
  before restore; the page's check of every tree also refuses, on its own,
  a changed leaf, note or salt, a leaf missing or invented, a record of a
  tree not read, a rollover before or after `treeLeaves` and a marker
  missing, invented or changed. The page's Keccak-256 and its 32-level roots
  and prefix roots equal the module's, and its 14-level roots, climbed over
  empty subtrees with the module's hash, give the module's 32-level root of
  the same leaves. Against a stand-in whose headers carry 14-level roots
  (16,384 leaves per tree), a device of the release depth refuses them, and
  one told the depth finds a coin in the full tree 0 with tree 0's final
  root as its tree state and one in tree 1, and refuses to prove.
- `test-depth-reveal.test.mjs`: the module built with `test-tree-depth`
  (`GHOST_WEBAPP_TEST_DEPTH_WASM`, or built into `ghost-test-depth` under the
  temporary directory) reveals a coin of a full 14-level tree against that
  tree's root in its header, and the stand-in takes it; the proof field is
  1,310,720 bytes, the stub of the binding digest the test computes from the
  envelope's own fields, then zeros, and a changed stub, a byte after it or
  a decoder of real proofs refuse it. The default module has none of the
  three test-depth exports and otherwise exports the same, and still refuses with `SMALL_TREE_REVEAL`, sending nothing, and a
  flow of 32 levels proves a STARK and never asks for the test-depth reveal.
- `salted-coin.test.mjs`: the commit is 206 bytes of version 2 with a fresh
  salt, in the module and as the wallet signs it, and the stand-in keeps
  that salt with the leaf; restore reads the salt beside the leaf, finds the
  coin with it (or from its note when none is served), refuses a coin whose
  salt beside the leaf is not its note's, and a page with a salt that is not
  16 bytes is refused.
- `words-flow.test.mjs`: the save check takes three typed words, whichever
  view is shown, and refuses a wrong, short or digit answer; a salted coin is
  revealed and claimed, its salt passed to the prover and its remainders
  salted; a version 1 coin of an old 12-group key still reveals and claims,
  with no salt and a version 1 decoy when its reveal cannot be made.
- `wasm.test.mjs`: the module against the golden vectors of spec 01 and
  spec 05, the header's RLP and hash included, the version 2 commit and the
  words key; a receipt's encoding and the receipts root; and the receipts
  check of leaves, notes, salts and markers, with its refusals.
- `commit-layout.test.mjs`: the version 2 commit payload (206 bytes) and the
  version 1 payload against the node's layouts and the shared vector
  `test/vectors/commit-payload.json`, and the default commit entry address.
- `reveal-fast-node.test.mjs`: a Summon reveal against the stand-in playing
  a fast-mining node: a block every 500 ms (the page checks each seal, so a
  node much faster than that cannot be followed), a send refused because the head
  moved, a fee that changes before the resend so the reveal is proved
  again, and a taken send the node drops before any block holds it. The
  reveal must land within a bound, the recipient paid once, every proof of
  the same coin and every envelope of the same marker.
- `reveal-reprove.test.mjs`, with no proof made: a Summon reveal against an
  in-process stand-in whose tip moves on every poll and that refuses every
  send of the first proof's envelope, with a stub prover (the stand-in's
  block receipts are checked by the built module, as the worker checks
  them). With a proof as
  slow as the real one the reveal is proved again after one refusal, with a
  quick one after 5; either way it goes through, paid once, every proof of
  the first proof's coin and of one marker.
- `reveal-moving-head.test.mjs`, with no proof made: an in-process stand-in
  whose tip moves on every poll and a stub prover, the block receipts again
  checked by the built module. A reveal refused there is
  sent again after one look at the tip, never after waiting for a still tip,
  and goes through; a refused proof whose root has fallen more than 34
  blocks below the tip is proved again for the tip instead of sent again;
  a node that refuses 40 sends in a row with the head-moving error over
  minutes of proving still gets the reveal, paid once; and a node that
  refuses every send stops the reveal after 10 minutes, or at 200 proofs, of
  at most 5 sends each.
- `stand-in.test.mjs`: the stand-in refuses what the node refuses for a
  commit (not to the commit entry address, data neither 206 bytes of
  version `0x0002` nor 190 bytes of version `0x0001`, among them the old
  189-byte layout, in the node's words) and accepts both payloads, serving a
  version 2 commit's salt beside its leaf; it serves every block's receipts
  by hash, in the node's log layout, under its header's `receiptsRoot`.
- `sent-and-done.test.mjs`: against the stand-in holding each transaction
  in its pool until the next block, Vanish, a partial Summon and a Claim
  show Sent, with the amount and hash, while no block holds the
  transaction, and Done in the block that holds it, with no later block
  mined. A reorganisation that drops a reveal or commit shown Done is found
  on Refresh or Check and said plainly; the coin can be revealed again, and
  an endpoint that takes the resend and still answers that its head moved
  gets no second payment from the remainder. An endpoint that hides the
  receipt of a reveal the chain still holds, in its block or moved to
  another, never makes it show dropped; a dropped reveal that comes back
  before the send again is not paid again from the remainder, and a Refresh
  then shows it Done and releases the pin. A receipt from a block replaced
  while the app checks it shows the claim dropped.
- `units.test.mjs`: the fee against the worked examples of spec 07, the
  base fee rule, the settled height, amounts and the save check on words.
- `early-reveal.test.mjs`, with nothing built: the tree-state choice with a
  stub prover. A coin is revealed against the root 2 blocks below the tip
  right after a later commit, the plan reports the leaf count that root
  covers, and a coin nobody followed waits with the plain warning and is
  never proved against its own block root.

- `page-layout.test.mjs`, with nothing built: `index.html` and `style.css`
  read as text. Every id `app.mjs` wires is in the page, once; the Vanish
  and Summon tabs are a tab list with Vanish selected; the Vanish panel
  holds the amount box (`0.00`, the ghost icon and GHOST inside it), the
  balance line reading `Balance: —` and Max, and the main button; the
  wallet button opens a panel with the create and restore flows; the
  Network and About panels are reached from the footer; Claim sits in a
  hidden container; the icons are inline SVG with no namespace attribute;
  the CSP keeps `default-src 'none'` and adds `font-src 'self'`; no
  external URL, inline script or inline style; the Midnight violet colors
  are CSS variables of one dark theme; the glow and motion sit inside
  `prefers-reduced-motion: no-preference`.

The key image download, drawn on a canvas in the page, and the digit-view
button are not covered by the headless tests; the flow's digit view is.
Neither are the tab, panel and Max wiring of `app.mjs`, which needs a
browser.

### Against a real node

`test/e2e/real-node.test.mjs` is not loaded from `test/index.js`. It starts
the release `geth` named by `GHOST_NODE_GETH` as a one-node internal network
(network 6777971, mining, the internal network's genesis, JSON-RPC
`eth,net,web3,ghost` over HTTP on a port the system picks) and runs Vanish, a
partial Summon and a Claim with the real prover. The wallet is restored from
the tests' seed words; its account is the miner's etherbase, so block rewards
fund it, and the commit and the strangers' commits are account transactions
it signs. The keys are 24 words, and the save checks are answered with
words. It checks on chain that the commit is type `0x52` from the wallet's
address, the commit's 206 bytes of version `0x0002` and its leaf, the salt
the node serves back beside that leaf (and none beside the remainder's),
the spent marker, the remainder's leaf, the recipient's balance and the
claimed coin. It also checks the tree-state rule: opened before anyone else
commits, the coin waits with the plain warning and its reveal is refused;
once a stranger's commit is 2 blocks deep the Summon goes out with no
further wait, and so does the Claim after another stranger's commit follows
the remainder. The commit, the reveal and the claim each show Sent with
their hash and amount, and Done at the block their receipt names. Without `GHOST_NODE_GETH` it prints
`SKIP: GHOST_NODE_GETH is not set` and runs nothing.
`webapp/scripts/build-node.sh` clones ghost-node at the commit in
`test/e2e/NODE_COMMIT`, builds it and prints the path to its `geth`:

```sh
GHOST_NODE_GETH="$(webapp/scripts/build-node.sh)" \
  node --test --test-timeout=3600000 webapp/test/e2e/real-node.test.mjs
```

`test/e2e/recovery.test.mjs` runs only under `scripts/recovery-blackout.sh`,
which blocks every project-run host and runs three nodes, one of them an
independent node synced from peers only, and a clean device that restores
keys from their digits alone and spends them; see
[recovery test](recovery-test.md).

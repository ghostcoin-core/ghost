# The web app

Status: first version, 2026-10-18. Experimental and unaudited. How to build,
check and run it is in [webapp/README.md](../webapp/README.md).

The web app is the first product on the client library: a user connects a
quantum-safe wallet and uses GHOST privately, with Phantom Keys of 24 words
over salted coins (see Phantom Keys). The page never creates, restores or
sees a wallet's seed or key (see Wallet). It does three things.

- **Vanish.** It creates a new Phantom Key of 24 words and shows them, in a
  numbered grid, for the user to write down (the flow can also write the
  same key as 21 groups of four digits; the Vanish card shows the words
  only). Copying the key and downloading it as an image are conveniences,
  never the only backup:
  before the commit is sent, the **save check** asks for three of the key's
  24 words, chosen at random with `crypto.getRandomValues`, shown by
  position and asked in order, whichever view is shown. A word is compared
  in any case and only whole; the connected wallet is asked to sign the
  commit only when all three match, and a wrong word sends nothing. Once the node has the
  commit, the app forgets the key and its digit view.
- **Summon.** The user types any valid key: its 24 words, or its 21 groups
  of digits. The app finds the key's coin on the
  chain and reveals any available amount to the payout address, by default a
  fresh address of the connected wallet that never vanished;
  the rest, minus the fee, stays under the same key as the next commitment.
  (The flow controller's `summonReveal` takes any 20-byte recipient.)
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

The palette: page `#0A0A12`; card and the tab in front `#15142A` with a
1px `#2A2850` border and 18px corners; the tab behind `#0E0D1C`, border
`#1E1C38`, text `#6E6A99`; input boxes `#0E0D1C`, border `#23214A`,
placeholder `#4E4A7A`; the GHOST token label a `#1F1D3D` pill with the
ghost icon in `#A78BFF`; main and secondary text `#ECEBFF` and `#8C88B8`;
accent (Max, links, focus ring, logo) `#A78BFF`; the main button a
`#6B4CFF` to `#A64CFF` gradient with large bold white text and a slightly
brighter hover; the wallet button a `rgba(167,139,255,.12)` tint, a
`rgba(167,139,255,.3)` border and `#CFC3FF` text; error text `#FF7A9A`.
Behind the card two large blurred circles glow, violet `#6B4CFF` at 35%
and cyan `#2EC5FF` at 18%. Motion: the circles drift in a 20s loop, the
tab slides forward in 200ms, the coin fades out on Vanish's Done screen
and fades in on Summon's. All motion sits inside
`prefers-reduced-motion: no-preference`. Text colors meet WCAG AA on their
backgrounds; white on the gradient's light end is 4.1:1, so the button
text is large bold text (AA 3:1), and 4.5:1 or more where it sits.

- **Top bar.** The ghost icon and "Ghost" top left; the wallet button top
  right. With no wallet connected the button reads "Connect wallet" and
  opens a small dialog, "Connect a wallet", listing the wallets the page can
  connect, one row each with its name and a short line: today one, the
  **Ghost wallet**, which opens in its own window. Only wallets that hold a
  quantum-safe Ghost account key are listed (see Wallet). With a wallet
  connected the button shows the short address (`0x3a…91c`), and the
  popover the full address, the balance, Refresh and "Disconnect". A failed
  connection is one plain line in the dialog ("You rejected the connection
  in your wallet.", "The wallet window was blocked. …").
- **The card.** One centered card, about 420px wide, with two filing-folder
  tabs, **Vanish** and **Summon** (a tab list: click, or the arrow keys,
  Home and End). The selected tab joins the card; the other sits behind it
  in a darker shade.
- **Vanish tab.** One rounded amount box: a large input (`0.00`) with the
  ghost icon and "GHOST" inside it on the right. Under it, right-aligned:
  `Balance:` and the connected wallet's balance (`—` with none connected),
  and Max, which fills in the balance less the most the commit's gas can
  cost (0.01 GHOST). The main button reads "Vanish", or "Connect wallet"
  with no wallet connected, when it opens the wallet list instead. Vanish runs the
  flow above in three screens inside the card, with the Vanish tab kept in
  front:
  1. **Save your Phantom Key.** "These 24 words are the only way to summon
     your *amount* GHOST. Anyone with them can take it. If you lose them,
     no one can get it back." The 24 words in a numbered grid of three
     columns, put in as text only; Copy and Download (the key image of
     `keyimage.mjs`); the main button "I saved it".
  2. **Check your key.** "Type these three words from your saved key."
     Three inputs, each labelled with its word's position. A wrong word
     shows "Those words don't match your key. Check what you saved and try
     again." and sends nothing. "Show key again" goes back to the grid. The
     main button, "Vanish *amount* GHOST", is the only control that sends
     the commit: the connected wallet shows its own approval prompt with the
     amount, the fee and the destination (the commit entry), and the page
     sends only the envelope the wallet returned. From the moment the three
     words match until the flow's check returns, the card shows a thin
     moving bar and one short line instead of the screen; while the wallet
     is asked (the flow's progress `WALLET_APPROVAL`) that line reads
     "Approve the Vanish in your wallet". Turned down in the wallet (error
     `code` 4001, or `name` `WalletRejected`), nothing is sent
     (`eth_sendRawTransaction` is never called), the new key is dropped
     from memory and the card returns to the amount screen, the amount
     still typed, with "You rejected it in your wallet. Nothing was sent."
     Any other failure to sign sends nothing either; it shows "Your wallet
     could not sign the Vanish. Nothing was sent." and the check screen
     stays, to try again.
  3. **Done**, once the check returns with the commit in a block: the ghost
     icon, "*amount* GHOST vanished", "Your Phantom Key now holds it. To use
     it, open Summon and paste your key." and the button "Done", which
     drops the key from memory and returns to an empty Vanish tab.

  An amount under `MIN_VANISH_FEES` (4) Summon fees for the next block,
  computed by the flow's `minVanish` from the endpoint's tip header alone (no
  header chain, `chain.mjs` `minVanishFor`), is refused before a key is made
  with "Vanish at least *X* GHOST: a smaller coin could not pay the Summon fee
  later.", *X* rounded up to 4 decimals; the protocol itself takes 1 wei
  (spec 07, section 5, "The smallest Vanish"). An error (the balance too low,
  the network refusing the commit) is one plain red line in the card, a fixed sentence chosen by what failed and
  never the error's own text; a failed send returns to the check screen.
  The key leaves the page's memory on Done, when the Summon tab is chosen
  and when the page is closed (`pagehide`): the grid is emptied and the
  flow's Vanish step cancelled. Leaving before the check passes sends
  nothing.
- **Summon tab.** One box, "Paste your Phantom Key" (the 24 words, or the
  digit form), and a greyed main button "Paste a key". The key is checked
  once the pasted text holds 24 words or the digits of the digit form's
  groups, and when the box is left; no error shows while typing, and a key
  that does not pass its check is not opened. Once it passes, the app scans
  for its coin and shows an amount box like Vanish's (`0.00`, the ghost icon
  and "GHOST"), with `In this key:` and the coin's amount and Max (the
  amount less the network fee) under it, right-aligned. The main button
  reads "Summon", or "Connect wallet" with no wallet connected, when it
  opens the wallet list. A coin the tree-state rule holds back (see Summon
  and Claim) shows a plain line and "Check again" instead of a Summon it
  would refuse.

  **Payout address.** Under the amount, "Pay to": a plain address input
  (`summon-payout`). Once a key's coin shows with a wallet connected, the
  page asks the wallet for a fresh receive address (the flow's
  `newReceiveAddress`, the connector's optional `newReceiveAddress()`,
  which the Ghost pop-up wallet answers as `ghost_newReceiveAddress` with a
  new account index each call) and fills the field with it. A wallet
  without that request (no such method, a null answer, or "method not
  found", -32601), or one that turns it down, leaves the field with the
  connected address instead. With no wallet connected the field is empty
  and the Summon button asks to connect. The user can type any address;
  a typed address is never replaced. On Summon it is checked with
  `parseAddress` ("Enter the address to pay, 0x and 40 hex digits."), and
  the zero address is refused. Each Summon gets a new address: Done,
  leaving the tab and `pagehide` empty the field. Nothing is stored.

  **Privacy warnings.** Two lines in the caution color, under the field
  and again on the confirm screen. Both are advice and never block the
  Summon:
  - the payout is the connected wallet's address, or an address this page
    sent a Vanish from in this session (the flow's `vanishedFrom`): the
    chain then shows the same public address on both sides, which links the
    Summon to its Vanish whatever the proof hides (threat model C31);
  - a full Summon (the amount plus the network fee is all the key holds):
    `out` is public and the fee is the same for every reveal of a block, so
    it publishes the Vanish's amount. The flow counts the commits of that
    amount among the receipts the page has already checked (the `v` of each
    commit log, `coinRecord`; the key's own commit included), with no new
    request, as `amountMatches`. Fewer than 10, and the line says how many
    and suggests a partial Summon, less than Max. A partial Summon shows no
    amount warning.

  A partial Summon whose remainder (what the key keeps after the amount and
  the network fee) is above 0 but under `MIN_VANISH_FEES` network fees (the
  flow's `smallestCoin`) shows one more caution line, on the form and the
  confirm screen, that what stays is too small to Summon again; a full
  Summon leaves nothing and shows none, and the line never blocks.
  1. **Confirm.** Pressing Summon proves and sends nothing: the card shows
     "Summon *amount* GHOST to *short address*" (the amount as typed and
     the payout address, the full address as the screen's title and in
     "The coin goes to *address*."), the warnings, the primary button
     "Confirm Summon" and "Cancel". Cancel
     returns to the form with the key and the amount kept and calls
     nothing. Only Confirm Summon calls the flow's `summonReveal`, with
     that amount and payout address; a second press while it runs does
     nothing, and a wallet changed since the screen opened sends nothing. The
     confirm step shows for every Summon. No wallet signature is asked
     for: the reveal goes out as a type 0x50 reveal with no sender,
     authorized by the Phantom Key's proof, so whoever holds the key can
     summon.
  2. **Waiting**, while the reveal goes out: "Summoning *amount* GHOST", a
     thin bar and three steps, Making your proof, Sending to the network and
     Confirming, each ticked off as the flow reaches it (from the flow's own
     progress and the reveal record's Sent, never from a timer), then "Keep
     this page open. This takes about 10 seconds."
  3. **Done**, once the reveal is in a block: the ghost icon, "*amount*
     GHOST summoned", "Sent to *short address*." (the payout address, the
     full one as its title), then
     "*rest* GHOST is still in your key. The same key still works." or
     "This key is now empty.", "Check the summon is still in the chain"
     (Refresh's recheck of the reveal's block), and the main button "Done",
     which drops the key from memory and returns to an empty Summon tab.

  An error is one plain red line under the fields, a fixed sentence and
  never the error's own text: "That doesn't look like a Phantom Key. It
  should be 24 words.", a word not in the list named by its position, a key
  or digits that fail their check, "Enter an amount to summon.", "This key
  holds *value* GHOST." (with the most that can go out after the fee when
  the amount fits the coin but not the fee), a key whose coin is already
  spent, a chain the page refused, and a reveal the network did not take or
  the chain dropped. An amount that does not parse or is more than the key
  can send is flagged, never rounded. The key leaves the page's memory on
  Done, when the Vanish tab is chosen (`summonClose`) and on `pagehide`.
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
about 128 bits of strength even against a quantum search. Words are the
only key format: the app neither makes nor accepts the digit keys of twelve
or twenty-four groups.

A typed key is read only by the client library's `PhantomKey::parse`, in
the worker:

- **Words**: 24 whole words of the list, in any case, separated by any mix
  of spaces and hyphens (the flow makes any other white space, a line break
  of a pasted key, one space). A word cut short, run on or misspelled is
  refused and named by its position (`word 5 is not in the word list`),
  never corrected to a near word; 23 or 25 words is its own error.
- **Digits**: 84 digits, the digit view of the words, with spaces or
  hyphens between them. Any other count, 48 or 96 among them, is refused.
- **The check first.** The words' check, or the digit view's check group,
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
| `webapp/src/header.mjs` | The header's 19-field RLP of spec 05, section 10 (`dataMarkerRoot` last), the table of networks this build knows, with the start of each one's header chain, and the IndexedDB store of the headers the page checked |
| `webapp/src/header-store.mjs` | The name the header store is imported by in tests (`createHeaderStore`); its code is in `header.mjs`, which the build ships |
| `webapp/src/receipts-at.mjs` | The receipts of the key's highest coin's own block: the block that appended a position, the 8 blocks asked for (that block and 7 decoys, drawn once per coin for the page session) and the check of the coin's record in them |
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
| `eth_getBlockByNumber` | height, `false` | A header with its `hash` and the 19 fields of spec 05, section 10, by their base client names (`parentHash` to `nonce`, `baseFeePerGas`, `coinTreeRoot`, `dataTreeRoot`, `dataMarkerRoot`); a header without `dataMarkerRoot` is refused |
| `ghost_getPageRoots` | `"coin"`, tree index, anchor block hash | An array of 32-byte page roots, of pages 0 to the last page with a leaf (`[]` for an empty tree) |
| `ghost_getTreePage` | `"coin"`, tree index, page, anchor block hash | `{ kind, treeIndex, page, filled, entries }`: `filled` positions of the page, and `entries`, one `{ leaf, note, salt }` (32, 156 and 16 bytes of hex) per filled position, in order; `salt` beside the leaf of a commit, left out for a reveal's remainder |
| `ghost_getTreePage` | `"coin-markers"` | Not asked: the app no longer reads the spent marker pages; it takes the spent markers from the block receipts it has checked (see Block receipts) |
| `ghost_getNoteBucket` | `"coin"`, tree index, bucket bits, prefix, anchor block hash | `{ kind, treeIndex, bits, prefix, count, entries }`: every filled position of the tree at the anchor whose note's lookup tag starts with the `bits`-bit `prefix`, one `{ position, leaf, note, salt }` each in increasing position order; `bits` must be `clamp(floor(log2(n / 4096)), 0, 24)` for the tree's `n` leaves at the anchor (see Summon and Claim, Restore). A node without it answers `-32601` |
| `eth_getBlockReceipts` | a block hash | The block's receipts in transaction order, each with `type`, `status`, `cumulativeGasUsed`, `logsBloom` and `logs` (`address`, `topics`, `data`) |
| `eth_sendRawTransaction` | the reveal envelope, or the commit's account transaction | The transaction hash |
| `eth_getBalance` | the wallet's address, `"latest"` | The account's balance |
| `eth_getTransactionCount` | the wallet's address, `"pending"` | The account's next nonce |
| `eth_maxPriorityFeePerGas` | none | The priority fee of the commit |
| `eth_estimateGas` | the commit as a call from the wallet's address | The commit's gas, without the account transaction's extra 63,256 |
| `eth_getTransactionReceipt` | a transaction hash | `null` until the transaction is in a block |

The page requests follow [spec 05](spec/05-trees-and-headers.md),
section 8: whole pages from page 0, as of a block hash, whatever the wallet
expects to find. The headers asked for depend only on the tip and on the
headers the page already holds: from the tip down to the first block its
header chain holds (see Headers), so the first time every block from the
pinned start (genesis on a network with no pin). The block receipts are
asked for the same way: by block hash, once for every block of the page's
header chain from its start to the tip, in chain order, whatever the key
(see Block receipts). No request names a key, a commitment, a position or
a marker, and the app never asks for a witness; it computes its own from the
pages. The note bucket reads of restore are the one exception to "whatever
the key": their prefixes are the first bits of the key's own lookup tags,
asked only after every page and receipt above (see Summon and
Claim, Restore); below 8,192 leaves a tree is one bucket, prefix 0, for
every key. The wallet's requests name its address, which the commit transaction
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
then tried on each tree's notes, one restore per tree: each restore is asked
with its tree's index (`treeIndex`), and the module returns that index on
each coin it finds, beside the coin's position in the tree (the page adds
none itself). A tree of more leaves than one tree holds (2^32) is refused
by the module, never read in part. The current coin is the unspent one in
the latest tree, at its highest position.

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
digest (`salted_coin_reveal_binding`; a coin without a salt is refused) in
place of a STARK, never a proof that claims to be real. It also
exports `ghost_decode_envelope_test_depth`, the envelope decoder that takes
that stub as the test node does, for the tests' stand-in node; its
`ghost_decode_envelope` still takes real proofs only. All of it is the last
item of `lib.rs`, behind the feature, so the module the page ships is built
from the same source as before. At a depth below 32 the flow asks the worker
`testDepthProver` for the depth the module's reveal is made for; when that is
the flow's depth it asks `proveTestDepth` for the coin, and otherwise refuses
with `SMALL_TREE_REVEAL`; a reveal that cannot be made is not proved at all.
A flow of 32 levels asks for neither.

## Headers

The page keeps its own header chain, in the background worker's memory for
the length of the page session: the client library's
`client/src/header_chain.rs`, exported by `webapp/wasm` (`ghost_chain_start`,
`ghost_chain_add`, `ghost_chain_add_saved`, `ghost_chain_view`). It holds
public headers only. The headers it adopted on the best chain are also saved
in the page's own IndexedDB (Saved headers, below), so that a later session
does not check their seals again. The app adopts a header only through it:

- **Start.** The released build holds a table of networks in
  `webapp/src/header.mjs`, keyed by chain identifier. An entry has the chain
  constants of [spec 06](spec/06-consensus-and-emission.md), section 4.2
  (block time, half-life, start and minimum difficulty, future drift), the
  genesis timestamp, the genesis hash and the start: genesis for a network
  with no pin, or a pinned header (its hash, height, total work and the key
  blocks below it). The page fetches the start header from the endpoint and
  keeps it only if its hash is the pinned one. Each release is meant to ship
  a pinned checkpoint this way; its value is taken from the launch network by
  whoever cuts the release (a host step), and the pin's total work is an
  assumption, not a check (see "The pinned start is the one assumption
  left"). **The table is empty today**:
  no launch network or pinned start exists yet, so on any network this build
  shows no confirmations and says, in plain words, that it has no pinned
  start for the network. `createFlow` takes another table; the stand-in tests
  and the real-node test add their own entry (the real-node test reads the
  genesis hash from the node it started).
- **Every header after it.** The endpoint's headers are read from its tip
  down to the first one the chain holds, then added from there up, with the
  page's clock in Unix seconds. A header is adopted only if keccak256 of its
  RLP, the list of the 19 fields of
  [spec 05](spec/05-trees-and-headers.md), section 10, `dataMarkerRoot` last
  (`webapp/src/header.mjs` builds it), is the hash the endpoint returned with it; its parent is a
  header the chain holds and its number the parent's plus one; its
  timestamp is after the parent's and at most the future drift ahead of the
  clock; its difficulty is the one the ASERT rule of spec 06, section 4.3,
  requires; and its RandomX seal is valid under the key block on its own
  branch ([spec 08](spec/08-randomx-seal.md)). No seal after the start is
  skipped, except for headers this page itself checked in an earlier session
  and read back from its own storage (Saved headers). A header that is only
  ahead of the clock is offered again after a short wait, three times at
  most.
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

### Saved headers

After each sync, the headers newly adopted on the best chain are saved in
the page's own IndexedDB (`webapp/src/header-store.mjs`, whose code is in
`header.mjs`; database `ghost-headers`), under the chain identifier and the
start's hash. A record is the endpoint's header JSON of one block: the
fields of `HEADER_FIELDS` and the hash, nothing else. No key, word, address
or amount is ever saved. After a reorganisation the heights that changed
are written again and those above the new tip dropped. A failed save is
ignored.

A later session, after the start is checked, loads that entry in height
order and adds the headers to the worker's chain with
`ghost_chain_add_saved` (`HeaderChain::add_saved_header`): every check of
`ghost_chain_add` is made again, the hash, the parent held (so the saved
headers re-link by parent hash from the start to the saved tip), the number,
the timestamp, the required difficulty and so the total work (recomputed,
never read from storage) and the drift, except the RandomX seal, which needs
no key block or cache. The endpoint is then read from its tip down to the
saved tip only, and only the headers above it are checked with their seals.
If the saved list does not start at the height after the start, skips or
repeats a height, or any header in it is refused, or the storage throws, the
entry is discarded, the worker's chain is started again and every header is
checked from the start, seals included, as on a first visit. Browser storage
may be missing, refused or blocked; the page works the same without it.

The cost: the first session checks one RandomX seal per header above the
start; a later one checks one per header above its saved tip and none below
(the test `a second session checks no seal below the saved tip` counts them:
600, then 0, then 5 after 5 new blocks). Saving does not shorten a first
visit on a clean device, which still reads every header from the start: the
year-one header volume of [phone-results.md](scale/phone-results.md) (611.8
MB of headers a year from genesis, modeled, not measured here) and the
[stage 1 verdict](scale/stage1-verdict.md)'s finding on headers for a clean
device stand. Only a pin above genesis shortens that first visit, by trust in
the pin, not by a check.

Querying more than one endpoint and refusing on conflict is not built
(front-desk decision, 2026-10-20): agreement between endpoints would be extra
evidence, never a substitute for the checks above.

## Block receipts

No header root covers the notes stored with the leaves, the salts beside
them or the spent markers, so the app checks the notes and salts against
the block receipts and takes the spent markers from them
([spec 05](spec/05-trees-and-headers.md), section 8, item 5 and "Marker
status"), through the client library's receipt checks
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
- **Markers.** The endpoint is not asked for spent markers. The app takes
  them from the receipts it has just checked: the markers of the reveal
  logs of the blocks from the chain's start up to the tip's depth of Done
  (the tip itself), in block and log order (`heldMarkers` in
  `webapp/src/flow.mjs`). The worker's marker check is still made against
  that list, as a guard. From a pinned start, the markers of the blocks
  before the pin are in no receipt the page checks, so a coin whose only
  spend is before the pin shows unspent (Before a pinned start); a reveal
  of it is refused by every node at the marker check, so no value is lost.
- **The coin's own block.** After restore, the key's highest-numbered coin
  (every earlier number is spent) is checked against the one coin tree
  record at its tree index and position in the receipts of the block that
  appended it (`webapp/src/receipts-at.mjs`). That block's receipts are
  asked for with those of 7 decoy blocks of the chain from its start to the
  tip, by hash, in block order, and checked by the worker as above; the
  decoys are drawn once per coin and kept in memory for the page session,
  so a repeat scan asks the same 8. A key with no coin, or a coin older
  than a pinned start, asks its own fixed 8 with no real block. The
  receipts of every block are already held by then, so an honest scan sends
  no request for this step.
- **Uncertain means refused.** A leaf, note or salt the receipts do not
  show, a missing, repeated or reordered page or block, a receipts root
  that differs, a block whose receipts cannot be fetched, a receipt or
  coin tree log not in that shape or a start the app cannot place: the scan
  stops with a plain message (`the endpoint's coin tree does not match the
  block receipts`), shows no coin, and the key is used for nothing, so no
  restore, marker lookup, proof or reveal follows. Every request of the
  scan comes before this check, so the endpoint sees the same requests
  whether the data it altered is the key's or another's, and nothing it
  sees afterwards depends on the key.

## Wallet

The wallet is connected, not built in (decision of 2026-10-24): the page
has no create or restore flow and never sees a seed or an account key.
Ghost accounts are quantum-safe from genesis: the account key is ML-DSA-44
(spec 09, section 9) and the node refuses every elliptic-curve transaction,
so a wallet that signs only with an elliptic curve cannot sign a Ghost
transaction and the page never offers one. "Connect wallet" lists only
wallets that hold a Ghost account key; today that is the Ghost pop-up
wallet (`wallet/` in this repository, with its own README), a small static
site hosted on its own origin, `https://ghost-wallet-nine.vercel.app`, that
creates and keeps the Ghost account key there and signs the account's
transactions once the user approves them in its window. The wallet answers
only the hosted web app, `https://ghost-webapp-alpha.vercel.app`
(`wallet/src/config.mjs`). The address is the account's as spec 09 gives
it:

```text
address  = first 20 bytes of K("ghost/account-address/v1", 0x0001, pk)
```

`webapp/src/wallet-connect.mjs` holds the connector interface, and
`webapp/src/popup-wallet.mjs` the pop-up wallet's connector. A connector is `{ id, name, connect() -> { address },
signTransaction(fields) -> { sender, txHash, envelope }, disconnect() }`,
where `fields` is `{ chainId, genesis, nonce, maxPriorityFeePerGas,
maxFeePerGas, gasLimit, to, value, data }` (bigints and byte arrays) and the
answer is byte arrays. The flow controller takes one with
`flow.walletConnect(connector)` and lets it go with `flow.walletDisconnect()`;
`flow.state.wallet` is `{ id, name, address, balance }` and nothing else.

The pop-up connector opens the wallet's origin with `window.open` when the
user picks the wallet, posts its requests to that origin only over
`postMessage`, reads replies only from that origin and the window it
opened, and asks exactly two things:

| Request | Parameters | Answer |
|---|---|---|
| `ghost_getAccount` | none | `{ address, publicKey, scheme, rescueKey }`: `address` and `publicKey` 0x hex, `scheme` `"0x0001"` or `"0x0003"`, `rescueKey` a boolean |
| `ghost_signTransaction` | `{ chainId, genesisHash, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data }`, 0x hex (quantities without leading zeros, `to` null for a contract creation), and `from` optional (account 0) | `{ sender, txHash, envelope, scheme }`, 0x hex, `scheme` as above |
| `ghost_rescue` (the connector does not send it) | `{ chainId, genesisHash, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, balance }`, 0x hex, `balance` the account's balance in wei as read from the node, and `from` optional (account 0); the destination is typed by the user in the wallet, never taken from the request | `{ sender, txHash, envelope, scheme: "0x0004" }`, 0x hex |

The connector reads only `address`, `sender`, `txHash` and `envelope`; the
`scheme` and `rescueKey` fields change nothing for it. New accounts of the
pop-up wallet are rescue-key accounts (spec 09, section 5, scheme `0x0003`,
a 1,344-byte public key), signed with ML-DSA-44; accounts a wallet issued
before rescue keys stay scheme `0x0001` and answer `rescueKey: false`.
`ghost_rescue` signs a scheme `0x0004` transaction with the account's
SLH-DSA key alone, moving `balance - gasLimit * maxFeePerGas` to the typed
destination with empty data; it is refused for a scheme `0x0001` account,
for a request that carries `to`, `value` or `data`, and for a balance that
does not cover `gasLimit * maxFeePerGas`. The module's
`ghost_wallet_rescue_account`, `ghost_wallet_sign_rescue_key` (0x0003) and
`ghost_wallet_sign_rescue` (0x0004) do this work; `ghost_wallet_account` and
`ghost_wallet_sign` stay scheme `0x0001`.

It calls no other signing method. A request the user turns down, or a
wallet window closed before it answers (code 4001), becomes "the
transaction was rejected in your wallet; nothing was sent" (or the
connection). The flow treats any connector's signing error the same way
for what is sent, which is nothing: one with `code` 4001 or `name`
`WalletRejected` becomes a `WalletRejected`, any other a `WalletSignFailed`
("the wallet could not sign the transaction: …; nothing was sent"), and in
neither case is `eth_sendRawTransaction` called; a browser that blocks the
wallet's window asks the user to open the page in their browser; an answer
that is not the hex the protocol names is refused. The
connection is not remembered: nothing goes to browser storage or a cookie,
and after a reload the user connects again. The page shows the address and
its balance, read from the endpoint. The commit is an account
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
checks the payload is 206 bytes of version 2 before it signs anything. The
module makes only version 2 and refuses any other commit version (`unknown
commit version`); the tests' stand-in node refuses any other length or
version, the 190-byte commit of version `0x0001` included (`commit data is
not 206 bytes of version 2: N bytes`).

The connected wallet signs it, as the client library does
(`client/src/account.rs`): ML-DSA-44 in pure mode with the context
`ghost/tx/v1`, over `K("ghost/account-tx/v1", 0x52, genesis_hash,
keccak256(unsigned))`; the user approves it in the wallet first. The page
builds the fields it asks the wallet to sign. The genesis hash is the one this build's table holds
for the network (see Headers), and the base fee is read from the tip the
page's header chain adopted. The nonce is `eth_getTransactionCount` of the
pending block, the priority fee `eth_maxPriorityFeePerGas` held at 2 gwei at
most, the fee cap twice the next block's base fee plus the priority fee, and
the gas limit `eth_estimateGas` plus 63,256, the gas the node adds for the
scheme, key and signature bytes and the check of a rescue-key account
(scheme `0x0003`, 16 x (2 + 1,344 + 2,420) + 3,000), the wallet's default;
for a scheme `0x0001` account the node adds 62,744, and the unused 512 gas
is not charged. Those answers come from the
endpoint, so the app bounds what they can make it sign: it refuses a gas
limit above 500,000 and a commit whose gas could cost more than 0.01 GHOST
(`maxCommitFee`, a setting of the flow controller). A commit the balance
cannot pay for is not sent to the wallet either. The wallet's answer is sent
only if its sender is the connected address and its transaction hash is
`keccak256` of its envelope; the endpoint must then answer with that same
hash. When `eth_sendRawTransaction` answers the commit with an error, the
app asks `eth_getTransactionByHash` and counts the commit as sent only if the
node holds it: ghost-node at the pinned commit takes a type `0x52`
transaction into its pool and still answers `transaction type not supported`,
and its JSON shows such a transaction's `from` as the zero address until its
RPC derives it from the public key. A reveal is a native transaction with no account, so Summon and
Claim sign nothing with the wallet. The page pays a Summon to the payout
field's address, by default a fresh address of the connected wallet (see
Summon tab); the flow controller's `summonReveal` pays any 20-byte address it
is given.

The commit entry address defaults to the internal network's coin commit
entry, `0x67686f7374000000000000000000000000000005` ("ghost" in ASCII, then
5; `params/ghost/privaccounts.go` in ghost-node). The data commit entry of
that network, `0x67686f7374000000000000000000000000000007`, is not used: the
app makes no data commitments.

## Summon and Claim

1. **Restore.** The app reads the coin tree as of the tip in whole pages and
   checks each page against the page-root list and the list against the tip's
   `coinTreeRoot`. It does not ask the endpoint for the spent markers: it
   takes them from the reveal logs of the block receipts it has checked
   (Block receipts), of the blocks from the chain's start up to the tip (the
   depth of Done, the block itself), so a key shows claimed as soon as a
   block holds its spend. From a pinned start, a spend before the pin is in
   no checked receipt, so its coin shows unspent; every node refuses a reveal
   of it at the marker check (Before a pinned start). With each leaf and its note the app reads the
   salt served beside it, if any, and hands restore one salt (or none) per
   leaf, beside the leaf (the records stay leaf and note, 188 bytes each).
   The worker tries the key's note key on every note and recomputes
   each found commitment (spec 01, section 8): a note carries its coin's
   salt, which goes into `F`, `C` and the marker; a coin whose salt beside
   the leaf is not its note's is not trusted. Restore is asked about one
   coin tree at a time, by its index, and returns each found coin's tree
   index, position and salt; more leaves than one tree holds is an error,
   not a scan that stops part way. The prover refuses a coin without a salt
   (`a coin without a salt cannot be revealed`). The current coin is
   the found commitment whose marker is not spent. The app asks for
   everything a reveal needs (the headers, the tree and the block receipts,
   in that order, fixed by the tip and by what the page already holds)
   before the key is tried, and restore runs only once the leaves, notes
   and salts have passed the check of Block receipts and the markers have
   been taken from it.

   The restore itself reads the key's note buckets first
   (`webapp/src/buckets.mjs`, the twin of the client library's
   `restore_coins_by_tags`; spec 01, sections 8 and 9). Every note's nonce
   starts with the 3-byte lookup tag of its commitment number under the
   key's note key, and a bucket is the notes of one tree whose tag starts
   with the same `clamp(floor(log2(n / 4096)), 0, 24)` bits, `n` the tree's
   page-read leaf count. For each tree, as of the tip the pages were read
   at, the worker gives the tags of numbers 0 to 15 (always 16) and the app
   asks `ghost_getNoteBucket` once for each distinct prefix, then for
   numbers 16 to 31 only if number 15 was found, and so on; after each batch
   the worker's `restoreAt` tries the key on every note read so far, with
   its position. A bucket is a hint, not completeness: no header root covers
   it, and a node can withhold a note. So each entry must be the leaf, note
   and salt the pages read (and checked against the tip's root and the block
   receipts) hold at its position, and each bucket must hold every position
   whose page-read note starts with its prefix, none withheld, before the
   key is tried on it. The full
   page scan stays the fallback, and a scan's coins are wholly from one or
   the other, never partly: a node that answers "method not found"
   (`-32601`) is not asked again for the life of the flow, and a node that
   answers any other error, or serves a bucket that is malformed (not the
   kind, tree, bits, prefix or count asked for, positions not strictly
   increasing, a field of the wrong length, a note of another bucket) or
   that disagrees with the pages (an entry they do not hold, or a note of
   the bucket left out, an empty bucket included), gets the full page scan for that scan
   only. The pages are still read whole for the root and receipt checks, so
   the buckets do not yet save a page read.
2. **Same requests after restore.** On a reveal or claim, every path after
   restore, the one where the key holds no unspent coin included, then asks
   the endpoint the same thing in the same order before anything depends on
   what restore found: `eth_blockNumber`, the tip's header and the fee
   headers for the next block. Before these requests the worker proves the
   coin when it can be revealed; a reveal that cannot be made (no unspent
   coin, more than the coin can send) is not proved at all. The page used
   to prove a decoy in its place, a full proof of about 260 MB only to say
   "no coin", which hid almost nothing, so it no longer does (the module's
   `decoy` argument stays, unused by the page). A coin's proof that the
   worker refuses (its coin not under the root, amounts that do not
   balance) still takes a proof's time in the worker before the refusal.
   Only after these requests does a failure surface or the reveal go out.
   Found or not, failing or not, the endpoint sees the same requests in the
   same order up to the reveal, though not at the same pace; the reveal
   itself tells it the connection holds a coin.
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
   - **Cover, as information.** Opening a key shows, for its coin, the block
     whose root a reveal or claim made now would use and how many coins that
     tree covers (its leaf count), and how many newer coins are not settled
     yet. The text says the count is of commitments, not of people, and that
     amounts and timing can still match a reveal to its commit; it gives no
     advice to wait, since the membership proof over the settled root
     already hides which leaf is opened. The app never makes the holder wait.
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
   to the prover as a private witness: the coin is proved as salted and its
   remainder is salted under a fresh salt, carried only in the remainder's
   note. A coin without a salt is refused before any proof work, a decoy's
   included. The worker and the stand-in verify a reveal as salted, and only
   as salted. A claim sends nothing out and names the zero address.
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
   because the markers are taken from the receipts up to the tip. An endpoint whose chain fails
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
  pin would follow the wrong chain. **The pin's total work is assumed, not
  checked**: the page cannot recompute the work of the headers below the pin,
  so it takes `totalWork` from the table as given and adds each later
  header's difficulty to it. Every branch the page holds descends from the
  pin, so the same assumed value lies under all of them and the choice of the
  heaviest is exact; a total work the page reports is that assumed value plus
  the work it checked above the pin, and a chain that forks below the pin is
  never followed (Before a pinned start). The headers below the pin are not
  authenticated: the page does not walk back from it by parent hashes. The table is empty today, so
  the released build shows no confirmations on any network until a launch
  network and its start are added; the value of each release's pin is a host
  step taken from the launch network.
- **Saved headers trust the page's own storage.** A header read back from
  the page's IndexedDB skips only its RandomX seal (Saved headers); every
  other check, the parent link to the pin and the total work included, is
  made again. The one assumption this adds is that the page's own storage
  for its origin was written only by this page in an earlier session. It
  holds public header fields only, never a key; whoever can write the page's
  storage can already run code on its origin and read the wallet in it.
- **One endpoint.** The page asks one endpoint. Asking several and refusing
  on conflict is not built; agreement between endpoints would be extra
  evidence, never a substitute for the checks of Headers.
- **The chain lives as long as the page; its headers outlive it.** The
  header chain is held in the worker's memory, and its best chain's headers
  are saved in the page's IndexedDB (Saved headers). A new page session
  re-links the saved headers from the start, checking everything again but
  their seals, and checks seals only above the saved tip. With no storage, or
  a saved header that does not re-link, it reads and checks every header from
  the start again.
- **Before a pinned start.** The receipts start at the chain's start, so on
  a network whose build pins a header above genesis, the notes and salts of
  the leaves before it rest on the pin as its coin root does: no header of
  the page's chain covers their receipts. The spent markers are taken from
  the checked receipts alone, so the markers of the blocks before the pin
  are not among them: a coin whose only spend is before the pin shows
  unspent. A reveal of it is refused by every node at the marker check, so
  no value is lost; the page cannot learn it, because no query names a marker.
  From genesis, every note and salt is checked and every marker is in the
  receipts. (Closed: the notes are checked against block receipts and the
  markers come from them, so an endpoint can no longer test for a coin one
  bit at a time by spoiling notes or markers and watching whether a reveal
  follows; see Block receipts.)
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
  or missing salt, a dropped, repeated or reordered page, receipts that do
  not give the header's `receiptsRoot`, a block whose receipts are not
  returned and a malformed receipt are each refused before restore, marker
  lookup, proving or any reveal, with no coin shown. The requests (method
  and parameters) of a scan whose altered note is the key's are those of one
  whose altered note is another's, and of an honest scan.
- `spent-from-receipts.test.mjs`: against the same stand-in, a scan after a
  partial reveal never asks for a `coin-markers` page and still opens the
  key on its remainder, the spent coin shown spent; a marker list the
  endpoint hides, invents or replaces changes neither the requests, the
  worker's steps nor the result; a fully claimed key opened on a fresh page
  shows claimed from the markers of the reveal receipts; and `heldMarkers`
  gives the markers of the reveal records of the first `markerBlocks`
  blocks, in order, none for commits.
- `receipts-at.test.mjs`: `blockOfPosition` across a tree rollover and for
  a position no block holds; `drawBlocks` gives 8 distinct blocks in block
  order with the real one among them (every block when fewer exist) and
  rejects the random values that would favour the low blocks; the decoys
  are drawn once per coin and reused on every later scan; `findRecord`
  refuses none or two records at a place and `checkRecord` a changed leaf,
  note or salt. Against the stand-in, with the worker's whole-chain receipts
  check stood down, a coin record changed, dropped or repeated in the
  receipts of the coin's own block is refused after restore, and an honest
  scan asks each block's receipts once.
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
- `header-store.test.mjs`: the saved headers, session after session on one
  stand-in pinned at block 10 and one in-memory store, with the headers sent
  to `chainAdd` (seal checked) and `chainAddSaved` counted. A first session
  on 600 blocks above the pin checks 600 seals, a second none (600 re-linked),
  a third after 5 new blocks exactly 5. A saved header whose parent hash is
  changed, one whose number is changed and a list with a gap each make the
  page discard the entry and check every header from the pin, showing what a
  clean session shows; the entry is then written again. A store that throws,
  an IndexedDB that throws or is blocked and none at all leave the page
  working as with no store. The records hold the header JSON fields and the
  hash only. `client/tests/header_chain.rs` checks `add_saved_header`
  directly: only the seal is skipped, and saved headers re-link to a pin with
  the height and total work `add_header` gives.
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
  whose tree 0 is just full still finds the coin that filled it. The scan
  of a rolled-over chain asks restore with tree index 0, then 1, and the
  key's coin reports tree 1 as the module found it. A coin of
  the full tree 0 is revealed against tree 0's final root with no wait, a
  clean device restores it spent and its remainder in tree 1, and that
  remainder is revealed against a settled root of tree 1. A note of either
  tree or a salt that the receipts do not show is refused before restore;
  the page's check of every tree also refuses, on its own,
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
  salt beside the leaf is not its note's, a scan whose served salt is not
  its receipt's, and a page with a salt that is not 16 bytes.
- `words-flow.test.mjs`: the save check takes three typed words, whichever
  view is shown, and refuses a wrong, short or digit answer; a salted coin is
  revealed and claimed, its salt passed to the prover and its remainders
  salted.
- `wasm.test.mjs`: the module against the golden vectors of spec 05, the
  header's RLP and hash included, the version 2 commit and the words key; a
  version 1 commit and a coin without a salt refused; restore naming the
  coin tree it was asked about (tree 0 when not told); a receipt's encoding
  and the receipts root; and the receipts check of leaves, notes, salts and
  markers, with its refusals.
- `commit-layout.test.mjs`: the version 2 commit payload (206 bytes) against
  the node's layout, its note opening with the key at its chain only, and
  the default commit entry address.
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
  commit (not to the commit entry address, data not 206 bytes of version
  `0x0002`, among them the 190-byte commit of version `0x0001` and the old
  189-byte layout, in its words) and accepts the salted payload, serving its
  salt beside its leaf; it serves every block's receipts by hash, in the
  node's log layout, under its header's `receiptsRoot`. The app refuses a
  228-byte commit log, with no salt, and reads the 244-byte one.
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
  balance line reading `Balance: —` and Max, and the main button reading
  "Connect wallet"; the Connect wallet button top right opens a dialog
  listing one wallet, the Ghost wallet, and the connected view holds
  the address, balance, Refresh and Disconnect; the wallet dialog has no
  text box, no create or restore flow, and no code of the page asks the
  worker for a wallet or uses browser storage; the
  Network and About panels are reached from the footer; Claim sits in a
  hidden container; the icons are inline SVG with no namespace attribute;
  the CSP keeps `default-src 'none'` and adds `font-src 'self'`; no
  external URL, inline script or inline style; the Midnight violet colors
  are CSS variables of one dark theme; the glow and motion sit inside
  `prefers-reduced-motion: no-preference`.
- `midnight-violet.test.mjs`, with nothing built: `style.css`,
  `index.html` and `vercel/config.json` read as text. Every color of the
  Midnight violet table is a `:root` variable with its role, and the card,
  tabs, inputs, token label, main button, wallet button and error lines
  use it; the card's corners are 18px; the two glow circles are violet at
  35% and cyan at 18%, blurred, fixed behind the page; their drift (about
  20s), the tab slide (about 200ms) and the coin fades sit inside
  `prefers-reduced-motion: no-preference` and nothing moves outside it;
  main, secondary, accent, error, button and wallet text meet WCAG AA; the
  served CSP is the page's plus `frame-ancestors 'none'`, with
  `font-src 'self'` in both; one dark theme with Inter first.
- `vanish-screens.test.mjs`, with nothing built: `index.html` read as text
  for the three Vanish screens' fixed wording, and `app.mjs` read as text
  and run against a small stand-in page and a stand-in flow. The key shows
  as a grid of its 24 numbered words; the check has three labelled inputs;
  a wrong word shows the wrong-answer line, no waiting bar and sends
  nothing; the right words show the waiting bar until the check returns,
  then Done; the send happens only from the check form's submit; Done, the
  switch to Summon and `pagehide` empty the grid and call `vanishCancel`;
  an error is a fixed plain line, never the error's own text.
- `summon-screens.test.mjs`, with nothing built: `index.html` read as text
  for the Summon tab's fixed wording (the paste box, the amount box with
  `In this key:` and Max, the payout field under it, the waiting steps,
  Done), and `app.mjs` read as text and run against a small stand-in page
  and a stand-in flow. A pasted key opens and shows its coin; an unfinished
  or wrong key typed shows no error until the box is left, and then a plain
  line naming a position at most; an amount that does not parse, or more
  than the key can send, is flagged and sends nothing; after Confirm Summon
  the reveal goes to the fresh address the payout field was filled with (a
  new one for the next Summon), with the three steps ticking off from the
  flow's progress; Done shows the rest, then "This key is now empty." after
  the rest is summoned; with no wallet connected the button reads "Connect
  wallet" and opens the wallet list; the list holds only the Ghost wallet,
  which connects through the pop-up connector, then shows the short
  address, the full address and the balance, and Disconnect lets it go; a
  rejection in the wallet, a blocked pop-up and any other failure are each
  a plain line; Done,
  the switch to Vanish and `pagehide` empty the box and call
  `summonClose`; a failed reveal is a fixed plain line.
- `wallet-connect.test.mjs`: the wallet module, with nothing built, then
  the flow with a connected wallet against the node stand-in. The module
  offers no connector but the pop-up wallet's; the transaction fields go to
  the wallet as 0x hex and read back the same. A Vanish through a stand-in
  wallet that speaks the pop-up wallet's two requests, with the tests'
  account signing behind it, is
  first rejected in the wallet (nothing is sent and the flow keeps the
  check; the page is what drops the key), then
  approved and sent from the connected account; an answer from another
  account, with a hash that is not its envelope's, or not bytes, is never
  sent; Disconnect lets the wallet go and Vanish then needs one again. The
  tests' wallet is a connector in `test/support/env.mjs`, the one place
  that holds the tests' seed words and asks the worker's `walletSign`.
- `vanish-approval.test.mjs`: the wallet's approval of a Vanish, against
  the node stand-in with the tests' wallet holding each signature until the
  test answers it, first through the flow and then through `app.mjs` on a
  stand-in page over that same flow. While the wallet is asked, nothing has
  reached the endpoint and the waiting line reads "Approve the Vanish in
  your wallet"; approved, the commit is sent once, with the envelope the
  wallet returned; rejected (code 4001, or a `WalletRejected`),
  `eth_sendRawTransaction` is never called, the key is gone from the flow
  and the page, and the card is back at the amount with "You rejected it in
  your wallet. Nothing was sent."; any other signing error sends nothing
  and shows its own line, never the wallet's text.
- `summon-confirm.test.mjs`: Summon's confirm step through `app.mjs` with a
  stand-in flow that logs every call. Summon shows "Summon *amount* GHOST
  to 0x7c…44d" (the payout address) with the full address as the title and
  calls nothing; with a wallet that has no fresh address it names the
  wallet's own and warns; Cancel returns to the form with the key and
  amount kept and calls nothing; Confirm Summon calls `summonReveal` once
  with the amount and the payout address, and a second press does nothing;
  a wallet changed meanwhile, leaving the tab and `pagehide` send nothing.
- `summon-payout.test.mjs`: the payout field and the privacy warnings
  through `app.mjs` with a stand-in flow, then the flow against the node
  stand-in. By default the field holds a fresh address and the Summon pays
  it with no warning; a wallet without the request (null, or method not
  found) leaves the connected address, with the same-address warning on the
  form and the confirm screen, and the Summon still goes; with no wallet the
  field is empty and Summon asks to connect; a typed address is kept, warned
  about when it is the wallet's or one this page vanished from, and checked
  with `parseAddress`; a full Summon whose amount fewer than 10 checked
  commits share warns and suggests a partial Summon, and a partial one does
  not. The pop-up connector sends `ghost_newReceiveAddress` and reads
  method not found as null. The flow's `newReceiveAddress` gives a new
  account of the tests' wallet each call; `amountMatches` counts the
  checked commits of the coin's amount; a reveal that cannot be made is not
  proved.

The key image download, drawn on a canvas in the page, and Claim's
digit-view button are not covered by the headless tests; the flow's digit
view is. Neither are the panel and Max wiring of `app.mjs`, which needs a
browser.

### Against a real node

`test/e2e/real-node.test.mjs` is not loaded from `test/index.js`. It starts
the release `geth` named by `GHOST_NODE_GETH` as a one-node internal network
(network 6777971, mining, the internal network's genesis, JSON-RPC
`eth,net,web3,ghost` over HTTP on a port the system picks) and runs Vanish, a
partial Summon and a Claim with the real prover. The tests' wallet connector
is connected as the page connects the Ghost wallet; its account is the
miner's etherbase, so block rewards fund it, and the commit and the
strangers' commits are account transactions it signs. The keys are 24 words, and the save checks are answered with
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

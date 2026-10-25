# Specification 05: trees, header tree states and reorganisation

Status: draft for the founder's review, 2026-10-17. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the [outline](../ghost-outline.md) ("Core
protocol" 6, 8 and 9), the front desk decisions recorded with this
specification, the base client plan (section 7.3), [decision
0001](../decisions/0001-base-client.md), the
[commitments and keys](01-commitments-and-keys.md), the
[proof statements](02-proof-statements.md), the [coin rules](03-coin-rules.md),
the [data commitments](04-data-commitments.md), the
[consensus specification](06-consensus-and-emission.md) or the
[threat model](../threat-model.md), and is cited to it, not decided again here.
Where a point is not settled, the check rejects (fails closed), and the point is
listed in section 12.

This document fixes the two trees and what happens when one fills, the two tree
states in every block header, which roots a proof may use, where the one-time
markers are kept, what a reorganisation does to all of them, how a wallet gets
the tree data it needs without telling anyone which commitment is its own, which
nodes keep that history, and the exact bytes of a header. Section 11 holds the
golden vectors, and section 15 names the script that checks this document and
the separately written encoder that produced the header vectors.

It does not redefine the node and empty-leaf hashes, the commitment, the marker
or the note; those are fixed by [spec 01](01-commitments-and-keys.md) and used
here by name. It writes no node code, no circuit and no proof-system choice.

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Trees | Two binary Keccak-256 trees, coin and data, each of depth 32: 2^32 leaves, about four billion commitments | Outline ("Core protocol" 8); front desk decision |
| Node and empty leaf | The tree-node tags and the empty leaf of spec 01, section 4 | Spec 01 |
| Rollover | When a tree holds 2^32 leaves, the next append of that type goes to a new empty tree with the next index; the full tree is final and its last root stays valid forever | Front desk decision |
| Rollover inside one block | A block never appends to two tree indices of one type, so every final root appears in a header | **Proposed** (section 3) |
| Tree state | Tree index, leaf count and frontier of each type in reserved system-account storage, covered by the state root | Front desk decision; base client plan 7.3 |
| Header | Exactly two new fields: the current coin tree root and the current data tree root | Front desk decision |
| Spent-marker-set root in the header | Not added; undecided ([spec 04](04-data-commitments.md), question 2); proofs of holding stay rejected | Fail closed |
| Eligible roots | Exactly the roots in headers of canonical blocks before the including block, of the matching type, with no age limit | Front desk decision; [spec 03](03-coin-rules.md), question 4 |
| Marker storage | One set per marker tag in reserved system-account storage, keyed by the marker; checked in the canonical state at block execution and pool admission | Front desk decision |
| Reorganisation | Tree state and markers roll back with the journaled state; disconnected roots leave the eligible set at once; disconnected transactions return to the pool and are fully rechecked; no new depth limit | Front desk decision |
| Wallet tree data | Whole pages of 4,096 consecutive leaves with their notes, by position, and a bulk list of page roots; the wallet builds its witness itself; no per-commitment request exists | Front desk decision; page size **Proposed** |
| History | Every full node keeps and serves all commitments and notes of both trees; no pruning in version 1; header-only clients keep none; project-run indexers are optional | Front desk decision |
| Header encoding | The pinned base header's fields in order with the base fee required, then the two roots; no optional fields; withdrawals, blob and beacon-root fields forbidden; any extra trailing field rejected | Front desk decision |

## 2. Conventions

The conventions of [spec 01](01-commitments-and-keys.md), section 2, apply:
`K(tag, ...)` is tagged Keccak-256, `||` is concatenation, integers are unsigned
and big-endian at the stated width, hex is lower case, and "reject" means the
value or transaction is invalid and changes no state. In addition:

- **Type.** "Coin" and "data" name the two trees, the two marker sets and the
  two header roots. A coin value is never looked up among data values, or the
  other way round.
- **Canonical chain.** The chain from genesis to the node's current head under
  the base client's fork choice (heaviest total difficulty, spec 06). A block is
  canonical if it is on that chain now; having been canonical before does not
  count.
- **Including block.** The block that contains a transaction, or for a pool
  check, the block the node would build next on its head.
- **Page.** 4,096 consecutive leaf positions of one tree, starting at a multiple
  of 4,096 (section 8).
- **RLP.** The recursive length prefix encoding of the base client, in its
  canonical form only (section 10).
- **Uncertain means rejected.** Every classification in this document (is this
  root canonical, is this marker spent, is this field allowed, is this page
  right) answers "yes" only on positive evidence. Missing data, an unavailable
  lookup, an unknown value or a disagreement between sources rejects; nothing is
  guessed.

## 3. Trees and rollover

There are two trees: the coin tree and the data tree (outline, "Core protocol"
8). Each is a complete binary tree of depth 32 with room for 2^32 leaves, about
four billion commitments (front desk decision).

**Parameters.**

| Name | Value | Meaning |
|---|---|---|
| `TREE_DEPTH` | 32 | Levels of inner nodes above the leaves |
| `LEAVES_PER_TREE` | 4294967296 | 2^32 leaf positions per tree |
| `PAGE_LEAVES` | 4096 | Leaves per page of wallet tree data (section 8) |
| `LEAF_BYTES` | 32 | Bytes of one leaf, a commitment `C` |
| `NOTE_BYTES` | 156 | Bytes of one encrypted note on the chain ([spec 01](01-commitments-and-keys.md), section 9) |
| `MARKER_BYTES` | 32 | Bytes of one marker |
| `TREE_INDEX_MAX` | 18446744073709551615 | Largest tree index, 2^64 - 1 |

**Nodes and leaves.** A leaf is a commitment `C` (spec 01, section 3). An unused
position holds the empty leaf `E = K("ghost/empty-leaf/v1")`. An inner node at
level `l` (0 for the nodes just above the leaves, up to 31 for the root) is

```text
coin tree:  node = K("ghost/coin-tree-node/v1", l as 1 byte, left, right)
data tree:  node = K("ghost/data-tree-node/v1", l as 1 byte, left, right)
```

exactly as spec 01, section 4 fixes. The root is the level-31 node. Leaf
position `p` is a 32-bit integer; its bit `l` (counting from the least
significant) says whether the leaf's ancestor at level `l - 1` is a right child
(the leaf itself for `l = 0`). This is the position and path of spec 02,
section 3, item 2.

**Empty subtrees.** `Z_0 = E` and `Z_(l+1) = node(l, Z_l, Z_l)` with the tree's
own node tag. `Z_32` is the root of an empty tree; the coin and data values
differ because their tags do (vectors `empty-coin-tree` and `empty-data-tree`).

**Root of a tree with `n` leaves.** The root over positions `0` to `2^32 - 1`
with the `n` leaves at positions `0` to `n - 1` in the order they were appended
and `E` everywhere else. A node computes it from the frontier below, never from
a list it was given.

**Tree state (front desk decision).** For each type the consensus state holds:

| Item | Width | Meaning |
|---|---|---|
| tree index `k` | 8 bytes | Index of the current tree of this type, starting at 0 at genesis |
| leaf count `n` | 8 bytes | Leaves in tree `k`, from 0 to 2^32 |
| frontier `f_0` to `f_31` | 32 bytes each | `f_l` is the root of the last complete left subtree of height `l` on the path of the next position, as in an incremental Merkle tree |
| last filled height | 8 bytes | Height of the block in which tree `k` last became full; 0 if it never did |

**Proposed:** these live as storage of one reserved system account per type, so
they are journaled state covered by the state root (base client plan 7.3; the
Core-Geth survey's recommended option). The account addresses are constants of
the frozen chain configuration, fixed by the transaction-format specification;
the accounts hold no code and no balance and no transaction can write to them
except through the steps below. Leaves and notes themselves are history, not
state (section 9).

**Appending.** Only spec 03, section 6, step 10 (commit), spec 03, section 7,
step 13 (remainder) and spec 04, section 4, commit check 3 (data commit) append.
An append of leaf `C` to the tree of a type, in a block at height `H`:

1. If `n < 2^32`: write `C` at position `n` of tree `k`, update the frontier,
   set `n = n + 1`; if now `n = 2^32`, set last filled height to `H`.
2. If `n = 2^32` (rollover): if last filled height equals `H`, the transaction
   cannot be included in this block (below). If `k = TREE_INDEX_MAX`, it is
   rejected. Otherwise set `k = k + 1`, `n = 0`, clear the frontier, and
   continue as in step 1 with position 0 of the new tree.

The position of a leaf is the pair (tree index, position), recorded in the
receipt (spec 03, section 6, step 10). The tree index is never an input of any
hash: two trees with the same leaves would have the same root, which cannot
happen because every commitment has fresh blinding (spec 01, section 8).

**Rollover (front desk decision).** When the coin (or data) tree holds 2^32
leaves, the next commit, remainder or data commit of that type goes to a new
empty tree with the next index. The full tree is final: nothing is ever
appended to it again, and its last root stays valid for showing membership
forever (section 5). This replaces spec 03's default of rejecting commits when
the tree is full (section 13, item 1).

**One tree index per type in one block (Proposed).** The header carries only the
current root of each type (section 4). If one block both filled tree `k` and
appended to tree `k + 1`, the final root of tree `k` would appear in no header,
and the leaves added to tree `k` in that block could never be proven from
headers. So a block that fills a tree may not also start the next tree of the
same type. A transaction whose append would do so is not includable in that
block: a block that contains one is invalid, and the pool keeps the
transaction, unchanged, for a later block. It is not rejected from the pool,
because it is valid on the next block. The other type is unaffected.

**Room for a remainder.** With rollover there is always room for one more leaf,
except in the case above, so spec 03, section 7, step 12 and section 6, step 8
become "the append is includable in this block".

**Conformance requirements.**

- **TH-1. Depth is 32.** A release build with any tree depth other than 32, or
  any leaf count limit other than 2^32, refuses to start. Expected: the node
  exits with an error naming the parameter; no block is imported.
- **TH-2. Roots follow the rule.** Appending the leaves of the vectors of
  section 11 in order to an empty tree gives exactly the roots stated there, for
  both types. Expected: equal roots; a node whose frontier update is off by one
  level fails the test.
- **TH-3. Rollover.** A test state with the coin tree at index 0 and `n = 2^32`
  (frontier prefilled), and last filled height below the current block. A
  commit is included. Expected: the leaf is at tree 1, position 0; the header's
  coin root is the root of tree 1 with one leaf; tree 0's final root is still
  in the header of the block that filled it and is still accepted (TH-8).
- **TH-4. No second index in the filling block.** A block whose transactions
  fill coin tree `k` and then append to coin tree `k + 1`. Expected: the block
  is invalid. The same second transaction in the next block is accepted, and a
  data commit in the filling block is accepted.

## 4. Tree states in headers

Every block header carries the tree state of both trees (outline, "Core
protocol" 6), as exactly two new fields (front desk decision):

- `coinTreeRoot`: the root of the current coin tree (index `k`, count `n` of
  the coin tree state) after the last transaction of the block.
- `dataTreeRoot`: the same for the data tree.

A block whose two roots differ from the roots the node computes by executing it
is invalid; the check sits with the state root and receipt root checks of the
base client. The genesis roots are the empty roots (section 10).

When no leaf of a type is added in a block, its root equals the parent's. After
a tree fills, its final root stays in the header of every block until the first
append to the next tree, and at least in the header of the block that filled it
(section 3).

**Headers alone suffice to verify a proof (outline, "Core protocol" 6).** A
one-time reveal proof (spec 02, S1 and S2) is checked against public inputs that
are all in the transaction or computed by the verifier, plus one root. A
verifier that holds only a header chain it has checked (proof of work, parent
links, encoding) takes the root from the field of the right type of a header on
that chain and verifies the proof with no other data. What headers alone do not
give is marker status:

- For a reveal, whose marker is public, a header-only verifier can check
  "spent" or "not spent" with a state proof of the marker's storage slot
  (section 6) against the state root of a header it trusts. Asking for that
  proof names the marker, which is already public.
- For a proof of holding (spec 02, S3), the marker is private, so its
  non-membership must be proven inside the proof against a set root from a
  header. That root is not in the header (spec 04, question 2, undecided), so
  every proof of holding stays rejected (spec 02, section 13, item 2). This
  document adds no third header field.

**Seal coverage.** The proof-of-work seal must cover both tree-root fields, so
that no relay can change a root without redoing the work (Core-Geth survey,
"Seal hash coverage"). The seal hash's exact layout is in
[spec 08](08-randomx-seal.md), section 4: Keccak-256 of the header's RLP with
`mixDigest` and `nonce` set to zero, so it covers every header field except
those two seal fields, both roots included. Spec 08 also fixes what RandomX
hashes, the target and the key; its RS-6 is TH-6 below.

- **TH-5. Wrong root in a header.** A block whose `coinTreeRoot` or
  `dataTreeRoot` differs from the executed value by one bit. Expected: the
  block is invalid and nothing of it is imported.
- **TH-6. Roots are sealed.** A valid sealed header with one bit of
  `coinTreeRoot` changed. Expected: the seal check fails.

## 5. Historical roots

The outline keeps historical tree states on the canonical chain valid for
showing membership ("Core protocol" 9). The rule (front desk decision):

1. **Eligible roots.** A root `R` presented with a reveal of type `T` in an
   including block `B` at height `H` is eligible if and only if there is a block
   at a height `h < H` among the ancestors of `B` (the chain from `B`'s parent
   back to genesis) whose header's root field for type `T` equals `R`. There is
   no age limit (spec 03, question 4, default). The answer depends only on `B`'s
   own ancestry, never on which branch the validating node follows at the
   time, so every node that validates `B` gets the same answer, including a
   node that validates `B` on a side branch during a reorganisation (review 01,
   F6). For pool admission, which has no including block yet, `B` is the next
   block on the node's canonical head, so the ancestors are the canonical chain
   up to the head.
2. **Ancestry, not seen.** The lookup is against `B`'s ancestors, never against
   a cache of roots seen, imported, gossiped or once canonical. A root that
   appears only in a block outside `B`'s ancestry, such as a block of a
   discarded branch, is rejected, even if the node imported that block,
   accepted proofs against it, or saw it canonical before a reorganisation. A
   root that appears both on a discarded branch and among `B`'s ancestors (for
   example in a block that added no leaf of that type) is eligible because of
   the ancestor.
3. **Earlier blocks only.** A reveal may use only roots of blocks before its
   including block. The including block's own root is never eligible (it does
   not exist when the proof is made, and spec 02, section 8 forbids the root of
   the block that added the wallet's leaf anyway).
4. **Right type.** A coin reveal's root is looked up only among coin roots, a
   data reveal's only among data roots (spec 03, section 7, step 7; spec 04,
   section 6, step 8).
5. **Full trees.** The final root of a full tree is in a canonical header
   (section 3), so it stays eligible for as long as that header is canonical,
   which is forever once the block is buried beyond any reorganisation.
6. **Unavailable means rejected.** A node that cannot answer the lookup (it is
   still syncing headers, or its root index is being rebuilt) rejects the
   reveal at block validation and does not admit it to the pool. It never
   accepts a root because it cannot rule it out.

**How a node looks it up (Proposed).** The node keeps an index from each
(type, root) to the canonical heights whose header carries it. It updates the
index in the same step as its canonical-chain pointers, so that a reorganisation
changes both at once (section 7). When it validates a block whose parent is not
its canonical head (a side branch, or the new branch of a reorganisation before
the switch), it answers from the canonical index below the fork point and walks
the branch's own headers above it. An implementation may look roots up any
other way that gives the same answer for the same block's ancestry.

**The shared epoch.** Which eligible root a wallet uses is the wallet's rule:
the epoch root of spec 02, section 8, unchanged. The node accepts any eligible
root, because it never learns which leaf is opened. For a leaf in a tree that is
no longer current, no later epoch root contains it; section 13, item 4 records
this gap and its default.

- **TH-7. Old roots stay valid.** A reveal against the coin root of a canonical
  block 10,000 blocks below the tip. Expected: accepted at spec 03, section 7,
  step 7, with no window.
- **TH-8. The final root of a full tree.** After the rollover of TH-3 and many
  more blocks, a reveal of a tree-0 leaf against tree 0's final root. Expected:
  accepted at step 7.
- **TH-9. A discarded branch is rejected even if seen.** The node imports a
  side branch, then the canonical branch overtakes it. A reveal against a coin
  root that appears only on the side branch. Expected: rejected at step 7, at
  pool admission and in a block, although the node imported the root. In
  reverse: a node following branch A receives a heavier branch B whose blocks
  hold a commit and then a reveal against a coin root of B's own earlier
  block. Expected: the reveal passes step 7 while B is validated, the node
  switches to B, and a node that followed B from the start ends in the same
  state (review 01, F6).
- **TH-10. Own block, later block or wrong type.** A reveal whose root is the
  coin root of its own including block, of a block above it, or a data root.
  Expected: rejected at step 7.
- **TH-11. Lookup unavailable.** A node still syncing headers receives a reveal
  whose root it has not yet indexed. Expected: not admitted to the pool, and a
  block containing it is not accepted until the node can answer.

## 6. Markers

The one-time marker of spec 01, section 3 names a one-time reveal, and the
chain rejects any repeat on the canonical chain (outline, "Core protocol" 5).

**Where they are stored (front desk decision).** The spent markers live in
reserved system-account storage, journaled and covered by the state root (base
client plan 7.3):

- **One set per marker tag.** The coin spent-marker set holds the markers of
  `ghost/coin-marker/v2`, the data set those of `ghost/data-marker/v2`, each in
  its own reserved account. A coin marker is never looked up in the data set or
  the other way round (spec 04, section 2).
- **Keyed by the marker.** In the set's account, the storage slot whose key is
  the 32-byte marker holds the word `1` once the marker is spent. A slot that
  is zero (absent) means not spent. **Proposed:** any non-zero value counts as
  spent.
- **Written only by the apply step** of a reveal (spec 03, section 7, step 13;
  spec 04, section 6, step 11), in the same state change as everything else the
  reveal does. Nothing ever clears a slot except the rollback of a
  reorganisation (section 7).

**How a repeat is rejected.**

1. **Block execution.** At spec 03, section 7, step 8 and spec 04, section 6,
   step 9, the node reads the slot in the state as executed up to this
   transaction. That state already holds the markers of earlier transactions
   in the same block, so one lookup covers "no earlier transaction in the same
   block uses it".
2. **Pool admission.** The node reads the slot in the state of its canonical
   head. A spent marker is not admitted. **Proposed:** the pool holds at most one
   transaction per marker; a second with the same marker is not admitted while
   the first is pending, because at most one can ever be included.
3. **Uncertain means rejected.** A read that fails, a state that is not
   available yet (for example during snap sync), or a slot value the node cannot
   read rejects the transaction.

**Header-only verifiers.** The state root covers both sets, so a state proof
for one slot against a trusted header shows a public marker's status (section
4). That is not a set root a proof of holding can use; whether a separate
spent-marker-set root goes in the header stays undecided (spec 04, question 2),
and this document adds no third header field.

- **TH-12. Repeats.** After a reveal with marker `m` is included, a second
  reveal with `m` in a later block, in the same block, and offered to the pool.
  Expected: rejected each time; the block carrying it is invalid (spec 03,
  CR-6; spec 04, CR-D7).
- **TH-13. Sets are separate.** A data marker value written into the coin set
  by a test build, then a data reveal with that value. Expected: the data
  reveal is checked against the data set only and is not rejected because of
  the coin set.
- **TH-14. Stored where stated.** After a reveal, a state proof of the slot
  keyed by the marker in the coin marker account, against the block's state
  root, shows the value 1; before the block it shows zero. Expected: both
  proofs verify against their headers.

## 7. Reorganisation

When the canonical chain changes from an old head to a new head with common
ancestor `A`, the node does the following (front desk decision). Nothing here
depends on how deep the reorganisation is.

1. **State rolls back.** The state becomes the state after `A`, then the new
   branch is executed on it. Because the tree state and the marker sets are
   journaled state (sections 3 and 6), the commitments appended by disconnected
   blocks, the frontier, the leaf count, the tree index (a rollover in a
   disconnected block is undone with it), the last filled height and the spent
   markers all return to their values at `A` together with the balances, the
   mints and spec 03's running totals (spec 03, CR-11).
2. **Roots leave at once.** The roots in the headers of disconnected blocks
   leave the eligible set in the same step as the canonical-chain pointers
   change, before any transaction is admitted or any block is validated on the
   new head. The roots of the new branch join it in the same step. While the
   new branch is executed (step 1), each of its blocks is validated against its
   own ancestry (section 5, item 1) and the state of its own parent, not
   against the old head, so the switch cannot depend on the order in which the
   node learned of the branches.
3. **Transactions return to the pool.** Transactions of disconnected blocks that
   are not in the new branch go back to the pool and are fully rechecked
   against the new head: every check of spec 03, sections 6 and 7, and spec 04,
   section 6, including the root, the marker and the proof. A reveal whose root
   is no longer canonical is rejected and dropped. A reveal whose marker is now
   spent on the new branch is dropped.
4. **In-flight proofs.** Every pending reveal in the pool is rechecked in the
   same way, whether it came from a disconnected block or not. A proof against a
   root that is no longer canonical is rejected; the wallet must build a new
   reveal against a canonical root, with the same remainder number (spec 01,
   section 8).
5. **Positions may change.** A commit re-included on the new branch may land at
   a different position or in a different tree index. Receipts of the new
   branch are the only source of positions; nothing caches a position across a
   reorganisation.
6. **No new depth limit.** This document invents no reorganisation depth limit:
   the node uses whatever the pinned base client enforces. Decision 0001 removes
   Ethereum Classic's artificial finality rule, so none is added back here.
7. **Wallets.** A wallet that sees its header chain reorganise rewinds its scan
   to the page that held the last leaf at `A`, re-reads the page roots for the
   new head, and rebuilds any witness (section 8). A history server answers only
   for anchors on its own canonical chain (section 9).

- **TH-15. Everything rolls back together.** A block with a commit, a reveal
  and the rollover of a tree is removed by a reorganisation to a branch without
  them. Expected: leaf count, frontier, tree index, last filled height, marker
  slots, balances and totals equal their values at the common ancestor; both
  header roots of the new head match a node that never saw the removed block.
- **TH-16. Roots and in-flight proofs.** A reveal against the coin root of a
  block that is then disconnected is pending in the pool. Expected: after the
  reorganisation it is dropped from the pool, and the same transaction offered
  again is rejected at the root check.
- **TH-17. Returned transactions are rechecked.** A disconnected block held a
  commit and a reveal; the new branch spends the same marker in another reveal.
  Expected: the commit returns to the pool and is included again; the returned
  reveal is dropped at the marker check.
- **TH-18. Deep reorganisation.** A reorganisation of 1,000 blocks on a test
  network. Expected: the node handles it as any other, with no Ghost-specific
  limit, and the result equals a node that synced only the new branch.

## 8. Wallet tree data

A wallet needs every leaf and note of a tree to restore (spec 01, section 8;
spec 04, section 8) and the siblings of its own leaf to prove. It gets both in
bulk, never one commitment at a time, so no endpoint learns which commitment is
its own (outline, "Do not carry over"; threat model, section 6 item 8).

**Pages (front desk decision).** Tree data is served in fixed-size pages of
`PAGE_LEAVES = 4096` consecutive leaves, by position: page `p` of tree `k` of a
type holds positions `4096 p` to `4096 p + 4095`. A page is always served whole,
as of an anchor block:

```text
request:  type, tree index k, page number p, anchor block hash
response: for each filled position in the page, in order: leaf C (32 bytes)
          and its note (156 bytes); the number of filled positions
```

Positions at or above the leaf count at the anchor are empty and not sent. The
**page root** is the level-11 node above the page's 4,096 positions (empty
positions are `E`).

**Page-root list.** For a type, a tree index and an anchor, the list of page
roots of pages 0 to the last page with any leaf, 32 bytes each, in one bulk
response. Pages above the list are empty; their root is `Z_12`.

**What the wallet does.**

1. It downloads the page-root list and computes the tree root from it: the 20
   levels above the pages, with `Z_12` for missing pages. It checks the result
   against the header root field of the right type at the anchor, in its own
   header chain, and that the anchor is canonical in that chain. For a full
   tree, the anchor is a block whose header carries the tree's final root.
2. It downloads every page from its scan start onward to the last page, in
   order, whatever it expects to find in them. For each page it recomputes the
   page root from the leaves and checks it against the list.
3. It restores by trial decryption of every note (spec 01, section 8), reads
   its own leaf's position from the page, and computes the witness itself: 12
   siblings from the leaves of its page, 20 from the page-root list.
4. Any mismatch, missing page or disagreement rejects the data from that
   endpoint; the wallet asks another. It never fills a gap with a guess.
5. **Notes are authenticated separately (review 01, F3).** The page root covers
   the leaves only, not the notes stored with them, so a page whose leaves
   match can still carry altered notes; an altered note of the wallet's own
   simply fails to decrypt and would be passed over as someone else's. The
   wallet therefore treats the notes of a page as unchecked until it has
   compared every one of them, byte for byte, with the note in the receipt of
   the transaction that appended the leaf, taken from the block receipts of
   the page's blocks and checked against each block's `receiptsRoot` in its
   own header chain. Receipts are fetched in bulk for every block from the
   scan start, whatever the wallet expects in them, so the fetch names no
   commitment. So the receipt of every transaction that appends a leaf (a coin
   commit, a data commit, a coin reveal's remainder) carries the appended leaf,
   its tree index and position, and its note bytes, and the receipt of every
   reveal, coin or data, carries its marker (spec 03, section 6, step 10 and
   section 7, step 13; spec 04, section 4 and section 6, step 11). A data
   reveal appends nothing, so its receipt carries no leaf and no note, and no
   receipt ever carries a spent commitment (review 01, N4). The receipt layout
   fixes where (section 12, item 5). Receipts are fetched by block range, never
   by transaction, commitment or marker. A restore result, "found"
   or "nothing found", is final only once every note it read is checked this
   way; until then the wallet reports it as unchecked.

**The scan start.** A clean restore starts at page 0 of tree 0 of each type. A
wallet that is up to date starts at the first page it has not yet stored whole,
and always re-reads the last, partly filled page whole. **Proposed:** a wallet
may start earlier than it needs, never later. The scan start tells an endpoint
roughly when the wallet last synced, never which leaf is its own.

**Forbidden.** There is no request keyed by a commitment, a single position, a
range that is not whole pages, a marker, a note or a transaction for tree data,
and no endpoint that returns a witness. A wallet never sends such a request,
and a Ghost node refuses one. A wallet never asks an endpoint for its own
leaf's position or path.

**Marker status.** A wallet also needs the spent markers of its type to know
which found commitment is unspent (spec 01, section 8, step 5). **Proposed:**
they are served the same way, as marker pages of 4,096 markers of one set in the
order their reveals were included, as of an anchor. These pages are not
checkable against a header root (no spent-marker-set root is in the header,
section 6), so they are hints only (review 01, F4). A lying endpoint, or
several that agree, can make a commitment look spent or unspent, and agreement
between peers proves nothing against an attacker that runs many of them
(threat model T8). **Rule:** the wallet takes marker status only from the
markers in the reveal receipts of every block from its scan start, checked
against each block's `receiptsRoot` (item 5 above), in the same bulk fetch as
the notes; this names no marker. A marker page may let it show a provisional
answer sooner, marked as unchecked, and a page that disagrees with the
receipts is rejected with its endpoint. A status that is not yet checked is
"unknown", never "unspent" or "spent". A wrong status can never make the chain
accept a bad reveal (every node checks the marker itself), but it can mislead
the holder, which is what this rule prevents.

**Why 4,096 (Proposed).** Every wallet downloads every page from its scan start,
so the page size does not change what an endpoint learns; it sets the size of
one response and of the page-root list. 4,096 keeps a page under 1 MiB, below
common peer-message limits, and keeps the page-root list of a full tree at 32
MiB, small enough for a phone to download once.

| Leaves per page | Page bytes | Pages per full tree | Page-root list bytes |
|---|---|---|---|
| 1024 | 192512 | 4194304 | 134217728 |
| 4096 | 770048 | 1048576 | 33554432 |
| 16384 | 3080192 | 262144 | 8388608 |

Page bytes are `leaves × (LEAF_BYTES + NOTE_BYTES)` for a full page.

- **TH-19. Whole pages only.** A wallet restores, then builds a witness and
  reveals. Expected: every serving node's request log shows only page-root
  lists and whole pages in order from the scan start, with no request naming a
  commitment, position, marker, note or transaction. A request for half a page
  or one position is refused by the node.
- **TH-20. Wrong data is caught.** An endpoint serves a page with one leaf
  changed, then a page-root list with one root changed. Expected: the wallet
  rejects both and finishes from another peer; its witness hashes to the header
  root of its anchor.

## 9. History availability

The trees' leaves and notes are history: the state holds only the frontier
(section 3). Restoring from the digits needs all of it (threat model, A9 and
section 6 item 8).

**Who keeps what (front desk decision).**

| Node class | Keeps | Serves |
|---|---|---|
| Full node, including an archive node | Every leaf and note of every tree index of both types, every page root, every spent marker, and the receipts of every block (review 01, N5); no pruning of these in version 1, whatever the base client prunes of old state or history | Pages, page-root lists, marker pages and block receipts by block range to any peer |
| Snap-synced node | State first, then the history above, including every block's receipts, downloaded from peers | Only pages and receipts it has checked against canonical headers |
| Header-only client (light verifier, wallet) | None of it, beyond the pages a wallet keeps for its own keys | Nothing |
| Project-run indexer | Whatever it chooses | A convenience only, never required; a wallet checks its answers as any peer's |

**How a clean node gets it.** A node that syncs every block derives the leaves
and notes from block bodies and receipts as it executes them. A snap-synced node
gets the state, including the tree states, then downloads the history pages of
every tree index of both types from peers. It checks each page-root list against
the root in the canonical header of its anchor, each page against its page
root, and each note and marker against the receipts checked against their
headers' `receiptsRoot`, exactly as a wallet does (section 8, items 5 and
"Marker status"), and serves a page or a marker page only after that.
Until its history is complete it says so and serves nothing it has not checked.
It never needs a project-run indexer.

**Storage per full tree.** Computed from the parameters of section 3; these are
the floor until the node phase measures the real figures, which include the
database's own overhead.

| Item | Count | Bytes each | Total bytes |
|---|---|---|---|
| Commitments | 4294967296 | 32 | 137438953472 |
| Notes | 4294967296 | 156 | 670014898176 |
| Page roots | 1048576 | 32 | 33554432 |
| Spent markers, at most | 4294967296 | 32 | 137438953472 |
| Total | | | 944926359552 |

That is about 945 GB (880 GiB) per full tree of either type, of which 807 GB are
leaves and notes. Each tree index of each type adds as much once it fills. A
wallet's full scan downloads the leaves and notes of every page from its scan
start: 188 bytes per leaf, about 188 MB per million commitments, up to about
807 GB for a full tree (section 14, question 4).

**Recovery test.** Written now as a procedure with expected results; it runs in
the node phase, which records the measured figures. The figures above are the
floor until then. No project-run indexer is reachable during any step.
The part that runs today, with every project-run host blocked by a firewall
rule, is `scripts/recovery-blackout.sh` ([recovery test](../recovery-test.md)).

- **RT-1. Network.** Part A: a test network at the release parameters (depth
  32), with three full nodes run by different parties and one snap-synced node
  that joins last. Part B: the same with a test build whose tree depth is 14
  (16,384 leaves, four pages), so that a rollover is reachable; the depth is a
  build parameter that the release build rejects (TH-1). Expected: both
  networks run; Part B's release check refuses the test build's parameter.
- **RT-2. Wallet history.** Key A commits 1 GHOST and reveals 0.3 GHOST
  (numbers 0 and 1). In Part B, filler commits from other keys then fill coin
  tree 0, key B's commitment sits in tree 0 unspent, and key A's remainder of
  a later partial reveal lands in coin tree 1. A data commitment is made in
  each part. Expected: the receipts show tree indices 0 and 1 for the coin
  type in Part B.
- **RT-3. No indexer.** Every project-run indexer host is blocked at the network
  and none runs. Expected: no step below fails because of it.
- **RT-4. Clean device.** A device with the app installed and nothing else
  receives only the original wallet data: the digits of keys A and B and the
  data key's digits. Expected: the wallet syncs and checks the header chain
  from peers alone.
- **RT-5. Bulk scan.** The wallet downloads the page-root lists and every page of
  every tree index of both types from page 0. Expected: every page-root list
  matches the root of a canonical header, including tree 0's final root in Part
  B; every request in every node's log is a whole page or a page-root list.
- **RT-6. Restore.** Expected: key A's numbers 0, 1 (and in Part B the later
  remainder in tree 1) are found with their tree index and position; key B's
  leaf is found in full tree 0; the data commitment is found; every recomputed
  `C` equals its leaf.
- **RT-7. Status.** Expected: key A's earlier numbers are spent, its last
  remainder unspent; key B unspent; the data commitment unrevealed.
- **RT-8. Reveal from the restored state.** Key A reveals its remainder; key B
  reveals against tree 0's final root. Part B uses a test build with a stub
  verifier (as in spec 03, CR-12), because the proofs are made for depth 32.
  Expected: both are accepted at the root check, and in Part A the real proof
  verifies.
- **RT-9. A lying peer.** One full node serves a page with one changed leaf, a
  page whose leaves are right but whose note of key A's remainder is replaced
  by random bytes of the same length, and marker pages missing one marker; in a
  second run three peers serve the same altered marker pages. Expected: the
  wallet rejects the page with the changed leaf, finds the altered note by its
  receipt check and takes the page from another peer, still restores key A's
  remainder, and takes every status from checked receipts, never from the
  agreeing marker pages.
- **RT-10. Snap-synced node.** The node that joined last serves history after
  its own checks. Expected: before they finish it serves no page; afterwards its
  pages are byte-identical to the others', and the wallet can restore from it
  alone.
- **RT-11. Reorganisation during restore.** The last blocks are replaced by a
  heavier branch while the wallet scans. Expected: the wallet rewinds its scan
  (section 7, step 7) and ends with the state of the new branch.
- **RT-12. Cost.** Record the bytes downloaded, the time to restore and each
  full node's history storage. Expected: the bytes downloaded are at least 188
  per leaf plus 32 per page root, plus the block receipts from the scan start
  that authenticate notes and markers (section 8, item 5), and the recorded
  figures, receipts included, replace the computed floor of this section.

- **TH-21. Full nodes keep everything.** A full node run with the base client's
  most aggressive pruning setting. Expected: it still serves every page of
  every tree index of both types, and the receipts of every block from
  genesis, each matching its header's `receiptsRoot`.
- **TH-22. No unchecked page.** A snap-synced node is fed one altered page by a
  peer. Expected: it rejects the page, fetches it again elsewhere, and never
  serves the altered one.

## 10. Header encoding

The header is the RLP list of the fields below, in this order, with nothing
before, between or after them (front desk decision). The header hash is
`keccak256(rlp(header))`, as in the base client. There are no RLP-optional
fields: every field is required in every header, from genesis on.

**Fields.**

| Index | Field | Encoding | Source |
|---|---|---|---|
| 0 | `parentHash` | 32 bytes | base |
| 1 | `uncleHash` | 32 bytes | base |
| 2 | `coinbase` | 20 bytes | base |
| 3 | `stateRoot` | 32 bytes | base |
| 4 | `transactionsRoot` | 32 bytes | base |
| 5 | `receiptsRoot` | 32 bytes | base |
| 6 | `logsBloom` | 256 bytes | base |
| 7 | `difficulty` | integer below 2^256 | base |
| 8 | `number` | integer below 2^64 | base |
| 9 | `gasLimit` | integer below 2^64 | base |
| 10 | `gasUsed` | integer below 2^64 | base |
| 11 | `timestamp` | integer below 2^64 | base |
| 12 | `extraData` | at most 32 bytes | base |
| 13 | `mixDigest` | 32 bytes | base |
| 14 | `nonce` | 8 bytes | base |
| 15 | `baseFee` | integer below 2^256 | base, required |
| 16 | `coinTreeRoot` | 32 bytes | Ghost |
| 17 | `dataTreeRoot` | 32 bytes | Ghost |

Fields 0 to 14 are the base header of the pinned Core-Geth commit (decision
0001), in its order. The base client's sanity check on a block a peer announces
also refuses a `difficulty` longer than 80 bits; finding a seal at that difficulty takes about 2^80
hashes on average, out of practical reach, so in practice the bound never
decides a block (milestone 1 review). Field 15 is the base client's first optional field, here
required. Fields 16 and 17 are the two tree roots of section 4.

**Forbidden fields.** These later fields of the base client are absent in every
Ghost header (decision 0001 removes the features behind them):

| Field | Base client name |
|---|---|
| `withdrawalsRoot` | `WithdrawalsHash` |
| `blobGasUsed` | `BlobGasUsed` |
| `excessBlobGas` | `ExcessBlobGas` |
| `parentBeaconRoot` | `ParentBeaconRoot` |

**Decoding.** A node accepts a header's bytes only if all of these hold, and
otherwise rejects them with the first reason that applies:

1. The bytes are one RLP list, in canonical RLP: a single byte below `0x80` is
   never wrapped, a length below 56 never uses the long form, and a long length
   has no leading zero byte. Otherwise `non-canonical-rlp`.
2. Nothing follows the list. Otherwise `trailing-bytes`.
3. The list holds exactly 18 items, none of them a list. Any other count,
   whether from a forbidden field, an extra trailing field or a missing field,
   is `item-count`. A decoder never skips, ignores or defaults a field.
4. Each fixed-size field has exactly its size, and `extraData` at most 32
   bytes. Otherwise `field-size`.
5. Each integer is canonical: no leading zero byte, and zero is the empty
   string. Otherwise `non-canonical-integer`. An integer longer than its width
   allows is `integer-range`.

The consensus checks on the values (seal, difficulty, timestamp, base fee, uncle
hash, the two roots) follow decoding; they are in spec 06 and section 4.

**Genesis fields.** Spec 06, section 8.3 fixes the Bitcoin-dependent fields and
a few constants, and leaves every other field to this document. Every field of
the genesis header:

| Field | Genesis value | Fixed by |
|---|---|---|
| `parentHash` | 32 zero bytes | spec 06 |
| `uncleHash` | the hash of the empty list | spec 06 |
| `coinbase` | 20 zero bytes | spec 06 |
| `stateRoot` | `56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`, the root of the empty state (empty allocation; the reserved accounts hold only zero values) | this chapter |
| `transactionsRoot` | `56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`, the empty trie | this chapter |
| `receiptsRoot` | `56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`, the empty trie | this chapter |
| `logsBloom` | `zero`, 256 zero bytes | this chapter |
| `difficulty` | `D_START` | spec 06 |
| `number` | 0 | spec 06 |
| `gasLimit` | `30000000` (**Proposed**, question 1) | this chapter |
| `gasUsed` | `0` | this chapter |
| `timestamp` | `MTP(B) + GENESIS_OFFSET` | spec 06 |
| `extraData` | the 32 bytes of `B`'s hash | spec 06 |
| `mixDigest` | zero | spec 06 |
| `nonce` | zero | spec 06 |
| `baseFee` | `1000000000` wei (**Proposed**, the base client's initial base fee, question 1) | this chapter |
| `coinTreeRoot` | `8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8`, the empty coin tree | this chapter |
| `dataTreeRoot` | `3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03`, the empty data tree | this chapter |

The fields of this chapter are constants of the frozen chain configuration, with
no operator input (spec 06, section 8.3). The genesis state root holds as long
as no reserved account carries code, a balance or a non-zero slot at genesis.

- **TH-23. Golden vectors.** The node's header decoder and encoder run over the
  vectors of section 11. Expected: each positive vector decodes, re-encodes to
  the same bytes and hashes to the stated hash; each negative vector is
  rejected with the stated reason.
- **TH-24. Genesis.** The release's genesis tool derives a genesis from the
  example inputs of vector `header-genesis-example`. Expected: byte-identical
  output and the same hash.

## 11. Golden vectors

The blocks below are the golden vectors of this document. Each starts with
`[name]`; each line is `field = value`; byte values are hex. Run

```sh
python3 scripts/check_trees_and_headers.py
```

to recompute every tree vector from the rules of section 3 and every header
vector with the checker's own RLP code, and to compare the header vectors with
the output of the separately written encoder,

```sh
python3 scripts/header_golden_encoder.py
```

which has its own RLP code and imports nothing from the checker. The header
vectors here are its output, copied unchanged.

### Tree vectors

The leaves are the salted (format version 2) commitments of spec 01's
vectors `coin-commit-salted`, `coin-remainder-salted` and
`data-commit-salted`, made with its words example keys. The two
`header-example` trees hold fixed example leaves instead: their roots are the
tree roots that the header vectors below carry, as written by the separate
encoder, so those header vectors stay unchanged. Their leaves are opaque
32-byte values here, the commitments of a retired twelve-group digit key that
no client makes or accepts any more.

```text
[empty-coin-tree]
kind = empty-tree
tree = coin
root = 8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8

[empty-data-tree]
kind = empty-tree
tree = data
root = 3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03

[coin-tree-two-leaves]
kind = tree-root
tree = coin
leaves = 1525d1f6caa2f9314988542a3dcb7ab5a76a9ba5dd3fef97a1ecf72ddeb516bc a1f0774fc85bd02f9661ce63b14484abc808950848b3797a980c201a2946af72
root = f2a8cb20f27775cb0888dfe39577a9fab8a2630f2b8406b07e281e142f317a16

[data-tree-one-leaf]
kind = tree-root
tree = data
leaves = 523c415b17bb5c6b2270b71193a2737273d1be5aa519cd253155323aaad97e3f
root = caa746ecf6160767cdf1cdffb8c1aa5628cce4e6037cac1b90e5978ae65cc5e8

[coin-page-two-leaves]
kind = page
tree = coin
page = 0
leaves = 1525d1f6caa2f9314988542a3dcb7ab5a76a9ba5dd3fef97a1ecf72ddeb516bc a1f0774fc85bd02f9661ce63b14484abc808950848b3797a980c201a2946af72
page-root = 800197aa295fe821dd1e103f68f100b61067fb81370d0611a09b33e78aff2f93
empty-page-root = b50ae40977b91a1a10c7965cd40294eac6f63cbc40b5e57b9d4aa215956142d4
root = f2a8cb20f27775cb0888dfe39577a9fab8a2630f2b8406b07e281e142f317a16

[coin-tree-header-example]
kind = tree-root
tree = coin
leaves = 562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15
root = 142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5

[data-tree-header-example]
kind = tree-root
tree = data
leaves = 39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06
root = dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
```

`page-root` is the level-11 node over the page, `empty-page-root` is `Z_12`,
and `root` is the tree root computed from the page-root list alone (this page
root, then `Z_12` for every other page); it equals the root of the tree vector.

### Rollover vectors

One append to a tree in the given state. `filled-this-block` says whether the
tree became full in the block being built.

```text
[append-ordinary]
kind = append
index-before = 0
count-before = 2
filled-this-block = no
includable = yes
index-after = 0
count-after = 3
position = 2

[append-fills-tree]
kind = append
index-before = 0
count-before = 4294967295
filled-this-block = no
includable = yes
index-after = 0
count-after = 4294967296
position = 4294967295

[rollover]
kind = append
index-before = 0
count-before = 4294967296
filled-this-block = no
includable = yes
index-after = 1
count-after = 1
position = 0

[rollover-in-filling-block]
kind = append
index-before = 0
count-before = 4294967296
filled-this-block = yes
includable = no
index-after = 0
count-after = 4294967296
position = none

[rollover-index-exhausted]
kind = append
index-before = 18446744073709551615
count-before = 4294967296
filled-this-block = no
includable = no
index-after = 18446744073709551615
count-after = 4294967296
position = none
```

### Header vectors

`header-genesis-example` is a genesis header with example inputs: the stand-in
for Bitcoin block `B` is the hash of Bitcoin's own first block and `MTP(B)` is
1798761600. Neither is Ghost's anchor. `header-block-one-example` builds on it
with the roots of the tree vectors above and example values elsewhere. The
negative vectors are `header-block-one-example` with one fault each, and a
decoder must reject each with the reason given.

```text
[header-genesis-example]
kind = header
parentHash = 0000000000000000000000000000000000000000000000000000000000000000
uncleHash = 1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347
coinbase = 0000000000000000000000000000000000000000
stateRoot = 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
transactionsRoot = 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
receiptsRoot = 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
logsBloom = 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
difficulty = 16777216
number = 0
gasLimit = 30000000
gasUsed = 0
timestamp = 1798767600
extraData = 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
mixDigest = 0000000000000000000000000000000000000000000000000000000000000000
nonce = 0000000000000000
baseFee = 1000000000
coinTreeRoot = 8e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8
dataTreeRoot = 3d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03
rlp = f90260a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000808401c9c38080846b3703f0a0000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fa00000000000000000000000000000000000000000000000000000000000000000880000000000000000843b9aca00a08e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8a03d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03
hash = ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7
valid = yes

[header-block-one-example]
kind = header
parentHash = ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7
uncleHash = 1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347
coinbase = 00000000000000000000000000000000000004d2
stateRoot = 1111111111111111111111111111111111111111111111111111111111111111
transactionsRoot = 2222222222222222222222222222222222222222222222222222222222222222
receiptsRoot = 3333333333333333333333333333333333333333333333333333333333333333
logsBloom = 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
difficulty = 16777216
number = 1
gasLimit = 30000000
gasUsed = 126000
timestamp = 1798767630
extraData =
mixDigest = 4444444444444444444444444444444444444444444444444444444444444444
nonce = 0102030405060708
baseFee = 875000000
coinTreeRoot = 142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5
dataTreeRoot = dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
rlp = f90243a0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
hash = 943182f201b34dae77dc5c8efb5c84083dda907eac51f8ac3fc6f6c36a791c23
valid = yes

[header-forbidden-field]
kind = header-negative
base = header-block-one-example
fault = forbidden-field
reject = item-count
rlp = f90264a0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
valid = no

[header-extra-trailing-field]
kind = header-negative
base = header-block-one-example
fault = extra-trailing-field
reject = item-count
rlp = f90244a0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a80
valid = no

[header-missing-required-field]
kind = header-negative
base = header-block-one-example
fault = missing-required-field
reject = item-count
rlp = f9023ea0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a04444444444444444444444444444444444444444444444444444444444444444880102030405060708a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
valid = no

[header-non-canonical-integer]
kind = header-negative
base = header-block-one-example
fault = non-canonical-integer
reject = non-canonical-integer
rlp = f90245a0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084010000008200018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
valid = no

[header-short-tree-root]
kind = header-negative
base = header-block-one-example
fault = short-tree-root
reject = field-size
rlp = f90242a0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c09f142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ea0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
valid = no

[header-trailing-bytes]
kind = header-negative
base = header-block-one-example
fault = trailing-bytes
reject = trailing-bytes
rlp = f90243a0ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a00
valid = no
```

The faults: `forbidden-field` puts a withdrawals root where the base client
would put it, after the base fee; `extra-trailing-field` appends an empty
string; `missing-required-field` drops the base fee; `non-canonical-integer`
writes the block number with a leading zero byte; `short-tree-root` cuts the
coin tree root to 31 bytes; `trailing-bytes` appends one byte after the list.

## 12. Not settled: fail closed

Each point rejects until the founder or a later specification settles it.

1. **Spent-marker-set root in headers.** Undecided (spec 04, question 2).
   No header carries one; every proof of holding is rejected (spec 02, section
   13, item 2).
2. **Reserved account addresses.** The addresses of the two tree-state accounts
   and the two marker-set accounts are for the transaction-format
   specification. Until fixed, no commit or reveal is valid.
3. **Peer messages for pages.** The request and response messages of section 8
   in the node's peer protocol and in its JSON-RPC interface are for the node
   phase. Any message that returns tree data for a single commitment, position,
   marker, note or transaction is refused.
4. **Marker page integrity.** Marker pages are not checkable against a header
   (section 8); they are hints, and status is taken only from receipts checked
   against `receiptsRoot` (review 01, F4). Until checked, status is "unknown",
   never "unspent" or "spent".
5. **Indexed logs.** If the transaction-format specification gives commit or
   reveal receipts logs, no leaf, marker or note may be an indexed topic, so
   that a log filter cannot become a per-commitment lookup. Whatever layout it
   picks, the receipt of a transaction that appends a leaf must carry the
   leaf, its tree index and position and its note bytes, and the receipt of
   every reveal its marker, so that `receiptsRoot` authenticates them; a data
   reveal's receipt carries no leaf or note, and no receipt carries a spent
   commitment (section 8, item 5).

## 13. Conflicts with other chapters

This document does not edit other chapters. Where they differ from it, the
difference is listed here for the founder's review.

1. **Full tree: reject or roll over.** [Spec 03](03-coin-rules.md), section 6,
   step 8, section 7, step 12, and question 6 default to rejecting commits and
   reveals once the coin tree is full, until the rollover is specified. This
   document specifies it (section 3): the next append goes to a new tree, and
   only the case of a tree filled in the same block waits for the next block.
2. **Data tree room.** [Spec 04](04-data-commitments.md), section 4, commit
   check 2 applies the same "reject when full" default to the data tree. The
   rollover of section 3 replaces it.
3. **Spent-marker-set root in the header.** Spec 04, section 5 proposes that the
   data spent-marker-set root go into every header, and spec 04, question 2
   leaves it open. By front desk decision this document adds no third header
   field; the question stays open and proofs of holding stay rejected, as
   [spec 02](02-proof-statements.md), section 13, item 2 already says.
4. **Epoch root after a rollover.** Spec 02, section 8 picks the epoch root of
   the tree of the leaf's type. Once a tree is full, later epoch roots are roots
   of the next tree and do not contain its leaves. Default here: a leaf in a
   full tree is proven against that tree's final root, which every holder of a
   leaf in it shares. Leaves added in the block that filled the tree have only
   that block's root, the root of their own block. Review 01 (F1) settles how
   they use it: they wait until the next tree has started, and then prove
   against the final root like every other leaf of the tree, so the reveal says
   only "a leaf of this tree" and does not name the block of their commit
   (spec 02, section 8, "A leaf of a full tree"). Question 5 asks whether that
   default should change.
5. **Any canonical height.** Spec 03, section 7, step 7 accepts "any canonical
   height". This document narrows it to heights below the including block
   (section 5), which no valid proof could break.
6. **Genesis fields.** [Spec 06](06-consensus-and-emission.md), section 8.3
   leaves every genesis field it does not fix to the header specification, and
   its section 10 asks for the list. Section 10 of this document gives every
   field and its value; spec 06's values are used unchanged.
7. **Where the remainder goes.** Spec 03, section 6, step 10 and section 7,
   step 13 append "to the coin tree". With rollover this is the current coin
   tree, which may be a new index (section 3).
8. **Bulk marker set.** [Spec 01](01-commitments-and-keys.md), section 8, step
   5 and spec 04, section 8, step 4 fetch the spent-marker set in bulk and
   treat the answer as authoritative. This document serves it as marker pages
   that a header cannot authenticate; after review 01 (F4) they are hints only,
   and status is taken from receipts checked against `receiptsRoot` (section
   8).

## 14. Questions for the founder

Each has a default that this document already applies.

1. **Genesis gas limit and base fee.** No chapter sets them. Default: a gas
   limit of 30,000,000 and the base client's initial base fee of 1 gwei, to be
   confirmed by the block-time test of spec 06, section 3, which fills blocks
   to the maximum size.
2. **Page size.** 4,096 leaves per page. Default: 4,096 (section 8).
3. **Test-build depth.** The rollover part of the recovery test needs a test
   build with a smaller tree depth (RT-1). Default: allowed in test builds only,
   refused by release builds (TH-1).
4. **Restore cost.** A full scan downloads 188 bytes per leaf, about 807 GB for
   a full tree. Any shortcut that skips pages tells an endpoint where to look.
   Default: the full scan from page 0, with the computed cost stated.
   Measured cost, with the receipts the scan also needs, and the designs that
   cut it: [recovery cost](../research/recovery-cost.md).
5. **Leaves of the filling block.** Their only root is their own block's (section
   13, item 4). Default (review 01, F1): the wallet waits until the next tree
   has started and proves against the final root, which every leaf of the full
   tree shares, so nothing names their block.

## 15. Checking this document

Run

```sh
python3 scripts/check_trees_and_headers.py
```

from the repository root. It uses Python's standard library only, with the
Keccak-256 of `scripts/check_commitment_vectors.py`, and exits nonzero on any
gap. It checks that the required sections are present and numbered; that the
tree depth is 32 with 2^32 leaves and the note size is spec 01's; that the page
and storage tables are right; that the header field table lists the pinned base
header in order with the base fee required and exactly two tree roots, that no
forbidden field and no marker-set root is in it, and that every genesis field
is listed with its source and agrees with the genesis vector; that every tree,
rollover and header vector is right, every negative header vector is rejected
for the stated reason, and the header vectors equal the output of
`scripts/header_golden_encoder.py`; that the conformance requirements and the
recovery test are numbered and state their expected results; that the conflicts
named in section 13 are listed; and that every hash tag named here is in the tag
table of spec 01. `scripts/test_check_trees_and_headers.py` damages each part
and expects the check to fail.

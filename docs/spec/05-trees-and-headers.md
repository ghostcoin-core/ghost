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
markers are kept and the tree over the data markers whose root every header
carries, what a reorganisation does to all of them, how a wallet gets
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
| Header | Exactly three new fields: the current coin tree root, the current data tree root and the data spent-marker-set root `dataMarkerRoot` | Front desk decision |
| Spent-marker-set root in the header | Data only: `dataMarkerRoot`, field 18, the root of an append-only indexed Keccak-256 tree of depth 40 (section 6), answering [spec 04](04-data-commitments.md), question 2; no coin marker-set root; the proof circuit checks constraint 4 of spec 02's S3, so data proofs of holding are verified and coin ones stay rejected | Front desk decision, 2026-10-25 |
| Eligible roots | Exactly the roots in headers of canonical blocks before the including block, of the matching type, with no age limit | Front desk decision; [spec 03](03-coin-rules.md), question 4 |
| Marker storage | One set per marker tag in reserved system-account storage, keyed by the marker; checked in the canonical state at block execution and pool admission | Front desk decision |
| Reorganisation | Tree state and markers roll back with the journaled state; disconnected roots leave the eligible set at once; disconnected transactions return to the pool and are fully rechecked; no new depth limit | Front desk decision |
| Wallet tree data | Whole pages of 4,096 consecutive leaves with their notes, by position, and a bulk list of page roots; the wallet builds its witness itself; no per-commitment request exists; note buckets by key-derived tag prefix, at least 4,096 expected notes each; a page-root tail from a multiple of 65,536 pages and a read of 8 pages (7 of them decoys) to extend a witness | Front desk decision; page size **Proposed** |
| History | Every full node keeps and serves all commitments and notes of both trees; no pruning in version 1; header-only clients keep none; project-run indexers are optional | Front desk decision |
| Header encoding | The pinned base header's fields in order with the base fee required, then the two tree roots and the data marker-set root, 19 items; no optional fields; withdrawals, blob and beacon-root fields forbidden; any extra trailing field rejected | Front desk decision |

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
protocol" 6) as two new fields, and the root of the data spent-marker set as a
third (front desk decision; the third, 2026-10-25):

- `coinTreeRoot`: the root of the current coin tree (index `k`, count `n` of
  the coin tree state) after the last transaction of the block.
- `dataTreeRoot`: the same for the data tree.
- `dataMarkerRoot`: the root of the data marker-set tree (section 6, "The data
  marker-set tree") after the last transaction of the block.

A block whose three roots differ from the roots the node computes by executing
it is invalid; the check sits with the state root and receipt root checks of the
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
  header. For data that root is `dataMarkerRoot` (spec 04, question 2,
  answered), and the witness is the `absence` of section 6. The proof circuit
  checks that non-membership (spec 02, S3, constraint 4; section 13, item 2
  there), so a proof of holding for data is verified. There is no coin
  marker-set root: a proof of holding for coins stays rejected (spec 02,
  section 13, item 3).

**Seal coverage.** The proof-of-work seal must cover the three root fields, so
that no relay can change a root without redoing the work (Core-Geth survey,
"Seal hash coverage"). The seal hash's exact layout is in
[spec 08](08-randomx-seal.md), section 4: Keccak-256 of the header's RLP with
`mixDigest` and `nonce` set to zero, so it covers every header field except
those two seal fields, all three roots included; `dataMarkerRoot` needs no new
rule. Spec 08 also fixes what RandomX hashes, the target and the key; its RS-6
is TH-6 below.

- **TH-5. Wrong root in a header.** A block whose `coinTreeRoot`,
  `dataTreeRoot` or `dataMarkerRoot` differs from the executed value by one
  bit. Expected: the block is invalid and nothing of it is imported.
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
4). That is not a set root a proof of holding can use. For data the header
carries one: `dataMarkerRoot`, the root of the data marker-set tree below
(spec 04, question 2, answered by front desk decision, 2026-10-25). The coin
set has no such root, and a proof of holding for coins stays rejected (spec 02,
section 13, item 3).

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

### The data marker-set tree

The data spent markers are also kept as an append-only indexed Keccak-256 tree
of depth 40, whose root after the block's last transaction is the header field
`dataMarkerRoot` (front desk decision, 2026-10-25). It holds the same markers as
the storage slots above, in the order they were spent; it does not replace the
slot check, which still rejects a repeat. 2^40 positions, about 1.1 x 10^12,
last about 300 years at 10 million markers a day, so the set never rolls over.

**Leaves and nodes.** The leaf at a used position is a triple
`(value, nextValue, nextIndex)` of 32, 32 and 5 bytes, `nextIndex` a big-endian
position. Its hash and the inner node at level `l` (0 just above the leaves, up
to 39 for the root) are

```text
leaf = K("ghost/data-marker-set-leaf/v1", value, nextValue, nextIndex)   99 input bytes, 1 permutation
node = K("ghost/data-marker-set-node/v1", l as 1 byte, left, right)      95 input bytes, 1 per level
```

An unused position holds the empty leaf `E = K("ghost/empty-leaf/v1")` of spec
01, and the empty subtrees are `Z_0 = E`, `Z_(l+1) = node(l, Z_l, Z_l)` with
the marker-set node tag. Position `p` is a 40-bit integer whose bit `l` says
whether its ancestor at level `l - 1` is a right child, as in section 3. Both
tags are in the tag table of spec 01, section 4.

**Genesis.** Position 0 holds the sentinel `(0, 0, 0)`; every other position is
empty. That root is the genesis `dataMarkerRoot` and the root of vector
`marker-set-empty`. `nextValue = 0` means "no larger marker". Values compare as
256-bit big-endian integers. The marker value 0 is never valid and is rejected.

**Insert.** Marker `m` goes into a set with `n` used positions in the apply
step of the reveal that spends it (spec 04, section 6, step 11), so the markers
of one block are inserted in transaction order:

1. Find the used leaf `low` with `low.value < m` and (`m < low.nextValue` or
   `low.nextValue = 0`). Exactly one leaf has this property.
2. Write `(m, low.nextValue, low.nextIndex)` at position `n`.
3. Rewrite `low` as `(low.value, m, n)`, and set `n = n + 1`.

A marker already present is rejected before it reaches the tree: the slot check
of "How a repeat is rejected" stays. **Proposed:** the node keeps the set's leaf
count and every used leaf as journaled storage of the data marker-set account,
in a layout of its own in which the genesis set occupies no non-zero slot (so
the genesis state root of section 10 stays the empty root), and so that the
set is covered by the state root and rolls back with it (section 7).

**Non-membership witness.** The witness `absence` for a marker `m` against a
root `R` is the bytes

```text
low.value (32) || low.nextValue (32) || low.nextIndex (5) || position of low (5) || 40 siblings (32 each)
```

1,354 bytes, the siblings from level 0 up. It is valid if and only if `m` is
not 0, the low leaf's hash folded with the siblings along the position's bits
gives `R`, `low.value < m`, and (`m < low.nextValue` or `low.nextValue = 0`).
Any other witness, of any other length, is rejected. A wallet builds it itself:
it rebuilds the set from the data markers it already reads in block order
(section 8, "Marker status"), checks the rebuilt root against `dataMarkerRoot`,
and asks no endpoint for a witness.

**Reorganisation.** The set rolls back with the journaled state (section 7).

**Vectors.** Section 11, "Marker-set vectors", and TH-25.

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
   mints and spec 03's running totals (spec 03, CR-11). The data marker-set
   tree is part of that state: its used leaves and its leaf count return to
   their values at `A`, so every `dataMarkerRoot` of the new branch equals that
   of a node that never saw the disconnected blocks.
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
  slots, the data marker-set tree, balances and totals equal their values at
  the common ancestor; all three header roots of the new head match a node
  that never saw the removed block.
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

**Note buckets (front desk decision).** Every note's nonce starts with a 3-byte lookup
tag that only its key can compute (spec 01, section 9). A bucket is the set of
notes of one tree whose tag starts with the same `m` bits, and is served whole,
as of an anchor block:

```text
request:  type, tree index k, bucket bits m, prefix, anchor block hash
response: for each filled position whose note's tag starts with the m-bit
          prefix, in position order: its position (4 bytes), leaf C
          (32 bytes) and its note (156 bytes)
```

The leaf count `n` is the tree's at the anchor, and `m` must be
`bucket_bits(n) = clamp(floor(log2(n / 4096)), 0, 24)`: an expected bucket
holds at least 4,096 notes, `m = 0` is the whole tree (below 8,192 notes) and
`m = 24` is every bit of the tag. A Ghost node refuses any other `m` and a
prefix of `2^m` or more. A wallet asks for the prefixes of its own tags
16 numbers a batch, always 16, each distinct prefix once, and the next batch
only if the last number of the one before was found (spec 01, section 8,
"The bucket path").

A bucket query shows `m` bits of a key-derived hash among at least 4,096
expected other notes, 16 at a time; not a leaf, an amount or a position. A
bucket is a hint, not a complete answer: an endpoint can withhold a note, and
the wallet then shows less, never more. The whole-page scan below remains the
fallback. Proving that a returned leaf sits at its position is not specified
yet, so a bucket result is unchecked like any page result, and its notes are
checked against the receipts as in item 5 below. The scale model of
`benchmarks/scale/restore_sim.py` still models a 4-byte tag with a per-leaf
tag column; this design reads no such column and adds no header root.

**What the wallet does.**

1. It downloads the page-root list and computes the tree root from it: the 20
   levels above the pages, with `Z_12` for missing pages. It checks the result
   against the header root field of the right type at the anchor, in its own
   header chain, and that the anchor is canonical in that chain. For a full
   tree, the anchor is a block whose header carries the tree's final root.
2. It downloads every page from its scan start onward to the last page, in
   order, whatever it expects to find in them. For each page it recomputes the
   page root from the leaves and checks it against the list.
3. It restores by trial decryption of every note (spec 01, section 8), or of
   the notes of its own buckets (above), reads
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

**Forbidden.** Tree data is requested by whole pages. Besides the page-root
list and the pages in order from the scan start, the requests allowed are a
bucket read by tag prefix (above), the page-root tail from a multiple of
65,536 pages, the 8-page read of one page with 7 decoy pages and the
block-range receipts request (the subsections below), and no others. There is
no request keyed by a commitment, a single position, a range that is not whole
pages, a note or a transaction, no request that names a marker, alone or among
others (subsection "No query names a marker" below), and no endpoint that
returns a witness. A wallet never sends such a request, and a Ghost node
refuses one. A wallet never asks an endpoint for its own leaf's position or
path.

**Marker status.** A wallet also needs the spent markers of its type to know
which found commitment is unspent (spec 01, section 8, step 5). **Proposed:**
they are served the same way, as marker pages of 4,096 markers of one set in the
order their reveals were included, as of an anchor. These pages are not
checkable against a header root on their own (no coin spent-marker-set root is
in the header, and a data page holds only part of the set whose root
`dataMarkerRoot` is, section 6), so they are hints only (review 01, F4). A lying endpoint, or
several that agree, can make a commitment look spent or unspent, and agreement
between peers proves nothing against an attacker that runs many of them
(threat model T8). **Rule:** the wallet takes marker status only from the
markers in the reveal receipts of every block from its scan start, checked
against each block's `receiptsRoot` (item 5 above), in the same bulk fetch as
the notes; this names no marker. A marker page may let it show a provisional
answer sooner, marked as unchecked, and a page that disagrees with the
receipts is rejected with its endpoint. A status that is not yet checked, from
marker pages or anything else, is "unknown", never "unspent" or "spent". A
wrong status can never make the chain
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

- **TH-19. Whole pages only.** A wallet restores, then builds a witness,
  extends it after more blocks and reveals. Expected: every serving node's
  request log shows only page-root lists, whole pages in order from the scan
  start, bucket reads of `bucket_bits(n)` bits, 16 tags a batch, page-root
  tails from a multiple of 65,536 pages, 8-page reads of one page and 7 decoy
  pages, and block-range receipts requests, with no request naming a lone
  commitment, position, marker, note or transaction. A request for half a page
  or one position, a bucket read of any other bit count, or a page-root tail
  from any other page is refused by the node.
- **TH-20. Wrong data is caught.** An endpoint serves a page with one leaf
  changed, then a page-root list with one root changed, then a page-root tail
  with one root changed. Expected: the wallet rejects all three and finishes
  from another peer; its witness, extended from its last synced leaf count,
  hashes to the header root of its anchor (vectors
  `witness-extension-same-page` and `witness-extension-new-pages`).

### Reading the tail of the page roots

A stored witness is the 12 in-page siblings and the 20 upper siblings of item 3
above (front desk decision, 2026-10-25). The in-page siblings are final once
the leaf's page holds 4,096 leaves: no later leaf enters that page, so they are
never read again. The 20 upper siblings change as pages are added; the wallet
recomputes them from the page-root list, which it extends with one read, the
page-root tail:

```text
request:  type, tree index k, first page s, anchor block hash
response: the page roots of pages s to the last page with any leaf at the
          anchor, 32 bytes each, in page order
```

`s` is the wallet's scan start rounded down to a multiple of 65,536 pages
(268,435,456 leaves, about 27 days at 10 million leaves a day, modeled), so a
tail request tells an endpoint a window of about a month, never a leaf. A Ghost
node refuses any other `s`. The wallet keeps the roots below `s` from its
earlier list, appends the tail, and authenticates the whole list exactly as in
item 1: the root over the list, with `Z_12` for every page above it, must equal
the header root field of the right type at the anchor in its own header chain,
or the tail is rejected with its endpoint. The roots it already held and gets
again are fewer than 65,536, at most 2 MiB a request. The root of the leaf's
own page in the list must equal the root the wallet climbs from its leaf and
its stored in-page siblings. The extended witness is those 12 siblings and the
20 upper siblings recomputed from the list, and it hashes to the header root
at the new leaf count (vectors `witness-extension-same-page` and
`witness-extension-new-pages`).

**A page not yet full.** A leaf whose own page holds fewer than 4,096 leaves,
and a first witness, are built from that page read whole together with 7
decoy pages: 8 pages in one request, in page order (the 8-page read). The
decoys are drawn uniformly at random among the full pages of the tree at the
anchor, chosen once per wallet and leaf and reused on retry, so that repeated
requests cannot be intersected. When the tree has fewer than 8 pages, the
8-page read is every page of it. Each page read is checked against the
page-root list as in item 2.

**No new witness endpoint.** Nothing returns a witness or a path: the tail and
the 8-page read return page roots and whole pages, and the wallet computes its
witness itself, as in item 3.

### No query names a marker

A wallet asks no endpoint about a marker, alone or among decoys. A marker is public once its coin is spent and a random decoy never is, so any query that names a marker before the spend can be linked to the spend by the endpoint. The spent status of a found commitment comes only from the checked receipts of every block from the scan start (the "Marker status." Rule above); until it is so checked it is "unknown".

### Cost against the restore ceilings

Every figure here is modeled, from the inputs of
`benchmarks/scale/restore_sim.py` (10 million new leaves and 10 million spends
a day) and the figures of `docs/scale/stage1-verdict.md` and
`docs/scale/phone-results.md`, against the proposed ceilings of
`docs/scale/workload.md`: 500 MB for a full restore, 50 MB a month to keep up
and 10 minutes for a restore, each not yet established. None is measured.

| Step (modeled) | What it reads (modeled) | Ceiling it misses (modeled) |
|---|---|---|
| Headers for a clean device | 611.8 MB a year of chain, for every design alike (stage1-verdict.md, line "Headers for a clean device") | alone over the 500 MB download ceiling after about 298 days |
| Leaves and notes, one year | 686.2 GB for the full scan; 131.9 GB with the note buckets of the design modeled there | the 500 MB download and the 10 minutes |
| Page-root tail | at most 65,536 roots already held, 2 MiB a request, beside the new roots; the whole list grows 28.5 MB a year | none on its own |
| 8-page read | 8 pages, at most 6,160,384 bytes | none on its own |
| Spent markers | no longer read for restore: the 116.8 GB of the first year leave the full-restore download, which is 132.0 GB with buckets instead of 248.8 GB | the 500 MB download, still, by the leaves, notes and headers |
| Keeping up | unchanged: 66.0 GB a month for the full scan and 20.4 GB with buckets (stage1-verdict.md, with markers); the leaf and note bytes alone are 10.8 GB a month with buckets | the 50 MB a month |

So the restore ceilings stay missed (modeled): the headers alone pass the
500 MB download ceiling after about 298 days, the leaf and note bytes are over
it and over 10 minutes at one year, and the keeping-up and fresh-header costs
do not change with this design. The verdict of `docs/scale/stage1-verdict.md`
stays "Not feasible as designed" until the header side (the checkpoint pinned
with each release and the headers a wallet saves) is joined by a header-chain
proof, and the leaf and note bytes are cut as well. The receipt bytes that
authenticate notes and spent answers are not counted, as in the verdict: their
layout is open (section 12, item 5).

## 9. History availability

The trees' leaves and notes are history: the state holds only the frontier
(section 3). Restoring from the digits needs all of it (threat model, A9 and
section 6 item 8).

**Who keeps what (front desk decision).**

| Node class | Keeps | Serves |
|---|---|---|
| Full node, including an archive node | Every leaf and note of every tree index of both types, every page root, every spent marker, and the receipts of every block (review 01, N5); no pruning of these in version 1, whatever the base client prunes of old state or history | Pages, page-root lists and their tails, 8-page reads, marker pages and block receipts by block range to any peer |
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
| 18 | `dataMarkerRoot` | 32 bytes | Ghost |

Fields 0 to 14 are the base header of the pinned Core-Geth commit (decision
0001), in its order. The base client's sanity check on a block a peer announces
also refuses a `difficulty` longer than 80 bits; finding a seal at that difficulty takes about 2^80
hashes on average, out of practical reach, so in practice the bound never
decides a block (milestone 1 review). Field 15 is the base client's first optional field, here
required. Fields 16 and 17 are the two tree roots of section 4, and field 18
is the data marker-set root of sections 4 and 6. There is no coin marker-set
root.

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
3. The list holds exactly 19 items, none of them a list. Any other count,
   whether from a forbidden field, an extra trailing field or a missing field,
   is `item-count`; so is an 18-item header without `dataMarkerRoot`. A decoder never skips, ignores or defaults a field.
4. Each fixed-size field has exactly its size, and `extraData` at most 32
   bytes. Otherwise `field-size`.
5. Each integer is canonical: no leading zero byte, and zero is the empty
   string. Otherwise `non-canonical-integer`. An integer longer than its width
   allows is `integer-range`.

The consensus checks on the values (seal, difficulty, timestamp, base fee, uncle
hash, the three roots) follow decoding; they are in spec 06 and section 4.

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
| `dataMarkerRoot` | `0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3`, the data marker set holding only its sentinel (vector `marker-set-empty`) | this chapter |

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

to recompute every tree vector from the rules of section 3, every marker-set
vector from those of section 6, every witness-extension vector with the
checker's own tree code, and every header
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
leaves = cb3181bcb1a051e9b2e9eb947f4dfe6aa30b70f37f1518153de92b15d5049e44
root = f06603ac6e6f5a0ccac7e2e90aff6e8d9aa4c28b66df5690668e990fb582a77a

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

### Marker-set vectors

The data marker-set tree of section 6. A `marker-set` vector inserts its
`markers` in order into the genesis set and gives the used leaves as
`value nextValue nextIndex`, then the root. The markers are the data markers of
spec 01's vectors `data-commit-salted` and `data-commit-salted-other`; the
second is smaller than the first, so its insert rewrites the sentinel rather
than the last leaf. `marker-set-absence` is the witness for an example marker
`8888...88`, which no data commitment of spec 01 has, against the set of
`marker-set-two-markers`: it is accepted for that marker and rejected for
`reject-equal` (the low leaf's own value), `reject-below` (below the low leaf's
value) and `reject-above-next` (above its non-zero `nextValue`).

```text
[marker-set-empty]
kind = marker-set
markers =
count = 1
leaf-0 = 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 0000000000
root = 0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3

[marker-set-one-marker]
kind = marker-set
markers = c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b
count = 2
leaf-0 = 0000000000000000000000000000000000000000000000000000000000000000 c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b 0000000001
leaf-1 = c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b 0000000000000000000000000000000000000000000000000000000000000000 0000000000
root = 7ae4f1311ba5ecc3ca3b0c0bbef0e4882aea294a01756ee6cd469ce3e596d0d4

[marker-set-two-markers]
kind = marker-set
markers = c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b 40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8
count = 3
leaf-0 = 0000000000000000000000000000000000000000000000000000000000000000 40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8 0000000002
leaf-1 = c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b 0000000000000000000000000000000000000000000000000000000000000000 0000000000
leaf-2 = 40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8 c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b 0000000001
root = f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f

[marker-set-absence]
kind = marker-set-absence
set = marker-set-two-markers
root = f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
marker = 8888888888888888888888888888888888888888888888888888888888888888
low-position = 2
low-leaf = 40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8 c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b 0000000001
absence = 40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b00000000010000000002e050b25c8ab09717b0a6846b688b5047b93c0d37e18599cc7deec37f914bcca44ea6a8ee61bc6088043aa51b7fe211a30ed4afbad6614a5ed4642594799a582ee702fd7244730a2f7c21930175e8ba27388ad5ee16f47fd3b345cb814f2ee457bf1bb0cd4300d7b5f26c515d9398b43cc223c18bd78046c9a96e61950cef69f44ba9ed34b85fef73ebd7cfdd77d0c40c075fb4ef9a97e6d912371dcc0d43516c1c884fa8c1f2e920088be4ba8290df43ffa79e12ba1113a0ac1ad4be7ca33f22f77df031b2ae9c9b0963659de6cd9a5c0eb16469bd6df50e4f422b28de2fe2d2e6c6693c4f6dd34dde81f71e98a52badd5222aadeaf8f792578c4586cec7de55bfcf47336a172192c9d5d67a83aaa7a0c22b11b32cc7dc0c586a6abf5783494e9fbfacdf2a8e034743404034cc630559299a54ccf66b9fe222d7ca6d2360e7ef327e6891a664a288ab6ccf9ec0f383679080892d309d57449d8cb7148b2f0e41a4ab7a1dc68c3c0bc4708ff3bb327258dfa8801cd7ec67a021412aa87f758f481f42ab6477874eeb4bef0f93c10c3615f83c2d7177ef44515834e8b7a7f1d26c684b9ea1007f2734400476e3bf7f10c2a22b879519de27b37f7e4d453f7161a61aad7bbb537be5cfbe05c7f51e51f2a17788bc47672be7937dff230b71b4a26686766020320251cc13d61054e3b74394e336e8234e3fa55db4f50cd8678f21aab6ab4e0ebcfecabb20d93e4de624902e4fbf74e013a5215a16ee742eb9a53dcab5190ab0ecb877d5db52f4171bc53f2e7ed83d98ed20302624c0a8a38d89bba79fc96af77127a01bb537e45a267d7c814bab87bb0fd5c0526b0cffbec118554e91a1c973aa6f55168d9a32d8eacad5474c713c4706f69c34e4ccb85e914a8f1c661ab98645af3e22fc8741d3efff5206fc20c88ab5b3a2fb2978bcb3b4d10e833d8574e220c5bbe9e84ff7c6747928150c491f8dc05ef1585695ef0ac64ae129a03471f04b05120f7b03aba24e95d1818190ef39199d5d735311237c316ccfcbf8de0d90d862351496a1a5f04bcde96fe4ef1c1c528ea610201e556571b5a1a1bf88db1f2998915dca951647431cd03c3b8708028715588deadc5961e852bccf3cd821daa726a202f7e931839af161739f92fe9ffeab8504239e3f33d5deef1583c8a80559336db1c0c436ff834f3f5fbbd1367cefeea499c477e9b9c45d03e6c7f1c2e988f75022d74d433d117eed8f4fc8d6457c68a20c958edda3ad0f9acad9be956071cc3edae14806e32e2e05efb9d330a9e82e7663e1bec6f5a8aef3de0a0b7a3e26e0803c1b930d835d29208e2af1e4af786a891f293a00d25edf68cdfde32aff3cad2b6603ed24d8ded2f25288d86d62ce528ea15ad3785e74dea79b6ab8fc23099a65f228251123650a2c1f3105af54d5c26fb4b2d40f2a5f28864fe669575ab7bbaa8e8f93be87a9fa0f188fee6356bc71bd057a774d4e5d4d7654ec8b2802fa43783d28f63b20238c0aec64c24da99d9a37e4fe6bd4551e5b7555b69a1f94e0dbec5aacc0ea590f5e129dbb8e08bf77f01fab77f504e96eb5ae46f8249d347d19ee3070eb92f918ba6bb2abb7000b5fa48c0b7f8c2e97be5605ec691b673fa9e2f1baffb246ada7f306660b4e1eb835c21cb05fde0faae996c828dea2ccb9878aabf8718279d8de39801f6a9fb07470a906d6feae034ad0c135ad4ff966585e087198ab5696924d492a22c57d967610f54617de22f083206cf7e9e546584e3eee640274de49aa122fe00585da51c6e9d9761aa2e0f75856b8f121
valid = yes
reject-equal = 40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8
reject-below = 1111111111111111111111111111111111111111111111111111111111111111
reject-above-next = eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
```

- **TH-25. Marker-set vectors.** The node's marker-set code inserts the markers
  of every `marker-set` vector in order into the genesis set, and checks the
  witness of `marker-set-absence` against its root. Expected: the same leaves,
  counts and roots; the witness is accepted for its marker and rejected for
  each of the three rejected markers; a node that rewrites the wrong low leaf
  or hashes `nextIndex` at another width fails.

### Witness-extension vectors

The read of section 8, "Reading the tail of the page roots". The
witness-extension vectors use the real page size of 4,096 leaves
and list no full page; `witness-before` and `witness-after` are the 32 siblings
of the leaf from level 0 up, the 12 in-page siblings first, then the 20 upper
siblings from the page-root list. `stored-page-roots` are the roots the wallet
keeps below `tail-start` (none here), `page-roots` the tail served from
`tail-start`, and `header-root` the root over the whole list with `Z_12` for
every page above it, as the coin root field of the anchor carries it.

- `witness-extension-same-page`: page 0 of the coin tree holds the two opaque
  leaves of `coin-tree-header-example` before and one more opaque leaf after,
  so leaf 0's page is not full and is read whole; `pages-read` is every page of
  a one-page tree. `header-root-before` is the root of
  `coin-tree-header-example`.
- `witness-extension-new-pages`: leaf 0 sits in page 0, already full at the
  last sync. Its 12 stored in-page siblings are opaque values, and the root of
  page 0 is climbed from the leaf through them, so no 4,096 leaves are listed.
  The wallet's scan start is page 1, so the tail starts at page 0 and serves
  pages 0 to 2; the roots of pages 1 and 2 are opaque.

```text
[witness-extension-same-page]
kind = witness-extension
tree = coin
position = 0
count-before = 2
count-after = 3
scan-start = 0
tail-start = 0
leaves-before = 562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15
leaves-after = 562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15 c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2
pages-read = 0
witness-before = 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15 f4845eed7550d3a13e340017d66f57e59379889301c259392b4752801744c54b 5a838e3d98a7d16dc2778d5099ec54e178f063cc64d35a86db51ee12ad51d8fe 361f95d542a24172a2115c36a9cb8144bfe5f778872d468ba27436660128b10e 08401a24d074d37fbf4a566d90643f9824ffb732a45bd7b17776d9b1893ca1a9 db9350852cd7a2e044cfb3bc9e268b48f63828777dc9cab432ae5f0a912cdf56 a4929f42c476fa760eea0911531bf75e9ed01648e1b12bdd38ece7d5389d1d05 038e9b109aa53d6ebd7da11e7c9858c7af7473eafddd4f3710d03da68a8ab09d 82552c640589a6ec5cf9764165eaf35f74fed124e23aabe27e942a10b7ecf636 7d92fcf28d4850d2cb0b51823f57b4cedaa0dbcf168e4ec860c55a41cd62a49c 3c3dc5b21d410c5a8a5d4157fa15e2056cc5663ff881172ab4dec15d6a2141b6 fefefed088acd823b9088617b13fb36eab0dd9fe082fb393ff1716a008a4ec8a b50ae40977b91a1a10c7965cd40294eac6f63cbc40b5e57b9d4aa215956142d4 da1d233440916f312ba21ab442b52efc7eb9e41f31a396458d93f71fbea3ec02 7a04cae3422b09862b052461bdf3fdabd1701b5848d6c7c457d28a8486f7c17c 1dd3c81e4e390b32f25c696f1dc0c17e05cf86e0fab870ce53d5bccdcfef1603 b5d9b22171f75552635565fdcd7229f360c2dfe4fc883b9ba86d01f7fda849f1 5037b977992ff9c6315931c21c0b7da37ee9232d8cbdf3f32a26a28c66ba3eab d7abc911715bb38aac28e1465b260943d651e152df2d846cb72d9c32210cccd7 cd74a8288da24dc7171ebeb3d2a9b41eb4890669c04c5d1012dd9e7368a106bb 885935f6f826c1d722b32fd4176dd68f3a214fc24c96fe99ef49855f0295cb58 f01030d347243da62a8006b6b2a963334c8d75fbdd4cd29ec17e6eee9161ccf3 e5c157634719410469743931b0d6fdfd9ed8ba10a83df52d69196bcfb561ca27 47f00c274cceed311b72eb711f1b541cf0a9b64adb245013072ae91a7e317fe9 a1b6b879ff5ea4a91fe79b036f7c1c541dd7b8bc3dea6ad5fc55c35dfa79e87d cfa896957f0ae3ca413e746b76935bad1092eef537cb33807b7ae22a3121f5a4 bdaa4253c959d9e6fbb035774ce5af92475a09d825e46f7d224ed22f1189b17a 0056f319b8f4caa0ef317e9da648b97404b0bba382acaeebc715b4844fef4982 8fd326425cde256254578888caf18b4aaae00ab81ab79a6bb841c338dc4e67e5 41df46222cbee4fba640fe035378aa0746d9d412d3d1dfbf3a7d9c9aa1ac98d8 bfc8015e9d9909bf6ca3b1f2bd21fc2c9f3af0739fbe96f9bc7be87d30c3906b e6e3779f2407af6cd0ae24335bc6ce9e73fdc504a5d397d5e81dbe046158a274
header-root-before = 142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5
stored-page-roots =
page-roots = 96c579df26776fc1392c499d35702a7b33accf42d5087edacc22fa70dd3cfaea
header-root = ad00a34b5bee7b1021456d5986d76aa73885f342df270a60a4c44e2627b1e195
witness-after = 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15 c4961615f978b6cce1114d435d792b57eb51955010c16527cdaaa2acbfad13a6 5a838e3d98a7d16dc2778d5099ec54e178f063cc64d35a86db51ee12ad51d8fe 361f95d542a24172a2115c36a9cb8144bfe5f778872d468ba27436660128b10e 08401a24d074d37fbf4a566d90643f9824ffb732a45bd7b17776d9b1893ca1a9 db9350852cd7a2e044cfb3bc9e268b48f63828777dc9cab432ae5f0a912cdf56 a4929f42c476fa760eea0911531bf75e9ed01648e1b12bdd38ece7d5389d1d05 038e9b109aa53d6ebd7da11e7c9858c7af7473eafddd4f3710d03da68a8ab09d 82552c640589a6ec5cf9764165eaf35f74fed124e23aabe27e942a10b7ecf636 7d92fcf28d4850d2cb0b51823f57b4cedaa0dbcf168e4ec860c55a41cd62a49c 3c3dc5b21d410c5a8a5d4157fa15e2056cc5663ff881172ab4dec15d6a2141b6 fefefed088acd823b9088617b13fb36eab0dd9fe082fb393ff1716a008a4ec8a b50ae40977b91a1a10c7965cd40294eac6f63cbc40b5e57b9d4aa215956142d4 da1d233440916f312ba21ab442b52efc7eb9e41f31a396458d93f71fbea3ec02 7a04cae3422b09862b052461bdf3fdabd1701b5848d6c7c457d28a8486f7c17c 1dd3c81e4e390b32f25c696f1dc0c17e05cf86e0fab870ce53d5bccdcfef1603 b5d9b22171f75552635565fdcd7229f360c2dfe4fc883b9ba86d01f7fda849f1 5037b977992ff9c6315931c21c0b7da37ee9232d8cbdf3f32a26a28c66ba3eab d7abc911715bb38aac28e1465b260943d651e152df2d846cb72d9c32210cccd7 cd74a8288da24dc7171ebeb3d2a9b41eb4890669c04c5d1012dd9e7368a106bb 885935f6f826c1d722b32fd4176dd68f3a214fc24c96fe99ef49855f0295cb58 f01030d347243da62a8006b6b2a963334c8d75fbdd4cd29ec17e6eee9161ccf3 e5c157634719410469743931b0d6fdfd9ed8ba10a83df52d69196bcfb561ca27 47f00c274cceed311b72eb711f1b541cf0a9b64adb245013072ae91a7e317fe9 a1b6b879ff5ea4a91fe79b036f7c1c541dd7b8bc3dea6ad5fc55c35dfa79e87d cfa896957f0ae3ca413e746b76935bad1092eef537cb33807b7ae22a3121f5a4 bdaa4253c959d9e6fbb035774ce5af92475a09d825e46f7d224ed22f1189b17a 0056f319b8f4caa0ef317e9da648b97404b0bba382acaeebc715b4844fef4982 8fd326425cde256254578888caf18b4aaae00ab81ab79a6bb841c338dc4e67e5 41df46222cbee4fba640fe035378aa0746d9d412d3d1dfbf3a7d9c9aa1ac98d8 bfc8015e9d9909bf6ca3b1f2bd21fc2c9f3af0739fbe96f9bc7be87d30c3906b e6e3779f2407af6cd0ae24335bc6ce9e73fdc504a5d397d5e81dbe046158a274

[witness-extension-new-pages]
kind = witness-extension
tree = coin
position = 0
count-before = 4096
count-after = 10000
scan-start = 1
tail-start = 0
leaf = c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1
in-page-siblings = d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0 d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1 d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2 d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3 d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4 d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5 d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6 d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7 d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8 d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9 dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb
witness-before = d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0 d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1 d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2 d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3 d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4 d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5 d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6 d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7 d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8 d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9 dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb b50ae40977b91a1a10c7965cd40294eac6f63cbc40b5e57b9d4aa215956142d4 da1d233440916f312ba21ab442b52efc7eb9e41f31a396458d93f71fbea3ec02 7a04cae3422b09862b052461bdf3fdabd1701b5848d6c7c457d28a8486f7c17c 1dd3c81e4e390b32f25c696f1dc0c17e05cf86e0fab870ce53d5bccdcfef1603 b5d9b22171f75552635565fdcd7229f360c2dfe4fc883b9ba86d01f7fda849f1 5037b977992ff9c6315931c21c0b7da37ee9232d8cbdf3f32a26a28c66ba3eab d7abc911715bb38aac28e1465b260943d651e152df2d846cb72d9c32210cccd7 cd74a8288da24dc7171ebeb3d2a9b41eb4890669c04c5d1012dd9e7368a106bb 885935f6f826c1d722b32fd4176dd68f3a214fc24c96fe99ef49855f0295cb58 f01030d347243da62a8006b6b2a963334c8d75fbdd4cd29ec17e6eee9161ccf3 e5c157634719410469743931b0d6fdfd9ed8ba10a83df52d69196bcfb561ca27 47f00c274cceed311b72eb711f1b541cf0a9b64adb245013072ae91a7e317fe9 a1b6b879ff5ea4a91fe79b036f7c1c541dd7b8bc3dea6ad5fc55c35dfa79e87d cfa896957f0ae3ca413e746b76935bad1092eef537cb33807b7ae22a3121f5a4 bdaa4253c959d9e6fbb035774ce5af92475a09d825e46f7d224ed22f1189b17a 0056f319b8f4caa0ef317e9da648b97404b0bba382acaeebc715b4844fef4982 8fd326425cde256254578888caf18b4aaae00ab81ab79a6bb841c338dc4e67e5 41df46222cbee4fba640fe035378aa0746d9d412d3d1dfbf3a7d9c9aa1ac98d8 bfc8015e9d9909bf6ca3b1f2bd21fc2c9f3af0739fbe96f9bc7be87d30c3906b e6e3779f2407af6cd0ae24335bc6ce9e73fdc504a5d397d5e81dbe046158a274
header-root-before = 20ac69c2e03c21f036765915b2743aefffe81ec2c8234f57bbb41cf818269c62
stored-page-roots =
page-roots = 2716f68f96662291f3213f03618e0e17f30146654ca1278da24f92c2c2c09ee1 e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1 e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2
header-root = c81d94ca55f0d04a7d8a4bf40d78e5799c8f3adcdc28ffbe2b6263ce4149cad5
witness-after = d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0 d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1 d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2 d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3 d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4 d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5 d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6 d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7 d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8 d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9 dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1 9f146ce6910cd2e18f28dd03fd68a80cc769715b124ccaa3a4644cde3b93c90b 7a04cae3422b09862b052461bdf3fdabd1701b5848d6c7c457d28a8486f7c17c 1dd3c81e4e390b32f25c696f1dc0c17e05cf86e0fab870ce53d5bccdcfef1603 b5d9b22171f75552635565fdcd7229f360c2dfe4fc883b9ba86d01f7fda849f1 5037b977992ff9c6315931c21c0b7da37ee9232d8cbdf3f32a26a28c66ba3eab d7abc911715bb38aac28e1465b260943d651e152df2d846cb72d9c32210cccd7 cd74a8288da24dc7171ebeb3d2a9b41eb4890669c04c5d1012dd9e7368a106bb 885935f6f826c1d722b32fd4176dd68f3a214fc24c96fe99ef49855f0295cb58 f01030d347243da62a8006b6b2a963334c8d75fbdd4cd29ec17e6eee9161ccf3 e5c157634719410469743931b0d6fdfd9ed8ba10a83df52d69196bcfb561ca27 47f00c274cceed311b72eb711f1b541cf0a9b64adb245013072ae91a7e317fe9 a1b6b879ff5ea4a91fe79b036f7c1c541dd7b8bc3dea6ad5fc55c35dfa79e87d cfa896957f0ae3ca413e746b76935bad1092eef537cb33807b7ae22a3121f5a4 bdaa4253c959d9e6fbb035774ce5af92475a09d825e46f7d224ed22f1189b17a 0056f319b8f4caa0ef317e9da648b97404b0bba382acaeebc715b4844fef4982 8fd326425cde256254578888caf18b4aaae00ab81ab79a6bb841c338dc4e67e5 41df46222cbee4fba640fe035378aa0746d9d412d3d1dfbf3a7d9c9aa1ac98d8 bfc8015e9d9909bf6ca3b1f2bd21fc2c9f3af0739fbe96f9bc7be87d30c3906b e6e3779f2407af6cd0ae24335bc6ce9e73fdc504a5d397d5e81dbe046158a274
```

### Header vectors

`header-genesis-example` is a genesis header with example inputs: the stand-in
for Bitcoin block `B` is the hash of Bitcoin's own first block and `MTP(B)` is
1798761600. Neither is Ghost's anchor. Its `dataMarkerRoot` is the root of
`marker-set-empty`. `header-block-one-example` builds on it with the roots of
the tree vectors above, the root of `marker-set-two-markers` and example values
elsewhere. The negative vectors are `header-block-one-example` with one fault
each, and a decoder must reject each with the reason given.

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
dataMarkerRoot = 0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3
rlp = f90281a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000808401c9c38080846b3703f0a0000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fa00000000000000000000000000000000000000000000000000000000000000000880000000000000000843b9aca00a08e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8a03d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03a00ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3
hash = 039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4
valid = yes

[header-block-one-example]
kind = header
parentHash = 039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4
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
dataMarkerRoot = f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
rlp = f90264a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
hash = 81ca961404b518ee3ded78ebee1c4e23eba18b7c86515b6471e970cfed8538f4
valid = yes

[header-forbidden-field]
kind = header-negative
base = header-block-one-example
fault = forbidden-field
reject = item-count
rlp = f90285a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
valid = no

[header-extra-trailing-field]
kind = header-negative
base = header-block-one-example
fault = extra-trailing-field
reject = item-count
rlp = f90265a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f80
valid = no

[header-missing-required-field]
kind = header-negative
base = header-block-one-example
fault = missing-required-field
reject = item-count
rlp = f9025fa0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a04444444444444444444444444444444444444444444444444444444444444444880102030405060708a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
valid = no

[header-non-canonical-integer]
kind = header-negative
base = header-block-one-example
fault = non-canonical-integer
reject = non-canonical-integer
rlp = f90266a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000084010000008200018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
valid = no

[header-short-tree-root]
kind = header-negative
base = header-block-one-example
fault = short-tree-root
reject = field-size
rlp = f90263a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c09f142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ea0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
valid = no

[header-trailing-bytes]
kind = header-negative
base = header-block-one-example
fault = trailing-bytes
reject = trailing-bytes
rlp = f90264a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f00
valid = no

[header-eighteen-items]
kind = header-negative
base = header-block-one-example
fault = eighteen-items
reject = item-count
rlp = f90243a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a
valid = no
```

The faults: `forbidden-field` puts a withdrawals root where the base client
would put it, after the base fee; `extra-trailing-field` appends an empty
string; `missing-required-field` drops the base fee; `non-canonical-integer`
writes the block number with a leading zero byte; `short-tree-root` cuts the
coin tree root to 31 bytes; `trailing-bytes` appends one byte after the list;
`eighteen-items` drops `dataMarkerRoot`, leaving the 18 items of a header from
before it.

## 12. Not settled: fail closed

Each point rejects until the founder or a later specification settles it.

1. **Spent-marker-set root in headers.** Settled (front desk decision,
   2026-10-25; spec 04, question 2): every header carries `dataMarkerRoot`,
   the root of the data marker-set tree of section 6, and none carries a coin
   marker-set root. The proof circuit checks the marker's absence under that
   root (spec 02, S3, constraint 4; section 13, item 2 there), so a proof of
   holding for data is verified; a proof of holding for coins stays rejected
   (spec 02, section 13, item 3).
2. **Reserved account addresses.** The addresses of the two tree-state accounts
   and the two marker-set accounts are for the transaction-format
   specification. Until fixed, no commit or reveal is valid.
3. **Peer messages for pages.** The request and response messages of section 8
   in the node's peer protocol and in its JSON-RPC interface are for the node
   phase. Any message that returns tree data for a single commitment, position,
   marker, note or transaction is refused.
4. **Marker page integrity.** Marker pages are not checkable against a header
   (section 8); they are hints, and status is taken only from receipts checked
   against `receiptsRoot` (review 01, F4). Until checked, status from marker
   pages is "unknown", never "unspent" or "spent".
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
   asks whether it should. By front desk decision (2026-10-25) this document
   adds it as the third header field, `dataMarkerRoot`, with the tree of
   section 6, and adds no coin marker-set root. The proof circuit checks
   the absence under it, as [spec 02](02-proof-statements.md), section 13,
   item 2 says.
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
6. **Coin marker-set root.** The header carries the data marker-set root only
   (section 6). Default: no coin marker-set root, so a proof of holding for
   coins stays rejected (spec 02, section 13, item 3); adding one later is a
   new header field and a new header layout.

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
header in order with the base fee required, the two tree roots and
`dataMarkerRoot` as field 18, exactly 19 fields, that no forbidden field and no
other marker-set root is in it, and that every genesis field is listed with its
source and agrees with the genesis vector; that every tree, rollover and header
vector is right; that every marker-set vector is recomputed by the script's own
indexed tree (leaves, counts, roots, the absence witness and its three rejected
markers) and every header's `dataMarkerRoot` is the root of one; that every
`witness-extension` vector is recomputed with the script's own tree code (the
witness before, the page read whole or the root climbed from the stored
in-page siblings, the page-root tail against the header root, which rejects a
wrong tail, and the witness after); that section 8 states the tail read and
its cost against the restore ceilings, and that its "Forbidden." paragraph, TH-19, the "Marker status."
Rule and section 12, item 4 follow them; that every
negative header vector is rejected for the stated reason, and the header
vectors equal the output of `scripts/header_golden_encoder.py`; that the conformance requirements and the
recovery test are numbered and state their expected results; that the conflicts
named in section 13 are listed; and that every hash tag named here is in the tag
table of spec 01. `scripts/test_check_trees_and_headers.py` damages each part
and expects the check to fail.

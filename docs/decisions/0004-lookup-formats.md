# Decision 0004: byte formats for lookup tags, lookup index trees, the coin marker tree and the block lookup digest

Status: byte formats fixed for the build, 2026-11-04. The format changes
themselves are the founder decision that the
[stage 2 design](../scale/stage2-design.md) lists ("Decisions for the
founder"); this record fixes their bytes so that they can be written into the
specifications with golden vectors and checked. Nothing here is built.

## Decision

The stage 2 design ("What changes on the chain") gives the restore formats only
as modeled sizes. This record fixes them byte for byte:

| Item | Settled |
|---|---|
| Lookup tag | The first 16 bytes of `S("ghost/note-lookup/v1", k_note, i as 8 bytes)`, carried beside every new leaf and entering only the lookup index and the block lookup digest; never an input of the commitment, the tree leaf or the note |
| Position | A leaf's global position `g = k * 2^32 + p`, 5 bytes, for tree index `k` and position `p` |
| Lookup index | One append-only indexed Keccak-256 tree of depth 40 per type, over the key (tag, position); leaf of 47 bytes; equal tags ordered by position; one 1,332-byte witness layout for membership, first entry and absence |
| Coin spent-marker set tree | The data marker-set tree of spec 05, section 6, with a fourth field, the global position of the leaf the same reveal appended, or `ff ff ff ff ff` for none; leaf of 74 bytes; 1,359-byte witnesses |
| Header | Four new fields after field 18: `coinLookupRoot` (19), `dataLookupRoot` (20), `coinMarkerRoot` (21), `lookupDigest` (22); 23 items |
| Block lookup digest | Keccak-256 under its own tag over the block's new coin tags, data tags, coin markers and data markers, each list in transaction order with its count, the tag lists with the global position of their first leaf |
| Proofs of holding | Coin proofs of holding stay rejected; `coinMarkerRoot` does not settle spec 02, question 2 |
| Reorganisation | The three new trees are journaled state and roll back with it; every root follows the canonical chain |

The header MMR of the stage 2 design is not part of this record and takes none
of the indices above.

## Conventions

The conventions of [spec 01](../spec/01-commitments-and-keys.md), section 2,
apply: `K(tag, ...)` is tagged Keccak-256, `S(tag, ...)` is tagged SHA3-256,
`tagbytes(tag)` is one length byte then the tag's ASCII bytes, `||` is
concatenation, integers are unsigned and big-endian at the stated width, and
hex is lower case. In addition:

- **Global position.** A leaf at position `p` of tree index `k` of one type has
  the global position `g = k * 2^32 + p`, written as 5 bytes. A tree fills
  completely before the next one starts (spec 05, section 3, "Rollover"), so
  `g` is exactly the number of leaves of that type appended before this one.
  Every position in this record is a global position.
- **None.** The 5 bytes `ff ff ff ff ff`, 2^40 - 1, are never a global
  position (see "Proofs of holding, rollover and reorganisation") and mean "no
  leaf".
- **Order.** Byte strings of one width compare as big-endian unsigned integers.
- **Depth.** Every tree in this record has depth 40: 2^40 positions, levels 0
  (just above the leaves) to 39 (the root), the empty leaf
  `E = K("ghost/empty-leaf/v1")` of spec 01 at every unused position, and empty
  subtrees `Z_0 = E`, `Z_(l+1) = node(l, Z_l, Z_l)` under the tree's own node
  tag, exactly as spec 05, section 6 builds the data marker-set tree.

## Lookup tag

**Inputs and encoding.** For a key's commitment number `i` (spec 01,
section 8), with its note key `k_note` (spec 01, section 7):

```text
lookupTag_i = the first 16 bytes of S("ghost/note-lookup/v1", k_note, i as 8 bytes)
```

The domain string is the 20 ASCII bytes `ghost/note-lookup/v1`, written with
its length byte `0x14`. `k_note` is the 32-byte note key and `i` is 8 bytes,
big-endian, the same width the note's plaintext gives the number (spec 01,
section 9). The hash input is 61 bytes. Of the 32-byte SHA3-256 digest the
first 16 bytes are kept and the last 16 dropped: truncation to 16 bytes, no
other reduction. It is SHA3-256, not Keccak-256, because it is derived from the
digits off the chain and never recomputed inside a proof (spec 01, section 4,
"Two hashes, by use").

The tag is not the 3-byte nonce tag of spec 01, section 9: that one has its
own domain `ghost/note-tag/v1` and stays as spec 01 has it until the build
ticket withdraws the bucket path. Knowing `k_note` gives both, and holding
`k_note` already reads every note of the key, so the tag shows such a holder
nothing more.

**Who writes it.** Whoever writes the note writes the tag (spec 01,
section 9): the wallet for a commit, the revealing wallet for a remainder, and
the claiming wallet, with the new key's `k_note` and number 0, for a claim's
new commitment. The chain cannot tell a claim from a partial reveal (spec 02,
section 4), so a claim's tag sits in the same field as a remainder's.

**Where it sits in each new leaf.** A new leaf of either tree is the
commitment `C` (32 bytes), its note and its lookup tag (16 bytes):

| New leaf | Where the tag is carried | What binds it |
|---|---|---|
| Coin commit | The last 16 bytes of the commit payload, after the note | The account signature of the commit transaction |
| Data commit | The last 16 bytes of the commit payload, after the note | The account signature of the commit transaction |
| Remainder of a coin reveal | `remainder_tag`, the last 16 bytes of the private transaction payload, after the note | The coin reveal binding, as the field `remainder_tag` after `remainder_note` |
| A claim's new commitment | The same `remainder_tag` field: a claim is a reveal | The same |

In the coin reveal binding of spec 02, section 7, `remainder_tag` takes
offset 415, after `remainder_note`, so the fields are 431 bytes after the tag
and 460 bytes with it, still 4 Keccak permutations. It is bound for the reason
the note is bound (spec 02, question 3): a relay that changed it would hide
the remainder from a lookup. In the private transaction of spec 07, section 3,
it takes offset 1,311,066 after the 156-byte note, and the payload grows to
1,311,082 bytes. The receipt of every transaction that appends a leaf carries
the tag with the leaf (spec 05, section 8, item 5; the receipt layout stays
open there).

**In the leaf hash.** The tag is not an input of the commitment `C`, of the
fingerprint `F`, of any coin-tree or data-tree node, or of the note's
associated data. The coin and data trees, their roots and every proof
statement are unchanged by it. The tag enters exactly two hashes: the leaf
hash of the lookup index of its type, with the leaf's global position (next
section), and the block lookup digest. Consensus cannot check that a tag was
derived as above and does not try; it checks only its width.

**The zero tag.** A tag of 16 zero bytes is rejected, at a commit's format
check and at a reveal's encoding check, because the all-zero key belongs to the
lookup index's sentinel. A derived tag is 16 zero bytes with probability
2^-128.

## Lookup index trees

There are two lookup indices, one per type, each the construction of the data
marker-set tree of spec 05, section 6 over a different key: an append-only
indexed Keccak-256 tree of depth 40 whose sorted linked list runs over the pair
(tag, position) of every leaf of that type.

**Leaves and nodes.** A used position holds the 47-byte leaf

| Field | Width | Meaning |
|---|---|---|
| `tag` | 16 bytes | The lookup tag of a leaf of the tree's type |
| `position` | 5 bytes | That leaf's global position |
| `nextTag` | 16 bytes | The tag of the next entry in key order; 16 zero bytes for none |
| `nextPosition` | 5 bytes | The global position of that next entry |
| `nextIndex` | 5 bytes | The position of that next entry in this lookup index |

The key of a leaf is `tag || position`, 21 bytes, so entries are ordered by tag
and, between equal tags, by position. The hashes are

```text
coin: leaf = K("ghost/coin-lookup-leaf/v1", tag, position, nextTag, nextPosition, nextIndex)   73 input bytes, 1 permutation
      node = K("ghost/coin-lookup-node/v1", l as 1 byte, left, right)                          91 input bytes, 1 per level
data: leaf = K("ghost/data-lookup-leaf/v1", tag, position, nextTag, nextPosition, nextIndex)   73 input bytes, 1 permutation
      node = K("ghost/data-lookup-node/v1", l as 1 byte, left, right)                          91 input bytes, 1 per level
```

The coin and data tags differ from each other and from the marker-set tags, so
no leaf or node of one tree can stand for one of another.

**The empty tree.** Position 0 holds the sentinel: every field zero, the 47
zero bytes. Every other position is empty. Its root is the genesis
`coinLookupRoot` (or `dataLookupRoot`), vectors `coin-lookup-empty` and
`data-lookup-empty`. `nextTag` of 16 zero bytes means "no larger entry".

**Insert.** Every leaf the tree of a type appends inserts one entry, in the
apply step of the transaction that appends it (spec 03, section 6, step 10 and
section 7, step 13; spec 04, section 4), right after the append, so the
entries of a block go in in transaction order. For a leaf with tag `t` at
global position `g`, key `q = t || g`, into an index with `n` used positions:

1. Find the used leaf `low` with `low.key < q` and (`q < low.nextKey` or
   `low.nextTag = 0`), `nextKey` being `nextTag || nextPosition`. Exactly one
   leaf has this property.
2. Write `(t, g, low.nextTag, low.nextPosition, low.nextIndex)` at
   position `n`.
3. Rewrite `low` as `(low.tag, low.position, t, g, n)`, and set `n = n + 1`.

Each leaf of the type is one insert, in append order, so the entry of the leaf
at global position `g` sits at index position `g + 1`, and
`nextIndex = nextPosition + 1` in every leaf whose `nextTag` is not zero.

**Equal tags.** Two leaves can carry the same tag: a retry of one number on
another branch, or a copied tag, which anyone can write into a commit they pay
for (stage 2 design, "Denial of service"). Their keys still differ, because
their positions do, and the earlier leaf comes first. A new leaf's position is
larger than every position already in the index, so a copied tag is inserted
right after the last entry with the same tag and never sorts before the
original (vector `coin-lookup-copied-tag`).

**Witnesses.** All lookup witnesses have one layout, the low leaf's fields, its
index position and its 40 siblings from level 0 up:

```text
tag (16) || position (5) || nextTag (16) || nextPosition (5) || nextIndex (5) || index position of the leaf (5) || 40 siblings (32 each)
```

1,332 bytes. The leaf's hash folded with the siblings along the bits of its
index position, as in spec 05, section 6, must give the root `R` taken from a
header; any witness of another length, or one that does not fold to `R`, is
rejected.

- **Membership witness** for a pair (`t`, `g`): valid if and only if `t` is not
  zero, the leaf folds to `R`, `tag = t` and `position = g`. It also names the
  next entry: when its `nextTag` is `t`, that is the next leaf carrying the
  same tag, so a wallet passes over a copy one witness at a time.
- **Lookup witness** for a tag `t`: the low leaf of the query `t || 0^5`. Valid
  if and only if `t` is not zero, the leaf folds to `R`, `tag < t`, and either
  `nextTag = 0` or `nextTag >= t`. Its answer:
  - `nextTag = t`: the **first entry** with tag `t` is the leaf at global
    position `nextPosition` (index position `nextIndex`); no leaf with that tag
    has a smaller position (vector `coin-lookup-first-entry`).
  - `nextTag = 0` or `nextTag > t`: no leaf of this type carries `t` under
    `R`; the tag is **absent**, and the witness is its absence witness (vector
    `coin-lookup-absence`, which "no first commitment" of the stage 2 design's
    restore uses).

## Coin spent-marker set tree

The coin spent markers are kept as the same construction as the data
marker-set tree of spec 05, section 6, with one more field. Its root after the
block's last transaction is `coinMarkerRoot`. It holds the same markers as the
coin set's storage slots, in the order they were spent, and does not replace
the slot check, which still rejects a repeat (spec 05, section 6, "How a repeat
is rejected").

**Leaves and nodes.** A used position holds the 74-byte leaf

| Field | Width | Meaning |
|---|---|---|
| `value` | 32 bytes | A spent coin marker |
| `nextValue` | 32 bytes | The next larger marker in the set; 32 zero bytes for none |
| `nextIndex` | 5 bytes | The position of that marker's leaf in this tree |
| `appended` | 5 bytes | The global position of the coin leaf that the reveal spending `value` appended, or none, `ff ff ff ff ff` |

```text
leaf = K("ghost/coin-marker-set-leaf/v1", value, nextValue, nextIndex, appended)   104 input bytes, 1 permutation
node = K("ghost/coin-marker-set-node/v1", l as 1 byte, left, right)               95 input bytes, 1 per level
```

**The empty set.** Position 0 holds the sentinel `(0, 0, 0, none)`: 69 zero
bytes and then `ff ff ff ff ff`. Its root is the genesis `coinMarkerRoot`
(vector `coin-marker-set-empty`). The marker value 0 is never valid.

**Insert.** In the apply step of a coin reveal (spec 03, section 7, step 13),
which spends marker `m` and appends its remainder, or a claim's new
commitment, at global position `a` (after the rollover rule of spec 05,
section 3 has chosen its tree index and position):

1. Find the used leaf `low` with `low.value < m` and (`m < low.nextValue` or
   `low.nextValue = 0`). Exactly one leaf has this property.
2. Write `(m, low.nextValue, low.nextIndex, a)` at position `n`.
3. Rewrite `low` as `(low.value, m, n, low.appended)`: a rewritten leaf keeps
   its own `appended`. Set `n = n + 1`.

The append and the insert are one state change, so `a` is the same whatever
order a node performs them in. In version 1 every coin reveal appends exactly
one remainder (spec 03, section 7: one shape), so every leaf except the
sentinel records a position; none is the sentinel's, and is there for any later
reveal kind that appends no leaf.

**Witnesses.** Both kinds have one layout:

```text
value (32) || nextValue (32) || nextIndex (5) || appended (5) || position of the leaf (5) || 40 siblings (32 each)
```

1,359 bytes, folded as above with the coin marker-set tags.

- **Absence witness** for a marker `m`: valid if and only if `m` is not zero,
  the leaf folds to the root, `value < m`, and (`m < nextValue` or
  `nextValue = 0`): `m` is unspent under that root (vector
  `coin-marker-set-absence`).
- **Membership witness** for `m`: valid if and only if `m` is not zero, the
  leaf folds to the root and `value = m`: `m` is spent on the chain of that
  root, and `appended` is the global position of the leaf its reveal appended,
  where the wallet reads the next commitment, or none (vector
  `coin-marker-set-membership`).

The data marker-set tree keeps its three fields and its 1,354-byte witness:
data commitments have no remainder in version 1 (spec 04, question 3).

## Header fields

The header of spec 05, section 10 gets four new fields after its current
fields 0 to 18, in this order:

| Index | Field | Encoding | Source |
|---|---|---|---|
| 19 | `coinLookupRoot` | 32 bytes | Ghost |
| 20 | `dataLookupRoot` | 32 bytes | Ghost |
| 21 | `coinMarkerRoot` | 32 bytes | Ghost |
| 22 | `lookupDigest` | 32 bytes | Ghost |

- `coinLookupRoot` and `dataLookupRoot`: the root of the lookup index of each
  type after the block's last transaction.
- `coinMarkerRoot`: the root of the coin spent-marker set tree after the
  block's last transaction.
- `lookupDigest`: the block lookup digest of the next section.

A header is then exactly 23 items; a decoder rejects a 19-item header as
`item-count`, as it rejects any other count. Each field is a 32-byte RLP
string, 33 bytes encoded, so the header grows by 132 bytes. A block whose four
values differ from those the node computes by executing it is invalid, with
the root checks of spec 05, section 4. When a block adds no leaf or marker of a
tree, its root equals the parent's. The genesis values are those of vector
`header-genesis-new-fields`.

**The change from the current rule.** Spec 05 records that the header carries
exactly three new fields and that there is no coin marker-set root, so the
data set alone has a root, `dataMarkerRoot` (its decision table, row
"Spent-marker-set root in the header", front desk decision, 2026-10-25, and
sections 4, 6 and 10). The stage 2 design superseded that rule: the coin set
gets the same tree with the `appended` field, so that a spent marker leads to
the next commitment with a witness and no request names it. This record fixes
`coinMarkerRoot` as field 21. `dataMarkerRoot` stays field 18, unchanged.

## Block lookup digest

**The list.** The node collects, from the transactions of the block that
apply, in transaction order (a rejected transaction, or a reveal a bundle
skips, contributes nothing):

1. the coin tags: the tag of every coin leaf the block appends, commits' and
   remainders' alike, in append order;
2. the data tags: the tag of every data commit;
3. the coin markers: every marker the block's coin reveals insert;
4. the data markers: every marker the block's data reveals and revocations
   insert.

Tags come before markers, and the coin list of each before the data list.

**Encoding.**

```text
coinStart (5) || coinTagCount (4) || coin tags (16 each)
|| dataStart (5) || dataTagCount (4) || data tags (16 each)
|| coinMarkerCount (4) || coin markers (32 each)
|| dataMarkerCount (4) || data markers (32 each)
```

Each count is 4 bytes, big-endian, and may be zero. `coinStart` and
`dataStart` are the global positions of the block's first new leaf of each
type, the number of leaves of that type appended before the block, written
even when the count is zero; the `j`-th coin tag of the list is the tag of the
coin leaf at global position `coinStart + j`. A wallet that finds its tag in a
later block's list therefore learns the leaf's position from data its header
checks.

**Hash.**

```text
lookupDigest = K("ghost/block-lookup-digest/v1", encoding)
```

Keccak-256 under its own tag, over 55 bytes with the tag plus 16 a tag and 32
a marker, never recomputed inside a proof. It is a flat hash, not a tree: the
list of a block is read whole after a PIR snapshot (stage 2 design, "What a
wallet does", step 4), never one item at a time, and the wallet checks it by
recomputing the digest and comparing it with the header's `lookupDigest`,
field 22. A block of 3,500 private reveals and nothing else lists
26 + 3,500 x 48 = 168,026 bytes.

## Proofs of holding, rollover and reorganisation

**Spec 02, S3, constraint 4.** A proof of holding needs an authenticated set
root for its non-membership. `coinMarkerRoot` is one for coins, but this record
does not settle spec 02, question 2: coin proofs of holding stay rejected, S3
with `COIN` as spec 02, section 13, item 3 has it, and nothing here states
otherwise. If that question is
settled later, constraint 4 for coins would open a coin marker-set leaf of 104
input bytes, still one permutation, from the 1,359-byte absence witness of
this record, not the data layout, and the circuit and its statement change with
it. S3 for data is unchanged: `dataMarkerRoot` and the 1,354-byte witness of
spec 05, section 6.

**Rollover.** The lookup indices and the coin marker set span every tree index
of their type and never roll over: global positions count across a rollover,
and the first leaf of tree `k + 1` has `g = (k + 1) * 2^32`. The rule that a
block never appends to two tree indices of one type (spec 05, section 3) is
unchanged, and `coinStart` counts across it. The lookup index has room for
2^40 - 1 entries besides its sentinel, so an append whose global position
would be 2^40 - 1 is rejected, as an append past `TREE_INDEX_MAX` is today.
That makes the last usable leaf position 4294967294 of tree index 255 (vector
`global-position-examples`), about 301 years at 10 million leaves a day
(modeled), in place of the 2^64 tree indices of spec 05. The coin marker set
holds at most one marker for each coin leaf, so it never fills before the
coin lookup index does.

**Reorganisation.** The two lookup indices and the coin marker set are
journaled storage of reserved system accounts, in a layout of the node's own in
which the genesis sentinels occupy no non-zero slot, exactly as spec 05,
section 6 keeps the data marker set. So they roll back with the state (spec 05,
section 7, step 1): after a reorganisation to common ancestor `A`, their used
leaves and counts return to their values at `A` and the new branch is executed
on them, and every root of the new branch equals that of a node that never saw
the disconnected blocks. The roots follow the canonical chain:

- A spend only on a disconnected block is absent from the `coinMarkerRoot` of
  every block of the new chain, so an absence witness against it is valid and
  the coin shows unspent again; a spend kept on the new chain is in its set.
- A commit re-included on the new branch at another position gets its lookup
  entry at the new position; the entry of its old position is gone with the
  disconnected block.
- The `lookupDigest` of a disconnected block leaves with its header. A wallet
  takes roots and digests only from headers on its own checked chain; a
  snapshot whose header is no longer canonical is discarded, and the restore
  runs again (stage 2 design, "Spent status follows the canonical chain").

## Specification 08 is not touched

[Spec 08](../spec/08-randomx-seal.md) fixes the RandomX seal: what RandomX
hashes, the target, the key and the seal hash. Its seal hash is Keccak-256 of
the RLP of the header with `mixDigest` and `nonce` set to zero, so it already
covers every field of the header, the four new ones included, and needs no
change. The four fields are defined where the header encoding is, in spec 05,
section 10, and that is where the build ticket writes them.

## Tag table rows

The rows the build ticket adds to the tag table of spec 01, section 4, with the
same columns. Input bytes count the length byte and the tag.

| Tag | Hash | Use | Inputs after the tag | Input bytes | Keccak permutations |
|---|---|---|---|---|---|
| `ghost/note-lookup/v1` | SHA3-256 | Lookup tag of the key's commitment number `i`, its first 16 bytes | `k_note`, `i` as 8 bytes | 61 | not in a proof |
| `ghost/coin-lookup-leaf/v1` | Keccak-256 | Leaf of the coin lookup index | `tag`, `position`, `nextTag`, `nextPosition`, `nextIndex` | 73 | 1 |
| `ghost/coin-lookup-node/v1` | Keccak-256 | Inner node of the coin lookup index | level as 1 byte, left child, right child | 91 | 1 per level |
| `ghost/data-lookup-leaf/v1` | Keccak-256 | Leaf of the data lookup index | `tag`, `position`, `nextTag`, `nextPosition`, `nextIndex` | 73 | 1 |
| `ghost/data-lookup-node/v1` | Keccak-256 | Inner node of the data lookup index | level as 1 byte, left child, right child | 91 | 1 per level |
| `ghost/coin-marker-set-leaf/v1` | Keccak-256 | Leaf of the coin spent-marker set tree | `value`, `nextValue`, `nextIndex`, `appended` | 104 | 1 |
| `ghost/coin-marker-set-node/v1` | Keccak-256 | Inner node of the coin spent-marker set tree | level as 1 byte, left child, right child | 95 | 1 per level |
| `ghost/block-lookup-digest/v1` | Keccak-256 | Block lookup digest, header field `lookupDigest` | the encoding of the block's list | 55 + 16 a tag + 32 a marker | not in a proof |

## Worked examples

Every block below is the output of `python3 scripts/check_decision_0004.py
--print`, copied unchanged; the same script checks that this record still
matches it. Each starts with `[name]`; each line is `field = value`; byte values
are hex. The keys are spec 01's example words key (secret `00 01 .. 1f`) and its
data example key (secret `7f 7f .. 7f`), examples only, which must never hold
value. Leaf fields are written in their order, separated by spaces; an entry
`tag@g` is a tag at global position `g`, and a spend `marker@a` a marker whose
reveal appended the leaf at global position `a`.

### Lookup tag examples

Numbers 0, 1 and 2 of the example key, and number 0 of the data example key.
`note-key` is spec 01's `k_note` of the same key bytes, `digest` the whole
SHA3-256 output and `tag` its first 16 bytes.

```text
[lookup-tag-index-0]
kind = lookup-tag
key-bytes = 20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
note-key = 35136c4a7bdccb4b26159c15f86567a483ac58e1b2c40dca49a5d099272c4181
index = 0
index-bytes = 0000000000000000
digest = 74c5d993f5f018e3174926b2c8e8fb68e9444bfe3fdb48a847ef99c2446ef1a5
tag = 74c5d993f5f018e3174926b2c8e8fb68

[lookup-tag-index-1]
kind = lookup-tag
key-bytes = 20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
note-key = 35136c4a7bdccb4b26159c15f86567a483ac58e1b2c40dca49a5d099272c4181
index = 1
index-bytes = 0000000000000001
digest = 98f00763f51d9e982a7814297473729f085ae21e5a0f398ffbe70a4c95d159af
tag = 98f00763f51d9e982a7814297473729f

[lookup-tag-index-2]
kind = lookup-tag
key-bytes = 20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
note-key = 35136c4a7bdccb4b26159c15f86567a483ac58e1b2c40dca49a5d099272c4181
index = 2
index-bytes = 0000000000000002
digest = b3e8df15fdd3d0f3ac8c7562c50ba57ec7d2688a9a57a685661be28f9d4b13f8
tag = b3e8df15fdd3d0f3ac8c7562c50ba57e

[lookup-tag-data-index-0]
kind = lookup-tag
key-bytes = 207f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
note-key = 08f3c586fe83f60374f0551ad5a25ddab61fd4fc70ab71572c0aae3b042c82ab
index = 0
index-bytes = 0000000000000000
digest = 9d77715bd859976996087ca266cf37b02c73e1deff301d4ae4ed04d77c88546f
tag = 9d77715bd859976996087ca266cf37b0
```

### Lookup index examples

The empty indices; the coin index after the commit of number 0 at coin leaf 0
(one leaf beside the sentinel); after the remainder of number 1 at coin leaf 1
(two leaves); after a commit by someone else that copies the tag of number 0
at coin leaf 2; and the data index after the data commit of number 0. In the
copied-tag index the copy, `leaf-3`, sorts right after the original,
`leaf-1`, and before the tag of number 1.

```text
[coin-lookup-empty]
kind = lookup-index
tree = coin
entries =
count = 1
leaf-0 = 00000000000000000000000000000000 0000000000 00000000000000000000000000000000 0000000000 0000000000
root = 994a8bc5ba72f53f4449d4981c3ea8294d504b148afa58abec873819b143554b

[data-lookup-empty]
kind = lookup-index
tree = data
entries =
count = 1
leaf-0 = 00000000000000000000000000000000 0000000000 00000000000000000000000000000000 0000000000 0000000000
root = c0ad355e8462fbe6093fa0ac37c0afc450b36cbe679bb7de3050a9a1b2cddece

[coin-lookup-one-leaf]
kind = lookup-index
tree = coin
entries = 74c5d993f5f018e3174926b2c8e8fb68@0
count = 2
leaf-0 = 00000000000000000000000000000000 0000000000 74c5d993f5f018e3174926b2c8e8fb68 0000000000 0000000001
leaf-1 = 74c5d993f5f018e3174926b2c8e8fb68 0000000000 00000000000000000000000000000000 0000000000 0000000000
root = 09cf86c7dd4db859ff77e3ee9b988e324cc4fe53a384f6b4b674a4b9ddc64954

[coin-lookup-two-leaves]
kind = lookup-index
tree = coin
entries = 74c5d993f5f018e3174926b2c8e8fb68@0 98f00763f51d9e982a7814297473729f@1
count = 3
leaf-0 = 00000000000000000000000000000000 0000000000 74c5d993f5f018e3174926b2c8e8fb68 0000000000 0000000001
leaf-1 = 74c5d993f5f018e3174926b2c8e8fb68 0000000000 98f00763f51d9e982a7814297473729f 0000000001 0000000002
leaf-2 = 98f00763f51d9e982a7814297473729f 0000000001 00000000000000000000000000000000 0000000000 0000000000
root = 489542787d7482d68a5bbd92c21f8225be3b0420bf06f1232c01af1f9f4c4451

[coin-lookup-copied-tag]
kind = lookup-index
tree = coin
entries = 74c5d993f5f018e3174926b2c8e8fb68@0 98f00763f51d9e982a7814297473729f@1 74c5d993f5f018e3174926b2c8e8fb68@2
count = 4
leaf-0 = 00000000000000000000000000000000 0000000000 74c5d993f5f018e3174926b2c8e8fb68 0000000000 0000000001
leaf-1 = 74c5d993f5f018e3174926b2c8e8fb68 0000000000 74c5d993f5f018e3174926b2c8e8fb68 0000000002 0000000003
leaf-2 = 98f00763f51d9e982a7814297473729f 0000000001 00000000000000000000000000000000 0000000000 0000000000
leaf-3 = 74c5d993f5f018e3174926b2c8e8fb68 0000000002 98f00763f51d9e982a7814297473729f 0000000001 0000000002
root = 2f880d0d3c8d149461815119475cc2c32bb5932ff3fa98a7dd771cdd2a18957e

[data-lookup-one-leaf]
kind = lookup-index
tree = data
entries = 9d77715bd859976996087ca266cf37b0@0
count = 2
leaf-0 = 00000000000000000000000000000000 0000000000 9d77715bd859976996087ca266cf37b0 0000000000 0000000001
leaf-1 = 9d77715bd859976996087ca266cf37b0 0000000000 00000000000000000000000000000000 0000000000 0000000000
root = 04d419113c03c7b976eea6b1e9334f91d529faa05a89355e64b8439d6b96f9cc
```

### Lookup witness examples

`coin-lookup-absence` is the absence witness for the tag of number 2 against
the two-leaf index: its low leaf is the entry of number 1, the largest, so its
`nextTag` is zero. The script accepts it as "absent" for that tag and gives no
answer for `reject-equal` (the low leaf's own tag) or `reject-below` (a tag
below it). `coin-lookup-first-entry` is the lookup witness for the tag of
number 0 against the copied-tag index: it answers with position 0, the
original, not the copy. `coin-lookup-membership` is the membership witness of
the copy at position 2; its `nextTag` is not the same tag, so no third leaf
carries it.

```text
[coin-lookup-absence]
kind = lookup-witness
tree = coin
set = coin-lookup-two-leaves
root = 489542787d7482d68a5bbd92c21f8225be3b0420bf06f1232c01af1f9f4c4451
tag = b3e8df15fdd3d0f3ac8c7562c50ba57e
low-position = 2
low-leaf = 98f00763f51d9e982a7814297473729f 0000000001 00000000000000000000000000000000 0000000000 0000000000
witness = 98f00763f51d9e982a7814297473729f000000000100000000000000000000000000000000000000000000000000000000000002e050b25c8ab09717b0a6846b688b5047b93c0d37e18599cc7deec37f914bcca45ed47d0a6b4ea73fe42ec422c53ea5feca683dadb97cca79670ff66034efb5bb428d8a99174610ecde2b557298e4f11f1be3a4e8c9e044b7344cbf887b03fae511895d5e152e7e726b8a981bfac5553b7961f828c8b0769d93cfed2b1569560c5d4744935b927c9326f3f0c150e6f82abce2dc6859a5513e1ee9fc2d57a539e9ea373e6700a4f82ff20f05923f02d2d9a75652b2b4b84189c3b20a847970976eb095a7ac6911792ebd21e086f4cbc0715a1203e0de606a299f047ad9942b00c4b2b8a834c52590ba0a6b5a235463055523e507ad0f466d0c298bb1ec2edfc4ae5ce9e115dd2e93d6950af5be90adc53ff3254eb86efb0321ed2e3db4765ee645cf405852c390193d38e3344af6fd0f52cc426972e17404bfb487cb3153665d26a6c4cc57c8c0f7a2bd16f05ef0d8a9f7dafc3a5893b5d14f51db262a71c67464363ee61f5319d915807383ae1082376337f3ed2fad3b30778d3651a289e93e45a367a24666cdc2c799b84b343e294a3ee406500f1af35bc9c75949ee96358c8f2009ece35f1d5f97d7bc48989c61bcbfac0fd31faed2fcb7f163c4195cef171a3210cfed4b00fa1565328b3d6beff79a877115cb4b51d497472551f52089704e56d977ae04d7b609d3f942232e353880a60526189150ea28c15179060b50d3dfa0a670926d5409ff2baee65f35f29176b3e449e2139a48ef2428218e93dd1d3d546a706ea4252b199339b31d7e259e4efeb2fb102d948a73e8c1ba6b802626731f43b08ac080fbf6cedb3a32485296ef398ff13d8edf9796372b30458ce6409d5a1aa568c4d2a133b45eb85cbbf7b6f2f26f61901364f0aeb66a58aff4213453d9c9bf5f6de0247fa608c37d3cd1a6bfa08bdc0c9ce1c574fb8f56649a6c77a50368f17f3ff9e4b7b69e0b4e79623f8c70bac3088a2a17f19fcd932a7f61bc491980aa5c90bd9faab2044d58e002481db5b3ba3dcd14cd80319b17d697c79512197c5f3e7ed37233929de277213a76a38a958427b94abcb65630a2b17e45f0c93121378420c00b94a7858650fb875f8f1db1890f9c890ecf8d22ac1e7bbb1eea77ca607e6a15dcc2dc1779f20acca12c071dd3f8b76265ae3609be7e82bc6de065cf55c78a65a4de1a37e661465d7c58b5e8e2a49dc317e82a1c3c47d52240bee785dc24fa2d21629a0c3031db7556b4ca1f9d406d79b9cdc6941c2123caf2cd8f04059f914b6b40757b635333116527ff1e8d58443f005065707140d92d46dd9a337899179aac597ee38e583ca989c9c737b20533de354b98e2297591eb70e824245b91e31d20d05b7ef583368f40f49902e555b87b95b0e08800462fdff29a288485e9d2526ef527a1e56b91fce754fc69d05e9896fb3ebc32dce0ceeeeaf071f5bd5f14415f1d690d7d7d183b5615548fe9c09431f7bb7edb0da5aaf9a30afcf356f59daa3c92b30f01676906ed13d85f48b1dd44d8e898b1d23ae287ff9df6971399ad8cb6685355f2ee410bb37b4ba87251679d1fe5a18f923b5e4d05fcd285b77585eff225f0421e06818262b1131f24ef1683e76f5cbf3004a34915f533630b68fee85c02d5b9e19a603a58851c78a8ff0bdb05ea8f8dc7d84de2e4d5595f91136e75b515e743886957a7745932da92209097fab68800e6c97f337eb4a34704909aa5bf80dac98372c04de297250e02df8087aca893fd878ede413f4f0be64a3ae94364c325dae725b95b921791b492c39ab8ea37eecadfb1f47a6840
outcome = absent
reject-equal = 98f00763f51d9e982a7814297473729f
reject-below = 98f00763f51d9e982a7814297473729e

[coin-lookup-first-entry]
kind = lookup-witness
tree = coin
set = coin-lookup-copied-tag
root = 2f880d0d3c8d149461815119475cc2c32bb5932ff3fa98a7dd771cdd2a18957e
tag = 74c5d993f5f018e3174926b2c8e8fb68
low-position = 0
low-leaf = 00000000000000000000000000000000 0000000000 74c5d993f5f018e3174926b2c8e8fb68 0000000000 0000000001
witness = 00000000000000000000000000000000000000000074c5d993f5f018e3174926b2c8e8fb68000000000000000000010000000000b5c781588b658babf151dbdeec8c29874c45f51e521c9605fa6f6a2b61a8bb684d833df486f489bbe0af605a689b5c66e28ccc5973c0ce7ad50d8a1318055dea428d8a99174610ecde2b557298e4f11f1be3a4e8c9e044b7344cbf887b03fae511895d5e152e7e726b8a981bfac5553b7961f828c8b0769d93cfed2b1569560c5d4744935b927c9326f3f0c150e6f82abce2dc6859a5513e1ee9fc2d57a539e9ea373e6700a4f82ff20f05923f02d2d9a75652b2b4b84189c3b20a847970976eb095a7ac6911792ebd21e086f4cbc0715a1203e0de606a299f047ad9942b00c4b2b8a834c52590ba0a6b5a235463055523e507ad0f466d0c298bb1ec2edfc4ae5ce9e115dd2e93d6950af5be90adc53ff3254eb86efb0321ed2e3db4765ee645cf405852c390193d38e3344af6fd0f52cc426972e17404bfb487cb3153665d26a6c4cc57c8c0f7a2bd16f05ef0d8a9f7dafc3a5893b5d14f51db262a71c67464363ee61f5319d915807383ae1082376337f3ed2fad3b30778d3651a289e93e45a367a24666cdc2c799b84b343e294a3ee406500f1af35bc9c75949ee96358c8f2009ece35f1d5f97d7bc48989c61bcbfac0fd31faed2fcb7f163c4195cef171a3210cfed4b00fa1565328b3d6beff79a877115cb4b51d497472551f52089704e56d977ae04d7b609d3f942232e353880a60526189150ea28c15179060b50d3dfa0a670926d5409ff2baee65f35f29176b3e449e2139a48ef2428218e93dd1d3d546a706ea4252b199339b31d7e259e4efeb2fb102d948a73e8c1ba6b802626731f43b08ac080fbf6cedb3a32485296ef398ff13d8edf9796372b30458ce6409d5a1aa568c4d2a133b45eb85cbbf7b6f2f26f61901364f0aeb66a58aff4213453d9c9bf5f6de0247fa608c37d3cd1a6bfa08bdc0c9ce1c574fb8f56649a6c77a50368f17f3ff9e4b7b69e0b4e79623f8c70bac3088a2a17f19fcd932a7f61bc491980aa5c90bd9faab2044d58e002481db5b3ba3dcd14cd80319b17d697c79512197c5f3e7ed37233929de277213a76a38a958427b94abcb65630a2b17e45f0c93121378420c00b94a7858650fb875f8f1db1890f9c890ecf8d22ac1e7bbb1eea77ca607e6a15dcc2dc1779f20acca12c071dd3f8b76265ae3609be7e82bc6de065cf55c78a65a4de1a37e661465d7c58b5e8e2a49dc317e82a1c3c47d52240bee785dc24fa2d21629a0c3031db7556b4ca1f9d406d79b9cdc6941c2123caf2cd8f04059f914b6b40757b635333116527ff1e8d58443f005065707140d92d46dd9a337899179aac597ee38e583ca989c9c737b20533de354b98e2297591eb70e824245b91e31d20d05b7ef583368f40f49902e555b87b95b0e08800462fdff29a288485e9d2526ef527a1e56b91fce754fc69d05e9896fb3ebc32dce0ceeeeaf071f5bd5f14415f1d690d7d7d183b5615548fe9c09431f7bb7edb0da5aaf9a30afcf356f59daa3c92b30f01676906ed13d85f48b1dd44d8e898b1d23ae287ff9df6971399ad8cb6685355f2ee410bb37b4ba87251679d1fe5a18f923b5e4d05fcd285b77585eff225f0421e06818262b1131f24ef1683e76f5cbf3004a34915f533630b68fee85c02d5b9e19a603a58851c78a8ff0bdb05ea8f8dc7d84de2e4d5595f91136e75b515e743886957a7745932da92209097fab68800e6c97f337eb4a34704909aa5bf80dac98372c04de297250e02df8087aca893fd878ede413f4f0be64a3ae94364c325dae725b95b921791b492c39ab8ea37eecadfb1f47a6840
outcome = first
position = 0

[coin-lookup-membership]
kind = lookup-membership
tree = coin
set = coin-lookup-copied-tag
root = 2f880d0d3c8d149461815119475cc2c32bb5932ff3fa98a7dd771cdd2a18957e
tag = 74c5d993f5f018e3174926b2c8e8fb68
position = 2
leaf-position = 3
leaf = 74c5d993f5f018e3174926b2c8e8fb68 0000000002 98f00763f51d9e982a7814297473729f 0000000001 0000000002
witness = 74c5d993f5f018e3174926b2c8e8fb68000000000298f00763f51d9e982a7814297473729f0000000001000000000200000000039372941be88e4dcec10afb1f0c3f7a27a5aba1d9c11066021731ec18a30dfe88260d969e2292a99f7a7e41ad92caa2caf82d9fd74aa440649bf670f61859761b428d8a99174610ecde2b557298e4f11f1be3a4e8c9e044b7344cbf887b03fae511895d5e152e7e726b8a981bfac5553b7961f828c8b0769d93cfed2b1569560c5d4744935b927c9326f3f0c150e6f82abce2dc6859a5513e1ee9fc2d57a539e9ea373e6700a4f82ff20f05923f02d2d9a75652b2b4b84189c3b20a847970976eb095a7ac6911792ebd21e086f4cbc0715a1203e0de606a299f047ad9942b00c4b2b8a834c52590ba0a6b5a235463055523e507ad0f466d0c298bb1ec2edfc4ae5ce9e115dd2e93d6950af5be90adc53ff3254eb86efb0321ed2e3db4765ee645cf405852c390193d38e3344af6fd0f52cc426972e17404bfb487cb3153665d26a6c4cc57c8c0f7a2bd16f05ef0d8a9f7dafc3a5893b5d14f51db262a71c67464363ee61f5319d915807383ae1082376337f3ed2fad3b30778d3651a289e93e45a367a24666cdc2c799b84b343e294a3ee406500f1af35bc9c75949ee96358c8f2009ece35f1d5f97d7bc48989c61bcbfac0fd31faed2fcb7f163c4195cef171a3210cfed4b00fa1565328b3d6beff79a877115cb4b51d497472551f52089704e56d977ae04d7b609d3f942232e353880a60526189150ea28c15179060b50d3dfa0a670926d5409ff2baee65f35f29176b3e449e2139a48ef2428218e93dd1d3d546a706ea4252b199339b31d7e259e4efeb2fb102d948a73e8c1ba6b802626731f43b08ac080fbf6cedb3a32485296ef398ff13d8edf9796372b30458ce6409d5a1aa568c4d2a133b45eb85cbbf7b6f2f26f61901364f0aeb66a58aff4213453d9c9bf5f6de0247fa608c37d3cd1a6bfa08bdc0c9ce1c574fb8f56649a6c77a50368f17f3ff9e4b7b69e0b4e79623f8c70bac3088a2a17f19fcd932a7f61bc491980aa5c90bd9faab2044d58e002481db5b3ba3dcd14cd80319b17d697c79512197c5f3e7ed37233929de277213a76a38a958427b94abcb65630a2b17e45f0c93121378420c00b94a7858650fb875f8f1db1890f9c890ecf8d22ac1e7bbb1eea77ca607e6a15dcc2dc1779f20acca12c071dd3f8b76265ae3609be7e82bc6de065cf55c78a65a4de1a37e661465d7c58b5e8e2a49dc317e82a1c3c47d52240bee785dc24fa2d21629a0c3031db7556b4ca1f9d406d79b9cdc6941c2123caf2cd8f04059f914b6b40757b635333116527ff1e8d58443f005065707140d92d46dd9a337899179aac597ee38e583ca989c9c737b20533de354b98e2297591eb70e824245b91e31d20d05b7ef583368f40f49902e555b87b95b0e08800462fdff29a288485e9d2526ef527a1e56b91fce754fc69d05e9896fb3ebc32dce0ceeeeaf071f5bd5f14415f1d690d7d7d183b5615548fe9c09431f7bb7edb0da5aaf9a30afcf356f59daa3c92b30f01676906ed13d85f48b1dd44d8e898b1d23ae287ff9df6971399ad8cb6685355f2ee410bb37b4ba87251679d1fe5a18f923b5e4d05fcd285b77585eff225f0421e06818262b1131f24ef1683e76f5cbf3004a34915f533630b68fee85c02d5b9e19a603a58851c78a8ff0bdb05ea8f8dc7d84de2e4d5595f91136e75b515e743886957a7745932da92209097fab68800e6c97f337eb4a34704909aa5bf80dac98372c04de297250e02df8087aca893fd878ede413f4f0be64a3ae94364c325dae725b95b921791b492c39ab8ea37eecadfb1f47a6840
```

### Coin marker-set examples

The markers are those of spec 01's vectors `coin-commit-salted` (number 0)
and `coin-remainder-salted` (number 1). The reveal that spends number 0
appends its remainder at coin leaf 1, and the one that spends number 1 appends
at coin leaf 2. In `coin-marker-set-two-markers` the rewritten `leaf-1` keeps
its own `appended`, 1. The membership witness of number 0's marker leads to
coin leaf 1; the absence witness is for an example marker `8888...88` that no
coin commitment of spec 01 has, and the script rejects it for the spent
`reject-spent`.

```text
[coin-marker-set-empty]
kind = coin-marker-set
spends =
count = 1
leaf-0 = 0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000 0000000000 ffffffffff
root = 84e7c602ab3870f46bf300eff5581ae88029f7c58afb3758a652e0129e9e85cc

[coin-marker-set-one-marker]
kind = coin-marker-set
spends = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78@1
count = 2
leaf-0 = 0000000000000000000000000000000000000000000000000000000000000000 d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78 0000000001 ffffffffff
leaf-1 = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78 0000000000000000000000000000000000000000000000000000000000000000 0000000000 0000000001
root = d2d2d35cf33c017a3bbe0d7867ce1f62948514d1294354c2a11795f046960df8

[coin-marker-set-two-markers]
kind = coin-marker-set
spends = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78@1 f7476caa827fa1478d8f2a561e2638a7d4817793176eaced88798bf7d28fa806@2
count = 3
leaf-0 = 0000000000000000000000000000000000000000000000000000000000000000 d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78 0000000001 ffffffffff
leaf-1 = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78 f7476caa827fa1478d8f2a561e2638a7d4817793176eaced88798bf7d28fa806 0000000002 0000000001
leaf-2 = f7476caa827fa1478d8f2a561e2638a7d4817793176eaced88798bf7d28fa806 0000000000000000000000000000000000000000000000000000000000000000 0000000000 0000000002
root = f073fe2b59b6fd3d2827569ccd5d8652f56aae3547109fb34030749ed6877fb3

[coin-marker-set-membership]
kind = coin-marker-set-membership
set = coin-marker-set-two-markers
root = f073fe2b59b6fd3d2827569ccd5d8652f56aae3547109fb34030749ed6877fb3
marker = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78
leaf-position = 1
leaf = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78 f7476caa827fa1478d8f2a561e2638a7d4817793176eaced88798bf7d28fa806 0000000002 0000000001
witness = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78f7476caa827fa1478d8f2a561e2638a7d4817793176eaced88798bf7d28fa8060000000002000000000100000000013eeaa536e9199f3168d5ef938c1185aefc3b59a695e735a456d38904f7df594ef7d8cd6be91af09bb109dc6cdda2d096919891cd12fd48865a09c3732d159448aa4b0696d0f6d262620471d23ebae1c10caddb8e4ed750d8806f428994ed4ebd012e57d1bb7b8deba720933c3dd35af261ca6a492825b1cca060e77272dedc8d3fb433528fda3950f7540b083bbab1fac69731d74c01e4871e87315b690dc582b738d317abf5383b00df5984c587c8090e423a75f017a60557d1ef76dcba48eecc67c4ce823d8ed577b2963f9a6076dd8b4a21cc629101ec1786fd5efbfb9920feeec66b44b51ce4734c65d3f5de22e6eb93b2523b33dd18e109db1c49dc2e62475e4c6b1c51bcfc8a1b8a363d6895c8bb282dc83d3afb7d6e412e78ac7b015765b41fff7373cc5d5ec51f0f2637fdee020af0976d80d8434ffd7b51662067fb6bba8b13fd714631fbe792c9715b0e43e9aec37efaf6e59b9e0aedd57e2baebc07f03fb4d7687c79e4e2469a0d053de7e9b875cbaa0e14e4e30213cfca434a438ef02ea92eb3e7b80c360a8b5a4e5e19755f09a7923af02c357438aff9158856e93ada6f4832a7a34fd078e327ea95cf0b94589e0ef41c4d66592012cd7ce9a915f76d382aeb416b5254419f63b86f0be2c9151cd59ff3f3e30f4628c53a3cccea5f3f582de906f458b7ec9f0b1d3c7186046663f124592d9153a986bcff82be7309fc633b16bca6e6b36b55f8ec119fb537808930a1ca52e0dd94a4437c5e954c65527e204be0744ca6287d89d335715c73e60ac4a69dd4060aeb6a36c780491c7dc92297b4ff0549f471b4d227897197b9ba3188b0afecc879b81d39c5406968293d461cfc6ee5823afdafb751e62cc04f2d07dfa469f0b997ad6929d7f50a8f7e84efe6f554e80eb44ab5b2846177836a496523242eab8db456e0e95de0ae870a2d7f1b02d7f5c0e39486555d7f31b913a739232bfc73f9100245d051484264a3c227005c914648944ab46052b917a236b988f1a5e854ce287b2fa8e0dd656438a213911b4bf251f363bcab474bfe443aab41cf1d6d683864742035eec13bb53f7075605ac7236e9909638dfda90a9867c662682f6bae239034b12fb2dc3d6f431cbeee64ac68a0226ffd116b14a3b9941b91413ffe2584c77daa515b02ea6dfffb3770c47d2624c4926f297acd8a87381ecf3961bad1da77d491589abe1c62d316a0f9d36b0858e246c149938accdefb4fceeda90b9b7b4ba03f9d9c3d6a67ee33536b536e36824a46e73f04a144d35252eb81290b1514f9d0ec9ff71d639e35ac9561c803cdb82bf5bdd97b9a22a7909d3ffa28d4baeaf30d81f02862f0540a5283d76e91b29e07e2e725bd41c144fdfa942216cee574140faf260bf21718c9662a3d6faa44c1f5d7a54caa7095624c95cf65544585152bb9231454420640e80f1dc280ee4c3951bee037f8c1b4522abe7a61b2cd33ea870d935367fe90d739aaa14b91c4961eefb40359b8b018f8b82584ad2d5b99b3371cb07259d7ea602240446fdac323e7249e75311b0acad9d5d2221c1cf490b7b65d4e84f002cbc0494aa709dd148c14afaede5c7ff214e605b8abbcc1a2c848c453c5152e2bbc5c4e3150c52121859166eb97004ee08722e5cca97002d85f4b8db127cede9486e4e9e11e635af05eb0226ac901d3c058a9c4bd7d416dd6960739384fd75be28d92c52a2e46540fdc7036e740afa942b407a47de4199b5396613cbd3d66af6b34ffce5ca5cc9af628ef3036dc07dd2fbed179b6ccc4a93164d1c4f4e42145ac29
appended = 1

[coin-marker-set-absence]
kind = coin-marker-set-absence
set = coin-marker-set-two-markers
root = f073fe2b59b6fd3d2827569ccd5d8652f56aae3547109fb34030749ed6877fb3
marker = 8888888888888888888888888888888888888888888888888888888888888888
low-position = 0
low-leaf = 0000000000000000000000000000000000000000000000000000000000000000 d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78 0000000001 ffffffffff
witness = 0000000000000000000000000000000000000000000000000000000000000000d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf780000000001ffffffffff000000000060da17a0a464ff17421186e8fb75b43468ff5d98e375fdef2dfe6e8f1026e2daf7d8cd6be91af09bb109dc6cdda2d096919891cd12fd48865a09c3732d159448aa4b0696d0f6d262620471d23ebae1c10caddb8e4ed750d8806f428994ed4ebd012e57d1bb7b8deba720933c3dd35af261ca6a492825b1cca060e77272dedc8d3fb433528fda3950f7540b083bbab1fac69731d74c01e4871e87315b690dc582b738d317abf5383b00df5984c587c8090e423a75f017a60557d1ef76dcba48eecc67c4ce823d8ed577b2963f9a6076dd8b4a21cc629101ec1786fd5efbfb9920feeec66b44b51ce4734c65d3f5de22e6eb93b2523b33dd18e109db1c49dc2e62475e4c6b1c51bcfc8a1b8a363d6895c8bb282dc83d3afb7d6e412e78ac7b015765b41fff7373cc5d5ec51f0f2637fdee020af0976d80d8434ffd7b51662067fb6bba8b13fd714631fbe792c9715b0e43e9aec37efaf6e59b9e0aedd57e2baebc07f03fb4d7687c79e4e2469a0d053de7e9b875cbaa0e14e4e30213cfca434a438ef02ea92eb3e7b80c360a8b5a4e5e19755f09a7923af02c357438aff9158856e93ada6f4832a7a34fd078e327ea95cf0b94589e0ef41c4d66592012cd7ce9a915f76d382aeb416b5254419f63b86f0be2c9151cd59ff3f3e30f4628c53a3cccea5f3f582de906f458b7ec9f0b1d3c7186046663f124592d9153a986bcff82be7309fc633b16bca6e6b36b55f8ec119fb537808930a1ca52e0dd94a4437c5e954c65527e204be0744ca6287d89d335715c73e60ac4a69dd4060aeb6a36c780491c7dc92297b4ff0549f471b4d227897197b9ba3188b0afecc879b81d39c5406968293d461cfc6ee5823afdafb751e62cc04f2d07dfa469f0b997ad6929d7f50a8f7e84efe6f554e80eb44ab5b2846177836a496523242eab8db456e0e95de0ae870a2d7f1b02d7f5c0e39486555d7f31b913a739232bfc73f9100245d051484264a3c227005c914648944ab46052b917a236b988f1a5e854ce287b2fa8e0dd656438a213911b4bf251f363bcab474bfe443aab41cf1d6d683864742035eec13bb53f7075605ac7236e9909638dfda90a9867c662682f6bae239034b12fb2dc3d6f431cbeee64ac68a0226ffd116b14a3b9941b91413ffe2584c77daa515b02ea6dfffb3770c47d2624c4926f297acd8a87381ecf3961bad1da77d491589abe1c62d316a0f9d36b0858e246c149938accdefb4fceeda90b9b7b4ba03f9d9c3d6a67ee33536b536e36824a46e73f04a144d35252eb81290b1514f9d0ec9ff71d639e35ac9561c803cdb82bf5bdd97b9a22a7909d3ffa28d4baeaf30d81f02862f0540a5283d76e91b29e07e2e725bd41c144fdfa942216cee574140faf260bf21718c9662a3d6faa44c1f5d7a54caa7095624c95cf65544585152bb9231454420640e80f1dc280ee4c3951bee037f8c1b4522abe7a61b2cd33ea870d935367fe90d739aaa14b91c4961eefb40359b8b018f8b82584ad2d5b99b3371cb07259d7ea602240446fdac323e7249e75311b0acad9d5d2221c1cf490b7b65d4e84f002cbc0494aa709dd148c14afaede5c7ff214e605b8abbcc1a2c848c453c5152e2bbc5c4e3150c52121859166eb97004ee08722e5cca97002d85f4b8db127cede9486e4e9e11e635af05eb0226ac901d3c058a9c4bd7d416dd6960739384fd75be28d92c52a2e46540fdc7036e740afa942b407a47de4199b5396613cbd3d66af6b34ffce5ca5cc9af628ef3036dc07dd2fbed179b6ccc4a93164d1c4f4e42145ac29
valid = yes
reject-spent = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78
```

### Block lookup digest examples

The genesis block's empty list, and the block after the commit of number 0
(coin leaf 0): it holds the reveal of number 0, whose remainder is coin leaf 1
with the tag of number 1, and the data commit of the data example key, data
leaf 0.

```text
[lookup-digest-empty]
kind = lookup-digest
coin-start = 0
coin-tags =
data-start = 0
data-tags =
coin-markers =
data-markers =
encoding = 0000000000000000000000000000000000000000000000000000
digest = 9217af84b49597c35c570275e095d6a0245cab03c6f0126ce995acaa5023cd7b

[lookup-digest-example]
kind = lookup-digest
coin-start = 1
coin-tags = 98f00763f51d9e982a7814297473729f
data-start = 0
data-tags = 9d77715bd859976996087ca266cf37b0
coin-markers = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78
data-markers =
encoding = 00000000010000000198f00763f51d9e982a7814297473729f0000000000000000019d77715bd859976996087ca266cf37b000000001d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf7800000000
digest = 91534b00a1395018530174d9b5512a570a8d78038cd7f9526926309196a7429e
```

### Genesis values and global positions

The genesis values of the four new fields: the empty lookup indices, the coin
marker set holding only its sentinel, and the digest of the empty list. Then
global positions at the edges of the trees, as 5 bytes: the last position of
tree 0, the first of tree 1 and the last usable one, in tree 255.

```text
[header-genesis-new-fields]
kind = genesis-fields
coinLookupRoot = 994a8bc5ba72f53f4449d4981c3ea8294d504b148afa58abec873819b143554b
dataLookupRoot = c0ad355e8462fbe6093fa0ac37c0afc450b36cbe679bb7de3050a9a1b2cddece
coinMarkerRoot = 84e7c602ab3870f46bf300eff5581ae88029f7c58afb3758a652e0129e9e85cc
lookupDigest = 9217af84b49597c35c570275e095d6a0245cab03c6f0126ce995acaa5023cd7b

[global-position-examples]
kind = global-position
tree-0-position-0 = 0000000000
tree-0-position-4294967295 = 00ffffffff
tree-1-position-0 = 0100000000
tree-255-position-4294967294 = fffffffffe
tree-255-position-4294967295 = rejected
none = ffffffffff
```

## What the build ticket writes into the specifications

The build ticket of the stage 2 design (its item 6, "Lookup tags, lookup index
and coin marker-set tree") writes these formats into the specifications with
golden vectors and extends their checkers. This record edits none of them.

- Spec 01: the lookup tag in section 7, the rows of "Tag table rows" in
  section 4, and its vectors.
- Spec 02: `remainder_tag` in the coin reveal binding, and the note on
  constraint 4 that a coin marker-set root now exists while coin proofs of
  holding stay rejected.
- Spec 03 and spec 04: the tag in the commit payload, the zero-tag rejection,
  and the inserts in the apply steps.
- Spec 05: the lookup indices and the coin marker-set tree in section 6, the
  four fields and 23 items in sections 1, 4 and 10, the global position and
  its limit in section 3, rollback in section 7, and the vectors of this
  record in section 11.
- Spec 07: `remainder_tag` in the payload, the payload size and the binding
  map.

## What would reverse this decision

- The PIR scheme, once chosen, needs records of another width than the 47-byte
  lookup leaf or the 74-byte coin marker-set leaf.
- A proof of holding for coins is accepted (spec 02, question 2) and its
  circuit cannot open the 104-byte coin marker-set leaf in one permutation.
- The lookup index needs more than 2^40 - 1 entries of a type within the
  chain's planned life, which would widen every position in this record.
- The stage 2 design's restore is replaced, or the founder declines its format
  changes.

## Reproduce

```sh
python3 scripts/check_decision_0004.py
python3 scripts/check_decision_0004.py --print
```

The first checks this record: its sections, every vector block above,
every witness accepted for what it shows and rejected for the listed values and
for any changed byte, the tag table, the header field table against spec 05's
current fields, and that the indexed-tree code gives spec 05's own marker-set
vectors byte for byte. The second prints the vector blocks. Both use Python's
standard library only, with their own Keccak-256 checked against known
digests and against `hashlib.sha3_256`.

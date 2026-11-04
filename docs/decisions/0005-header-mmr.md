# Decision 0005: the header MMR, its leaf, hash tags, work width, path layout and header field

Status: byte formats fixed for the build, 2026-11-04. The header MMR itself is
one of the format changes that the [stage 2 design](../scale/stage2-design.md)
lists for the founder ("Decisions for the founder"); this record fixes its bytes
so that they can be written into the specifications with golden vectors and
checked. Nothing here is built.

## Decision

The stage 2 design ("What changes on the chain") puts a Merkle mountain range
over all earlier headers and their cumulative work in every header, as FlyClient
does (Bünz, Kiffer, Luu and Zamani, IEEE S&P 2020), and gives it only as a
modeled size: 48 bytes a node, a 32-byte hash and 16 bytes of work.
[Decision 0004](0004-lookup-formats.md) fixed the other four header fields of
that design and left the MMR out, with no index. This record fixes the MMR byte
for byte:

| Item | Settled |
|---|---|
| Leaf | One leaf per block, in block order: `K("ghost/header-mmr-leaf/v1", keccak256(rlp(header)), D as 16 bytes)`, the hash of the whole header and its difficulty `D` as its work |
| Nodes | `K("ghost/header-mmr-node/v1", left hash, left work, right hash, right work)`; a node's work is the sum of its children's |
| Peaks and root | One perfect subtree per set bit of the leaf count `n`, highest first, bagged right to left under `ghost/header-mmr-bag/v1`; the root is `K("ghost/header-mmr-root/v1", n as 8 bytes, bag hash, bag work)` |
| Cumulative work | 16 bytes, big-endian, in every leaf, node, bag and root; a chain's total difficulty stays below 2^128, and a block that would reach it is invalid |
| Path | Only 48-byte entries: the siblings from the bottom, then the bag of the peaks to the right, then the peaks to the left, nearest first; its length is fixed by `n` and the index; at most floor(log2 n) + 1 entries; 23 entries, 1,104 bytes, from genesis at five years of chain |
| Header field | `headerMmrRoot`, field 23, right after decision 0004's `lookupDigest` (22): the root over blocks 0 to `N - 1` in the header of block `N`; 24 items |
| Header size | 780 bytes for spec 05's block one example with field 23, 809 for its genesis example; the design's modeled size is 38 bytes short |
| Reorganisation | The MMR follows the canonical chain: truncated to the common ancestor and extended along the new branch |

## Conventions

The conventions of [spec 01](../spec/01-commitments-and-keys.md), section 2,
apply: `K(tag, ...)` is tagged Keccak-256, `tagbytes(tag)` is one length byte
then the tag's ASCII bytes, `||` is concatenation, integers are unsigned and
big-endian at the stated width, and hex is lower case. In addition:

- **Header hash.** `keccak256(rlp(header))` of
  [spec 05](../spec/05-trees-and-headers.md), section 10: the hash of the whole
  header, its seal fields and its own `headerMmrRoot` included.
- **Work.** The work of a block is its `difficulty` field `D`
  ([spec 06](../spec/06-consensus-and-emission.md), section 4.5), and the
  total difficulty of a chain is the sum of `D` over its blocks, genesis
  included.
- **Entry.** A hash and its work, `hash (32) || work (16)`: 48 bytes. Every
  leaf, node, peak and bag is an entry, and a path is a list of entries.
- **MMR of `n` leaves.** Leaf `b` is the leaf of block `b`, for `b` from 0 to
  `n - 1`. A subtree of height `h` covers `2^h` consecutive leaves from a
  multiple of `2^h`; height 0 is one leaf.

## Leaf

For block `b` with header `H` and difficulty `D_b`:

```text
leaf_b = K("ghost/header-mmr-leaf/v1", keccak256(rlp(H)), D_b as 16 bytes)     work D_b
```

The tag is the 24 ASCII bytes `ghost/header-mmr-leaf/v1` with its length byte
`0x18`; the input is 73 bytes, one Keccak permutation. The header hash is
`keccak256(rlp(header))`, of the whole header, so the leaf binds the seal (`mixDigest` and `nonce`), `parentHash` and
every Ghost field: a wallet that holds a sampled header computes its leaf
itself and never takes a leaf from a server. The work is 16 bytes, the width of
section "Cumulative work"; a verifier takes it from the header's own
`difficulty` field.

The leaf carries no block number: its index in the MMR is the block number, the
root binds the leaf count, and a path fixes the index (section "Path from a
header to the tip"), so the verifier compares the index with the header's
`number` instead.

## Nodes, peaks and root

**Nodes.** An inner node over a left and a right entry is

```text
node = K("ghost/header-mmr-node/v1", left hash, left work, right hash, right work)     work = left work + right work
```

121 input bytes, one permutation. There is no level byte: the four tags keep
leaves, nodes, bags and roots apart, and the leaf count fixes every height.

**Peaks.** An MMR of `n` leaves has one perfect subtree, a peak, for each set
bit of `n`, ordered highest first: the first peak covers the oldest blocks.
For `n = 7` the peaks are leaves 0 to 3 (height 2), 4 and 5 (height 1) and 6
(height 0). Appending a leaf merges equal peaks, so the nodes of an MMR of `m`
leaves are exactly those of any longer one's first `m` leaves.

**Bag.** The peaks are bagged right to left: the bag starts as the last peak,
and each earlier peak `p`, from the last but one to the first, gives

```text
bag = K("ghost/header-mmr-bag/v1", p hash, p work, bag hash, bag work)     work = p work + bag work
```

120 input bytes, one permutation. With one peak the bag is that peak; with no
leaves it is the empty bag, 32 zero bytes with work 0. Bagging right to left
puts the peaks to the right of any leaf's peak under one entry, which keeps
every path within floor(log2 n) + 1 entries.

**Root.**

```text
headerMmrRoot = K("ghost/header-mmr-root/v1", n as 8 bytes, bag hash, bag work)
```

81 input bytes, one permutation. The leaf count binds the shape: one count
gives one set of peaks and one valid length for every path. The root of the
empty MMR, `n = 0`, is the genesis value of `headerMmrRoot` (vector
`header-mmr-empty`). The bag's work is the total difficulty of blocks 0 to
`n - 1`.

## Cumulative work

**Width.** Every work value, in a leaf, a node, a bag, a path entry and the
root, is 16 bytes, big-endian: the 16 bytes of work of the stage 2 design's
modeled node. A node's work is computed by whoever folds, from its children; it
is never taken from a message.

**Why 16 bytes are enough.** The base client refuses a `difficulty` longer than
80 bits (spec 05, section 10), and finding a seal at that difficulty takes
about 2^80 hashes. At that cap a total of 2^128 needs 2^48 blocks, about 267
million years of 30-second blocks. The five-year example chain of this record
has a total of 88,181,114,404,864, below 2^47.

**The rule.** A block whose chain's total difficulty, its own `D` included,
would reach 2^128 is invalid, with the reason `work-overflow`. No valid chain
then has a work value that does not fit, and the node's fork choice (heaviest
total difficulty, spec 06), which keeps its own wider integer, always agrees
with the work the MMR commits to. A verifier rejects any path whose fold would
reach 2^128 (fail closed). The total difficulty up to the tip `N` is the root's
work plus `D_N`.

**Work before a header.** A path gives the summed work of every block before
the sampled one: the work of each sibling that sits to its left and of each
peak to the left. A sampler that draws a point `x` of the chain's cumulative
work checks that the header it was sent is the one at `x`:
`work before <= x < work before + D`. The paths of the worked examples state
their work before and the total work.

## Path from a header to the tip

The tip is the header `T` of block `N` that the wallet checks against; its
`headerMmrRoot` is the root over blocks 0 to `N - 1`, so `n = N`. For a header
`H` of block `i < N`, let its leaf sit in peak number `j` (counting from 0,
highest first) of height `h`. Its path is

```text
siblings at heights 0 to h - 1, from the bottom (48 bytes each)
|| the bag of the peaks after peak j, if j is not the last peak (48 bytes)
|| the peaks before peak j, nearest first (48 bytes each)
```

that is `h + j` entries, plus one if `j` is not the last peak, 48 bytes each,
with no count, index or length prefix: `n` comes from `T`'s `number`, `i` from
`H`'s, and both give the length. To check it, a verifier:

1. takes `n` from the tip and `i` from the header, and rejects unless
   `0 <= i < n`;
2. rejects a path of any other length than the one `n` and `i` give;
3. folds the leaf of `H` with the siblings along the bits of `i`'s position in
   its peak (a set bit puts the sibling on the left, and adds its work to the
   work before), then bags the result with the bag after it, if any, then bags
   each earlier peak onto it (adding its work to the work before);
4. hashes the root with `n` and accepts only if it equals `T`'s
   `headerMmrRoot` and no work reached 2^128.

It answers with the work before `H` and the total work. Peak heights fall
strictly from left to right, so `h <= floor(log2 n) - j` and a path has at most
floor(log2 n) + 1 entries. At five years of 30-second blocks, `n` is
5,256,000, with peaks of heights 22, 20, 13, 12, 9, 8 and 6, and the longest
path, from any of the first 4,194,304 blocks, has 23 entries: 1,104 bytes
(vector `header-mmr-path-five-years-genesis`). That is the stage 2 design's
modeled path, log2 of the chain rounded up times 48 bytes, at one year (21
entries, 1,008 bytes) and at five.

The tip itself needs no path, and the last 64 headers are checked header by
header through `parentHash`. The key block of a sampled header
([spec 08](../spec/08-randomx-seal.md), section 8) is proven the same way, with
its own path at its own number, in place of a walk over parent hashes. Two
paths to one tip share their upper entries; a transport may send a shared entry
once, but what a verifier folds is these bytes.

## Header field

The header of spec 05, section 10 gets one new field after decision 0004's
last field, `lookupDigest` (22):

| Index | Field | Encoding | Source |
|---|---|---|---|
| 23 | `headerMmrRoot` | 32 bytes | Ghost |

- `headerMmrRoot` of block `N` is the root of the MMR over blocks 0 to `N - 1`
  of its own chain. The genesis value is the empty root (vector
  `header-mmr-empty`); block one carries the root over the genesis leaf alone
  (vector `header-mmr-one-leaf`).
- A block whose value differs from the root the node computes is invalid. The
  value depends only on earlier headers, so a node or a header-only client
  checks it with the header, as it checks `parentHash`, before any body is
  executed.

A header is then exactly 24 items. Fields 0 to 22 stay as spec 05 and
decision 0004 have them, the 23 items of decision 0004 untouched, and field 23
is the next index, so nothing moves. A decoder rejects a 23-item header, from
before this record, as `item-count`, as it rejects any other count. The field is
a 32-byte RLP string, 33 bytes encoded, so the header grows by 33 bytes.

## Header size

The encoded size of a header depends on its integers and its `extraData`, so
this record settles it on spec 05's example headers, every size computed from
their RLP:

| Key | Header | Bytes |
|---|---|---|
| `block-one-18` | Spec 05's `header-eighteen-items`: block one with fields 0 to 17 | 582 |
| `block-one-19` | Spec 05's `header-nineteen-items`: with `dataMarkerRoot` | 615 |
| `block-one-23` | Spec 05's `header-block-one-example`: the 23 items of decision 0004 | 747 |
| `block-one-24` | `header-block-one-with-mmr`: with `headerMmrRoot` | 780 |
| `genesis-23` | Spec 05's `header-genesis-example` | 776 |
| `genesis-24` | `header-genesis-with-mmr`: with `headerMmrRoot` | 809 |

So a Ghost header with every field of the stage 2 design is 780 bytes for the
block one example, whose `extraData` is empty, and 809 bytes for the genesis
example, whose `extraData` holds 32 bytes.

The stage 2 design models the header as 582 plus five 32-byte fields. Its five
fields are decision 0004's four (`coinLookupRoot`, `dataLookupRoot`,
`coinMarkerRoot`, `lookupDigest`) and `headerMmrRoot`, so the design and
decision 0004 agree on the fields: 23 items with the four, 24 with the MMR
root. The modeled size is 38 bytes short, for two reasons. Its 582 bytes are the
18-item header, which lacks `dataMarkerRoot`, 33 bytes encoded; and it counts
each new field at 32 bytes where RLP encodes a 32-byte string in 33 bytes, 5
bytes over five fields. 582 + 33 + 5 x 33 = 780. The design's header proof
grows by 38 bytes a header it carries, 749 headers at one year and 941 at five
(64 tail headers, the samples and the key blocks), about 0.03 MB and 0.04 MB on
its 1.2 MB and 1.7 MB (modeled), and turns no ceiling.

## Reorganisation

The MMR is a function of the chain: every header's root is computed from its
own branch. On a reorganisation to common ancestor `A`, a node truncates its
MMR to the `A + 1` leaves of blocks 0 to `A`, which drops the nodes after them
and leaves every node of the prefix as it was (section "Nodes, peaks and
root"), then appends the headers of the new branch. Every `headerMmrRoot` of the
new branch then equals that of a node that never saw the disconnected blocks,
and a branch header whose field does not match is invalid like any other.

A wallet takes a root only from a tip on its own checked chain. A path checked
against a tip that is no longer canonical is discarded with the tip, and the
check runs again against the new one (stage 2 design, "Spent status follows the
canonical chain"). A full node keeps the `2n - 1` entries of the MMR, 48 bytes
each, the design's modeled 96 bytes a block.

## Specification 08 is not touched

[Spec 08](../spec/08-randomx-seal.md) fixes the RandomX seal. Its seal hash is
Keccak-256 of the RLP of the header with `mixDigest` and `nonce` set to zero,
so it already covers field 23 as it covers every other field, and the RandomX
input does not change. The new field is defined where the header encoding is,
in spec 05, section 10, and that is where the build ticket writes it.

## Tag table rows

The rows the build ticket adds to the tag table of spec 01, section 4, with the
same columns. Input bytes count the length byte and the tag.

| Tag | Hash | Use | Inputs after the tag | Input bytes | Keccak permutations |
|---|---|---|---|---|---|
| `ghost/header-mmr-leaf/v1` | Keccak-256 | Leaf of the header MMR, one per block | header hash, difficulty as 16 bytes | 73 | 1 |
| `ghost/header-mmr-node/v1` | Keccak-256 | Inner node of the header MMR | left hash, left work, right hash, right work | 121 | 1 per level |
| `ghost/header-mmr-bag/v1` | Keccak-256 | One step of bagging the peaks, right to left | peak hash, peak work, bag hash, bag work | 120 | 1 |
| `ghost/header-mmr-root/v1` | Keccak-256 | Root of the header MMR, header field `headerMmrRoot` | leaf count as 8 bytes, bag hash, bag work | 81 | 1 |

## Worked examples

Every block below is the output of `python3 scripts/check_decision_0005.py
--print`, copied unchanged; the same script checks that this record still
matches it. Each starts with `[name]`; each line is `field = value`; byte values
are hex, counts and work totals decimal. An entry is written as its hash and
its 16 bytes of work, separated by a space; a leaf line gives the header it
stands for, its header hash, its work and its leaf hash.

### The empty MMR, the example headers and the header leaf

The empty MMR, the genesis value of `headerMmrRoot`. Then spec 05's genesis
example with field 23 set to it, 24 items; the leaf of that header; the MMR of
that one leaf, whose root is block one's `headerMmrRoot`; and spec 05's block
one example with that root as field 23 and the new genesis hash as its
`parentHash`. `base` names the spec 05 vector whose other fields are kept.

```text
[header-mmr-empty]
kind = header-mmr
n = 0
bag = 0000000000000000000000000000000000000000000000000000000000000000 00000000000000000000000000000000
root = b1f684aabd11aa3966ac25d6ac9c50e10cc53cbfb48957f3f514fb4b08fd23ac
total-work = 0

[header-genesis-with-mmr]
kind = header-with-mmr
base = header-genesis-example
headerMmrRoot = b1f684aabd11aa3966ac25d6ac9c50e10cc53cbfb48957f3f514fb4b08fd23ac
items = 24
bytes = 809
rlp = f90326a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000808401c9c38080846b3703f0a0000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fa00000000000000000000000000000000000000000000000000000000000000000880000000000000000843b9aca00a08e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8a03d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03a00ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3a0994a8bc5ba72f53f4449d4981c3ea8294d504b148afa58abec873819b143554ba0c0ad355e8462fbe6093fa0ac37c0afc450b36cbe679bb7de3050a9a1b2cddecea084e7c602ab3870f46bf300eff5581ae88029f7c58afb3758a652e0129e9e85cca09217af84b49597c35c570275e095d6a0245cab03c6f0126ce995acaa5023cd7ba0b1f684aabd11aa3966ac25d6ac9c50e10cc53cbfb48957f3f514fb4b08fd23ac
hash = 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65

[header-mmr-leaf-genesis]
kind = header-mmr-leaf
header = header-genesis-with-mmr
header-hash = 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65
difficulty = 16777216
work = 00000000000000000000000001000000
input = 1867686f73742f6865616465722d6d6d722d6c6561662f763131ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b6500000000000000000000000001000000
leaf = cfd870edbca7cee35cb8b110c3f971397b5ca834f8a40ba4b42b943c0bd5fa0a

[header-mmr-one-leaf]
kind = header-mmr
n = 1
leaf-0 = header-genesis-with-mmr 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65 00000000000000000000000001000000 cfd870edbca7cee35cb8b110c3f971397b5ca834f8a40ba4b42b943c0bd5fa0a
peak-0-0 = cfd870edbca7cee35cb8b110c3f971397b5ca834f8a40ba4b42b943c0bd5fa0a 00000000000000000000000001000000
bag = cfd870edbca7cee35cb8b110c3f971397b5ca834f8a40ba4b42b943c0bd5fa0a 00000000000000000000000001000000
root = f350a609073159867968bed20feef366627cadfa06e7e16149b9116b3b40d8ac
total-work = 16777216

[header-block-one-with-mmr]
kind = header-with-mmr
base = header-block-one-example
parentHash = 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65
headerMmrRoot = f350a609073159867968bed20feef366627cadfa06e7e16149b9116b3b40d8ac
items = 24
bytes = 780
rlp = f90309a031ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000018401c9c3808301ec30846b37040e80a0444444444444444444444444444444444444444444444444444444444444444488010203040506070884342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4fa0489542787d7482d68a5bbd92c21f8225be3b0420bf06f1232c01af1f9f4c4451a004d419113c03c7b976eea6b1e9334f91d529faa05a89355e64b8439d6b96f9cca0d2d2d35cf33c017a3bbe0d7867ce1f62948514d1294354c2a11795f046960df8a0daead9867c4447459915bdb77c163a1cfaa9e69e0f915c422a3f291bec8afcbca0f350a609073159867968bed20feef366627cadfa06e7e16149b9116b3b40d8ac
hash = c2a2926fc0d94c1b381f8c106eb0faf571d9c72b6b3e15b1a98bbd9e958375cb
```

### A seven-leaf MMR and its paths

Leaves 0 and 1 are the two example headers above; leaves 2 to 6 are example
header hashes `22..22` to `66..66` with example difficulties 2^24 + 65,536
times their index. The peaks are named `peak-start-height`. The three paths
reach the tip of block 7: leaf 0 in the first peak (two siblings and the bag of
the two later peaks), leaf 4 in the middle peak (one sibling, the last peak as
its bag and the first peak), and leaf 6, the last peak (no sibling and no bag,
the two earlier peaks, nearest first). `reject-index` is an index at which the
script rejects the same path.

```text
[header-mmr-seven-leaves]
kind = header-mmr
n = 7
leaf-0 = header-genesis-with-mmr 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65 00000000000000000000000001000000 cfd870edbca7cee35cb8b110c3f971397b5ca834f8a40ba4b42b943c0bd5fa0a
leaf-1 = header-block-one-with-mmr c2a2926fc0d94c1b381f8c106eb0faf571d9c72b6b3e15b1a98bbd9e958375cb 00000000000000000000000001000000 ea98f3073eabe1f43d9d6e6b13798a1db0c64146a596bbbec0c5dd5e17920af7
leaf-2 = example 2222222222222222222222222222222222222222222222222222222222222222 00000000000000000000000001020000 83ab28fd7237ecab556e8e44ad89f6c5f00a4ab9d2f2f182056d6700eb425c18
leaf-3 = example 3333333333333333333333333333333333333333333333333333333333333333 00000000000000000000000001030000 7e1342ca29cd2a2abffbd2a5e803ab0f6e24286253cf28fa16db3ff1825c9c7a
leaf-4 = example 4444444444444444444444444444444444444444444444444444444444444444 00000000000000000000000001040000 36fe0ff3d13a81dd0d7399fbe4c7572bdc6d7d838c408eb7fbfbf0503fc53e14
leaf-5 = example 5555555555555555555555555555555555555555555555555555555555555555 00000000000000000000000001050000 bb25aa2c8ba10dc7452bd5f83771fb0cc7d05c7ccda6a0828aad872672d33be0
leaf-6 = example 6666666666666666666666666666666666666666666666666666666666666666 00000000000000000000000001060000 d88640304cf3d36d1f3d64667b1cc18c006e4b223ee6386e7d0e26549284bd14
peak-0-2 = e4b5248c30741850b2386dc7594f75cf2049f1f53637da65dce718ebc8f6d55a 00000000000000000000000004050000
peak-4-1 = ae016d70e8f386b36fd0c59393b9078d1fbf016bb71baa80ab6525cc26fc64e2 00000000000000000000000002090000
peak-6-0 = d88640304cf3d36d1f3d64667b1cc18c006e4b223ee6386e7d0e26549284bd14 00000000000000000000000001060000
bag = e2d2180c537e295217c4c61b028377075a882172ed0289738cb94ac699cc7830 00000000000000000000000007140000
root = fb94d9e93c3815fe907f4420cc32aa620c904da8e4fee556790a0a5dc55306a0
total-work = 118751232

[header-mmr-path-seven-0]
kind = header-mmr-path
mmr = header-mmr-seven-leaves
n = 7
index = 0
header-hash = 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65
difficulty = 16777216
root = fb94d9e93c3815fe907f4420cc32aa620c904da8e4fee556790a0a5dc55306a0
entries = 3
bytes = 144
path = ea98f3073eabe1f43d9d6e6b13798a1db0c64146a596bbbec0c5dd5e17920af700000000000000000000000001000000e42eb4103ef56640a55a7dac21f244b92079cbffc129c7a5ebbe6a76dd309b0b0000000000000000000000000205000052fc7e559d7dcfd16c637d47602ac9ed6d09689dd6a09135ef758500489fc48a000000000000000000000000030f0000
work-before = 0
total-work = 118751232
reject-index = 1

[header-mmr-path-seven-4]
kind = header-mmr-path
mmr = header-mmr-seven-leaves
n = 7
index = 4
header-hash = 4444444444444444444444444444444444444444444444444444444444444444
difficulty = 17039360
root = fb94d9e93c3815fe907f4420cc32aa620c904da8e4fee556790a0a5dc55306a0
entries = 3
bytes = 144
path = bb25aa2c8ba10dc7452bd5f83771fb0cc7d05c7ccda6a0828aad872672d33be000000000000000000000000001050000d88640304cf3d36d1f3d64667b1cc18c006e4b223ee6386e7d0e26549284bd1400000000000000000000000001060000e4b5248c30741850b2386dc7594f75cf2049f1f53637da65dce718ebc8f6d55a00000000000000000000000004050000
work-before = 67436544
total-work = 118751232
reject-index = 5

[header-mmr-path-seven-6]
kind = header-mmr-path
mmr = header-mmr-seven-leaves
n = 7
index = 6
header-hash = 6666666666666666666666666666666666666666666666666666666666666666
difficulty = 17170432
root = fb94d9e93c3815fe907f4420cc32aa620c904da8e4fee556790a0a5dc55306a0
entries = 2
bytes = 96
path = ae016d70e8f386b36fd0c59393b9078d1fbf016bb71baa80ab6525cc26fc64e200000000000000000000000002090000e4b5248c30741850b2386dc7594f75cf2049f1f53637da65dce718ebc8f6d55a00000000000000000000000004050000
work-before = 101580800
total-work = 118751232
reject-index = 5
```

### A chain of five years

Five years of 30-second blocks, 5 x 365 x 2,880 = 5,256,000, the `n` in the
header of block 5,256,000. Leaves 0 and 1 are the two example headers;
4,200,000 and 5,255,999 are example header hashes `5a..5a` and `5b..5b` with
difficulties 2^25 and 2^26; every other leaf is the `filler`, one stand-in
header hash `ee..ee` at difficulty 2^24 repeated. No real chain repeats a
header, since each names its parent; the filler makes the root computable with
a few hundred hashes, and the vectors fix bytes and the shape of a path at that
depth, not a chain. For the same reason an all-filler sibling equals an
all-filler peak of the same height, and some path entries repeat peak lines.

The three paths: from genesis, the longest of the chain (22 siblings and the
bag of the six later peaks); from block 4,200,000 in the second peak (20
siblings, the bag of the five later peaks, then the first peak); and from block
5,255,999, the last before the tip (6 siblings in the last peak, then the six
earlier peaks, nearest first).

```text
[header-mmr-five-years]
kind = header-mmr
n = 5256000
filler = eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 00000000000000000000000001000000
leaf-0 = header-genesis-with-mmr 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65 00000000000000000000000001000000 cfd870edbca7cee35cb8b110c3f971397b5ca834f8a40ba4b42b943c0bd5fa0a
leaf-1 = header-block-one-with-mmr c2a2926fc0d94c1b381f8c106eb0faf571d9c72b6b3e15b1a98bbd9e958375cb 00000000000000000000000001000000 ea98f3073eabe1f43d9d6e6b13798a1db0c64146a596bbbec0c5dd5e17920af7
leaf-4200000 = example 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a 00000000000000000000000002000000 1d2c7122dad78ef02bf8c2eec9a82b63a1ed2a3facaf0685c829c541e8380a30
leaf-5255999 = example 5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b 00000000000000000000000004000000 8f77502f9553e59ce64c152e4a302967025cc730b13290ba2cc92ebb89773bb1
peak-0-22 = cd5cbc4a78c5caf9f599f7541db9c42e9e82cdb1fe59b1d69942cf59fc8f7309 00000000000000000000400000000000
peak-4194304-20 = d2ec1b2d75fc38f967141d9a58665a3d3fd30a05612a59083d9d055b0afab11d 00000000000000000000100001000000
peak-5242880-13 = 5ee783e7d624888f4db7dde9e27a0e6cb17d1e7be4e6093bb43bf5c3747e25af 00000000000000000000002000000000
peak-5251072-12 = 8f1be1db34cd942e378f9ef472c58003a50e13a5c72496f35513f1a3d2a80e00 00000000000000000000001000000000
peak-5255168-9 = 04a7ad2c1e2b4cf48eb033ec6984fa9391586b0995fb9bbbf1f11acc1291a047 00000000000000000000000200000000
peak-5255680-8 = d0ddccfbb6f202df2586f50ddb1454f2381f31bbb108541189d5779505f2f733 00000000000000000000000100000000
peak-5255936-6 = 68693741bb4f307b1fa6153549272acb1bf5a30cbc29edf2e9cce8c74d532a12 00000000000000000000000043000000
bag = ae1f9499b3cb178b4d168a57bf3ac893740bd035dabba50d5d8be70640b43c06 00000000000000000000503344000000
root = a262148a8926dd27bda83c8ae07bac1da59c1471f966301d4addc6f9d89dcb01
total-work = 88181114404864

[header-mmr-path-five-years-genesis]
kind = header-mmr-path
mmr = header-mmr-five-years
n = 5256000
index = 0
header-hash = 31ee4cd9bc68f5333a9b0ece3831202fa20b88ccbc63a55ef45bc4c6eaaf7b65
difficulty = 16777216
root = a262148a8926dd27bda83c8ae07bac1da59c1471f966301d4addc6f9d89dcb01
entries = 23
bytes = 1104
path = ea98f3073eabe1f43d9d6e6b13798a1db0c64146a596bbbec0c5dd5e17920af700000000000000000000000001000000e1e2e752142155b2705894920e7db2e0d245ca3955983d2a04cf3a28d1e0df7d000000000000000000000000020000001f5eb73b832f8f8516e43a0d6e089c942a643357dacb3a93f553101f7080e7ec0000000000000000000000000400000062ceb086561a4c565f04ac9bf9dfca830841412c7ec55c8be41a86b793f1c51a0000000000000000000000000800000090cf377b55720533ce0b1ffda4eef441901aa51cb94695c1a18bb684b9d037ba00000000000000000000000010000000e24f53f10b02602e6d8b7b5ce7d221a751e8093bb66f0c888085fdb844de19bd00000000000000000000000020000000376eaf927ced55e1d6b9611e4978cf42728895028251410e635daaf89e40ff0c000000000000000000000000400000006e704259d84151237283e340d917422e0f8be813fb157a51a7af566e86aab6c100000000000000000000000080000000d0ddccfbb6f202df2586f50ddb1454f2381f31bbb108541189d5779505f2f7330000000000000000000000010000000004a7ad2c1e2b4cf48eb033ec6984fa9391586b0995fb9bbbf1f11acc1291a04700000000000000000000000200000000a1bb0ee1bb469ba5fabb5dcd8e7715b8b71ef458bd229db20ba0e814a909c9630000000000000000000000040000000046c6265cd85fcc75c01ecb3880339a08c31f8aa7bbfe58006d1498d6aab5b62a000000000000000000000008000000008f1be1db34cd942e378f9ef472c58003a50e13a5c72496f35513f1a3d2a80e00000000000000000000000010000000005ee783e7d624888f4db7dde9e27a0e6cb17d1e7be4e6093bb43bf5c3747e25af00000000000000000000002000000000a93f028054e1ddf8e6fea6f9e1a8b61431b4e2d875240fcd0f922f8ac4aa2b8b000000000000000000000040000000007c6dfd35601a884f28aa3bac6b28fa73e7fe2c370f7a47507bc4fa00636c279a00000000000000000000008000000000ee817eeb5d9b8394e346a9ef2d89231012a9c1d407d9c1f05b9b3c0124581ea3000000000000000000000100000000008df51715f0b719776e6f76855927237d9c22c6ae4c180c147ecbce6833f5054b000000000000000000000200000000008893aa8f53d9f31c6e24c361a2e4b230c597831ada51a3ff5a125d5eff6d3e280000000000000000000004000000000056729dc9d4e0e8cc144125a757472bbcba52409284fd454e223ba20b43d8ca9f000000000000000000000800000000004d5ea36f534ed3c901c531ec272cfebb0087b813176dbe37c6708c705d640ad80000000000000000000010000000000057f8398677e5c7c518cef4191b922656177f60a7ae968b27f9d1d0d89b77370d00000000000000000000200000000000bf0b51b7e31f6453fcf73ede17c7b40997a6fa8ee336086e357638ce8918e9e100000000000000000000103344000000
work-before = 0
total-work = 88181114404864
reject-index = 1

[header-mmr-path-five-years-middle]
kind = header-mmr-path
mmr = header-mmr-five-years
n = 5256000
index = 4200000
header-hash = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
difficulty = 33554432
root = a262148a8926dd27bda83c8ae07bac1da59c1471f966301d4addc6f9d89dcb01
entries = 22
bytes = 1056
path = 9b4ff4f178f73bc97e48f29eff8e17830b0d97e808c1330ec7d7d1b461ecbcc400000000000000000000000001000000e1e2e752142155b2705894920e7db2e0d245ca3955983d2a04cf3a28d1e0df7d000000000000000000000000020000001f5eb73b832f8f8516e43a0d6e089c942a643357dacb3a93f553101f7080e7ec0000000000000000000000000400000062ceb086561a4c565f04ac9bf9dfca830841412c7ec55c8be41a86b793f1c51a0000000000000000000000000800000090cf377b55720533ce0b1ffda4eef441901aa51cb94695c1a18bb684b9d037ba00000000000000000000000010000000e24f53f10b02602e6d8b7b5ce7d221a751e8093bb66f0c888085fdb844de19bd00000000000000000000000020000000376eaf927ced55e1d6b9611e4978cf42728895028251410e635daaf89e40ff0c000000000000000000000000400000006e704259d84151237283e340d917422e0f8be813fb157a51a7af566e86aab6c100000000000000000000000080000000d0ddccfbb6f202df2586f50ddb1454f2381f31bbb108541189d5779505f2f7330000000000000000000000010000000004a7ad2c1e2b4cf48eb033ec6984fa9391586b0995fb9bbbf1f11acc1291a04700000000000000000000000200000000a1bb0ee1bb469ba5fabb5dcd8e7715b8b71ef458bd229db20ba0e814a909c9630000000000000000000000040000000046c6265cd85fcc75c01ecb3880339a08c31f8aa7bbfe58006d1498d6aab5b62a000000000000000000000008000000008f1be1db34cd942e378f9ef472c58003a50e13a5c72496f35513f1a3d2a80e00000000000000000000000010000000005ee783e7d624888f4db7dde9e27a0e6cb17d1e7be4e6093bb43bf5c3747e25af00000000000000000000002000000000a93f028054e1ddf8e6fea6f9e1a8b61431b4e2d875240fcd0f922f8ac4aa2b8b000000000000000000000040000000007c6dfd35601a884f28aa3bac6b28fa73e7fe2c370f7a47507bc4fa00636c279a00000000000000000000008000000000ee817eeb5d9b8394e346a9ef2d89231012a9c1d407d9c1f05b9b3c0124581ea3000000000000000000000100000000008df51715f0b719776e6f76855927237d9c22c6ae4c180c147ecbce6833f5054b000000000000000000000200000000008893aa8f53d9f31c6e24c361a2e4b230c597831ada51a3ff5a125d5eff6d3e280000000000000000000004000000000056729dc9d4e0e8cc144125a757472bbcba52409284fd454e223ba20b43d8ca9f0000000000000000000008000000000006509d332e2464412e53f19d03a5a5849d06338761e8cbfdf1bd59b0ca4ab9da00000000000000000000003343000000cd5cbc4a78c5caf9f599f7541db9c42e9e82cdb1fe59b1d69942cf59fc8f730900000000000000000000400000000000
work-before = 70464307200000
total-work = 88181114404864
reject-index = 4200001

[header-mmr-path-five-years-last]
kind = header-mmr-path
mmr = header-mmr-five-years
n = 5256000
index = 5255999
header-hash = 5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b
difficulty = 67108864
root = a262148a8926dd27bda83c8ae07bac1da59c1471f966301d4addc6f9d89dcb01
entries = 12
bytes = 576
path = 9b4ff4f178f73bc97e48f29eff8e17830b0d97e808c1330ec7d7d1b461ecbcc400000000000000000000000001000000e1e2e752142155b2705894920e7db2e0d245ca3955983d2a04cf3a28d1e0df7d000000000000000000000000020000001f5eb73b832f8f8516e43a0d6e089c942a643357dacb3a93f553101f7080e7ec0000000000000000000000000400000062ceb086561a4c565f04ac9bf9dfca830841412c7ec55c8be41a86b793f1c51a0000000000000000000000000800000090cf377b55720533ce0b1ffda4eef441901aa51cb94695c1a18bb684b9d037ba00000000000000000000000010000000e24f53f10b02602e6d8b7b5ce7d221a751e8093bb66f0c888085fdb844de19bd00000000000000000000000020000000d0ddccfbb6f202df2586f50ddb1454f2381f31bbb108541189d5779505f2f7330000000000000000000000010000000004a7ad2c1e2b4cf48eb033ec6984fa9391586b0995fb9bbbf1f11acc1291a047000000000000000000000002000000008f1be1db34cd942e378f9ef472c58003a50e13a5c72496f35513f1a3d2a80e00000000000000000000000010000000005ee783e7d624888f4db7dde9e27a0e6cb17d1e7be4e6093bb43bf5c3747e25af00000000000000000000002000000000d2ec1b2d75fc38f967141d9a58665a3d3fd30a05612a59083d9d055b0afab11d00000000000000000000100001000000cd5cbc4a78c5caf9f599f7541db9c42e9e82cdb1fe59b1d69942cf59fc8f730900000000000000000000400000000000
work-before = 88181047296000
total-work = 88181114404864
reject-index = 5255998
```

### Path sizes and header sizes

The entries of the longest path from each peak, at one year (1,051,200 blocks)
and at five, and the encoded header sizes of section "Header size".

```text
[header-mmr-path-size-one-year]
kind = header-mmr-path-size
chain = one year
n = 1051200
peak-heights = 20 11 9 6
entries-by-peak = 21 13 12 9
most-entries = 21
most-bytes = 1008

[header-mmr-path-size-five-years]
kind = header-mmr-path-size
chain = five years
n = 5256000
peak-heights = 22 20 13 12 9 8 6
entries-by-peak = 23 22 16 16 14 14 12
most-entries = 23
most-bytes = 1104

[header-sizes]
kind = header-size
block-one-18 = 582
block-one-19 = 615
block-one-23 = 747
block-one-24 = 780
genesis-23 = 776
genesis-24 = 809
```

## What the build ticket writes into the specifications

The build ticket of the stage 2 design (its item 5, "Header MMR and sampled
header proof") writes these formats into the specifications with golden
vectors and extends their checkers. This record edits none of them.

- Spec 01: the four rows of "Tag table rows" in section 4.
- Spec 05: field 23 and 24 items in sections 1 and 10, the genesis value, the
  rule that the field equals the root over the earlier headers with the checks
  of section 4, the truncation on reorganisation in section 7, and the header
  vectors of section 11 at 24 items, with `item-count` for a 23-item header.
- Spec 06: `work-overflow` and the 2^128 bound on total difficulty in
  section 4.5.
- The stage 2 model: a header of 780 bytes in place of its modeled size.

## What this record does not settle

- **The sampler and its proof for Ghost's difficulty rule:** the sampling
  density, the sample count, the attacker ratio and the assurance a wallet must
  reach, and the FlyClient bound for Ghost's difficulty rule (spec 06,
  section 4), which the stage 2 design lists as not yet established and as
  founder decisions. This record gives the sampler what it consumes: a header's
  place in the chain's cumulative work, proven against the tip.
- **The node's MMR:** its storage layout, and its cost inside the block budget
  (not yet established until built and measured).
- **The proof transport:** how a wallet asks for samples and how shared path
  entries are sent once.
- The other founder decisions of the stage 2 design, which this record does not
  touch.

## What would reverse this decision

- The proof for Ghost's difficulty rule needs each node to commit to more than
  a hash and a work, for example timestamps or difficulty bounds as Zcash's
  ZIP 221 does; the leaf and node tags would get a new version, and the header
  field would stay.
- A chain could reach a total difficulty of 2^128 within its planned life,
  which would widen every work value of this record.
- A light-client proof has to fold paths inside a circuit where Keccak is too
  costly, and the tags move to another hash.
- The founder declines the header MMR or the format changes of the restore
  design.

## Reproduce

```sh
python3 scripts/check_decision_0005.py
python3 scripts/check_decision_0005.py --print
```

The first checks this record: its sections, every vector block above, every
path accepted for its header with the stated work and rejected for any changed
byte, another length, index, leaf count, difficulty, header or root, the path
sizes against floor(log2 n) + 1 and the stage 2 design's modeled path, the tag
table, the header field against spec 05 and decision 0004, and the header size
table against the RLP of spec 05's vectors, which its own encoder reproduces
byte for byte. The second prints the vector blocks. Both use Python's standard
library only, with the Keccak-256 of `scripts/check_decision_0004.py` and its
self test.

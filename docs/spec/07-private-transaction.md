# Specification 07: the native private transaction and its fee

Status: draft for the founder's review, 2026-10-17. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the [outline](../ghost-outline.md)
("Transactions and fees", "Core protocol" 9, "First milestone" 8), the front
desk decisions recorded with this specification, the base client plan (section
7.3), [decision 0001](../decisions/0001-base-client.md),
[decision 0003](../decisions/0003-proof-system.md), the
[Reth survey](../surveys/reth.md) (section 3, "Block gas accounting and
receipts"), the [commitments and keys](01-commitments-and-keys.md), the
[proof statements](02-proof-statements.md), the [coin rules](03-coin-rules.md),
the [data commitments](04-data-commitments.md), the
[trees and headers](05-trees-and-headers.md), the
[consensus specification](06-consensus-and-emission.md) or the
[threat model](../threat-model.md), and is cited to it, not decided again here.
Where a point is not settled, the check rejects (fails closed), and the point is
listed in section 9.

A reveal is a native transaction with no account: the proof is the
authorization (outline, "Transactions and fees"; spec 03, section 7). This
document fixes that transaction: its type, its one fixed-length payload and its
hash; the fee it carries and how the chain computes it; what "the fee is
current" means when the base fee moves between proving and inclusion; how the
transaction pool admits, keeps and drops these transactions when there is no
sender to rate-limit; and the boundary cases of the first milestone, each with
a worked example. Section 12 names the script that checks this document.

It does not change what the proof proves (spec 02), the node's order of checks
on a reveal (spec 03, section 7), the eligible roots or the marker sets
(spec 05). It writes no node code, no circuit and no proof-system choice beyond
decision 0003. It does not settle the fee of a data reveal (spec 04,
question 1).

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Transaction type | A new EIP-2718 typed transaction, type byte `0x50`, outside Ethereum's `0x00` to `0x04` and not `0x7e` | Front desk decision |
| Shape | One fixed-length payload: version, chain identifier, marker, root, remainder, recipient, amount out, fee, proof, note. Every private transaction has the same size | Front desk decision; outline ("One private shape") |
| Proof field | 1,310,720 bytes (1.25 MiB) for every reveal kind, with a trace budget the prover enforces and a derived upper bound on the proof length; a change of width is a new version | Founder decision, 2026-10-18 (section 3) |
| Absent fields | No signature, nonce, gas price, gas limit, tip, sender, type tag, rule or digest field | Front desk decision; spec 02, PS-6 |
| Root | A plain 32-byte root with no tree index, resolved against the eligible coin roots of spec 05, section 5, across rollovers | Front desk decision; spec 05 |
| Hash | Keccak-256 of the type byte followed by the payload, the base client's typed-transaction hash | EIP-2718 |
| Gas | One fixed figure `G_PRIV` per private transaction, counted in the block's gas used | Front desk decision; Reth survey, section 3 |
| `G_PRIV` | The public calldata price for every byte of the envelope, plus the base transaction cost, plus a verification charge | **Proposed** (section 4) |
| Fee | `G_PRIV` times the window's base-fee price, plus the tip | Front desk decision |
| Burn and tip | The whole base-fee part is burned; the tip, one tenth of the base-fee part rounded up, goes to the block finder | Front desk decision; spec 03, section 4 |
| Fee is current | Strict equality with the fee in force for the including block; the fee is held for a window of 4 blocks and never charges less than `G_PRIV` times any block's base fee in it | Front desk decision; window length **Proposed** (section 5) |
| Pool | One transaction per marker, first in wins; cheap checks before the proof; hard caps; per-peer budgets; deterministic order; full recheck on every block and reorganisation | Front desk decision; caps and budgets **Proposed** (section 6) |
| Data reveal | Has no encoding in version 1; every data reveal stays rejected | Spec 04, question 1 (fail closed) |

## 2. Conventions and parameters

The conventions of [spec 01](01-commitments-and-keys.md), section 2, and
[spec 02](02-proof-statements.md), section 2, apply: integers are unsigned
big-endian at the stated width, an **amount word** is 32 bytes and valid only
below `2^96`, `V_MAX = 2^96 - 1`, and "reject" means the transaction is invalid
and changes no state. In addition:

- **Private transaction.** A transaction of type `0x50`. In version 1 every
  private transaction is a coin reveal (statement S1 of spec 02).
- **Including block.** The block that contains a transaction, or, for a pool
  check, the block the node would build next on its head (spec 05, section 2).
  `H` is its height.
- **Base fee.** The `baseFee` field of a header (spec 05, section 10), set by
  the base client's EIP-1559 rule from the parent (decision 0001).
- **Window.** The blocks `wW` to `wW + W - 1` for a window index `w` and the
  window length `W = FEE_WINDOW`. Block `H` is in window `floor(H / W)`.
- **Uncertain means rejected.** Every classification in this document (is the
  fee current, is the root eligible, is the marker unused, is a field well
  formed, is the payload the right size) answers "yes" only on positive
  evidence. A missing header, an unavailable lookup, an unknown value or a
  disagreement rejects; nothing is guessed (spec 05, section 2).

**Parameters.**

| Name | Value | Meaning |
|---|---|---|
| `TYPE_BYTE` | `0x50` | EIP-2718 type of the private transaction |
| `TX_VERSION` | `0x0001` | The only accepted `version`; equal to the protocol version of spec 02, section 2 |
| `PROOF_BYTES` | 1,310,720 | Width of the proof field, 1.25 MiB, the same for every reveal kind (section 3, "Proof field") |
| `NOTE_BYTES` | 156 | Width of the encrypted note (spec 01, section 9) |
| `PAYLOAD_BYTES` | 1,311,066 | Sum of the payload widths (section 3) |
| `ENVELOPE_BYTES` | 1,311,067 | The type byte and the payload |
| `BYTE_GAS` | 16 | Gas per envelope byte: the base client's price of a non-zero calldata byte (EIP-2028) |
| `BASE_TX_GAS` | 21,000 | The base client's base cost of any transaction |
| `VERIFY_GAS` | 92,300 | Gas for verifying the proof (section 4) |
| `G_PRIV` | 21,090,372 | Gas of every private transaction: `BYTE_GAS * ENVELOPE_BYTES + BASE_TX_GAS + VERIFY_GAS` |
| `FEE_WINDOW` | 4 | Blocks for which one fee is in force (section 5) |
| `TIP_DIVISOR` | 10 | The tip is the base-fee part divided by this, rounded up |
| `MIN_GAS_LIMIT` | 5,000 | The base client's smallest block gas limit, used in the growth bound of section 5 |
| `POOL_MAX_COUNT` | 16 | Most private transactions a node's pool holds (section 6) |
| `POOL_MAX_BYTES` | 20,977,072 | Most bytes of private transactions a node's pool holds: `POOL_MAX_COUNT * ENVELOPE_BYTES` |

## 3. Encoding and hashing

**Envelope.** A private transaction is the EIP-2718 envelope

```text
tx = 0x50 || payload
```

with `payload` exactly `PAYLOAD_BYTES` long. The payload is a fixed-layout byte
string, not RLP: RLP drops the leading zero bytes of integers and would give
different transactions different lengths, which the outline forbids ("every
private transaction has an identical size and shape"). Where the base client
carries a typed transaction inside an RLP list (a block body, a pooled
transactions message), it wraps the envelope as one RLP byte string, as for
every typed transaction; that wrapper is the same length for every private
transaction.

**Payload.** The fields in this order, with nothing before, between or after
them:

| Offset | Width | Field | Content |
|---|---|---|---|
| 0 | 2 | `version` | `TX_VERSION`, `0x0001` |
| 2 | 8 | `chain_id` | This chain's identifier (spec 02, section 2) |
| 10 | 32 | `marker` | The coin marker `K("ghost/coin-marker/v1", r, b)` (spec 02, section 4) |
| 42 | 32 | `root` | A coin-tree root from the header of an earlier canonical block, with no tree index (spec 05, section 5) |
| 74 | 32 | `remainder` | The remainder commitment `C'` |
| 106 | 20 | `recipient` | The address credited with `out` |
| 126 | 32 | `out` | Amount word: the public amount out, zero allowed |
| 158 | 32 | `fee` | Amount word: the fee in force (section 4) |
| 190 | 1310720 | `proof` | The serialized proof followed by zero bytes to exactly `PROOF_BYTES` |
| 1310910 | 156 | `note` | The remainder's encrypted note (spec 01, section 9) |

Total: 1,311,066 bytes of payload; 1,311,067 bytes with the type byte.

**What is not in it.** There is no signature, nonce, gas price, gas limit,
priority fee, sender, access list or value field (front desk decision): the
proof authorizes the transaction, the marker makes it unique, and the fee is
fixed by the chain. There is no type tag, rule, purpose, statement code,
domain tag or binding digest either: the type byte and `version` say that the
transaction is a coin reveal, and the node supplies those values itself
(below). A field the node would read from the sender but that the proof does not
bind could be changed in transit (spec 02, section 7), so none exists.

**Root without a tree index.** The root is resolved against the set of
eligible coin roots of spec 05, section 5: the coin roots in headers of
canonical blocks below the including block, of every tree index, including the
final root of a full tree. The node never needs the index, so the shape does
not depend on the rollover and no transaction tells which tree its leaf is in.

**Binding.** Every field of the coin reveal binding of spec 02, section 7 comes
from the payload or from the node's own values, and every payload field except
the proof is bound. The node computes the digest itself (spec 02, PS-6).

| Binding field | Source |
|---|---|
| `chain_id` | `chain_id` |
| `version` | `version` |
| `domain` | Node: the genesis block hash |
| `statement` | Node: `0x01` |
| `statement_version` | Node: `0x01` |
| `type` | Node: `COIN` |
| `purpose` | Node: `0x01` spend |
| `root` | `root` |
| `marker` | `marker` |
| `remainder` | `remainder` |
| `recipient` | `recipient` |
| `out` | `out` |
| `fee` | `fee` |
| `rule` | Node: the empty rule, 32 zero bytes |
| `remainder_note` | `note` |

**Decoding.** A node accepts the bytes of a private transaction only if all of
these hold, and otherwise rejects them; these are steps 1 and 2 of spec 03,
section 7, made exact:

1. The first byte is `0x50` and the envelope is exactly `ENVELOPE_BYTES` long.
   Anything shorter, longer or wrapped differently is rejected.
2. `version` is `0x0001`. Any other value, including one a later version may
   define, is rejected by a node that does not implement it.
3. `out` and `fee` are amount words: their first 20 bytes are zero (spec 02,
   section 10).
4. The proof field decodes as one serialized proof of the configuration of
   decision 0003, and every byte after the serialization is zero. A non-zero
   padding byte, or a serialization that does not end inside the field, is
   rejected, so that one proof has one encoding.
5. `recipient`, `marker`, `root`, `remainder` and `note` are fixed-width byte
   strings with no further encoding rule (spec 02, section 10).

**Proof field.** `PROOF_BYTES` is 1,310,720 bytes (1.25 MiB) in version 1,
for the coin reveal and the data reveal alike: every reveal kind uses the same
field width and the same layout, so every private transaction has one size and
one shape whatever it reveals (founder decision, 2026-10-18). The data reveal
has no encoding yet ("Data reveals" below), but its proof already fits this
field. The width was chosen so that it never has to grow.

- **Why not 1,028,144.** The earlier width came from the benchmark statement
  of decision 0003, a trace of 1,024 rows by 3,271 columns. The coin reveal
  that shipped is 2,048 rows by 3,808 columns, and at the proof settings of
  that time (blowup 2^2, 57 queries) its proofs measured 1,188,348 bytes
  (median) to 1,194,788 bytes (largest), so none fitted. The data reveal and
  the proof of holding are 1,024-row traces, smaller than the coin reveal.
- **Proof settings.** Since 2026-10-20 the settings are those of the
  post-quantum rule of spec 09, section 4.1 (decision 0003, "Blowup"): blowup
  2^3 (rate 1/8), 43 queries, 16 grinding bits on the queries and before the
  batching challenge, extension degree 5, Keccak-256, zero-knowledge on. They
  make proofs shorter, so the width did not change: the coin reveal's proofs
  measure 957,516 bytes (median of 9) to 961,981 bytes (largest), natively
  ([measurements](../benchmarks/reveal-parameters.md)).
- **Budget.** Every reveal statement, the coin reveal, the data reveal and any
  later one, must fit the coin reveal's trace: at most 2,048 rows before
  zero-knowledge padding and at most 3,808 columns, at the version 1 proof
  settings. The prover's security gate refuses a statement over the budget
  before it proves or verifies anything (`MAX_TRACE_HEIGHT`,
  `MAX_TRACE_WIDTH` and the error `TraceOverBudget` in `proofs/src/stark.rs`),
  and a test fails when any statement the crate knows is over it.
- **Bound.** The longest proof the encoding can produce for a trace at the
  budget is 1,053,331 bytes, 257,389 bytes below the field (it was 1,268,539
  bytes at blowup 2^2 with 57 queries). It is derived from
  the structure of the proof at the pinned Plonky3 revision, not sampled, and
  computed by `proof_length_bound` in `proofs/src/stark.rs`; a test asserts it
  is at most `PROOF_BYTES`, and another proves each statement the prover
  supports and asserts each proof is at most `PROOF_BYTES` and at most the
  bound for its trace.
- **Version rule.** A change of width is a new `version`, never an edit of
  version 1. A statement that does not fit the budget needs a new version
  with its own width, not a wider field under version 1.

**Derivation of the bound.** The proof is the postcard serialization of the
library's proof. Each uncertain term takes its worst case:

- a BabyBear element is a fixed 4 bytes (the library writes it as a raw
  little-endian word, not a varint) and a challenge is 5 of them, 20 bytes;
- every length prefix, and `degree_bits`, is a varint at its maximum, 10
  bytes; an option's tag is 1 byte;
- a digest is four 64-bit Keccak lanes, each a varint of at most 10 bytes, so
  40 bytes; a commitment is a Merkle cap of one digest, 50 bytes;
- a pruned Merkle multiproof over a binary tree of `d` levels holds at most
  `min(43, 2^j)` digests at the level with `2^j` parents, the most the 43
  query indices can force there: 450 digests for the 15-level trees of the
  inputs;
- the gate allows a constraint degree of at most 8, the blowup, which gives at
  most 16 quotient chunks in zero-knowledge mode;
- the trace is padded to twice its rows for zero-knowledge, 4,096, and every
  committed codeword is 8 times that, 32,768 rows (15 levels); hiding adds 5
  random columns to each committed matrix and 5 salt elements to each opened
  row; FRI folds by 2 down to a final polynomial of one coefficient, so it
  commits 12 layers of 14 down to 3 levels.

For the budget trace of 2,048 rows by 3,808 columns:

| Part | What it holds | Bytes |
|---|---|---|
| Commitments | Trace, quotient and randomization caps, with the option tag | 151 |
| Opened values | The trace at both out-of-domain points (3,808 challenges each), 16 quotient chunks and the randomization polynomial, 5 challenges each, with the tags | 154,224 |
| Hidden openings | The 5 random columns of every opened matrix at every point | 2,310 |
| Trace openings | 43 rows of 3,813 elements, 43 salts, 450 digests | 676,446 |
| Quotient openings | 43 rows of 16 chunks of 10 elements, 43 salts per chunk, 450 digests | 73,930 |
| Randomization openings | 43 rows of 10 elements, 43 salts, 450 digests | 22,330 |
| FRI layers | 12 layers: per query one sibling challenge and a salt, and 2,168 digests over all layers | 123,210 |
| The rest | Length prefixes of the input batches, 12 layer commitments, the grinding witnesses, the final polynomial, `degree_bits` | 730 |
| Bound | | 1,053,331 |

The bound only grows with the trace: one more column adds 212 bytes (two
challenges and 43 elements), and a taller trace adds a level to every tree.
So every trace within the budget has a bound at most 1,053,331 bytes, and its
proof fits the field.

**Hash.** The transaction hash is `keccak256(0x50 || payload)`, the base
client's hash of every typed transaction. The type byte separates it from the
hash of every other transaction type, and it never enters a proof or a
commitment, so it needs no tag of spec 01. The hash identifies these exact
bytes, not the reveal: a wallet that proves again for a new fee window makes a
new hash with the same marker. The marker, not the hash, identifies a reveal
in the pool (section 6) and in a block (spec 03, section 7, step 8); a wallet
tracks its reveal by marker.

**Block and receipt.** In the transactions trie the value is the envelope, as
for every typed transaction. A private transaction has no sender: the base
client's sender recovery, nonce check and balance check are not run for type
`0x50`, and no account is touched except those spec 03, section 7, step 13
writes. Its receipt is a typed receipt of type `0x50` whose cumulative gas used
counts `G_PRIV`; the rest of its layout is not fixed here (section 9), except
that it must carry the marker, the remainder with its tree index and position,
and the note bytes, so that wallets can check notes and marker status against
`receiptsRoot` (spec 05, section 8, item 5; review 01, F3 and F4).

**Data reveals.** Version 1 has no field for a type tag or a purpose, so it
cannot carry a data reveal. A data reveal has no encoding and is rejected,
which is already the outcome of spec 04, section 6, step 6 until the founder
settles spec 04, question 1. The proof field is already sized for it: a data
reveal proof fits `PROOF_BYTES` (section 3, "Proof field"), and any later
encoding of data reveals must give them exactly `ENVELOPE_BYTES` and the same
1,310,720-byte proof field: one size for every private transaction is a hard
target, not a default.

## 4. Fee formula

A private transaction does not choose its fee. The chain fixes one fee for
every private transaction in a window of blocks, the proof binds it, and the
proof shows it comes out of the input commitment (spec 02, constraint 6 of S1:
`v = out + v' + fee`). No public account pays it: there is no sender.

**Gas.** Every private transaction uses exactly `G_PRIV` gas, counted in the
block's gas used like any other transaction (front desk decision; Reth survey,
section 3). So private transactions fill the block's gas limit and move the
base fee by the base client's own EIP-1559 rule, as public transactions do.
**Proposed** derivation of `G_PRIV`:

- **Bytes.** `BYTE_GAS * ENVELOPE_BYTES = 16 * 1,311,067 = 20,977,072`. The
  block gas limit is the base client's only bound on block size, and a public
  transaction pays 16 gas for each non-zero calldata byte. A private
  transaction pays the same for every byte, zero padding included, because the
  chain stores every byte. A lower price would let private transactions carry
  more bytes per block than the gas limit allows public ones.
- **Base cost.** `BASE_TX_GAS = 21,000`, as every transaction of the base
  client.
- **Verification.** Decision 0003 gives a verification budget of 3,000 ms per
  30-second block and a slowest native verification of 9.23 ms. Mapping the
  whole default gas limit of 30,000,000 (spec 05, question 1) onto that budget
  gives 10,000 gas per millisecond, so `VERIFY_GAS = 9.23 * 10,000 = 92,300`.
- **Total.** `G_PRIV = 20,977,072 + 21,000 + 92,300 = 21,090,372`.

`G_PRIV` is more than half of the default gas limit, so a block holds at most
one private transaction. That is the cost of a proof field of 1.25 MiB at
the public byte price, which decision 0003 already names as the binding limit;
it is question 1 of section 11. If the block gas limit is ever below `G_PRIV`,
no private transaction can be included.

**The fee.** For an including block in window `w`:

```text
price_w   = U_(W-1), the ceiling of section 5 started from b_ref = baseFee(block wW)
base_part = G_PRIV * price_w
tip       = ceil(base_part / TIP_DIVISOR)
fee       = base_part + tip
```

- **Base-fee part.** `G_PRIV` times the window's price, the base fee in force
  for private transactions. It is burned: it leaves the hidden set and is
  credited to nobody (spec 03, section 4; decision 0001). The whole of it is
  burned, including what it exceeds `G_PRIV` times the block's own base fee
  by, so that the block finder gains nothing from a high window price.
- **Tip.** A function of the window's price alone, so identical for every
  private transaction in the block and in the window (outline, "Tips"). It is
  credited to the block finder's address (the header's `coinbase`) in the
  apply step (spec 03, section 7, step 13). Default: one tenth of the base-fee
  part, rounded up (front desk decision).
- **Accounting.** The fee leaves the hidden set with `out`: spec 03's
  `total_out` grows by `out + fee` (spec 03, section 9). The recipient is
  credited `out`, the finder `tip`, and `base_part` is credited to nobody.
- **Range.** `fee` must be an amount word. If the formula gives a fee above
  `V_MAX` in some window, no private transaction is valid in it.
- **Data reveals.** This formula is for the coin reveal. Where a data reveal's
  fee comes from stays unsettled, and every data reveal stays rejected (spec
  04, question 1).

**Worked example.** At the genesis base fee of 1 gwei (spec 05, section 10),
`W = 4`. The script of section 12 recomputes every value.

```text
[window-genesis]
kind = window
b_ref = 1000000000
g_priv = 21090372
price = 1424017979
base_part = 30033068911798188
tip = 3003306891179819
fee = 33036375802978007
```

The fee is about 0.033 GHOST, of which about 0.0300 is burned and about
0.00300 goes to the block finder. A second window, used in section 5:

```text
[window-next]
kind = window
b_ref = 1100000000
g_priv = 21090372
price = 1566419776
base_part = 33036375783996672
tip = 3303637578399668
fee = 36340013362396340
```

## 5. Fee is current

The outline requires a one-time reveal to check that "the fee is current"
("Core protocol" 9). Here that is strict equality, as spec 03, section 7,
step 5 has it: **the fee bound in the proof must equal the fee of the formula
of section 4 for the including block; anything else is rejected**, before the
proof is verified. There is no tolerance band, no "at least" and no refund:
any of those would let the fee differ between transactions and so tell them
apart.

**Why a window.** A wallet proves before it knows which block will include its
transaction, and the base fee moves every block. If the fee followed every
block's base fee, a proof would be valid for one block only. So the fee is held
constant for a window of `W = FEE_WINDOW` blocks, and every block of the window
has the same fee.

**The window's price.** For window `w`, `b_ref` is the base fee of its first
block, `wW`. That block's base fee is a function of its parent, block
`wW - 1` (the base client's EIP-1559 rule), so the window's fee is known to
every node and every header-only wallet as soon as the last block of the
previous window exists. The price is

```text
U_0     = b_ref
U_(j+1) = U_j + floor(U_j / 8) + floor(U_j / 20000) + 1
price_w = U_(W-1)
```

**Why this never charges less than a block's base fee.** The front desk
requires `G_PRIV * price_w >= G_PRIV * baseFee(h)` for every block `h` of the
window. The base client sets a child's base fee from a parent with base fee
`b`, gas limit `L`, target `t = floor(L / 2)` and gas used `u` as
`b + max(1, floor((u - t) * b / t / 8))` when `u > t`, and lower or equal
otherwise. The largest step is with a full parent, `u = L <= 2t + 1`, so
`u - t <= t + 1` and the step is at most
`max(1, floor(b / 8 + b / (8t)))`. With `L >= MIN_GAS_LIMIT = 5,000`,
`t >= 2,500` and `b / (8t) <= b / 20,000`, so the step is at most
`floor(b / 8) + floor(b / 20000) + 1`, which is the ceiling's step. The
ceiling's step function is non-decreasing in `b`, so by induction
`baseFee(wW + j) <= U_j <= U_(W-1)` for every `j < W`. The `1/8` is Ethereum's
largest base-fee growth per block; the other two terms cover an odd gas limit
and the smallest step of 1 wei.

**The window's length (Proposed: 4 blocks).** A longer window gives a wallet
more blocks to be included in; a shorter one charges less above the actual base
fee, because the ceiling grows by about 12.5% per block of the window. With the
window's fee known when the window opens and a proof made in at most the
10-second target (decision 0003), the trade is:

**Window length.**

| Window (blocks) | Ceiling over b_ref | Open for (30-second blocks) |
|---|---|---|
| 1 | 1.000 | 30 s; the proof and its megabyte must reach a miner before the very next block, which comes within 10 s about 28% of the time |
| 2 | 1.125 | 60 s |
| 4 | 1.424 | 120 s |
| 8 | 2.281 | 240 s |
| 16 | 5.856 | 480 s |

Four blocks keep a reveal valid for about two minutes, several times the
proving target, while the worst-case charge stays under one and a half times the
base fee at the window's start. One block is too short to prove in reliably,
and eight blocks more than double the charge. The ratio is for `b_ref` of
1 gwei; the script recomputes it.

**Worst case inside a window.** Every block of the window full at an odd gas
limit of 30,000,001, the fastest the base fee can rise. Each base fee is the
base client's rule applied to the one before; `G_PRIV` times each stays at or
below the window's base-fee part.

```text
[growth-genesis-full-blocks]
kind = growth
window = window-genesis
gas_limit = 30000001
base_fees = 1000000000 1125000008 1265625018 1423828155
```

**A lapsed fee.** A wallet that proved in window `w` and is not included before
window `w + 1` begins holds a proof whose bound fee is no longer in force. The
transaction is rejected at step 5 and the wallet proves again for the new fee,
with a new remainder blinding (spec 01, section 8). If the base fee did not
move, the two windows have the same fee and the transaction stays valid.

```text
[lapse-window-change]
kind = lapse
fee_proved = 33036375802978007
fee_in_force = 36340013362396340
valid = no

[lapse-fee-unchanged]
kind = lapse
fee_proved = 33036375802978007
fee_in_force = 33036375802978007
valid = yes
```

**Window change and reorganisation.** The fee of a window depends on block
`wW - 1` of the canonical chain. A reorganisation that replaces that block can
change the fee of the current window, and the pool's full recheck (section 6)
drops every transaction whose fee no longer equals the fee for the next block.
A node that cannot compute the fee for a block (it lacks the parent header of
the window's first block) rejects every private transaction for that block.

**What the wallet does.** It computes the fee from headers alone, proves for
the window of the next block, and if fewer than two blocks of that window
remain when the proof is ready, waits for the next window's fee rather than
race the change. These are wallet choices; the node checks only equality.

## 6. Transaction pool

A private transaction has no sender account, so the base client's per-account
limits (nonce ordering, balance, per-account slots) do not apply. The pool
keeps them apart by marker and limits spam by making every expensive step come
after cheap ones and by budgeting peers (front desk decision; spec 05,
section 6).

**Admission.** A node admits a private transaction to its pool only if all of
these hold, checked in this order and stopping at the first failure. Steps 1 to
7 cost no proof verification.

1. **Exact size and decoding.** Section 3, "Decoding". A transaction of the
   wrong size is refused before it is stored.
2. **Chain and version.** `chain_id` and `version` are this node's values.
3. **Fee in force.** `fee` equals the fee of section 4 for the next block on
   the node's head.
4. **Root eligible.** `root` is an eligible coin root for the next block
   (spec 05, section 5).
5. **Marker unused.** The marker's slot is zero in the state of the head (spec
   05, section 6).
6. **Marker not pending.** No transaction with this marker is in the pool. The
   first one admitted wins; a second is refused, whatever its other fields, and
   never replaces the first, because there is no fee to bump (all fees are
   equal).
7. **Room.** The pool holds fewer than `POOL_MAX_COUNT` private transactions
   and admitting this one keeps it within `POOL_MAX_BYTES`. A full pool refuses
   the newcomer; it never evicts an admitted transaction to make room.
8. **Peer budget.** The peer that sent it is within its budget below.
9. **Proof.** The binding digest is computed by the node (section 3) and the
   proof verifies against it.

**Hard caps (Proposed).** At most `POOL_MAX_COUNT = 16` private transactions
and `POOL_MAX_BYTES = 20,977,072` bytes, whichever binds first; private
transactions do not count against, and cannot evict, public transactions. At
the default gas limit at most one private transaction fits in a block, so at
most four are included in one window; sixteen holds four windows' worth for
propagation and for transactions returned by a reorganisation.

**Per-peer budgets (Proposed).**

- **Unverified.** A node holds at most one private transaction from a peer
  waiting for step 9 at a time, and verifies at most four proofs from one peer
  per block. Transactions beyond that are not fetched; their announcements are
  ignored. At about 9 ms per verification (decision 0003), 50 peers at their
  full budget cost under two seconds of verification per 30-second block.
- **Failed.** A transaction that passes steps 1 to 8 and fails step 9 is a
  failed proof. An honest peer relays only transactions it verified, so a
  failed proof is the peer's fault. A peer's first failed proof is recorded; a
  second within 1,024 blocks disconnects it. A peer whose transaction fails
  steps 3 to 6 is not penalised, because its head may differ from the node's.
  A transaction of the wrong size or chain (steps 1 and 2) counts as a failed
  proof.
- **Local submissions** through the node's own interface are subject to steps
  1 to 9 and the caps, not to the peer budgets.

**Order (Proposed).** All fees are identical, so the pool orders private
transactions by arrival at this node, then by marker value as a 256-bit
big-endian integer, lowest first, for transactions that arrive together (for
example those returned by one reorganisation). A miner building a block takes
them in that order, as many as the gas limit allows; at most one per marker can
ever be in a block (spec 03, section 7, step 8).

**Recheck.** On every new head, whether from a new block or a reorganisation,
the node rechecks every pending private transaction with steps 2 to 6 and 9
against the new head, in pool order, and drops each that fails (spec 05,
section 7, items 3 and 4). In the recheck, step 6 looks only at the other
transactions still in the pool, never at the transaction being rechecked
itself, so a pending reveal is not dropped for finding its own marker (review
01, F8); since admission already keeps one transaction per marker, the
recheck never finds a second one. A transaction that is not includable in the
next block only because of the one-tree-index rule (spec 05, section 3) passes
the recheck and stays in the pool unchanged. At a window change this drops every transaction
whose fee lapsed. A transaction from a disconnected block re-enters through
steps 1 to 9 as a new arrival. The proof is verified again in the recheck; at
the caps above that is at most 16 verifications, about 150 ms per block.

**Competing reveals.** Two transactions with one marker are two reveals of one
commitment, for example made by two holders of the same digits. The first in a
node's pool wins there and the second is refused at step 6. Different nodes may
hold different ones; the one in a canonical block wins on the chain, and the
other is rejected at spec 03, section 7, step 8, in the same block and in any
later one. A block that holds both is invalid.

## 7. Boundary cases

These are the boundary cases of the outline ("First milestone" 8) and spec 03,
section 8, worked through with the fee of window `window-genesis` (section 4),
`fee = 33,036,375,802,978,007` wei. Every case has the same size and shape: one
input, the recipient and `out` fields present (zero allowed), one remainder
commitment (zero allowed) and one note. `burned` is the base-fee part, `tip`
the finder's tip and `minted` what the recipient is credited; all three are zero
when no valid proof exists. The script of section 12 recomputes each.

**A full reveal.** Everything after the fee goes out: `out = v - fee`, and the
remainder holds zero but still exists (spec 02, PS-13).

```text
[full-reveal]
kind = reveal
window = window-genesis
v = 1000000000000000000
out = 966963624197021993
remainder = 0
fee = 33036375802978007
valid = yes
burned = 30033068911798188
tip = 3003306891179819
minted = 966963624197021993
```

**A zero-amount claim.** Nothing goes out; the remainder takes everything after
the fee, under a new key (spec 03, section 8). The recipient field is still
present and bound; with `out = 0` no balance is written to it. Wallets put the
zero address there.

```text
[zero-amount-claim]
kind = reveal
window = window-genesis
v = 1000000000000000000
out = 0
remainder = 966963624197021993
fee = 33036375802978007
valid = yes
burned = 30033068911798188
tip = 3003306891179819
minted = 0
```

**A fee that uses the whole balance.** The commitment holds exactly the fee:
`out = 0`, the remainder holds zero, and the whole balance is the fee.

```text
[fee-uses-whole-balance]
kind = reveal
window = window-genesis
v = 33036375802978007
out = 0
remainder = 0
fee = 33036375802978007
valid = yes
burned = 30033068911798188
tip = 3003306891179819
minted = 0
```

One wei less and the fee is above the balance: the remainder would be
negative, no valid proof exists, and the transaction is rejected (spec 03,
section 7, step 10). The commitment can be revealed only in a window whose fee
it covers.

```text
[fee-above-balance]
kind = reveal
window = window-genesis
v = 33036375802978006
out = 0
remainder = 0
fee = 33036375802978007
valid = no
burned = 0
tip = 0
minted = 0
```

**Two competing reveals.** Two holders of the same digits reveal the same
1 GHOST commitment in the same window: reveal `a` sends 0.5 GHOST and reveal `b`
0.3 GHOST. Each conserves value on its own, and both carry the same marker.
Reveal `a` reaches the pool first: it is admitted, `b` is refused at section 6,
step 6, and `a` is included. Only `a`'s amount is minted, and spec 03's
`total_out` grows by `a`'s `out` plus the fee. Had `b` reached a miner first,
`b` would be the one included and `a` rejected; the first to reveal wins
(outline, "Phantom Keys").

```text
[competing-reveals]
kind = competing
window = window-genesis
v = 1000000000000000000
fee = 33036375802978007
marker_a = m
marker_b = m
out_a = 500000000000000000
remainder_a = 466963624197021993
out_b = 300000000000000000
remainder_b = 666963624197021993
first = a
included = a
rejected = b
minted = 500000000000000000
total_out_change = 533036375802978007
```

## 8. Properties

These must always hold. Each is numbered so that a test can cite it, and each
names how a test checks it. A test that still passes with the check it names
removed does not count (spec 03, section 10).

- **PT-1. One size.** Every private transaction is exactly `ENVELOPE_BYTES`
  long. Check: a valid transaction with one byte added or removed, at the end
  or inside the proof field, is rejected at decoding; transactions with
  `out = 0` and `out > 0` have the same length.
- **PT-2. No sender.** The node recovers no sender, checks no nonce or balance
  and debits no account for a private transaction. Check: a valid reveal is
  included in a test state where no account but the block finder holds any
  balance, and its state diff touches only the recipient, the finder and the
  reserved accounts of spec 05.
- **PT-3. One encoding per proof.** A proof field with a non-zero padding byte
  is rejected. Check: set the last byte of a valid transaction's proof field to
  `0x01`; it is rejected and nothing applies.
- **PT-4. Every payload field is bound.** Every payload field except the proof
  is a field of the coin reveal binding, and the node supplies the rest.
  Check: change each payload field of a valid transaction in turn; each change
  is rejected (spec 02, PS-7).
- **PT-5. The fee is the formula's.** A transaction is valid only if its fee
  equals the fee of section 4 for the including block. Check: the same reveal
  with the fee one wei higher and one wei lower is rejected before the proof is
  verified (spec 03, CR-8).
- **PT-6. The fee is constant in a window.** Every block of a window has the
  same fee, and the fee is computable from the parent of the window's first
  block. Check: compute the fee from headers alone for each block of a window
  and compare with the node's value.
- **PT-7. The fee never undercharges.** `G_PRIV` times every block's base fee
  is at most the window's base-fee part. Check: the growth example of section 5
  and a randomised test over gas limits from `MIN_GAS_LIMIT` upwards with every
  block full.
- **PT-8. A lapsed fee is rejected.** A transaction proven for one window is
  rejected in a later window whose fee differs. Check: the lapse examples of
  section 5.
- **PT-9. Burn and tip.** A valid reveal burns exactly the base-fee part and
  credits exactly the tip to the block finder, and the tip is the same for
  every private transaction in the block. Check: the boundary examples of
  section 7; the finder's balance grows by the tip and the public supply falls
  by the base-fee part.
- **PT-10. The user does not choose the fee.** No field, option or wallet input
  changes the fee of a valid transaction. Check: the fee field is the only fee
  field, and PT-5's test rejects every other value.
- **PT-11. One per marker.** The pool holds at most one transaction per marker,
  the first admitted, and a block holds at most one. Check: the competing
  example of section 7, against the pool and against a block holding both.
- **PT-12. Cheap checks first.** No proof is verified for a transaction that
  fails a size, chain, fee, root, marker or room check. Check: count proof
  verifications while sending 1,000 transactions that each fail one cheap
  check; the count is zero.
- **PT-13. Pool caps and peer budgets hold.** The pool never exceeds
  `POOL_MAX_COUNT` or `POOL_MAX_BYTES`, and a peer that sends a second failed
  proof within 1,024 blocks is disconnected. Check: flood the pool with valid
  and invalid transactions from several peers.
- **PT-14. Full recheck.** After every new head the pool holds no transaction
  that fails steps 2 to 6 or 9 of section 6 against it. Check: spec 05, TH-16
  and TH-17, and a window change with a pending lapsed transaction.
- **PT-15. Data reveals stay rejected.** No private transaction carries a data
  reveal in version 1. Check: a type `0x50` transaction with any other
  `version` is rejected, and a data reveal built to spec 04 has no encoding to
  submit (spec 02, PS-20).

## 9. Not settled: fail closed

Each point rejects until the founder or a later specification settles it.

1. **The longest proof.** Settled (founder decision, 2026-10-18): `PROOF_BYTES`
   is 1,310,720 bytes for every reveal kind, above the bound of 1,053,331
   bytes derived from the proof's structure for any trace within the budget
   (section 3, "Proof field"). Every proof the prover makes therefore fits,
   and the prover refuses a statement over the budget. A change of width is a
   new `version`, never an edit of version 1. The item keeps its number so
   that the items below keep theirs.
2. **Fee of a data reveal.** Unsettled (spec 04, question 1). Version 1 has no
   data reveal; every data reveal is rejected.
3. **Receipt layout.** The receipt's fields beyond its type and cumulative gas
   used are for the transaction-format work on receipts (spec 05, section 12,
   item 5 limits its logs). Until fixed, no block with a private transaction is
   valid.
4. **Reserved accounts.** The tree-state and marker-set accounts are not fixed
   (spec 05, section 12, item 2). Until they are, no reveal is valid.

## 10. Conflicts with other chapters

This document does not edit other chapters. Where they differ from it, the
difference is listed here for the founder's review.

1. **Type tag and rule set by the transaction.** [Spec 02](02-proof-statements.md),
   section 4 lists `type` ("Transaction, must be `COIN`") and `rule`
   ("Transaction, must be the empty rule") as read from the transaction. By
   front desk decision the payload has neither; the node supplies `COIN` and
   the empty rule (section 3). The proof is the same; spec 02's section 13,
   item 5 ("fields map one to one onto the binding layout") holds for the
   fields the payload has.
2. **Version set by the node.** Spec 02, section 4 lists `version` as set by
   the node. Here it is also a payload field, which the node checks equals its
   own value before using it.
3. **The type check.** [Spec 03](03-coin-rules.md), section 7, step 3 checks a
   type tag carried in the transaction. Here the type byte `0x50` and
   `version` `0x0001` mean the coin reveal, so step 3 becomes part of
   decoding.
4. **The fee is not the block's base fee.** Spec 03, section 7, step 5 says the
   fee is "base fee plus the fixed private tip" for the block. Here the
   base-fee part is `G_PRIV` times the window's price (section 4), which is at
   least `G_PRIV` times the block's base fee and usually more; all of it is
   burned.
5. **Fee field set by the node.** Spec 02, section 4 says `fee` is set by the
   node's formula for the block. Here it is a payload field that must equal the
   formula's value, and the formula is per window; every block of a window has
   the same value, so the bound fee is still the block's.
6. **Data reveal shape.** [Spec 04](04-data-commitments.md), section 6, step 1
   proposes that a data reveal be the same private type with the amount-out and
   remainder fields zero. Version 1 here has no type or purpose field, so a data
   reveal has no encoding; the outcome (every data reveal rejected) is the same
   as spec 04's default until question 1 is settled, and any later layout must
   have the same size.
7. **Public input size.** Decision 0003 counts 164 bytes of public inputs next
   to the proof. The payload carries 346 bytes besides the proof, because it
   also carries the note and fixed-width amount words.
8. **Proof field width.** Decision 0003 ("Cost on the chain") pads a proof to
   1,028,144 bytes, from its benchmark statement of 1,024 rows by 3,271
   columns. The coin reveal that shipped is 2,048 rows by 3,808 columns and
   its proofs do not fit that width, so this document sets 1,310,720 bytes
   (section 3, "Proof field"). Decision 0003 and the benchmark results record
   the earlier figure as history and are not edited.

## 11. Questions for the founder

Each has a default that this document already applies.

1. **One private transaction per block.** At the public byte price, `G_PRIV`
   is more than half of the default gas limit of 30,000,000, so a block holds
   one private transaction. A higher gas limit or a lower byte price for
   private transactions would change it; the move to blowup 2^3 (decision
   0003) does not, because the proof field keeps its width. Default: the
   public byte price and the gas limit of spec 05.
2. **Window length.** Four blocks. Default: 4.
3. **Tip.** One tenth of the base-fee part, rounded up. Default: one tenth.
4. **Pool caps and peer budgets.** 16 transactions; one pending and four
   verifications per peer per block; disconnect at a second failed proof
   within 1,024 blocks. Default: as stated.

## 12. Checking this document

Run

```sh
python3 scripts/check_private_transaction.py
```

from the repository root. It uses Python's standard library only and exits
nonzero on any gap. It checks that the required sections are present and
numbered without gaps; that the parameter table holds every constant, the type
byte is not one of Ethereum's, `PROOF_BYTES` is the version 1 width of
1,310,720, and the payload size, envelope size, `G_PRIV`
and the pool's byte cap equal their recomputed values; that the payload table
lists exactly the fields of section 3 in order, contiguous, at their widths,
with no sender, signature, nonce or gas field, and adds up to the stated fixed
size; that every field of the coin reveal binding is mapped and every payload
field but the proof is bound; that every worked example (the window fees and
window-length ratios, the worst-case growth, the lapses, each boundary case and
the competing reveals) is right; that the properties are numbered PT-1 upwards
without gaps and each names its check; and that the conflicts name spec 02,
03 and 04. `scripts/test_check_private_transaction.py` damages each part and
expects the check to fail.

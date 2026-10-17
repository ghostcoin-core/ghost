# Specification 02: proof statements

Status: draft for the founder's review, 2026-10-17. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the [outline](../ghost-outline.md) ("Core
protocol", "Coin rules", "Transactions and fees"), the base client plan
(section 7.3), the [commitments and keys](01-commitments-and-keys.md), the
[coin rules](03-coin-rules.md), the [data commitments](04-data-commitments.md)
or the [threat model](../threat-model.md), and is cited to it, not decided
again here. Where a point is not settled, the check rejects (fails closed), as
in spec 04, and the point is listed in section 13.

This document fixes what each proof proves. The old design's reveal publicly
named the commitment it spent, so anyone could put a commit and its reveal side
by side. The statements here never do that: a one-time reveal publishes a
one-time marker that only the digits can compute, and a proof of holding
publishes no value tied to the commitment at all. For each statement this
document lists every public input and why it does not link to the commit, every
private input, and the constraints. It then fixes the binding digests that tie
a proof to its purpose, the shared tree state a wallet proves against, the
conservation of value, the one encoding of amounts, and the properties and
adversarial vectors that tests check. Section 16 names the script that checks
the structure of this document.

It does not redefine the commitment format, the tags or the key derivation;
those are fixed by [spec 01](01-commitments-and-keys.md) and used here by name.
It chooses nothing inside the proof system beyond what the statements need.

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Statements | Three: S1 one-time reveal of a coin, S2 one-time reveal of data (reveal or revoke), S3 proof of holding (data, and coins once settled) | Outline ("Core protocol" 5); spec 04 |
| What a reveal publishes | A one-time marker computed from the reveal secret and blinding, never the commitment, its fingerprint or its position | Outline (core requirement 3); spec 01, section 3 |
| What a proof of holding publishes | Nothing tied to the commitment: no marker, no commitment, no position | Spec 04, section 5 |
| Binding | One binding digest per statement, computed by the node or verifier from its own values, never taken from the prover | Outline ("Core protocol" 10); base client plan 7.3; spec 03, section 7, step 6 |
| Binding layouts | Fixed-width fields in a fixed order under the three binding tags of spec 01 | **Proposed** (section 7) |
| Domain tag | The genesis block hash of the chain | **Proposed** (question 1) |
| Tree state | A shared epoch root, never the root of the block that added the wallet's own leaf | Outline ("Core protocol" 10); epoch rule **Proposed** (question 4) |
| Conservation | `v = out + v' + fee` over the integers, on every coin reveal, including the full reveal | Outline ("Coin rules"); spec 03, section 7 |
| Amount encoding | One 32-byte big-endian word for Go, the wire, the binding digest and the proof; valid only below `2^96` | **Proposed** (section 10) |
| Range constraints in the proof | Six 16-bit limbs per amount, limb-wise conservation with bounded carries | **Proposed** (section 10, question 6) |
| Remainder note | Bound by the coin reveal's binding digest | **Proposed** (question 3) |
| Proof of holding for coins | Same statement with `COIN`; rejected until the founder settles it | **Proposed** (fail closed, question 2) |
| Spent-marker-set non-membership | Required by S3; its set structure belongs to the tree and header specification; until then every proof of holding is rejected | Fail closed (spec 04, question 2) |

## 2. Conventions

The conventions of [spec 01](01-commitments-and-keys.md), section 2, apply:
`K(tag, ...)` is tagged Keccak-256, `||` is concatenation, integers are unsigned
big-endian at the stated width, `COIN` and `DATA` are the type tags of version
1, and "reject" means the value or transaction is invalid and changes no state.
In addition:

- **Amount word.** Every amount (`v`, `out`, `v'`, `fee`) is carried as a
  32-byte big-endian unsigned integer, the amount word of section 10.
  `V_MAX = 2^96 - 1` ([spec 03](03-coin-rules.md), section 2).
- **Chain constants.** `chain_id` is the chain identifier as 8 bytes, as in the
  note's associated data (spec 01, section 9). `version` is the protocol
  version as 2 bytes, `0x0001` for version 1 (**Proposed**). `domain` is the
  domain tag, 32 bytes: the hash of this chain's genesis block (**Proposed**,
  question 1). A node or verifier always uses its own values of all three.
- **Statement codes.** `statement` is one byte: `0x01` for S1, `0x02` for S2,
  `0x03` for S3. `statement_version` is one byte, `0x01` for this document.
  Together they are the "transaction type and version" of
  [spec 03](03-coin-rules.md), section 7, step 6.
- **Purpose codes.** `purpose` is one byte: `0x01` spend (S1), `0x02` reveal
  (S2), `0x03` revoke (S2), `0x04` hold (S3). `0x00` and every other value are
  rejected wherever a purpose is checked.
- **Public input** is a value the verifier of the proof knows and checks: it is
  in the transaction, or the node or verifier supplies it. **Private input** is
  a value only the prover knows; the proof shows it exists without showing it.
- **Prover** is the wallet that holds the digits. **Verifier** is the node for
  S1 and S2 and whoever checks a proof of holding for S3 (spec 04, section 2).
- **Tree depth.** Both trees have 2^32 leaves, so a membership path has 32
  sibling hashes and a position of 32 bits (spec 01, section 4, "Tree nodes").

## 3. What every statement shares

Every statement opens one commitment, shows that it is a leaf of the tree of
its type, computes its marker inside the proof, and is tied to its purpose by a
binding digest. These parts are the same in all three statements.

1. **Opening, in two steps.** The prover knows `s`, `r`, `b`, `cf` and `rule`
   (and `v` for a coin) such that the fingerprint and the commitment are built
   exactly as in spec 01, section 3: `F = K("ghost/coin-fingerprint/v1", ...)`
   and `C = K("ghost/coin-commitment/v1", COIN, F, v)` for a coin;
   `F_d = K("ghost/data-fingerprint/v1", ...)` and
   `C = K("ghost/data-commitment/v1", DATA, F_d)` for data. The type tag inside
   both hashes is the statement's public `type`, so a data leaf never opens as
   a coin or the other way round. For `COIN`, `cf` is the constant 32 zero bytes
   (spec 01, section 3), not an input.
2. **Membership.** Starting from `C` at the private `position`, hashing with
   the private `path` level by level with the tree-node tag of the statement's
   type (`ghost/coin-tree-node/v1` or `ghost/data-tree-node/v1`, level byte 0 to
   31) gives the public `root`. `C` is never public.
3. **Marker.** `m = K("ghost/coin-marker/v1", r, b)` for a coin and
   `m = K("ghost/data-marker/v1", r, b)` for data, with the same `r` and `b`
   that open `C` in item 1. S1 and S2 publish `m`; S3 keeps it private and
   proves it is not in the spent-marker set.
4. **Binding.** The proof establishes `binding = K(tag, fields)` with the
   statement's binding tag and the field layout of section 7, over exactly the
   public inputs the node or verifier holds. The node or verifier computes
   `binding` itself from its own values and the transaction's fields, and never
   takes it from the prover.
5. **No secret leaves.** `s`, `r`, `b`, `cf`, `v`, `v'`, `position`, `path`,
   the remainder secrets, the digits, `k_note` and `k_data` are never public
   inputs. No statement takes the digits, `k_note` or `k_data` at all: they are
   derived off the proof with SHA3-256 (spec 01, section 7). The proof system's
   zero-knowledge mode is on (outline, "Cryptography").
6. **Fail closed.** A public input with an unknown type, purpose, statement
   code or version is rejected before any proof is verified. A point this
   document leaves open (section 13) rejects until it is settled.

## 4. Statement S1: One-time reveal of a coin

A coin reveal uses one coin commitment up, mints `out` to a public recipient,
pays the fee from inside the commitment, and creates exactly one remainder
commitment (outline, "Transactions and fees": "One private shape"). The node
checks it in the order of [spec 03](03-coin-rules.md), section 7. Its binding
tag is `ghost/coin-reveal-binding/v1`.

**Public inputs.** Every value the node reads from the transaction or
supplies itself. The commit, for comparison, published the sender, the burned
amount `v`, the fingerprint `F`, the leaf `C`, its position and the note `N`.

| Input | Width | Set by | Why it does not link |
|---|---|---|---|
| `chain_id` | 8 | Node | A chain constant, the same in every transaction on the chain |
| `version` | 2 | Node | A chain constant |
| `domain` | 32 | Node | A chain constant |
| `statement` | 1 | Node | `0x01`, the same in every coin reveal |
| `statement_version` | 1 | Node | `0x01`, the same in every coin reveal |
| `type` | 2 | Transaction, must be `COIN` | The same in every coin reveal |
| `purpose` | 1 | Node, `0x01` spend | The same in every coin reveal |
| `root` | 32 | Transaction, checked against a canonical header | The shared epoch root of section 8, used by every wallet that reveals in that window and never the root of the block that added the wallet's own leaf. The commit transaction does not contain it |
| `marker` | 32 | Transaction | `K("ghost/coin-marker/v1", r, b)` was never published before. It has a tag of its own, so it equals no `F`, `C` or tree node, and computing it from `F` or `C`, or `F` or `C` from it, needs `r` and `b` (preimage resistance, threat model A1) |
| `remainder` | 32 | Transaction | A new leaf `C'` built from fresh blinding `b'` (spec 01, section 8). It differs from `C` and from every earlier leaf, and hides `s'`, `r'`, `b'` and `v'` |
| `remainder_note` | 156 | Transaction | A new ciphertext under a fresh random nonce, unreadable without `k_note`, with the fixed length of every note (spec 01, section 9) |
| `recipient` | 20 | Transaction | Chosen by the user. The chain adds no link, but a recipient equal to the commit's sender correlates (outline, "Privacy claim": destinations can correlate) |
| `out` | 32 | Transaction | Chosen by the user. The chain adds no link, but amounts can correlate, most of all a full reveal whose `out` is the public commit amount minus the fee (outline, "Privacy claim") |
| `fee` | 32 | Node's fee formula for the block | The same for every private transaction in the block (outline, "Transactions and fees") |
| `rule` | 32 | Transaction, must be the empty rule | The empty rule is the only rule in version 1, so every coin reveal carries the same value |
| `binding` | 32 | Node, section 7 | A hash of the values above; it adds nothing they do not |

Nothing else is public. In particular the reveal never publishes `C`, `F`, the
position, `v`, `v'` or any value computed from them without the digits.

**Private inputs.**

| Input | Width | Meaning |
|---|---|---|
| `s` | 32 | Secret of the input commitment |
| `r` | 32 | Reveal secret of the input commitment |
| `b` | 32 | Blinding of the input commitment |
| `v` | 32 | Amount of the input commitment, an amount word |
| `position` | 4 | Position of `C` in the coin tree |
| `path` | 1024 | The 32 sibling hashes from `C` to `root` |
| `s'` | 32 | Secret of the remainder (equal to `s` by default, new for a claim) |
| `r'` | 32 | Reveal secret of the remainder (equal to `r` by default, new for a claim) |
| `b'` | 32 | Fresh blinding of the remainder |
| `v'` | 32 | Amount of the remainder, an amount word |

**Constraints.** The proof establishes all of them together:

1. `F = K("ghost/coin-fingerprint/v1", s, r, b, COIN, 0^32, rule)` and
   `C = K("ghost/coin-commitment/v1", COIN, F, v)` (section 3, item 1).
2. `C` is the leaf at `position` under `root` in the coin tree (section 3,
   item 2).
3. `marker = K("ghost/coin-marker/v1", r, b)` with the `r` and `b` of
   constraint 1.
4. `F' = K("ghost/coin-fingerprint/v1", s', r', b', COIN, 0^32, rule)` and
   `remainder = K("ghost/coin-commitment/v1", COIN, F', v')`: the remainder
   keeps the input's type tag, `cf` and `rule` ([spec 03](03-coin-rules.md),
   section 8). `s'`, `r'` and `b'` are otherwise unconstrained, so the chain
   cannot tell a claim from a partial reveal.
5. `v`, `out`, `v'` and `fee` are amount words below `2^96` (section 10).
6. `v = out + v' + fee` over the integers (section 9).
7. `binding` is the coin reveal binding of section 7 over the public inputs.

Steps 1 to 9 and 11 to 13 of spec 03, section 7 are the node's checks around
this proof; constraint 7 is what makes its step 6 effective.

## 5. Statement S2: One-time reveal of data

A data reveal uses one data commitment up with the reveal or the revoke purpose
([spec 04](04-data-commitments.md), sections 6 and 7). It mints nothing,
creates no remainder and carries no amount out. Its binding tag is
`ghost/data-reveal-binding/v1`.

**Public inputs.**

| Input | Width | Set by | Why it does not link |
|---|---|---|---|
| `chain_id` | 8 | Node | A chain constant |
| `version` | 2 | Node | A chain constant |
| `domain` | 32 | Node | A chain constant |
| `statement` | 1 | Node | `0x02`, the same in every data reveal |
| `statement_version` | 1 | Node | `0x01`, the same in every data reveal |
| `type` | 2 | Transaction, must be `DATA` | The same in every data reveal |
| `purpose` | 1 | Transaction, `0x02` reveal or `0x03` revoke | One of two values, shared by every data reveal of that purpose |
| `root` | 32 | Transaction, checked against a canonical header | The shared epoch root of the data tree (section 8), never the root of the block that added the wallet's own leaf |
| `marker` | 32 | Transaction | `K("ghost/data-marker/v1", r, b)`, never published before and not computable from `F_d` or `C` without `r` and `b`, as for S1 |
| `party` | 32 | Transaction | The verifier or recipient the ticket is for, or zero for none (spec 04, section 6). Chosen by the user; nothing is credited to it |
| `fee` | 32 | Node | Not settled; every data reveal is rejected at spec 04, section 6, step 6 until it is |
| `rule` | 32 | Transaction, must be the empty rule | The same in every data reveal of version 1 |
| `binding` | 32 | Node, section 7 | A hash of the values above |

The data reveal never publishes `C`, `F_d`, `cf`, the position, the data, the
data key or any part of it (spec 04, section 6).

**Private inputs.**

| Input | Width | Meaning |
|---|---|---|
| `s` | 32 | Secret of the data commitment |
| `r` | 32 | Reveal secret of the data commitment |
| `b` | 32 | Blinding of the data commitment (`b_0`, spec 01, section 8) |
| `cf` | 32 | Content fingerprint |
| `position` | 4 | Position of `C` in the data tree |
| `path` | 1024 | The 32 sibling hashes from `C` to `root` |

**Constraints.**

1. `F_d = K("ghost/data-fingerprint/v1", s, r, b, DATA, cf, rule)` and
   `C = K("ghost/data-commitment/v1", DATA, F_d)`.
2. `C` is the leaf at `position` under `root` in the data tree.
3. `marker = K("ghost/data-marker/v1", r, b)` with the `r` and `b` of
   constraint 1.
4. `binding` is the data reveal binding of section 7 over the public inputs,
   including `purpose`, so a reveal cannot be passed off as a revocation or the
   other way round.

No constraint ties `fee` to a value inside the commitment, because a data
commitment holds none. That is why the node rejects every data reveal at the
fee step until the founder settles where its fee comes from (spec 04,
question 1). There is no conservation constraint: nothing goes in and nothing
comes out.

## 6. Statement S3: Proof of holding

A proof of holding shows that the prover holds a commitment that has not been
used up, without using it up, any number of times, on or off the chain
(outline, "Core protocol" 5; [spec 04](04-data-commitments.md), section 5). It
publishes no marker and writes no state. Its binding tag is
`ghost/hold-binding/v1`.

The statement is the same for both types. **Proposed:** version 1 accepts it
for `DATA`; for `COIN` it is rejected until the founder settles question 2,
and in both cases it is rejected until the spent-marker-set structure and its
place in the header are fixed (section 13).

**Public inputs.**

| Input | Width | Set by | Why it does not link |
|---|---|---|---|
| `chain_id` | 8 | Verifier | A chain constant |
| `version` | 2 | Verifier | A chain constant |
| `domain` | 32 | Verifier | A chain constant |
| `statement` | 1 | Verifier | `0x03`, the same in every proof of holding |
| `statement_version` | 1 | Verifier | `0x01` |
| `type` | 2 | Proof, `DATA` (or `COIN` once settled) | The same in every proof of holding of that type |
| `purpose` | 1 | Verifier, `0x04` hold | The same in every proof of holding |
| `root` | 32 | Verifier, from a header it trusts | The shared epoch root of the tree of `type` (section 8), the same for every prover in that window |
| `marker_set_root` | 32 | Verifier, from the same header | The root of the spent-marker set of `type`, a chain-wide value |
| `verifier` | 32 | Verifier | The verifier's own identity; it names the verifier, not the commitment |
| `challenge` | 32 | Verifier, fresh and random | Chosen by the verifier, at least 256 bits from a secure random source (spec 04, question 7) |
| `binding` | 32 | Verifier, section 7 | A hash of the values above |

Two proofs of holding of the same commitment share no public value except the
tree state, the chain constants and what the verifiers chose. Neither shares a
value with the commit or with a later reveal: the marker stays private.

**Private inputs.**

| Input | Width | Meaning |
|---|---|---|
| `s` | 32 | Secret of the commitment |
| `r` | 32 | Reveal secret of the commitment |
| `b` | 32 | Blinding of the commitment |
| `cf` | 32 | Content fingerprint (`DATA`); 32 zero bytes for `COIN` |
| `v` | 32 | Amount (`COIN` only); no amount is claimed or published |
| `rule` | 32 | Rule of the commitment |
| `position` | 4 | Position of `C` in the tree of `type` |
| `path` | 1024 | The 32 sibling hashes from `C` to `root` |
| `marker` | 32 | The commitment's own marker, computed in the proof |
| `absence` | set-defined | The witness that `marker` is not in the set under `marker_set_root` |

**Constraints.**

1. `C` is opened as in section 3, item 1, with the public `type`.
2. `C` is the leaf at `position` under `root` in the tree of `type`.
3. `marker` is computed from the `r` and `b` of constraint 1 with the marker tag
   of `type` (section 3, item 3).
4. `marker` is not in the spent-marker set of `type` under `marker_set_root`,
   shown with `absence`. The non-membership concerns exactly the marker of the
   commitment opened in constraint 1, so a proof never rests on "some marker is
   unspent" (spec 04, section 5, item 2).
5. `binding` is the hold binding of section 7 over the public inputs.

The verifier makes the checks of spec 04, section 5, in that order, with both
roots taken from one header it trusts. An on-chain verifier is a contract that
checks the proof through the chain's verifier; it uses its own address, padded
to 32 bytes on the left with zeros, as `verifier`. How it issues a challenge is
for the transaction-format specification.

## 7. Purpose binding

A proof is bound to its purpose so that a captured proof cannot be replayed or
redirected (outline, "Core protocol" 10). Each statement has one binding digest
under its own tag from [spec 01](01-commitments-and-keys.md), section 4, over
fixed-width fields in a fixed order, so no field can shift into another. The
proof of holding is bound to the verifier, the chain and a verifier-chosen
challenge; the one-time reveal is bound to its destination, amount and fee, and
to everything else the node executes.

The rule is the same for all three: **the node or verifier computes the digest
itself from its own constants and the transaction's fields**, and verifies the
proof against its own value. A digest supplied by the prover is never read.
Whatever the node executes (who is credited, how much, the fee, which leaf is
appended with which note, which marker is recorded, under which rule) is a field
of the digest; the node executes no field that is not in it (base client plan
7.3).

These are the binding mistakes the layouts avoid:

- **A field left out.** A proof that does not bind the fee, the chain or the
  remainder can be resubmitted with that field changed. Every executed field
  is in the digest (property PS-7).
- **A digest taken from the sender.** The sender could pair a valid proof with
  any fields. The node computes it (PS-6).
- **A value reduced before it is bound.** An address or amount folded into a
  smaller field lets two different values bind the same. Every field here is a
  fixed number of bytes, and an amount word with any of its high 20 bytes set
  is rejected (section 10).
- **One digest for two purposes.** Each statement has its own tag, statement
  code and purpose code, so a digest made for one cannot verify another
  (PS-23).

### Coin reveal binding

`binding = K("ghost/coin-reveal-binding/v1", fields)`, with the fields in this
order:

| Offset | Width | Field | Value |
|---|---|---|---|
| 0 | 8 | `chain_id` | This chain's identifier |
| 8 | 2 | `version` | `0x0001` |
| 10 | 32 | `domain` | Genesis block hash |
| 42 | 1 | `statement` | `0x01` |
| 43 | 1 | `statement_version` | `0x01` |
| 44 | 2 | `type` | `COIN` |
| 46 | 1 | `purpose` | `0x01` spend |
| 47 | 32 | `root` | Coin-tree root |
| 79 | 32 | `marker` | Coin marker |
| 111 | 32 | `remainder` | Remainder commitment `C'` |
| 143 | 20 | `recipient` | Address credited with `out` |
| 163 | 32 | `out` | Amount word |
| 195 | 32 | `fee` | Amount word |
| 227 | 32 | `rule` | Empty rule |
| 259 | 156 | `remainder_note` | The remainder's encrypted note |

Total: 415 bytes after the tag; 444 bytes with the tag; 4 Keccak permutations.

### Data reveal binding

`binding = K("ghost/data-reveal-binding/v1", fields)`:

| Offset | Width | Field | Value |
|---|---|---|---|
| 0 | 8 | `chain_id` | This chain's identifier |
| 8 | 2 | `version` | `0x0001` |
| 10 | 32 | `domain` | Genesis block hash |
| 42 | 1 | `statement` | `0x02` |
| 43 | 1 | `statement_version` | `0x01` |
| 44 | 2 | `type` | `DATA` |
| 46 | 1 | `purpose` | `0x02` reveal or `0x03` revoke |
| 47 | 32 | `root` | Data-tree root |
| 79 | 32 | `marker` | Data marker |
| 111 | 32 | `party` | Verifier or recipient, or zero |
| 143 | 32 | `fee` | Amount word |
| 175 | 32 | `rule` | Empty rule |

Total: 207 bytes after the tag; 236 bytes with the tag; 2 Keccak permutations.

### Hold binding

`binding = K("ghost/hold-binding/v1", fields)`:

| Offset | Width | Field | Value |
|---|---|---|---|
| 0 | 8 | `chain_id` | The verifier's chain |
| 8 | 2 | `version` | `0x0001` |
| 10 | 32 | `domain` | Genesis block hash |
| 42 | 1 | `statement` | `0x03` |
| 43 | 1 | `statement_version` | `0x01` |
| 44 | 2 | `type` | `DATA` (or `COIN` once settled) |
| 46 | 1 | `purpose` | `0x04` hold |
| 47 | 32 | `root` | Tree root of `type` |
| 79 | 32 | `marker_set_root` | Spent-marker-set root of `type` |
| 111 | 32 | `verifier` | Verifier identity |
| 143 | 32 | `challenge` | Verifier's challenge |

Total: 175 bytes after the tag; 197 bytes with the tag; 2 Keccak permutations.

**Cost.** The digests add 4, 2 and 2 permutations to proofs that already spend
about 40 (spec 01, section 4, "Cost"), within the measured margin of the
[benchmark results](../benchmarks/results.md).

## 8. Shared tree state

A wallet proves against a recent, widely shared tree state, never the one its
own commit created, because that value would appear in both transactions and
link them (outline, "Core protocol" 10; threat model C17). The root in the
header of the block that added a leaf is the first root that contains it; a
reveal against that root names the block of the commit.

**Rule (Proposed).** The wallet proves against the **epoch root**: the root of
the tree of its type in the header of the most recent canonical block whose
height `h` satisfies

```text
h mod 32 = 0   and   h <= tip - 12   and   h > h_leaf
```

where `tip` is the wallet's current best height and `h_leaf` is the height of
the block that added the wallet's leaf (the commit, or the reveal that created
the remainder). If no such block exists yet, the wallet waits. At 30-second
blocks a new epoch root appears every 16 minutes, so every wallet that proves
within one 16-minute window uses the same root, and no wallet ever uses the
root its own leaf's block created. The 12-block depth keeps the root on the
canonical chain through ordinary reorganisations.

- **The same rule for S1, S2 and S3.** For S3 the spent-marker-set root comes
  from the same header. A verifier that wants current status accepts the
  latest epoch root as current; a revocation therefore reaches verifiers after
  at most about 22 minutes (one epoch plus the depth), which is the price of a
  shared state.
- **Each hop.** A remainder is a new leaf with its own `h_leaf`, so a reveal of
  a remainder also never uses the root of the reveal that created it (outline,
  "First milestone" 7: three hops).
- **Who checks it.** The node cannot, because it never learns which leaf is
  opened; it accepts any canonical root of the right tree
  ([spec 03](03-coin-rules.md), question 4). The rule is the wallet's, and the
  linkage test (PS-18) checks it.
- **What it does not hide.** A root shared by many wallets protects only while
  many wallets reveal in the same window; with little traffic the anonymity set
  is small (threat model C17).

## 9. Conservation

Conservation is proven on every coin reveal (outline, "Coin rules"): the input
amount equals the amount out plus the remainder plus the fee,

```text
v = out + v' + fee
```

over the integers, never modulo a field. It holds in every case, including the
full reveal, where `v' = 0` and the remainder commitment still exists
([spec 03](03-coin-rules.md), section 8). The proof shows it with the limb
equations of section 10, which hold over the integers because no intermediate
value comes near the field's modulus.

| Case | `out` | `v'` | `fee` |
|---|---|---|---|
| Partial reveal | any up to `v - fee` | `v - out - fee` | formula |
| Full reveal | `v - fee` | 0 | formula |
| Zero-amount claim (new key) | 0 | `v - fee` | formula |
| Fee uses the whole balance | 0 | 0 | `v` |
| Fee above the balance | none | none | no valid proof exists |

A data reveal has no amounts and no conservation constraint (section 5). The
node's own accounting backstop ([spec 03](03-coin-rules.md), section 9) is
separate and does not replace this constraint.

The vectors below give `v`, `out`, `v'` (as `remainder`) and `fee` in wei and
whether a proof can exist. `scripts/check_proof_statements.py` recomputes each
with the integer rule and with the limb rule of section 10 and checks that both
agree with `valid`.

```text
[conservation-full-reveal]
kind = conservation
v = 1000000000000000000
out = 999979000000000000
remainder = 0
fee = 21000000000000
valid = yes

[conservation-partial-reveal]
kind = conservation
v = 1000000000000000000
out = 299979000000000000
remainder = 700000000000000000
fee = 21000000000000
valid = yes

[conservation-zero-amount-claim]
kind = conservation
v = 1000000000000000000
out = 0
remainder = 999979000000000000
fee = 21000000000000
valid = yes

[conservation-fee-uses-balance]
kind = conservation
v = 21000000000000
out = 0
remainder = 0
fee = 21000000000000
valid = yes

[conservation-largest]
kind = conservation
v = 79228162514264337593543950335
out = 79228162514264316593543950335
remainder = 0
fee = 21000000000000
valid = yes

[conservation-one-wei-more]
kind = conservation
v = 1000
out = 500
remainder = 480
fee = 21
valid = no

[conservation-field-wrap]
kind = conservation
v = 10
out = 20
remainder = 18446744069414584311
fee = 0
valid = no

[conservation-wrap-at-two-to-96]
kind = conservation
v = 5
out = 79228162514264337593543950335
remainder = 6
fee = 0
valid = no

[conservation-out-above-range]
kind = conservation
v = 79228162514264337593543950335
out = 79228162514264337593543950336
remainder = 0
fee = 0
valid = no
```

`conservation-field-wrap` is the example of spec 03, CR-7, with the modulus of
a 64-bit field (`2^64 - 2^32 + 1`): `20 + (p - 10) = 10` modulo `p`. Its
remainder is below `V_MAX`, so the range check alone does not catch it; the
integer equation does. `conservation-wrap-at-two-to-96` sums to `2^96 + 5`,
which a 96-bit wrapping sum would accept; the final carry rule rejects it.

## 10. Range and encoding of amounts

There is one encoding of an amount, shared by the wire, the Go node, the
binding digest and the proof (base client plan 7.3), so that the value the node
executes is the value the proof constrained.

**The amount word.** An amount is a 32-byte big-endian unsigned integer. It is
valid if and only if its first 20 bytes are zero, that is, it lies in
`[0, V_MAX]` with `V_MAX = 2^96 - 1`.

- **On the wire and in the digest** the amount is these 32 bytes, unchanged.
- **In the Go node** it is read into the base client's 256-bit unsigned integer
  type, never a signed or 64-bit type. The node rejects a word with any of its
  first 20 bytes set at the encoding step, before any arithmetic or lookup
  ([spec 03](03-coin-rules.md), section 7, step 2). Sums such as `out + fee`
  are computed in 256 bits, and an overflow or underflow rejects.
- **In the proof** the word is the same 32 bytes that enter the binding
  digest. The statement constrains its first 20 bytes to zero and reads its
  last 12 bytes as six 16-bit limbs `a5 .. a0`, most significant first, each
  made of two bytes in `[0, 255]`. Arithmetic on amounts happens only on these
  limbs.

**Range constraint (Proposed).** Every amount word of a statement (`v`, `out`,
`v'` and `fee` in S1) has its high 20 bytes zero and its six limbs in
`[0, 2^16 - 1]`. So `v'` can never be negative and no amount can exceed
`V_MAX`.

**Conservation on limbs (Proposed).** With carries `c0 = 0` and, for limb
`j = 0 .. 5`,

```text
out_j + v'_j + fee_j + c_j = v_j + 2^16 * c_(j+1),   c_(j+1) in {0, 1, 2}
```

and the final carry `c6 = 0`. The left side is at most `3 * (2^16 - 1) + 2`,
below `2^18`, so each equation holds over the integers in any proof field
whose modulus exceeds `2^18`. Every field a hash-based proof system in
consideration uses (31-bit and 64-bit fields) does. The six equations with
`c6 = 0` are equivalent to `v = out + v' + fee` over the integers for amounts
below `2^96`.

**Fields other than amounts.** `recipient` is 20 bytes and enters the digest as
20 bytes; there are no other bits to set. `chain_id`, `version` and all codes
are fixed-width bytes. Hashes, roots and markers are 32-byte strings with no
modulus check (spec 01, section 12, item 2).

The vectors below show the word and the six limbs (in hex, most significant
first) of each amount, and whether the word is valid.
`scripts/check_proof_statements.py` recomputes the word and the limbs from
`value` and checks `valid`.

```text
[amount-zero]
kind = amount
value = 0
word = 0000000000000000000000000000000000000000000000000000000000000000
limbs = 0000 0000 0000 0000 0000 0000
valid = yes

[amount-one-ghost]
kind = amount
value = 1000000000000000000
word = 0000000000000000000000000000000000000000000000000de0b6b3a7640000
limbs = 0000 0000 0de0 b6b3 a764 0000
valid = yes

[amount-v-max]
kind = amount
value = 79228162514264337593543950335
word = 0000000000000000000000000000000000000000ffffffffffffffffffffffff
limbs = ffff ffff ffff ffff ffff ffff
valid = yes

[amount-two-to-96]
kind = amount
value = 79228162514264337593543950336
word = 0000000000000000000000000000000000000001000000000000000000000000
limbs = 0000 0000 0000 0000 0000 0000
valid = no

[amount-top-bit]
kind = amount
value = 57896044618658097711785492504343953926634992332820282019728792003956564819968
word = 8000000000000000000000000000000000000000000000000000000000000000
limbs = 0000 0000 0000 0000 0000 0000
valid = no
```

`amount-two-to-96` and `amount-top-bit` have all-zero limbs: a reader that kept
only the low 12 bytes would take them for zero, and a signed reader would take
the last one for a negative number. Both are rejected because their high bytes
are set.

## 11. Properties

These must always hold. Each is numbered so that a test can cite it, and each
names how a test checks it. A test that still passes with the check it names
removed does not count ([spec 03](03-coin-rules.md), section 10).

- **PS-1. A reveal shares no value with its commit.** No public input of S1 or
  S2 equals the commit's `F`, `F_d`, `C`, position, note or any value computed
  from them without the digits. Check: the linkage test pulls the raw commit
  and reveal transactions and finds no byte string of 16 bytes or more in both,
  apart from the whitelisted chain constants, codes and shared epoch root; it
  fails against a build whose reveal publishes `C`.
- **PS-2. Proofs of holding share nothing.** Two proofs of holding of one
  commitment, and a proof of holding and the later reveal of it, share no public
  value apart from the tree state, the chain constants and the verifiers'
  choices. Check: the linkage test of spec 04, section 9, over a commit, two
  proofs of holding and a revocation.
- **PS-3. One commitment, one marker.** The published marker is computed inside
  the proof from the `r` and `b` that open the leaf. Check: a prover run with a
  marker from another commitment, or from another `b`, fails to produce a proof
  that verifies.
- **PS-4. A marker is used once.** A marker already in the spent-marker set of
  the canonical chain, or used by an earlier transaction in the same block, is
  rejected. Check: spec 03, CR-6 and spec 04, CR-D7.
- **PS-5. Coin and data markers are apart.** Coin and data markers have
  different tags and separate spent-marker sets, so no marker counts in both.
  Check: a data marker recorded by a data reveal does not block a coin reveal,
  and a coin proof cannot be built whose marker equals a data marker for the
  same `r` and `b`.
- **PS-6. The node computes the digest.** The node and every verifier compute
  the binding digest from their own constants and the transaction's fields and
  never read one from the prover. Check: a transaction that carries a digest
  field is rejected at the shape check, and a proof made for a different digest
  fails.
- **PS-7. The proof authorises exactly what the node executes.** Every field the
  node acts on (recipient, out, fee, remainder, remainder note, marker, root,
  rule, type, purpose, chain identifier, protocol version, domain tag,
  statement code and version) is a field of the binding digest of section 7,
  and the node acts on no other transaction field. Check: changing any one
  field of a valid transaction, one at a time, makes it fail; the list of
  fields the apply step reads equals the layout.
- **PS-8. Chain, version and domain are bound.** A proof made with another
  `chain_id`, `version` or `domain` is rejected. Check: spec 03, CR-9; spec 04,
  CR-D16.
- **PS-9. Types do not mix.** S1 opens only a `COIN` leaf with the coin tags
  under a coin-tree root; S2 and S3 with `DATA` open only a data leaf with the
  data tags under a data-tree root; the empty leaf opens as neither. Check:
  spec 03, CR-4; spec 04, CR-D5 and CR-D6.
- **PS-10. Conservation holds on every coin reveal.** `v = out + v' + fee` over
  the integers, including the full reveal with `v' = 0`. Check: the
  conservation vectors of section 9; spec 03, CR-5 and CR-14.
- **PS-11. Every amount is in range.** `v`, `out`, `v'` and `fee` are each in
  `[0, V_MAX]`; no proof exists otherwise, and the node rejects an out-of-range
  public amount before the proof. Check: the amount vectors of section 10;
  spec 03, CR-1 and CR-7.
- **PS-12. One encoding.** The node, the digest and the proof read the same 32
  bytes for each amount and agree on its value. Check: for each amount vector,
  the Go node's parsed value, the proof's limbs and the digest input agree, and
  invalid words are rejected by both.
- **PS-13. Exactly one remainder, of the same kind.** Every coin reveal appends
  one remainder with the input's type tag, `cf` and `rule`, also when
  `v' = 0`. Check: a full reveal appends a leaf; a remainder built with another
  type tag or rule fails to verify.
- **PS-14. Data mints nothing.** A data reveal credits nothing, burns no
  committed value and appends no leaf. Check: spec 04, CR-D5.
- **PS-15. Holding uses nothing up.** A proof of holding publishes no marker,
  writes no state and can be repeated. Check: ten proofs of holding of one
  commitment all verify and leave the spent-marker set unchanged.
- **PS-16. Holding is bound to verifier, chain and challenge.** A proof of
  holding verifies only for the verifier identity, chain and challenge it was
  made for, and a verifier accepts each challenge it issued once. Check:
  spec 04, CR-D3, CR-D4 and CR-D16.
- **PS-17. Non-membership concerns the opened commitment.** The marker shown
  absent from the spent-marker set is the marker of the commitment opened in
  the same proof. Check: spec 04, CR-D2 and CR-D8.
- **PS-18. Shared tree state.** A wallet never proves against a root at or below
  the height of the block that added its own leaf, and proves against the epoch
  root of section 8. Check: across three hops (commit, partial reveal, reveal
  of the remainder), no reveal's root is the header root of the block that
  added the leaf it opens; the linkage test fails against a wallet that uses
  that root.
- **PS-19. Roots come from the canonical chain.** A root from a discarded
  branch, or from the other tree, is rejected. Check: spec 03, CR-10; spec 04,
  CR-D13.
- **PS-20. Unsettled points fail closed.** Every point of section 13 rejects
  until settled. Check: a data reveal that passes every other check is rejected
  at the fee step; a proof of holding for `COIN` is rejected; a proof of
  holding without a marker-set root from a trusted header is rejected.
- **PS-21. Only the empty rule.** Version 1 rejects any `rule` other than the
  empty rule in S1 and S2. Check: spec 03, section 7, step 11; spec 04,
  question 9.
- **PS-22. No secret is public.** No public input of any statement is `s`,
  `r`, `b`, `cf`, `v`, `v'`, a position, a path, the digits, `k_note` or
  `k_data`, and the proof system's zero-knowledge mode is on. Check: the public
  and private tables of each statement share no name (checked by the script
  of section 16), and the shipped configuration test confirms the mode.
- **PS-23. Purposes do not substitute.** A proof made for one statement or
  purpose (spend, reveal, revoke, hold) never verifies as another. Check: a data
  reveal resubmitted as a revocation, and a proof of holding submitted as a
  reveal, both fail; spec 04, CR-D16.
- **PS-24. The remainder and its note are bound.** A coin reveal whose
  remainder commitment or remainder note is replaced in transit fails. Check:
  replace the note of a valid reveal with another valid-length note; the
  transaction is rejected and nothing is applied.

## 12. Adversarial vectors

Each vector is an attack a test must run, the result it must get and the
properties it exercises. Every named vector of the base client plan 7.3 and of
threat model C16 and C22 is here.

- **AV-1. Recipient substitution.** An observer copies a valid coin reveal from
  the mempool and replaces `recipient` with its own address. Expected: the
  node's digest differs from the one the proof was made for, the proof fails,
  nothing is minted and the marker stays unspent (PS-6, PS-7; spec 03, CR-8).
- **AV-2. Fee substitution.** A miner or relay changes `fee` in a valid reveal,
  up or down. Expected: rejected at the fee check if it differs from the
  formula, and at the proof if the formula changed between proving and
  inclusion; no tip is paid (PS-7, PS-10; spec 03, CR-8).
- **AV-3. Cross-chain replay.** A valid reveal or proof of holding from a chain
  with another `chain_id` or `domain`, including a copy of the chain that kept
  the identifier, is submitted here. Expected: rejected at the chain check, and
  at the proof if the check were removed (PS-8).
- **AV-4. Cross-version replay.** A proof made under protocol version or
  statement version 1 is submitted to a node or verifier that runs another
  version, and the other way round. Expected: rejected at the version check and
  at the proof (PS-8, PS-23).
- **AV-5. Coin/data type confusion.** A data leaf is opened by S1; a coin leaf
  by S2 or S3 with `DATA`; a reveal claims `COIN` but proves against the
  data-tree root; a data marker is presented to the coin spent-marker set.
  Expected: rejected at the type check or root check before the proof, or at
  the proof; nothing minted (PS-5, PS-9, PS-14).
- **AV-6. Marker double use.** Two reveals of one commitment with the same
  marker, in one block and in two blocks; a reveal and a revocation of one data
  commitment; a second proof attempt with a marker of the prover's choosing.
  Expected: the second is rejected at the marker check and a block carrying it
  is invalid; a chosen marker cannot be proven (PS-3, PS-4).
- **AV-7. Overflow.** Amount words with any of the high 20 bytes set; `out` of
  `2^96`; a sum that wraps at `2^96`; the field-wrap remainder of section 9; a
  remainder that would be negative. Expected: rejected at the encoding check
  for public amounts and unprovable for private ones (PS-10, PS-11, PS-12).
- **AV-8. Remainder or note substitution.** A relay swaps the remainder
  commitment or the remainder note of a valid reveal for its own. Expected: the
  proof fails and nothing applies (PS-7, PS-24).
- **AV-9. Purpose substitution.** A data reveal is resubmitted as a revocation;
  a proof of holding is submitted as a data reveal; a purpose code of `0x00`
  or `0x05`. Expected: rejected at the purpose check or the proof (PS-23).
- **AV-10. Verifier substitution and challenge replay.** A proof of holding
  made for verifier X is shown to verifier Y; a proof is shown twice to the same
  verifier; a proof answers a challenge the verifier never issued. Expected:
  rejected by the verifier (PS-16).
- **AV-11. Linked tree state.** A wallet proves against the root of the block
  that added its own leaf. Expected: the linkage test finds the shared root
  and fails (PS-1, PS-18).
- **AV-12. Revoked commitment still held.** After a revocation, the holder
  proves holding against a spent-marker-set root that contains the marker, or
  opens another of its own commitments while presenting the revoked one.
  Expected: no proof exists, or it fails (PS-17).

## 13. Not settled: fail closed

Each point rejects until the founder or a later specification settles it.

1. **Fee of a data reveal.** Every data reveal is rejected at the fee step
   ([spec 04](04-data-commitments.md), question 1).
2. **Spent-marker-set structure and header root.** S3 needs non-membership
   under an authenticated set root taken from a header. The set's structure,
   its node hashes and tags, and whether its root is in the header belong to
   the tree and header specification. Until they are fixed, every proof of
   holding is rejected (spec 04, question 2).
3. **Proof of holding for coins.** S3 with `COIN` is rejected (question 2).
4. **Non-empty rules.** Rejected in S1 and S2 (spec 03, section 7, step 11;
   spec 04, question 9).
5. **Transaction encoding.** The exact bytes of a reveal transaction, its one
   size and where the proof sits are for the transaction-format specification.
   A transaction whose fields do not map one to one onto the binding layout of
   its statement is rejected.

## 14. Conflicts with other chapters

This document does not edit other chapters. Where they differ from it, the
difference is listed here for the founder's review.

1. **Fields of the coin reveal binding.** [Spec 03](03-coin-rules.md),
   section 7, step 6 lists the fields of the binding digest without the rule,
   the type tag, the purpose and the remainder note. Step 10 of the same
   section and base client plan 7.3 require the rule to be bound; this document
   binds all four (section 7).
2. **Fields of the data reveal binding.** [Spec 04](04-data-commitments.md),
   section 6 lists the data reveal's binding fields without the domain tag, the
   type tag and the rule. This document adds them.
3. **Width of the verifier or recipient field.** Spec 04, section 6 leaves the
   width open. This document uses 32 bytes for data (`party`) and the 20-byte
   address of spec 03 for the coin `recipient`.
4. **The field-wrap example.** Spec 03, CR-7 says the field-wrap reveal is
   rejected "by the range check on `v'`". That holds only for a field larger
   than `2^96`. In a 31-bit or 64-bit field the wrapped remainder can be below
   `V_MAX`; it is rejected by conservation over the integers (section 9,
   vector `conservation-field-wrap`). The outcome is the same; the reason
   differs.
5. **Canonical field elements.** Spec 03, section 6, step 4 and section 7,
   step 2 speak of field elements below the modulus. With Keccak-256 every
   value here is a byte string; the only canonical-form rule is the amount
   word's (section 10), as spec 01, section 12, item 2 already notes.
6. **Proof of holding for coins.** Spec 04, section 5 states the proof of
   holding for `DATA` only. This document writes one statement for both types
   and rejects `COIN` until settled.
7. **Spec 01 tag table.** The three binding rows of spec 01, section 4 leave
   their inputs to this document. Their sizes are 444, 236 and 197 bytes with
   the tag, at 4, 2 and 2 permutations (section 7); spec 01's table can take
   these when it is next revised.
8. **One private shape.** The outline gives every private transaction an
   identical size and shape. The coin and data bindings have different
   layouts; the transaction encoding must still give both the same size (spec
   04, section 6, step 1).

## 15. Questions for the founder

Each has a default that this document already applies.

1. **Domain tag.** The genesis block hash, so that a copy of the chain that
   keeps the chain identifier still gets different digests, or a fixed string?
   Default: the genesis block hash.
2. **Proof of holding for coins.** Should version 1 accept S3 with `COIN`
   (holding an unspent coin commitment without stating its amount)? Default:
   rejected.
3. **Binding the remainder note.** Binding the note costs one permutation and
   stops a relay from replacing it, which would hide the remainder from restore.
   Default: bound.
4. **Epoch length and depth.** 32 blocks and 12 blocks trade a wait of up to
   about 22 minutes against a larger shared set. Default: 32 and 12.
5. **Protocol version width.** Two bytes. Default: two bytes, `0x0001`.
6. **Limb width.** Six 16-bit limbs suit both 31-bit and 64-bit fields. A
   proof system with a field above `2^98` could check the sum directly. Default:
   16-bit limbs, whatever the field.

## 16. Checking this document

Run

```sh
python3 scripts/check_proof_statements.py
```

from the repository root. It uses Python's standard library only and exits
nonzero on any gap. It checks that every statement section lists public and
private inputs, with a reason for every public input and no name in both
tables; that every binding layout is contiguous, sums to its stated total and
holds the fields its statement must bind; that every binding tag is in the tag
table of [spec 01](01-commitments-and-keys.md); that the properties are
numbered PS-1 upwards without gaps and each names its check; that every named
adversarial vector has an entry citing existing properties; and that the
amount and conservation vectors are right.

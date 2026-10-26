# Specification 04: data commitments

Status: draft for the founder's review, 2026-10-17. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the [outline](../ghost-outline.md) ("Core
value proposition", "Core protocol", "Data storage", "Second milestone: data
lifecycle"), the [coin rules](03-coin-rules.md) or the
[threat model](../threat-model.md), and is cited to it, not decided again here.

This document fixes how a data commitment works from commit to revocation: its
type tag and content fingerprint, where the data lives and how it is
encrypted, what a proof of holding establishes, what a one-time reveal
publishes, how the holder revokes, and how the digits alone restore
everything. It names what each proof must establish and leaves the proofs'
internal constraints, tag strings and layouts to the proof-statement, key
derivation and transaction-format specifications (section 14). Where a point is
not settled, the check rejects (fails closed) and the point is listed in
section 13.

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Commitment format | The outline's one format with a type tag, the same as the coin's in [spec 03](03-coin-rules.md), without the amount | Outline |
| Data type | One type, `DATA` at the current version | **Proposed** (question 6) |
| Data and money | A data commitment goes only into the data tree, carries no amount the wallet chooses, burns the fixed reserve `DATA_RESERVE` at commit, never mints money, and is rejected at the coin reveal's type check | Outline; spec 03, section 3 and CR-4; reserve front desk decision, 2026-10-25 |
| Fee reserve | `DATA_RESERVE` = 2.5 x 10^17 wei (0.25 GHOST), a protocol constant: a data commit sends exactly it, the node burns it and binds it into the leaf | Front desk decision, 2026-10-25; size question 10 |
| Content fingerprint | A tagged hash over the plaintext bytes and their length, inside the commitment; the commit never publishes it, a data reveal publishes it and a proof of holding names it, each bound to it inside the proof, so anyone holding the bytes can check them | **Proposed**; question 8 |
| Where the data lives | Off the chain, wherever the user chooses; the chain never stores, checks or promises availability of it | Outline ("Data storage") |
| Encryption | Client-side, standard authenticated encryption under a data key derived from the digits with its own hash tag | Outline (second milestone 1); construction **Proposed** |
| What the chain holds | The commitment and the fixed-length encrypted note, nothing that unlocks the data | Outline |
| Storage location | Not in the commitment and not in the note | **Proposed** (question 5) |
| Proof of holding | Bound to the verifier, the chain, the data type, a verifier-chosen challenge and the content fingerprint; publishes no marker; repeatable | Outline ("Core protocol" 5 and 10); content fingerprint question 8 |
| Not-yet-revealed evidence | The proof of holding shows, inside the proof, that the commitment's marker is not in the spent-marker set under a root in a block header | **Proposed** (threat model, section 6 item 2; question 2) |
| One-time reveal | Publishes one marker, the content fingerprint and a node-computed binding digest; publishes no data, key, `F_d` or commitment; mints nothing | Outline; contents **Proposed**; content fingerprint question 8 |
| Remainder on a data reveal | None | **Proposed** (question 3) |
| Fee of a data reveal | The coin reveal's window fee and cover rule ([spec 07](07-private-transaction.md), section 5), paid out of the reserve, with `fee <= DATA_RESERVE`; the rest of the reserve is forfeited, credited to nobody, never refunded | Front desk decision, 2026-10-25 (question 1) |
| Revocation | A one-time reveal by the holder with the revoke purpose, settled like a reveal; afterwards every proof of holding that opens the revoked commitment against marker status that includes the revocation fails | Outline (second milestone 6); purpose tag **Proposed** (question 4) |
| Restore | The digits alone give the note key, the data key and the commitment; the wallet finds its note by bulk trial decryption | Outline; method **Proposed** |
| Lost host | The bytes are lost unless a copy exists; the commitment, marker status and proofs of holding still work | Outline ("Data storage") |
| Owner, pause switch, upgrade key | None, over any part of this | Outline ("Reference: old Specter code") |

## 2. Conventions

The conventions of [spec 03](03-coin-rules.md), section 2, apply: `H(tag, ...)`
is the tagged hash used inside proofs and trees, "type tag" is the commitment's
version and type, "marker" is the one-time marker, and "reject" means the
transaction is invalid and changes no state. In addition:

- **Digits** are the Phantom Key (outline, "Phantom Keys"). One set of digits
  controls one data commitment. Every secret named here is derived from the
  digits, each with its own hash tag (outline, "Core protocol" 10). How is for
  the key derivation specification; the names here are placeholders for
  distinct tags.
- **Data key** `k_data` is the symmetric key that encrypts the data.
- **Note key** `k_note` is the key that encrypts the note (outline, "Core
  protocol" 11).
- **Host** is wherever the user keeps the ciphertext: a disk, a cloud bucket, a
  public file network, a friend. The chain never names or contacts it.
- **Verifier** is whoever checks a proof of holding: a person, an agent, a
  service or a contract.
- **Spent-marker set** for data is the set of markers published by data
  reveals on the canonical chain. **Proposed:** it is kept apart from the coin
  spent-marker set, and data markers carry their own hash tag, so no marker can
  count in both.
- "Unlocks data" means any value that, alone or combined with others, lets
  someone decrypt the data or derive a key that does: the data key itself, any
  part or share of it, any wrapping of it, and any encryption of it under a key
  an observer can derive.

## 3. Type tag and content fingerprint

**Type tag.** A data commitment uses the outline's one commitment format with a
type tag ("Core protocol" 3), the same fields as a coin commitment in
[spec 03](03-coin-rules.md), section 5: a secret `s`, a separate reveal secret
`r`, random blinding `b`, a salt, the type tag, the content fingerprint and
the rule. This document adds one type: `DATA` (**Proposed**: the only data
type in the first version, question 6). A new data commitment is commitment
format version 2, type tag `0x02 0x02` ([spec 01](01-commitments-and-keys.md),
section 10). An unknown data type or an unknown version byte is rejected
wherever a type tag is checked, and never read with a guessed version.

**Commitment.** The wallet draws a fresh random 16-byte salt from its secure
random source for this commitment and computes the data fingerprint

```text
F_d = H(tag_data_fingerprint, s, r, b, salt, DATA, cf, rule)
```

with the tag `ghost/data-fingerprint/v2` (spec 01, section 3), and the commit
carries `F_d` and the salt. The salt is public: it is not a secret and is not
computed from the digits; it makes every data leaf a separate target, so one
guess at a key cannot be checked against every leaf at once (threat model,
C20). The data marker takes the same salt,
`K("ghost/data-marker/v2", r, b, salt)`. The node computes

```text
C = H(tag_data_commitment, DATA, DATA_RESERVE, F_d)
```

with `DATA` and `DATA_RESERVE` set by the node, and writes `C` as a leaf of the
data tree. This differs from the coin commitment of spec 03 in two ways: the
node's outer hash uses the data commitment tag and the `DATA` type, and the
amount in it is the constant `DATA_RESERVE`, not a value the wallet chooses
(the fee reserve, below). For the first version `rule` is the empty rule
(**Proposed**, as for coins in spec 03, section 2).

### The fee reserve

A one-time reveal pays a fee, and the outline takes that fee from the
commitment inside the proof, never from a public account ("Transactions and
fees"; "Reference: old Specter code"). A data commitment has no amount of its
own to pay from, so every data commit burns a small fixed reserve into the
commitment, and that reserve pays the reveal fee (section 6, "Fee settlement
at reveal and revoke"). Front desk decision, 2026-10-25.

**The constant.** The reserve is a protocol constant, the same for every data
commitment:

```text
DATA_RESERVE = 250,000,000,000,000,000 wei = 2.5 x 10^17 wei = 0.25 GHOST
```

It is sized from the genesis fee of a private reveal, 26,100,495,343,659,410
wei, about 0.0261 GHOST ([spec 07](07-private-transaction.md), section 4,
`window-genesis`): `DATA_RESERVE` is about 9.58 times that fee. The fee grows
with the base fee, so a data reveal or a revocation stays possible until the
base fee is about 9.6 times the genesis base fee; above that, a commitment
whose fee would exceed `DATA_RESERVE` cannot be revealed or revoked until the
base fee falls (section 6, step 6). Whether 0.25 GHOST is the right size is
question 10.

**The commit rule.** A data commit must send value exactly `DATA_RESERVE`. Any
other value, zero included, is rejected, as a coin commit's value is checked
(spec 03, section 6, step 6; section 4 below, commit check 1). The node burns
the value from the sender, credits it to nobody, adds it to `total_in`
(spec 03, section 9) and computes the leaf with `DATA_RESERVE` in the outer
hash. The amount is therefore bound by the node, not claimed by the wallet:
the only reserve that ever enters a data leaf is the one the node burned in
the same state change, and the wallet's `F_d` has no amount field to claim
another. "No amount" for data means no value the wallet chooses: the reserve
is a constant, burned at commit, and a data commitment never mints money.

**Why a constant.** A constant keeps the accounting exact: the hidden total
`total_in - total_out` stays equal to what the live commitments hold, the coin
amounts plus `DATA_RESERVE` for each data commitment not yet revealed or
revoked. And it leaks nothing: every data commitment holds the same amount, so
the commit's value says nothing about the data, its size or its owner beyond
"this is a data commit", which the entry point already shows. A reserve the
wallet chose would be either a hidden amount the data statement would have to
range-check and conserve, or a public one whose tiers set commitments apart.

**Format version.** `DATA_RESERVE` changes the node-computed outer hash of
`DATA`, so it is part of the commitment format. Nothing has launched and
version 1 is being removed, so the reserve re-sets data format version 2 (type
tag `0x02 0x02`, tags `v2`) rather than adding a version 3, on one condition:
no recorded network or fixture holds a version 2 data leaf made without the
reserve. The condition holds (checked 2026-10-25): the repository records no
proof or network fixtures, its test chain configuration holds no tree leaves,
and the only version 2 data leaves were the salted data vectors of
[spec 01](01-commitments-and-keys.md), section 14, and of
[spec 05](05-trees-and-headers.md), and values built inside tests, all now
recomputed with the reserve. So data format version 2 carries the reserve and
there is no data format version 3; the coin keeps version 2 unchanged. `DATA_RESERVE` belongs to the version: changing it later is a
new version, and existing leaves keep the reserve of theirs.

**Worked example: the commit.** Start from `total_in = 0` and
`total_out = 0`. A sender with public balance 1 GHOST makes a data commit with
value 250,000,000,000,000,000 wei:

```text
sender balance  1,000,000,000,000,000,000 -> 750,000,000,000,000,000 (plus the commit's own gas)
total_in        0 -> 250,000,000,000,000,000
total_out       0
hidden total    250,000,000,000,000,000 = 1 x DATA_RESERVE
leaf            C = H(tag_data_commitment, DATA, 250,000,000,000,000,000, F_d)
```

The same commit with value 249,999,999,999,999,999 wei, 250,000,000,000,000,001
wei or 0 is rejected, nothing is burned and no leaf is written.

**Never money.** A data commitment can never create money (outline, "Coin
rules"; [spec 03](03-coin-rules.md), section 3 and CR-4). It goes only into the
data tree, under its own hash tags, carries no amount the wallet chooses,
burns the constant reserve at commit and mints nothing: at reveal the reserve
pays the fee and the rest is forfeited, and nothing is ever credited to a
recipient. A data reveal presented to the coin reveal is rejected at the coin
reveal's type check (spec 03, section 7, step 3). Because the coin and data
outer hashes carry different tags, a leaf of one tree cannot be opened as a leaf
of the other without a collision of the tagged hash (threat model, A1).

**Content fingerprint (Proposed).** The wallet computes

```text
cf = H_content(tag_content_fingerprint, len(plaintext), plaintext)
```

over the plaintext bytes and their length in bytes. It is a tagged hash with
its own tag; whether it is the in-proof hash or a standard hash, and the exact
layout, are for the proof-statement specification. The ciphertext, the file
name, the size class, the host and the time of upload are not inputs, so the
same bytes give the same `cf` wherever they are stored. `cf` sits inside `F_d`,
and the commit never publishes it. A data reveal publishes it and a proof of
holding names it as a public input, each bound to it inside the proof
(sections 5 and 6; question 8), so anyone holding bytes can compute their
`cf` and check them against the reveal or the proof. It names the content,
not the commitment: every commitment of the same bytes has the same `cf`.

**What each party learns.**

- **A chain observer** (threat model, T1) sees the commit as a normal visible
  transaction: its sender, its time, the leaf `C`, the salt, and a note of the
  fixed length every note has. From these it learns nothing about the data, its
  fingerprint or its length, because `C` and `F_d` are hiding under `b` and the
  note is encrypted under a key it cannot derive.
- **A public host's readers** see a ciphertext and its length. They cannot tie
  it to `C` from its contents. The upload time and the commit time can still
  correlate, as amounts and timing can for coins (threat model, C31).
- **The host** learns the ciphertext length (the size class, if the wallet
  pads; section 4) and when and from where the ciphertext is stored and
  fetched. It learns nothing else without the digits.
- **Anyone shown the digits** (threat model, T6) learns everything: they derive
  the data key, decrypt, and can copy.

## 4. Off-chain storage

**Nothing that unlocks data is ever written to the chain.** No transaction, block,
event, receipt, note or state value carries the data key or anything that unlocks
data (section 2), in any form: plain, wrapped, split into parts, or encrypted
under a key an observer can derive. The chain holds the commitment and the small
fixed-length encrypted note, and nothing else (outline, "Data storage";
threat model, C32). This rules out the old design's split key, where one half
travelled to a contract in an ordinary transaction and stayed readable in
history after it was "deleted": a chain keeps every past transaction, so
nothing written to it can be taken back.

**Encryption (Proposed).** The wallet encrypts the data on the user's device
before it leaves, with a standard authenticated encryption scheme with a
256-bit key (outline, "Foundation": standard encryption; no new cryptography).

- The data key `k_data` is derived from the digits with its own hash tag. It is
  distinct from the note key, from `s`, `r` and `b`, from the marker and from
  every other derived value, and none of them can be computed from it.
  Derivation details are for the key derivation specification.
- One data key encrypts one plaintext. The nonce is chosen so it is never
  reused under that key; new data is a new commitment with new digits.
- The associated data binds the chain identifier, the protocol version and the
  `DATA` type tag, so a ciphertext made for one chain or type fails to decrypt
  as another.
- The wallet may pad the plaintext to a size class before encryption, so the
  host learns the class, not the exact length. Padding is not a fingerprint
  input.
- The data key protects the data only as well as the digits do: a ciphertext
  on a public host can be attacked offline by guessing digits (threat model,
  C20, C32).

**What the chain does not do.** The chain never stores, checks or promises the
availability of the ciphertext, and a commit does not contain a storage
location, a link or a host name. No node, contract or endpoint receives the
plaintext, the data key or the digits (outline, "Reference: old Specter code":
no service that receives a user's secrets).

**The note.** The note lets the digits recover the commitment's own details
(outline, "Core protocol" 11). It is encrypted under `k_note` and has the one
fixed length that every note has, coin or data, so its length is not a
fingerprint (threat model, C18). **Proposed:** for data it holds only what the
wallet cannot derive from the digits: the content fingerprint `cf`, the
plaintext length and the commitment's version, padded to the fixed length. It
never holds the data key, a part of it, or a storage location (question 5).

**Showing contents.** Showing data happens off the chain (outline, "Core
protocol" 7). **Proposed:** the holder gives the viewer the ciphertext and
`k_data`, never the digits. Because `k_data` is derived one way from the digits
and is distinct from `s` and `r`, the viewer can read the data but cannot make a
proof of holding, reveal or revoke (threat model, C14). The viewer can copy what
they read (section 10).

**Commit checks.** A data commit is a normal visible transaction to the chain's
data commit entry point. The node makes the checks of
[spec 03](03-coin-rules.md), section 6, steps 1 to 5 (ordinary validity, entry
and exact-length format, no final commitment and no type field, canonical
`F_d`, fixed note length), then:

1. **Reserve.** The transaction's value is exactly `DATA_RESERVE` (section 3,
   "The fee reserve"). Any other value, zero included, is rejected.
2. **Funds.** The sender's balance covers `DATA_RESERVE` plus the maximum gas
   cost, as spec 03, section 6, step 7.
3. **Tree room.** The data tree has room for one more leaf, as spec 03,
   section 6, step 8, with the same default until the rollover is specified.
4. **Compute and apply, all or nothing.** The node computes
   `C = H(tag_data_commitment, DATA, DATA_RESERVE, F_d)` and, in one state
   change, debits `DATA_RESERVE` from the sender and credits it to nobody,
   adds `DATA_RESERVE` to `total_in` (spec 03, section 9), appends
   `C` to the data tree, stores the note with it and writes the receipt (leaf
   `C`, tree index and position, and the note bytes; spec 05, section 8,
   item 5). If any part fails, none applies. The new data-tree root goes into
   the block header (outline, "Core protocol" 6).

## 5. Proof of holding

A proof of holding shows that the prover holds a data commitment that has not
been revealed, without using it up, any number of times, on or off the chain
(outline, "Core protocol" 5; "Agent readiness"). This section names what it
must establish; the constraints are for the proof-statement specification.

**Public inputs.** The data-tree root, the data spent-marker-set root, the
verifier's identity, the chain identifier, the protocol version, the `DATA`
type tag, the hold purpose tag, the challenge, the content fingerprint `cf` the
verifier asks about, and a binding digest over all of them. The verifier
computes the binding digest itself and never takes one from the prover.

**What the proof establishes.**

1. **Membership.** The prover knows `s`, `r`, `b`, the salt and `rule` such
   that `C`, built as in section 3 with type `DATA` and the public `cf`, is a
   leaf under the public data-tree root. The salt is a private input, never a
   public one: the commit published it, so showing it again would name the
   commitment. `cf` is public: the commitment's own content fingerprint must
   equal it, so the proof holds only for the content it was made for.
2. **Not used up (Proposed).** The marker derived from that same `C`'s secret
   parts, inside the proof, is not in the data spent-marker set under the
   public spent-marker-set root. Membership and non-membership are about one
   opened commitment in one proof, so access is never granted on the strength
   of "some marker was spent" or "some marker is unspent": the proof concerns
   exactly the commitment it opens, and a proof for commitment A says nothing
   about commitment B.
3. **Binding.** The verifier's identity, this chain's identifier and version,
   the `DATA` type tag, the hold purpose, the challenge and the content
   fingerprint enter the proof through the binding digest, so a proof made for
   one verifier, chain, purpose, challenge or content fingerprint fails for any
   other.
4. **Fresh answer.** The challenge is chosen by the verifier, not by the
   prover, and the proof answers it; a proof cannot be made before the
   challenge exists.

**What it does not do.** It publishes no marker, writes no state and does not
use the commitment up, so it can repeat any number of times. It reveals neither
`C` nor its position. Two proofs of holding of the same commitment share no
value except the public tree state, the chain constants, the content
fingerprint and anything the verifier chose (**Proposed**), so verifiers can
tell from the proofs only that they concern the same content, which any
commitment of those bytes shares, not that they concern one commitment.

**Verifier checks (Proposed order).** The verifier stops at the first failure.

1. The type tag is `DATA` at commitment format version 2, and the purpose
   is hold. Any other version byte is rejected.
2. The chain identifier and version are this chain's.
3. The challenge is one this verifier issued, has not been answered before, and
   has not expired under the verifier's own limit (question 7). A proof with
   a challenge the verifier did not issue, or one it already accepted, is
   rejected.
4. The verifier identity is the verifier's own.
5. The spent-marker-set root is taken from a block header on the chain the
   verifier trusts, at a height the verifier accepts as current. The data-tree
   root is taken from a header of the same chain at or below that height: the
   wallet's epoch root, or the final root of a full tree once the next tree has
   started (spec 02, section 8). The two need not come from one header, so a
   commitment in a full tree can still be checked against current revocation
   status (review 01, N2). A root seen only on a discarded branch is rejected
   (outline, "Core protocol" 9).
6. The verifier computes the binding digest, with the `cf` of the content it
   asks about, and checks the proof against it.

**Header-only verifiers.** The outline puts tree states in every header ("Core
protocol" 6) but does not say the marker set's root is there. **Proposed**, and
settled by front desk decision (2026-10-25): the data spent-marker-set root goes
into every header, as `dataMarkerRoot`
([spec 05](05-trees-and-headers.md), sections 6 and 10), so a header-only
verifier can check "not revealed" without asking an endpoint (threat model,
section 6 item 2). A verifier rejects any proof of holding whose
spent-marker-set root it cannot take from a header it trusts; a bare answer
from a node or endpoint is never enough (question 2). Until the proof circuit
checks the marker's absence under that root
([spec 02](02-proof-statements.md), S3, constraint 4), every proof of holding
is rejected.

**What it claims.** A proof of holding says "the prover held an unrevealed
`DATA` commitment to the content of fingerprint `cf`, unrevealed as of the
spent-marker-set state used, on the chain the verifier trusts, answering this
verifier's challenge", and nothing more. It does not say which commitment:
anyone who knows the content can make a data commitment of their own with its
`cf` and prove holding of it. So in version 1 a proof of holding is not a
capability for a particular resource; binding it to a
resource that the prover cannot make for itself belongs to the later layers of
granting access and delegation (outline, "Core protocol" 12; threat model,
section 6, item 11; review 01, F5 and N1). It does not say the data was never
viewed, never copied, or still available.

## 6. One-time reveal

A one-time reveal uses a data commitment up (outline, "Core protocol" 5). It is
a native private transaction with no account and no signature; the proof is the
authorization (spec 03, section 7). It is a single-use ticket (outline, "Agent
readiness"). The contents below are **Proposed** where the outline is silent.

**What it publishes.** One marker, the purpose tag (reveal or revoke), the
data-tree root, the verifier or recipient field, the fee, the `DATA` type tag,
the content fingerprint `cf` of the commitment, and the binding digest over
the chain identifier, protocol version, transaction type and version, purpose,
verifier or recipient field, root, marker, fee and `cf`. The verifier or
recipient field names who the ticket is for and may be zero for none; nothing
is credited to it. The proof shows that `cf` is the commitment's own, so
anyone holding the revealed bytes computes their `cf` (section 3) and compares
it: equal bytes match the commitment, other bytes do not (question 8).

**What it never publishes.** No data, no data key or part of one, no
commitment `C`, no position and no `F_d`. It mints nothing and creates no
remainder: the reserve pays the fee and the rest is forfeited, so there is no
value to carry (question 3; "Fee settlement at reveal and revoke", below).

**Order of checks.** The node stops at the first failure.

1. **Shape.** The private reveal type with the `DATA` layout at a supported
   version, of the exact size that version defines, with no sender, signature
   or account fields. **Proposed:** the same encoded size as the coin reveal,
   with the amount-out and remainder fields required to be zero.
2. **Encoding.** Every public input is canonical.
3. **Type.** The type tag is `DATA` at commitment format version 2. A `COIN`
   type or an unknown version byte is rejected here; a coin reveal follows spec 03, section 7.
4. **Chain, version and domain.** This chain's current values.
5. **Purpose.** The purpose is reveal or revoke. Any other value is rejected.
6. **Fee.** The fee is the coin reveal's, unchanged: it equals the window fee
   of [spec 07](07-private-transaction.md), section 4, for the including
   block's window or the window before it, and the cover rule of spec 07,
   section 5, holds for the including block (spec 03, section 7, step 5).
   Then one check the coin reveal does not have: `fee <= DATA_RESERVE`. A
   reveal or revocation that fails any of these is rejected here, before the
   proof is verified. The fee comes out of the commitment's reserve; no public
   account may pay it, because a public sender paying the fee on reveal is an
   old-design mistake (outline, "Reference: old Specter code").
7. **Binding digest.** The node computes it from the transaction's fields and
   uses its own value as the public input, never one taken from the sender.
8. **Root.** The data-tree root of an ancestor of the including block, which on
   the node's canonical chain is a block of that chain (spec 05, section 5). A
   coin-tree root, or a root seen only on a discarded branch, is rejected.
9. **Marker unused.** The marker is not in the data spent-marker set of the
   canonical chain, and no earlier transaction in the same block uses it.
10. **Proof.** The proof verifies against the public inputs. It establishes
    that the prover knows `r` and the other secret parts of a leaf `C` built as
    in section 3 with type `DATA` and the constant `DATA_RESERVE` (no new
    private input) under the public root, that the public marker
    is derived from that `C`'s secret parts and salt with the data marker tag
    (so one commitment has one marker), that the public `cf` is
    the content fingerprint inside that `C`, that the salt stays a private
    input, that the rule is the empty rule, and that the binding digest is the
    one in the public inputs.
11. **Apply, all or nothing.** In one state change: add the marker to the data
    spent-marker set; add `DATA_RESERVE` to `total_out` (spec 03, section 9);
    burn the base-fee part of the fee and pay the tip to the block finder, as
    for a coin reveal (spec 07, section 5, "The cover rule"); forfeit
    `DATA_RESERVE - fee`, credited to nobody; and write the receipt (marker,
    purpose, verifier or recipient field; the marker is what wallets take
    status from, spec 05, section 8). It carries no leaf and no note, because
    nothing is appended, and never the spent commitment `C`. Nothing is
    minted, nothing is credited to the verifier or recipient field, and
    nothing is appended to either tree. If any part fails, none applies. A
    reorganisation that removes the block reverts all of it together and makes
    the marker unspent again.

The marker rule is the coin's (spec 03, section 7, step 8; outline, "Core
protocol" 5): a marker is unique on the canonical chain, and a repeat is
rejected in the same block and in any later block. A reveal is final to the
degree that the chain is (threat model, section 6 item 3).

### Fee settlement at reveal and revoke

Front desk decision, 2026-10-25 (question 1). The reveal fee of a data
commitment is paid out of its reserve (section 3, "The fee reserve").

**The fee.** A data reveal's fee is the coin reveal's, unchanged: strict
equality with the window fee of [spec 07](07-private-transaction.md),
section 4, for the including block's window or the window before it, and the
cover rule of spec 07, section 5, for the including block. The data reveal
carries the same fee field, at the same position and size, as the coin reveal,
bound in the binding digest the same way. The node adds one check, before the
proof (step 6): `fee <= DATA_RESERVE`. The proof needs no new private input
and no remainder: the reserve is a constant inside `C`, and no part of it is
carried into a new commitment (question 3 stays).

**The accounting.** In the apply step (step 11) `total_out` grows by
`DATA_RESERVE`, the whole reserve, whatever the fee. Of it:

- the base-fee part of the fee is burned, as for a coin (spec 07, section 5,
  `burn = G_PRIV * max(price_w, beta)`);
- the tip, `fee - burn`, goes to the block finder, as for a coin;
- `DATA_RESERVE - fee` is forfeited: it leaves the hidden set with the rest
  and is credited to nobody.

So `burn + tip_paid + forfeit = DATA_RESERVE`, and the hidden total
`total_in - total_out` drops by exactly what the spent commitment held. Each
data commitment adds `DATA_RESERVE` to `total_in` once and to `total_out` at
most once, because its marker can be spent once.

**Revocation.** Revoke is a reveal with the revoke purpose, so it settles
identically: the same window fee and cover rule, the same `fee <= DATA_RESERVE`
check, `total_out` grows by `DATA_RESERVE`, the base-fee part is burned, the
tip goes to the finder and the rest is forfeited. A revocation never refunds,
to the holder or to anyone.

**Cost.** At the genesis fee, 26,100,495,343,659,410 wei, about 89.6% of the
reserve is forfeited per data commitment. The reserve is about 9.6 times that
fee so that a data reveal and a revocation stay possible until the base fee is
about 9.6 times the genesis base fee. A commitment whose current fee exceeds
`DATA_RESERVE` cannot be revealed or revoked until the base fee falls; it is
not lost, and its proofs of holding keep working.

**Worked example.** Two data commitments `A` and `B` are made from
`total_in = 0`, `total_out = 0`. `A` is revealed in a block of
`window-genesis` (spec 07, section 4) and `B` is revoked in a block of
`window-next`, each in a block whose base fee is at most the window's price,
so the burn is the base-fee part and the tip is the nominal tip. Amounts in
wei.

```text
after commit A and B
  total_in      500,000,000,000,000,000
  total_out     0
  hidden total  500,000,000,000,000,000 = 2 x DATA_RESERVE

reveal A, window-genesis
  fee           26,100,495,343,659,410   (<= DATA_RESERVE)
  burned        23,727,723,039,690,372
  tip to finder  2,372,772,303,969,038
  forfeited    223,899,504,656,340,590
  total_in      500,000,000,000,000,000
  total_out     250,000,000,000,000,000
  hidden total  250,000,000,000,000,000 = 1 x DATA_RESERVE (B)

revoke B, window-next
  fee           28,710,544,875,705,410   (<= DATA_RESERVE)
  burned        26,100,495,341,550,372
  tip to finder  2,610,049,534,155,038
  forfeited    221,289,455,124,294,590
  total_in      500,000,000,000,000,000
  total_out     500,000,000,000,000,000
  hidden total  0
```

In each settlement `burned + tip + forfeited = 250,000,000,000,000,000`. A
reveal of `A` with a fee of 26,100,495,343,659,411 (not the window's fee), or
in a window whose fee were above 250,000,000,000,000,000, is rejected at
step 6 and changes nothing.

**What each rule stops.**

- **A reveal that cannot pay.** `fee <= DATA_RESERVE`, checked before the
  proof, rejects a reveal whose fee the reserve does not cover, so no data
  reveal ever moves more out of the hidden set than its commitment put in.
- **A public payer.** The fee comes from the reserve bound inside `C`; the
  reveal has no sender, account or signature field to pay it, so no public
  account is tied to the reveal (outline, "Reference: old Specter code").
- **A refund that links commit to reveal.** The leftover is forfeited, not
  refunded. A refund to a public address would name who revealed and tie that
  address to the commit; a refund as a coin remainder commitment would add a
  coin leaf, a note and remainder constraints to the data statement, and a
  hidden amount to a statement that has none. Both cost more security surface
  than the waste they save.
- **Fee differences that tell data reveals from coin reveals.** The fee is the
  same window fee a coin reveal pays in the same window, in the same field, so
  the fee says nothing about whether a reveal is a coin or a data reveal, a
  reveal or a revocation.

## 7. Revocation

Revocation is how the holder uses a data commitment up so that proofs of
holding that open it fail afterwards, against any marker status that includes
the revocation (outline, second milestone 6). A proof of holding names no
particular commitment (section 5, "What it claims"), so another unspent
commitment still proves holding of itself.

- **What it is.** A one-time reveal (section 6) by the holder with the revoke
  purpose in the binding digest. **Proposed:** revoke is its own purpose tag,
  separate from the ordinary reveal, so a ticket presented to a verifier
  cannot be passed off as a revocation or the other way round (question 4).
  It needs the digits, like every one-time reveal; no administrator, miner or
  committee can revoke (outline, core requirement 1).
- **Fee.** Revocation settles as in section 6, "Fee settlement at reveal and
  revoke": the window fee out of the reserve, the rest forfeited, never a
  refund.
- **Effect.** The commitment's marker is in the data spent-marker set. Every
  later proof of holding for that commitment against a spent-marker-set root
  that includes the marker fails, because the proof must show the marker is not
  in the set (section 5, item 2). A later reveal or second revocation is
  rejected at section 6, step 9.
- **Earlier proofs.** A proof of holding made before the revocation stays
  valid only for the tree state and challenge it was bound to. A verifier that
  wants current status issues a fresh challenge and takes the roots from the
  latest header it trusts.
- **Reorganisations.** If the block with the revocation is removed, the marker
  is unspent again until the revocation is included on the canonical chain.
- **What it does not do.** It does not destroy, hide or recall any copy the
  holder or anyone shown the digits or the data already has, and it does not
  delete the ciphertext from any host. It does not stop someone else who holds
  the digits from having revoked or revealed first: the first to be included
  wins (threat model, section 6 item 9). Revocation is "used up", not
  "erased".

## 8. Restore and recovery

**Restore from the digits alone.** On a clean device the digits alone restore
everything that is on the chain or derivable (outline, second milestone 4):

1. Derive `k_note`, `k_data`, `s`, `r` and `b` from the digits.
2. Find the note by trying `k_note` against the data tree's note history,
   fetched in bulk, so that no endpoint learns which note is the wallet's
   (threat model, section 6 item 8). The one note that decrypts under
   authenticated encryption is the wallet's. **Proposed:** the wallet never
   asks an endpoint for one commitment, one position or one marker.
3. Recompute `F_d` and `C` from the derived values, the note's `cf` and the
   salt published with its commit (fetched in bulk
   with the note history, never asked for one leaf at a time), and check that
   `C` is the leaf stored with that note. If it is not, restore fails closed.
4. Compute the marker locally, with the same salt, and check it against the data spent-marker set,
   fetched in bulk, to learn whether the commitment is still unrevealed.

No step uses or publishes a value that ties the commitment to a reveal or to a
proof of holding, and no value is stored on the device beyond the digits.

**Locating the data.** The digits do not say where the ciphertext is, because
the chain does not store a location (section 4). The user or the app supplies
it. Re-hosting a copy anywhere needs no chain action, since the commitment does
not name a host.

**A wrong host answer.** If a host returns the wrong ciphertext or an altered
one, authenticated decryption under `k_data` fails and the wallet rejects it.
If a ciphertext decrypts (for example one made by someone else who holds the
digits), the wallet recomputes `cf` from the plaintext and its length and
compares it with the `cf` bound inside `C`; a mismatch is rejected. Both checks
fail closed: the wallet never shows unchecked bytes as the committed data.

**A lost host.** If the host is gone, the chain cannot recover the bytes. The
commitment, its marker status, proofs of holding, reveal and revocation all
still work, because none of them needs the data. The data itself is lost unless
a copy exists elsewhere. The chain does not guarantee the file stays available
(outline, "Data storage").

## 9. Linkage

The linkage test for data (outline, second milestone 5; core requirement 3)
pulls the raw commit transaction, every proof of holding and the reveal or
revocation of one data commitment and asserts that no value appears in more
than one of them, apart from a whitelisted shared tree state, the chain
constants (chain identifier, version, type and purpose tags), the content
fingerprint `cf` the reveal and the proofs of holding carry by design, and the
values each verifier chose (its identity and challenge). The commit
publishes `C`, `F_d` and the note, and never `cf`; a reveal publishes the
marker, `cf` and the binding digest; a proof of holding publishes no marker. A wallet proves against a
recent, widely shared tree state, never the one its own commit created
(outline, "Core protocol" 10). The test must fail against a deliberately linked
design, for example one whose reveal publishes `C`.

## 10. Claims limits

These repeat the outline's wording ("Core value proposition", claims; "Data
storage"; threat model, C7 and C32) and are the only claims made for data.

- The chain can prove a commitment **has not been revealed**. It can never prove
  nobody has **viewed** its contents: the author, and anyone the digits are
  shown to, can read them. Say "not revealed", never "not viewed".
- A Phantom Key controls authority and access. Data that has been shown can be
  copied; the key does not control the bytes after that.
- Availability is not guaranteed. The chain does not keep the data and does not
  promise the file stays available.
- Revocation is "used up", not "erased". It ends proofs of holding that open
  the revoked commitment; it does not remove a copy anywhere.
- "Not revealed" holds as of the tree state used, on the chain the verifier
  trusts, and only to the degree that chain is final.
- The data is protected by the digits' strength alone once its ciphertext is
  public (threat model, C20).

## 11. Conformance requirements

There is no code yet. These are the tests the node, the wallet and a reference
verifier must pass, written as inputs and the expected result. Each case
assumes every other check passes.

- **CR-D1. No key part on the chain.** A wallet commits, proves holding twice
  and revokes. Every byte string in every commit payload, note plaintext
  (decrypted with the digits), reveal and proof of holding, and every value
  derivable from them without the digits, is tried as `k_data` and as a share
  or wrapping of it against the ciphertext: every attempt fails to decrypt. A
  commit payload with an extra field to carry a key is rejected at the
  exact-length check (spec 03, section 6, step 2). The wallet's rule that
  writes nothing that unlocks data (section 4) is what this checks.
- **CR-D2. A proof for one commitment is not a proof for another.** After
  commitment A is revoked, while an unrelated commitment B (the prover's own)
  is unspent: A's earlier proof presented again is rejected at verifier check
  3 (its challenge was answered) or check 5 (its marker-set root is not
  current), and a new proof that opens A against a marker-set root that
  includes the revocation cannot be made, because the non-membership in
  section 5, item 2 concerns the marker of the commitment opened in the proof.
  A proof that opens B but uses A's marker for the non-membership check cannot
  be made (the marker is derived inside the proof). A new proof that opens B
  does verify, because a proof of holding names no particular commitment
  (section 5, "What it claims"); this test checks only that A's own proof and
  A's marker can no longer be used.
- **CR-D3. Verifier binding.** A proof of holding made for verifier X is
  presented to verifier Y with the same challenge value: Y rejects it at
  verifier check 4, and at check 6 if Y's identity is substituted.
- **CR-D4. Replayed challenge.** A verifier accepts a proof for challenge `c`.
  The same proof, and a new proof for `c`, are presented again: both are
  rejected at verifier check 3. A proof for a challenge the verifier never
  issued is rejected at the same check.
- **CR-D5. A data commitment mints nothing.** A data reveal presented to the
  coin reveal is rejected at spec 03, section 7, step 3, with no proof
  verified, no marker recorded and no balance changed (spec 03, CR-4). A valid
  data reveal credits nothing to its verifier or recipient field.
- **CR-D6. A coin leaf is not data.** A data reveal or proof of holding whose
  proof opens a coin leaf against a coin-tree root is rejected at section 6,
  step 8 (or verifier check 5). Against a data-tree root, a proof that opens a
  coin leaf with the data outer hash fails at step 10 (or verifier check 6).
- **CR-D7. Second reveal rejected.** After a valid data reveal with marker `m`,
  a second reveal or a revocation with `m` is rejected at section 6, step 9,
  both in a later block and in the same block, and the block carrying it is
  invalid.
- **CR-D8. No proof of holding after revocation.** A commitment is revoked at
  height `h`. A fresh proof of holding against the roots of height `h` or later
  fails, because no valid proof exists whose marker is outside a set that
  contains it (section 5, item 2). The same proof made against height `h - 1`
  is accepted only by a verifier that issued its challenge and accepts that
  height as current; a verifier that takes the latest header rejects it at
  verifier check 5.
- **CR-D9. Wrong or altered host answer.** The host returns a different
  ciphertext, then the right ciphertext with one bit flipped: authenticated
  decryption fails both times and the wallet shows nothing. A ciphertext that
  decrypts under `k_data` to bytes whose `cf` differs from the one in `C` is
  rejected by the fingerprint check (section 8).
- **CR-D10. Lost host.** With the host deleted, a proof of holding, a reveal
  and a revocation all still verify, and the wallet reports the data as
  unavailable rather than failing silently or showing other bytes.
- **CR-D11. Restore on a clean device.** On a device with nothing but the
  digits, the wallet restores `C`, its marker status and `k_data` and decrypts
  a supplied ciphertext. The endpoint's request log shows only bulk note and
  marker-set fetches, no request naming one commitment, position or marker.
  A restore whose recomputed `C` differs from the stored leaf fails closed.
- **CR-D12. Forged fingerprint.** Someone who holds the digits encrypts other
  bytes under `k_data` and hosts them: the wallet rejects them at the
  fingerprint check. A note whose `cf` is changed makes the recomputed `C`
  differ from the leaf, and restore fails closed at section 8, step 3.
- **CR-D13. Discarded branch.** A proof of holding and a data reveal against a
  data-tree root that exists only on a discarded branch are rejected at
  verifier check 5 and section 6, step 8.
- **CR-D14. Note length.** A data commit whose note is one byte shorter or
  longer than the fixed length is rejected at spec 03, section 6, step 5, as
  applied in section 4; nothing is written.
- **CR-D15. Linkage.** The test of section 9 passes over commit, two proofs of
  holding and a revocation, and fails against a deliberately linked design
  whose reveal publishes `C` or whose proofs of holding share a value other
  than the shared tree state, the chain constants, the content fingerprint and
  the verifiers' own choices.
- **CR-D16. Chain and purpose binding.** A proof of holding from a chain with
  another identifier or version is rejected at verifier check 2. A data reveal
  made with the reveal purpose and submitted as a revocation, or the other way
  round, fails at section 6, step 10, because the purpose is in the
  node-computed binding digest. An unknown purpose is rejected at step 5.
- **CR-D17. Reorganisation.** A block with a revocation is removed by a
  reorganisation. Afterwards the marker is unspent and a fresh proof of
  holding on the new canonical chain is accepted.
- **CR-D18. Fee settles from the reserve.** In a block of `window-genesis`
  whose base fee is at most the price, a data reveal and a revocation with
  `fee` = 26,100,495,343,659,410 are each accepted: `total_out` grows by
  exactly `DATA_RESERVE`, 23,727,723,039,690,372 is burned,
  2,372,772,303,969,038 is credited to the block finder, no other balance
  changes, and the remaining 223,899,504,656,340,590 is credited to nobody. A
  data reveal or revocation with a fee one wei off the window fee, or one
  that fails the cover rule, is rejected at section 6, step 6. A data reveal
  or revocation whose fee is the window's fee but above `DATA_RESERVE` (in a
  test chain whose window fee is `DATA_RESERVE + 1`) is rejected at section 6,
  step 6, before the proof is verified, and nothing changes; with the window
  fee exactly `DATA_RESERVE` it is accepted and nothing is forfeited.
- **CR-D19. Content fingerprint binding.** A valid data reveal whose `cf` is replaced with the fingerprint
  of other bytes fails at section 6, step 10, and a proof of holding made for
  one `cf` is rejected at verifier check 6 when the verifier asks about
  another; a prover that opens the commitment but claims another `cf` makes no
  proof that verifies. The revealed bytes recompute the reveal's `cf`, and
  other bytes do not (spec 02, PS-26).
- **CR-D20. A data commit sends exactly the reserve.** Data commits with value
  0, `DATA_RESERVE - 1`, `DATA_RESERVE + 1` and 1 GHOST are each rejected at
  section 4, commit check 1: nothing is burned, no leaf or note is written and
  `total_in` is unchanged. A data commit with value exactly `DATA_RESERVE`
  is accepted: the sender is debited `DATA_RESERVE` (plus gas), `total_in`
  grows by `DATA_RESERVE`, and the leaf equals
  `H(tag_data_commitment, DATA, DATA_RESERVE, F_d)`, so a proof that opens it
  with any other amount in the outer hash does not verify.

Each requirement must fail if the check it names is removed; a test that still
passes with the check deleted does not count.

## 12. No owner, no switch

No owner, administrator, contract, pause switch or upgrade key has any power
over data commitments, the data tree, the spent-marker set, proofs of holding,
reveals or revocations, and nothing can swap a verifier or change a setting
outside the chain's ordinary upgrade process (outline, "Upgrades and
incidents"). This rules out the old design's owner-swappable parts and
pausable settings.

## 13. Questions for the founder

Each has a default that rejects or adds nothing until the founder decides.

1. **Fee of a data reveal.** Where does the fee come from, when a public
   account paying it is ruled out? Answered (front desk decision,
   2026-10-25): from the fee reserve. Every data commit burns the constant
   `DATA_RESERVE` into the commitment (section 3, "The fee reserve"); a data
   reveal or revocation pays the coin reveal's window fee out of it, with
   `fee <= DATA_RESERVE`, and the rest is forfeited, credited to nobody
   (section 6, "Fee settlement at reveal and revoke"). Rejected: a
   wallet-chosen reserve, a public account paying the reveal, and a refund of
   the leftover.
2. **Spent-marker-set root in headers.** Should every header carry the data
   spent-marker-set root? Answered (front desk decision, 2026-10-25): yes.
   Every header carries `dataMarkerRoot`, the root of an append-only indexed
   Keccak-256 tree of depth 40 over the data markers, with a 1,354-byte
   non-membership witness ([spec 05](05-trees-and-headers.md), section 6
   "The data marker-set tree", and section 10). Proofs of holding are accepted
   only against a root the verifier takes from a header it trusts, and stay
   rejected until the proof circuit checks the absence. Rejected: a sparse
   tree of depth 256, buckets by marker prefix, non-membership in the storage
   trie, and a second root per type; no coin marker-set root is added.
3. **Remainder on a data reveal.** Should a data reveal create a remainder
   commitment? Default: none.
4. **Revoke purpose.** Is revoke a purpose separate from the ordinary reveal?
   Default: a separate purpose tag.
5. **The note's content for data.** Is the note's data content right, and may
   it carry a storage location hint? Default: `cf`, the length and the version
   only; no location, and never a data key.
6. **Application-defined data types.** Are they in the first version? Default:
   one `DATA` type; anything else is rejected.
7. **Challenge size and currency.** How large is the challenge, and how long
   may a verifier treat a proof as current? Default: at least 256 bits from a
   secure random source, and a proof counts only for the challenge and tree
   state it names.
8. **Proof that shown bytes match.** Should a viewer be able to check that
   shown bytes match a commitment's `cf` without receiving the digits?
   Answered: yes. A data reveal and a proof of holding carry `cf` as a public
   input, bound by their binding digests, and the proof shows it is the
   commitment's own (sections 5 and 6; spec 02, sections 5 and 6). A viewer
   computes `cf` from the shown bytes and compares. The fingerprint is public
   by design; it names the content, which any commitment of the same bytes
   shares, and not the commitment.
9. **Rules on data.** Are rules on data in the first version? Default: none;
   any non-empty rule is rejected at section 6, step 10.
10. **Size of the reserve.** Is 0.25 GHOST the right reserve? A larger one
    keeps data reveals and revocations possible at higher base fees and
    forfeits more per commitment; a smaller one forfeits less and blocks them
    sooner (about 90% forfeited and a limit of about 9.6 times the genesis base
    fee at 0.25 GHOST). Once a network holds data leaves, changing it is a
    new commitment format version (section 3, "Format version"). Default: `DATA_RESERVE` =
    2.5 x 10^17 wei as stated.

## 14. Follow-ups outside this document

This document is reviewed together with the other lifecycle specifications,
starting with [spec 03](03-coin-rules.md). It does not fix the following
itself:

- The proof-statement specification fixes the tag strings (data fingerprint,
  data commitment, data marker, content fingerprint, hold, reveal and revoke
  purposes), the content fingerprint's hash and layout, the proof-of-holding
  statement's public inputs and constraints, including the spent-marker-set
  non-membership, and the data reveal's constraints.
- The key derivation specification fixes how `k_data`, `k_note`, `s`, `r` and
  `b` are derived from the digits, each with its own tag, and the encryption
  scheme and nonce rule.
- The transaction-format specification fixes the data commit entry point, the
  note layout and its one fixed length, the data reveal's encoding and purpose
  values, and how an on-chain verifier issues a challenge.
- The data tree's root rules (which roots are canonical, the rollover) and the
  spent-marker-set tree with its header root `dataMarkerRoot` are fixed by the
  tree and header specification ([spec 05](05-trees-and-headers.md), sections
  6 and 10).
- The fee reserve (section 3, "The fee reserve"; section 6, "Fee settlement
  at reveal and revoke") touches other specifications, edited by the
  implementation work, not here: [spec 02](02-proof-statements.md), the S2
  inputs (the data leaf opened with `DATA_RESERVE` in its outer hash, and the
  fee bound against it); [spec 03](03-coin-rules.md), section 3 (beyond its
  sentence on data commits, changed with this document) and section 9 (`total_in` and `total_out` count the reserve, and
  the hidden total includes `DATA_RESERVE` for each live data commitment);
  [spec 07](07-private-transaction.md), the data reveal encoding (the same fee
  field as the coin reveal, and its "Data reveals" notes, which still say the
  data reveal fee is unsettled); and [spec 01](01-commitments-and-keys.md),
  section 10 (the data outer hash with the reserve, the re-set of data format
  version 2 or, under the condition of section 3, version 3), with its data
  test vectors.
- The threat model's C32, C41 and C43 rows should point to this document once
  it is accepted; this document does not edit it.

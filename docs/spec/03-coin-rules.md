# Specification 03: coin rules

Status: draft for the founder's review, 2026-10-17. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the [outline](../ghost-outline.md) ("Coin
rules", "Core protocol", "Transactions and fees"), the base client plan
(section 7.3) or the [threat model](../threat-model.md), and is cited to it, not
decided again here.

This document fixes the small set of rules that keeps the money sound: where a
coin commitment may come from, how public GHOST is burned on commit and minted
on reveal, how the chain binds the amount at commit, and the exact order of the
checks a node makes on a commit and on a reveal. It names what the reveal proof
must establish and leaves the proof's internal constraints to the proof-statement
specification. It sets no fee formula and no rule on GHOST. Where a point is not
settled, the check rejects (fails closed) and the point is listed in section 11.

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Origin of coin commitments | Only authorized issuance, conversion of public balances (commit), or a value-conserving reveal (the remainder). A data commitment can never create money | Outline |
| Authorized issuance in the first milestone | No issuance path exists; anything presented as issuance is rejected until a specification defines its authorization | **Proposed** (fail closed) |
| Burn on commit | The committed amount is debited from the sender and credited to nobody | Outline |
| Mint on reveal | Only the chain's own reveal rule mints; no contract address is ever authorized to mint | Outline |
| Custodian or reserve | None. No contract, account or handler holds committed value | Outline |
| Amount binding | The user submits a fingerprint of the commitment's secret parts and pays the value; the node computes the final commitment from the fingerprint, the burned amount and the type tag | Base client plan 7.3 |
| Hash construction for the binding | Two tagged hashes: the wallet's fingerprint, then the node's commitment over type tag, fingerprint and amount | **Proposed** (section 5) |
| Amount range | Every amount is an integer number of wei from 0 to 2^96 - 1; a commit amount is at least 1 wei | **Proposed** |
| Minimum commit amount above 1 wei, cooldown, second commitment | None | **Proposed** (question for the founder) |
| Order of checks | Cheap and stateless checks first, then state lookups, then the proof, then one atomic state change | **Proposed** order, outline rules |
| Data type on the coin path | Rejected at the first type check, before any lookup or proof verification | Outline; position **Proposed** |
| Conservation | `v = out + v' + fee` proven on every reveal | Outline |
| Fees in conservation | The fee comes from the commitment inside the proof; its base-fee part is burned | Outline; decision 0001 |
| Remainder | Every reveal adds exactly one remainder commitment, also when it holds zero | Outline ("one private shape") |
| Remainder key | Same Phantom Key by default; a new key as an option (claim) | Outline |
| Public accounting | Running totals in and out of the hidden set; a reveal that would take the hidden total below zero is rejected | Outline (backstop); rejection **Proposed** (threat model, section 6 item 5) |
| Rules on GHOST | None in the first milestone | Outline |

## 2. Conventions

- Amounts are integers in wei, 10^18 per GHOST. No floating point.
- `V_MAX = 2^96 - 1` wei (about 79 billion GHOST), **Proposed**, taken from the
  96-bit range checks in the [benchmark plan](../benchmarks/plan.md). Every
  amount that enters or leaves a commitment (`v`, `out`, `v'`, `fee`) lies in
  `[0, V_MAX]`. Node-side sums of amounts and the running totals of section 9
  use at least 256-bit unsigned integers, and any operation that would
  overflow or go below zero rejects.
- `H(tag, ...)` is the hash used inside proofs and trees (outline,
  "Cryptography"), with an explicit tag for every use (outline, "Core
  protocol" 10). Tag strings are fixed in the proof-statement specification;
  the names used here are placeholders for distinct tags.
- "Type tag" is the commitment's version and type (outline, "Core protocol" 3).
  `COIN` is the coin type at the current version. `DATA` is any data type.
- "Marker" is the one-time marker a one-time reveal publishes (outline, "Core
  protocol" 5).
- "Hidden set" is the set of coin commitments in the coin tree that have not
  been used up.
- "Reject" means the transaction is invalid: it is not included, and a block
  that contains it is invalid. A rejected transaction changes no state.

There are no rules on GHOST in the first milestone (outline, "Coin rules"): no
time lock, expiry or restricted destination, and nothing carries over into a
remainder or a claim. The rule field of a coin commitment must be the empty
rule (section 7, step 11).

## 3. Origin

A coin commitment is a leaf in the coin tree. Exactly three things can add one,
and each must establish something before the leaf is written.

1. **Conversion of a public balance (a commit).** Public GHOST of amount `v` is
   burned from the sender in the same state change that writes the leaf, and
   the leaf is the node's own computation over `v` (section 5). It establishes
   that the value entering the hidden set equals the value that left the public
   supply.
2. **A value-conserving reveal (the remainder).** The leaf is the remainder
   commitment of a valid reveal. The reveal proof establishes that the
   commitment it uses up held `v`, that the remainder holds `v'`, and that
   `v = out + v' + fee` (section 7). It establishes that no value is added.
3. **Authorized issuance.** The outline names it as an origin and does not say
   who authorizes it or how. A leaf from issuance would have to establish an
   authorization the chain can check without trusting any account, contract,
   administrator or committee (outline, core requirement 1), and an amount
   that the public accounting of section 9 counts as entering the hidden set.
   **Proposed:** the first milestone has no issuance path. The block reward is
   paid publicly to the block finder (consensus spec 06, section 7) and
   enters the hidden set only through a commit. Any transaction or block that
   tries to add a coin leaf by any other route is rejected. No issuance
   schedule is set here.

Nothing else writes to the coin tree. In particular:

- **A data commitment can never create money** (outline, "Coin rules"). Data
  commitments go only into the data tree, are written with a `DATA` type tag
  under their own hash tag, and are never accepted by the coin reveal
  (section 7, step 3). Data commits burn nothing and mint nothing.
- The general proof checker for developer-written statements can never add a
  coin leaf or mint (outline, "Extension points" 3; threat model C37).
- No contract, precompile caller or account has any right over the coin tree
  beyond calling the commit entry point as section 6 allows.

## 4. Burn and mint

- **Burn on commit.** The committed amount `v` is subtracted from the sender's
  public balance and added to no balance anywhere. It is removed from the
  public supply (outline, "Core value proposition", claims). The commit's own
  gas fee is separate from `v` and follows the ordinary transaction rules.
- **Mint on reveal.** A valid reveal creates `out` new public GHOST and credits
  it to the recipient bound in the proof. It is created from nothing, not
  transferred from a holding account. The fee leaves the commitment too: its
  base-fee part is burned (decision 0001) and its fixed private tip is paid to
  the block finder (outline, "Transactions and fees"). This document sets no fee
  formula.
- **No custodian, no reserve.** No contract or account holds committed value,
  and no balance anywhere can be drawn on to pay a reveal.
- **Only the chain's reveal rule mints.** The node's reveal rule (section 7) is
  the only code path that increases a balance for a coin reveal. No contract
  address is ever authorized to mint, there is no mint permission to grant,
  and there is no owner, pause switch or upgrade key over these rules (outline,
  "Coin rules" and "Reference: old Specter code").
- **Credit without execution.** **Proposed:** the mint is a plain balance credit
  to the recipient address and runs no code at that address, even if it is a
  contract, so a recipient cannot make a valid reveal fail or re-enter it.

## 5. Amount binding

The outline requires that "the chain itself ties the amount burned to the amount
inside the commitment". The base client plan (section 7.3) fixes how: the user
submits a fingerprint of the commitment's secret parts and pays the value, and
the node computes the final commitment from that fingerprint, the public burned
amount and the type tag. The user never submits a final commitment.

**Construction (Proposed).** The wallet computes

```text
F = H(tag_coin_fingerprint, s, r, b, type_tag, content_fingerprint, rule)
```

where `s` is the secret, `r` the reveal secret, `b` fresh random blinding,
`content_fingerprint` and `rule` the fields of the outline's commitment format
(for the first milestone `rule` is the empty rule). The commit carries `F`. The
node computes

```text
C = H(tag_coin_commitment, COIN, F, v)
```

with `v` the amount it has just burned and `COIN` set by the node, not by the
sender, and writes `C` as the leaf. The reveal proof opens a leaf only by
showing values that satisfy both equations (section 7). A remainder
commitment is built the same way inside the reveal proof, from `F'` and `v'`.

**Why this binds the amount.** The only `v` that ever enters the outer hash at
commit is the amount the node burned in the same state change. To open `C` at
any `v* != v`, a prover would need a second input to the outer hash with the
same output, which is a collision of the tagged hash (threat model, A1). So a
commitment created by a commit opens at exactly the amount burned, and by
conservation no remainder opens at more than its parent held.

**What a user cannot do.** A user cannot submit `C` directly: the commit has no
field for it, and whatever the user puts in the fingerprint field is hashed
again by the node. A value presented as a fingerprint but built as a final
commitment (for example a `C*` the user computed with a large `v*`) becomes
`H(tag_coin_commitment, COIN, C*, v)`, which opens at `v` at most, and only if
the user knows a fingerprint preimage of `C*`. A user cannot choose the type
tag of a coin leaf either.

**Difference from the benchmark plan.** The [benchmark plan](../benchmarks/plan.md)
hashes all fields including `v` in one tagged hash computed by the prover, as a
cost-shape stand-in that yields to the lifecycle specification; this document
follows base client plan 7.3 instead, which splits it into the wallet's
fingerprint and the node's outer hash over type tag, fingerprint and amount, at
the cost of one more short hash in the proof.

## 6. Order of checks on a commit

A commit is a normal, visible transaction from a public account (outline,
"Transactions and fees") addressed to the chain's commit entry point. Whether
the entry point is a reserved address or a transaction type is for the
transaction-format specification; the checks are the same. The node makes them
in this order and stops at the first failure.

1. **Ordinary transaction validity.** Signature, nonce, gas limit and fee
   fields, as for any transaction in the base client. This comes first so that
   nothing below runs for a transaction that would not be valid anyway.
2. **Entry and format.** The transaction is a top-level transaction to the
   commit entry point, with a supported commit format version and a payload of
   the exact length that version defines. **Proposed:** a commit reached by a
   contract call, not a top-level transaction, is rejected (question 6).
3. **No final commitment and no type field.** The payload carries the
   fingerprint `F` and the encrypted note, and nothing that the node would
   treat as a final commitment or as a type tag. A payload with any extra field
   is rejected by the exact-length check in step 2.
4. **Fingerprint encoding.** Every element of `F` is a canonical encoding of a
   field element (below the field's modulus). **Proposed:** an all-zero `F` is
   rejected.
5. **Note.** The encrypted note has the fixed length set by the lifecycle
   specification; a note of any other length is rejected (threat model C18).
6. **Amount range.** The burned amount `v` is the transaction's value, and
   `1 <= v <= V_MAX`. A zero or larger amount is rejected. No other minimum and
   no cooldown apply (question 4).
7. **Funds.** The sender's balance covers `v` plus the maximum gas cost. This
   is the base client's own check, restated because the burn depends on it.
8. **Tree room.** The coin tree has room for one more leaf. **Proposed:** if
   it is full, the commit is rejected until the rollover the outline requires
   ("Core protocol" 8) is specified.
9. **Compute the commitment.** The node computes
   `C = H(tag_coin_commitment, COIN, F, v)` (section 5).
10. **Apply, all or nothing.** In one state change: debit `v` from the sender
    and credit it to nobody; append `C` to the coin tree; store the note with
    it; add `v` to the running total in (section 9); record the commit in the
    receipt (leaf `C`, position, `v`). If any part fails, none applies and the
    transaction is rejected. The new coin-tree root goes into the block header
    (outline, "Core protocol" 6).

Not checked, by decision: an authorized-asset list (GHOST is the only coin), an
owner limit, a pause switch, a minimum amount above 1 wei, a per-sender
cooldown, and a second, separate commitment. None of these is in the outline;
the last three are questions for the founder with the default "none".

## 7. Order of checks on a reveal

A reveal is a native private transaction with no account and no signature; the
proof is the authorization (outline, "Transactions and fees"; threat model C28).
It has one shape: one commitment in, an optional public amount out and one
remainder commitment. Its public inputs are the tree root, the marker, the
remainder commitment, the amount out, the fee, the type tag, the recipient and
the binding digest. The node makes these checks in this order and stops at the
first failure. Steps 1 to 6 need no state, steps 7 to 9 read state, step 10
verifies the proof, steps 11 and 12 check what the proof outputs against the
chain, and step 13 is the only step that writes.

1. **Shape.** The transaction is the private reveal type at a supported
   version, has the exact size and number of public inputs that version
   defines, and carries no sender, signature or account fields. Anything else
   is rejected (outline: every private transaction has an identical size and
   shape).
2. **Encoding.** Every public input is canonical: field elements below the
   modulus, amounts `out` and `fee` in `[0, V_MAX]`, and the recipient a
   20-byte address with no other bits set.
3. **Type.** The type tag is `COIN` at the current version. A `DATA` type, an
   unknown type or an old version is rejected here, before any lookup or proof
   verification, so a data commitment never reaches the mint.
4. **Chain, version and domain.** The chain identifier, protocol version and
   domain tag are this chain's current values.
5. **Fee.** The fee equals the chain's formula for this block (base fee plus
   the fixed private tip). The user does not choose it (outline,
   "Transactions and fees").
6. **Binding digest.** The node computes the binding digest itself from the
   transaction's recipient, amount out, fee, remainder commitment, tree root,
   marker, chain identifier, transaction type and version, protocol version
   and domain tag, and uses its own value as the public input. It never takes
   a digest from the sender. A proof made for a different recipient, fee,
   amount, chain or purpose therefore fails at step 10.
7. **Root.** The tree root is the coin-tree root in the header of a block on
   the node's canonical chain (outline, "Core protocol" 9). A data-tree root,
   or a root seen only on a discarded branch, is rejected. **Proposed:** any
   canonical height is accepted, with no window.
8. **Marker unused.** The marker is not in the spent-marker set of the
   canonical chain, and no earlier transaction in the same block uses it.
9. **Accounting backstop.** `out + fee` is at most the hidden total of
   section 9 before this reveal. **Proposed** as a consensus rule; it is
   unreachable if the proof system is sound.
10. **Proof.** The proof verifies against the public inputs above. It must
    establish, as the proof-statement specification constrains:
    - **Membership:** an input commitment `C`, opened as in section 5 with type
      `COIN`, is a leaf under the public tree root.
    - **Marker derivation:** the public marker is derived from `C`'s secret
      parts, so one commitment has one marker.
    - **Remainder:** the public remainder commitment is built as in section 5
      from `F'` and `v'`, with the same type tag, content fingerprint and rule
      as `C`, fresh blinding, and `s'` and `r'` free (section 8).
    - **Conservation:** `v = out + v' + fee`.
    - **Ranges:** `v`, `out`, `v'` and `fee` are each in `[0, V_MAX]`, so `v'`
      cannot be negative and the sum cannot wrap.
    - **Bound outputs** (base client plan 7.3): the recipient, the amount out,
      the fee, the remainder commitment, the marker, the rule, the chain
      identifier, the protocol version and the domain tag, through the public
      inputs and the binding digest.
11. **Rule.** The rule bound in the proof is the empty rule. Any other rule is
    rejected in the first milestone, because no rule on GHOST exists yet.
12. **Tree room.** The coin tree has room for the remainder (as commit step 8).
13. **Apply, all or nothing** (base client plan 7.3, atomicity). In one state
    change: add the marker to the spent set; credit `out` to the recipient by
    the chain's mint (section 4); burn the base-fee part of the fee and pay the
    tip to the block finder; append the remainder commitment and its note to
    the coin tree; update the running totals of section 9; write the receipt
    (marker, remainder commitment and position, recipient, `out`). If any part
    fails, none applies. A reorganisation that removes the block reverts all of
    it together, so a marker never stays spent without its remainder, and a mint
    never stays without its marker.

Not checked, by decision: a second, separate proof or commitment, a policy
registry, and any check that needs the commitment `C` itself, which the reveal
never publishes (outline, core requirement 3).

## 8. Partial reveals and the remainder

- **Any amount, any number of times.** `out` can be any value from 0 up to the
  balance after fees, `v - fee` (outline, "Coin rules"). Each reveal uses up its
  input commitment and creates one fresh remainder holding `v' = v - out - fee`.
  The next reveal opens that remainder like any other coin leaf.
- **Always one remainder.** Every reveal appends exactly one remainder
  commitment, also when `v'` is 0, so that every reveal has the same shape. A
  zero remainder is a valid leaf that can only produce a reveal whose fee it
  cannot pay, so in practice it is never revealed.
- **Fresh blinding.** Each remainder uses blinding that differs from every
  earlier one in its sequence, so its commitment and its marker differ
  (threat model C26). How the wallet derives it from the digits is for the key
  derivation specification.
- **Same key by default.** By default `s' = s` and `r' = r`: the same Phantom
  Key controls the remainder (outline, "Phantom Keys").
- **New key as an option (claim).** A claim uses new, independent `s'` and
  `r'`, so only the new key controls the remainder. The proof does not require
  `s' = s`; the chain cannot tell a claim from a partial reveal.
- **What carries over.** Type tag, content fingerprint and rule are equal to
  the input's. There is nothing else to carry over in the first milestone.
- **Boundary cases** (outline, "First milestone" 8):
  - Full reveal: `out = v - fee`, `v' = 0`.
  - Zero-amount claim: `out = 0`, `v' = v - fee`, new key; nothing is minted to
    the recipient.
  - Fee that uses the whole balance: `out = 0`, `v' = 0`, `fee = v`.
  - Fee above the balance: no valid proof exists, because `v'` would be
    negative; such a reveal is rejected at step 10.
  - Two competing reveals of one commitment: they publish the same marker, and
    the second to be included is rejected at step 8.

## 9. Public accounting

The node keeps two running totals in the chain state, both 256-bit unsigned
integers that start at zero at genesis:

- `total_in`: the sum of `v` over every commit (and over issuance, if a
  specification ever adds it).
- `total_out`: the sum of `out + fee` over every reveal.

The hidden total is `total_in - total_out`. It equals the sum of the amounts in
the unspent coin commitments if every proof was sound, but nobody can check
that sum, because the amounts are hidden. Both totals are public, readable from
the state, and change only in commit step 10 and reveal step 13, together with
the rest of that step's state change.

This is a **backstop**, not a detector of counterfeits inside the set (outline,
"Coin rules"; threat model C27). Conservation is proven on every reveal, and
that is what keeps the money sound. If the proof system were broken, an
attacker could move value between hidden commitments without the totals
changing. **Proposed:** reveal step 9 makes the backstop a consensus rule, so
such a break can drain at most what was burned in and never mint beyond it,
and the damage is bounded and visible as the hidden total running short (threat
model, section 6 item 5).

Supply reads as: public supply = issuance from block rewards - burned base fees -
hidden total. "Removed from supply" is the claim for committed value, not
"destroyed" (outline, "Core value proposition", claims).

## 10. Conformance requirements

There is no node code yet. These are the tests the node must pass, written as
inputs and the expected result, so that no commitment can open to more than was
burned. Amounts are in wei; `fee` is whatever the formula gives for the block,
written `f` here, and each case assumes every other check passes.

- **CR-1. No opening above the burned amount.** A commit with `v = 1000` and
  fingerprint `F` makes the leaf `C`. A reveal of `C` whose proof claims an
  input amount of 1001 (any `out`, `v'` and `fee` that sum to 1001) is
  rejected at reveal step 10, and the totals and balances are unchanged. Repeat
  with claimed amounts `V_MAX` and `2^96`; both are rejected.
- **CR-2. A final commitment submitted as a fingerprint is hashed again.** The
  sender computes `C* = H(tag_coin_commitment, COIN, F, 10^24)` and commits it
  as the fingerprint with `v = 1`. The leaf written is
  `H(tag_coin_commitment, COIN, C*, 1)`, not `C*`. A reveal that opens the
  leaf `C*` with amount 10^24 is rejected (the root does not contain `C*`); no
  reveal of the written leaf can take out more than 1 in total.
- **CR-3. A commit payload with an extra field is rejected.** A commit whose
  payload carries a final commitment or a type tag in addition to `F` is
  rejected at commit step 2, and nothing is burned.
- **CR-4. A data commitment mints nothing.** A data commitment is made with the
  data path. A reveal with type tag `DATA` presented to the coin reveal is
  rejected at step 3; no proof is verified, no marker is recorded, no balance
  changes. A reveal that claims type `COIN` but proves membership of that data
  leaf under the data-tree root is rejected at step 7, and under a coin-tree
  root fails at step 10.
- **CR-5. Conservation cannot be exceeded.** For an input `v = 1000` and fee
  `f`, a reveal with `out + v' + f = 1001` is rejected at step 10; with
  `out + v' + f = 1000` it is accepted and mints exactly `out`.
- **CR-6. A repeated marker is rejected.** After a valid reveal with marker `m`,
  a second reveal with `m` (same or different recipient, root or amount) is
  rejected at step 8, both in a later block and in the same block, and the
  block carrying it is invalid.
- **CR-7. Overflow and wrap are rejected.** A reveal with `out = V_MAX + 1`
  is rejected at step 2. A proof where `out + v' + fee` equals `v` only modulo
  the field size (for example `v = 10`, `out = 20`, `v' = p - 10`, `fee = 0`,
  with `p` the field modulus) is rejected at step 10 by the range check on
  `v'`. A
  commit with value `2^96` is rejected at commit step 6.
- **CR-8. Recipient and fee are bound.** A valid proof made for recipient `A`
  and fee `f` is submitted with recipient `B`: rejected at step 10, nothing
  minted. The same proof submitted with fee `f + 1` is rejected at step 5 (and
  would fail step 10 as well).
- **CR-9. Chain, version and domain are bound.** A valid proof from a chain
  with another chain identifier, protocol version or domain tag is rejected at
  step 4 or step 10.
- **CR-10. Data roots and orphan roots are rejected.** A reveal against the
  data-tree root of a canonical block, and a reveal against a coin-tree root
  that exists only on a discarded branch, are both rejected at step 7.
- **CR-11. Atomicity under reorganisation.** A block with a valid reveal is
  imported and then removed by a reorganisation. Afterwards the marker is
  unspent, the recipient's mint and the tip are gone, the remainder leaf is
  gone, and both totals are back at their earlier values; all four changes
  revert together.
- **CR-12. The backstop holds.** With the hidden total at 1000 (one commit of
  1000), a reveal with `out + fee = 1001` is rejected at step 9 even if the
  proof is forced to verify (test build with a stub verifier).
- **CR-13. No other origin.** A transaction that tries to append a coin leaf
  through any route other than commit step 10 or reveal step 13 (a contract
  call, the general proof checker, a data commit) leaves the coin tree and
  `total_in` unchanged.
- **CR-14. Zero amounts.** A commit with `v = 0` is rejected at commit step 6.
  A reveal with `out = 0` and `v' = v - f` is accepted and mints nothing to
  the recipient; a reveal with `out = 0`, `v' = 0`, `fee = v` is accepted.

Each requirement must fail if the check it names is removed; a test that still
passes with the check deleted does not count.

## 11. Questions for the founder

Each has a default that rejects or adds nothing until the founder decides.

1. **Authorized issuance.** What authorizes it, and does the first milestone
   need it at all? Default: there is no issuance path; anything else is
   rejected.
2. **Amount range.** Is `V_MAX = 2^96 - 1` wei the right ceiling? Default:
   yes, rejecting anything above.
3. **Accounting as a consensus rule.** Should reveal step 9 reject, or only be
   reported? Default: reject.
4. **Minimum commit amount, cooldown, second commitment.** The old design had
   a minimum commit amount, a per-sender cooldown and a second, separate
   commitment stored next to each leaf. Default for each: none.
5. **Root age.** Should reveals accept any canonical root, or only roots from a
   recent window? Default: any canonical root.
6. **Commits from contracts.** May a contract call the commit entry point?
   Default: no, top-level transactions only.
7. **Full coin tree.** Default until the rollover is specified: reject commits
   and reveals once the tree is full.
8. **Where the totals live.** In the state only, or also in the header so that
   header-only verifiers can read them? Default: state only.

## 12. Follow-ups outside this document

- The proof-statement specification fixes the tag strings, the marker
  derivation, the fingerprint layout and the constraints behind section 7,
  step 10.
- The transaction-format specification fixes the commit entry point, the
  payload and note lengths, and the reveal's encoding.
- The key derivation specification fixes how fresh remainder blinding is
  derived from the digits.
- The threat model's C22, C24, C26 and C27 rows should point to this document
  once it is accepted.
- The benchmark plan's single-hash commitment yields to section 5; this
  document does not edit it.

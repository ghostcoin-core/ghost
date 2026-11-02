# Specification 10: private reveal policies and Ghost Guard

Status: draft for the founder's review, 2026-11-02. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the founder's request of 2026-10-30
(bring back open reveal policies, keep them private and secure, and make Ghost
Guard the first one), the design drafts
[version 2](../research/reveal-policies-v2.md),
[version 3](../research/reveal-policies-v3.md) and
[version 4](../research/reveal-policies-v4.md), the
[outline](../ghost-outline.md), the
[commitments and keys](01-commitments-and-keys.md), the
[proof statements](02-proof-statements.md), the [coin rules](03-coin-rules.md),
the [trees and headers](05-trees-and-headers.md), the
[consensus specification](06-consensus-and-emission.md), the
[private transaction](07-private-transaction.md), the
[quantum-safe accounts](09-quantum-safe-accounts.md) or the
[threat model](../threat-model.md), and is cited to it, not decided again
here. Where a figure needs a measurement, this document states the rule, gives
the value it sets from the benchmarks in the repository, and says what the
build ticket must measure. Where a point is not settled, the check rejects
(fails closed), and the point is listed in section 15.

Version 1 of Ghost has one private shape and no rules on GHOST. Version 2 adds
rules, called reveal policies, without giving that shape up for the coins that
do not use one. A coin may carry a rule. The rule names a policy: a small
contract with fixed code. The owner can still spend the coin in the one shape
every private transaction has. If the owner cannot, the words alone can start
a spend that a policy then holds in public escrow, where a second key can
cancel it. Ghost Guard is that policy.

The design drafts went through four rounds of attack. The design stops there.
This document is the specification: it fixes the byte layouts, the proof
constraints, the gas constants, the escrow functions, the frozen-context
opcode table and the pool rules that the drafts left open. Section 2 lists
what this document corrects in version 4 of the draft. It writes no node code,
no circuit and no contract. The build tickets of section 18 do.

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Rule | Six fixed-width fields hashed under one tag: policy address, policy code hash, parameters hash, override hash, action tag, action salt. The empty rule stays 32 zero bytes | Founder request, 2026-10-30; sixth field **Proposed** (section 3) |
| Two classes | The ordinary class is the private transaction of spec 07 with one new private switch. The policy class is a separate public statement | Draft version 4; sections 4 and 5 |
| Ordinary class | Type `0x50`, version `0x0002`. One AIR, one proof layout, one size. The input rule is empty or the opened rule with its override secret. The remainder rule is the prover's choice and stays private | Section 4 |
| Policy class | Type `0x53`. Publishes the policy, its code hash, the parameters hash, the action tag and salt and a payout instruction. Opens an escrow slot | Section 5 |
| Frozen policies | Created only through a native factory. Fixed code, no balance, no value calls, no delegation, a short list of precompiles | Section 6 |
| Escrow slots | Public, native, per spent coin. Only the slot's own policy moves them, through six native functions | Section 7 |
| Policy action | Type `0x54`. No account. Paid from the slot. Authorised by a proof of the action key | Section 8 |
| Notes | 380 bytes for every commitment: today's 128-byte plaintext plus a 224-byte capsule | Section 3 |
| Gas | `G_PRIV` 21,111,656; `G_POLICY` 21,274,216; `G_ACTION` 15,585,968; the data reveal keeps 21,090,372 | **Proposed** (section 10) |
| Pool | Actions share the reveal pool's peer budgets and check slots, have their own count and byte caps, reserve their `(marker, nonce)` only after the proof verifies | Draft version 4; section 11 |
| Ghost Guard | Policy with empty parameters; override secret for the normal spend; stop card for the cancel; 72 hour and 8,640 block hold before release | Draft version 4; section 12 |
| Not promised | A majority of miners that also holds the words can censor a cancel. A policy coin handed over as words alone stays under the giver's stop key | Section 12 |

## 2. What this document corrects in the draft

Writing the constraints out found one hole in version 4 and four places where
a figure or a name was stale. Each is fixed here.

1. **The action salt must be in the rule (Critical).** Version 4 put only
   `action_tag = K(action_root, action_salt)` in the rule and had the policy
   class publish `action_salt` as a separate public value. A policy-class
   prover is the holder of the words. It does not know `action_root`, so the
   proof cannot check that the published salt is the one inside the tag. A
   thief with the words could publish a wrong salt. The slot would then hold a
   tag that no stop card can open, and the owner could never cancel. In this
   document the salt is the sixth field of the rule (section 3). The policy
   class opens the rule, so the published salt is the committed one.
2. **`VERIFY_GAS` is stale.** Spec 07 sets 92,300 from the 9.23 ms of the
   earlier configuration (blowup 2^2, 57 queries). The configuration that
   ships (blowup 2^3, 43 queries) measured a slowest native verification of
   10.61 ms in nine runs ([reveal parameters](../benchmarks/reveal-parameters.md),
   "Verifying times"). Section 10 re-derives the verification charge from that.
3. **One `rule` field leaves the coin reveal binding.** Spec 02, section 7
   binds a public `rule` field fixed to zero. In the ordinary class neither
   rule is public, so the field goes (section 4.2).
4. **`G_ACTION` is split.** Version 4 used `G_ACTION` both as the whole gas of
   an action and as the cap on the policy call. Both cannot be true: the proof
   bytes alone cost over 15 million gas. Section 10 has one `G_ACTION` for the
   whole action and `ACTION_CALL_GAS` for the policy call inside it.
5. **Escrow value needs its own total.** Value in a slot is out of the hidden
   set and not yet in any balance. Spec 03, section 9 does not count it.
   Section 7.3 adds the public total `total_escrow`.

## 3. The rule, the capsule and the note

### 3.1 The rule

```text
rule = K("ghost/reveal-policy/v2",
         policy_address (20 bytes, left-padded to 32), policy_codehash (32),
         params_hash (32), override_hash (32), action_tag (32), action_salt (32))

params_hash   = K("ghost/policy-params/v1", params)               params: 0 to 64 bytes
override_hash = K("ghost/policy-override/v1", override_secret)    or 32 zero bytes: no override
action_tag    = K("ghost/policy-action/v1", action_root, action_salt)
                                                                   or 32 zero bytes: no actions
action_salt   = 32 fresh random bytes per coin
```

`K` is the tagged Keccak-256 of spec 01, section 2. Every field is fixed
width. The rule hash input is 23 bytes of tag, then six 32-byte fields:
215 bytes, two Keccak blocks.

- The empty rule is 32 zero bytes. A real rule is never zero (it is a
  Keccak-256 digest; a zero digest has no known preimage).
- A coin with no actions has `action_tag = 0` and `action_salt = 0`. A coin
  with actions has a fresh random salt. Two coins with the same `action_root`
  publish unrelated tags, and wallets never reuse a salt, including for a coin
  re-committed by a cancel.
- `override_hash = 0` means no override. It never means "skip the check": the
  ordinary class requires `override_hash != 0` to use the override case
  (section 4.3, constraint O5).
- The override secret and `action_root` are never stored with the coin and
  never derived from the Phantom Key. A wallet derives them from its wallet
  seed (spec 09, section 9) or from a card, so that the words alone give the
  policy class and nothing more.

### 3.2 The capsule and note version 3

Every commitment's encrypted note grows from 156 to 380 bytes. The plaintext
grows from 128 to 352 bytes: the note version 2 plaintext of spec 01, section
9, then a 224-byte capsule. The nonce (12 bytes) and the tag (16 bytes) are
unchanged, so `NOTE_BYTES = 12 + 352 + 16 = 380`. The note version byte is
`0x03`. Everything else about the note holds: ChaCha20-Poly1305, the 3-byte
lookup tag then 9 random bytes, the associated data `chain_id || C`.

```text
plaintext (352) = note version 2 fields (128, with version byte 0x03) || capsule (224)

capsule = version (1) || policy_address (20) || policy_codehash (32) ||
          override_hash (32) || action_tag (32) || action_salt (32) ||
          params_len (1) || params (64) || zero pad (10)
```

- A coin with the empty rule has a version 0 capsule: all 224 bytes zero.
- Any coin whose rule is not empty, whichever class created it, has a version
  1 capsule for its own rule. A restoring wallet recomputes the rule from the
  capsule and compares it with the 32-byte rule at offset 64 of the plaintext.
  A mismatch discards the note, as a mismatch with the leaf does today
  (`client/src/restore.rs`, the check after `coin_commit_with_salt`).
- A remainder or a re-commit gets a capsule built for its own rule: the
  input's capsule when the rule is kept, a new one when the rule is rotated.
  It is then freshly encrypted under a fresh nonce, never copied.
- `params_len` is at most 64 and the bytes of `params` after it are zero. A
  wallet rejects a capsule with another version, a longer length or non-zero
  padding.
- The chain cannot read a note, so it cannot check that a capsule matches the
  rule. That is the wallet's duty. A wrong capsule costs the holder the
  ability to restore from the words. It costs nobody else anything.

`NOTE_BYTES` is one length for every commitment, coin or data, so that the
length is not a fingerprint (spec 01, section 9; threat model C18). The
following change with it: the salted commit data (version `0x0003`, the
version `0x0002` layout with the longer note), the data commit, the tree note
store and its pages, the restore reads, and the note lookup buckets. The data
reveal keeps its own note slot of 156 bytes (section 10.5).

## 4. The ordinary class

The class is public: it is the transaction type. Type `0x50` stays, at
`TX_VERSION = 0x0002`. A version 1 reveal is not accepted by a version 2 node.
Nothing has launched, so spec 09, question 4 allows this one re-set before
genesis, and the test networks restart from a new genesis at the change.

### 4.1 Payload

Spec 07, section 3 is unchanged except for three points: `version` is
`0x0002`, `note` is `NOTE_BYTES = 380`, and the binding is the one in section
4.2. The payload is 1,311,290 bytes and the envelope 1,311,291 bytes:

```text
PAYLOAD_BYTES  = 2 + 8 + 32 + 32 + 32 + 20 + 32 + 32 + 1,310,720 + 380 = 1,311,290
ENVELOPE_BYTES = 1,311,291
```

Every ordinary transaction has this size, whether it spends a plain coin or
uses the override.

### 4.2 Binding

`binding = K("ghost/coin-reveal-binding/v2", fields)`. The fields are those
of spec 02, section 7 with the `rule` field removed and the note widened:

| Offset | Width | Field | Value |
|---|---|---|---|
| 0 | 8 | `chain_id` | This chain's identifier |
| 8 | 2 | `version` | `0x0002` |
| 10 | 32 | `domain` | Genesis block hash |
| 42 | 1 | `statement` | `0x01` |
| 43 | 1 | `statement_version` | `0x02` |
| 44 | 2 | `type` | `COIN` (`0x02 0x01`) |
| 46 | 1 | `purpose` | `0x01` spend |
| 47 | 32 | `root` | Coin-tree root |
| 79 | 32 | `marker` | Coin marker |
| 111 | 32 | `remainder` | Remainder commitment `C'` |
| 143 | 20 | `recipient` | Address credited with `out` |
| 163 | 32 | `out` | Amount word |
| 195 | 32 | `fee` | Amount word |
| 227 | 380 | `remainder_note` | The remainder's encrypted note |

Total: 607 bytes after the tag, 636 with the 29-byte tag, five Keccak
permutations (four today). The public values of the proof are these 607 bytes
and the 32-byte digest: 639 bytes. The node computes the digest itself and
never takes one from a sender (spec 02, PS-6). Neither rule is a public value
or a binding field.

Step 11 of spec 03, section 7 ("the rule is the empty rule") is replaced by the
proof itself: the proof opens the input rule as the empty rule or as the
override case of section 4.3. The node has nothing to check there.

### 4.3 Constraints (statement S1, version 2)

Statement S1 keeps constraints 1 to 6 of spec 02, section 4 (opening,
membership, marker, remainder, ranges, conservation) with these changes.
Write `R_in` for the rule inside the input fingerprint `F` and `R_out` for the
rule inside the remainder fingerprint `F'`.

Private inputs added: `use_override` (one bit), `policy_address`,
`policy_codehash`, `params_hash`, `override_hash`, `action_tag`,
`action_salt` (the six rule fields of the input rule), `override_secret` (32
bytes), `R_out` (32 bytes).

- **O1. Switch.** `use_override` is boolean: `use_override * (use_override - 1) = 0`.
- **O2. Rule opening.** `RIN = K("ghost/reveal-policy/v2", policy_address,
  policy_codehash, params_hash, override_hash, action_tag, action_salt)`, with
  the six fields as private bytes.
- **O3. Input rule.** `R_in = use_override * RIN`, byte by byte. So
  `use_override = 0` gives 32 zero bytes, the empty rule, and
  `use_override = 1` gives the opened rule. `F` is built with this `R_in`.
- **O4. Override secret.** `use_override * (K("ghost/policy-override/v1",
  override_secret) - override_hash) = 0`, byte by byte.
- **O5. Override is real.** `use_override * (S * Sinv - 1) = 0`, where `S` is
  the sum of the 32 bytes of `override_hash` as a field element and `Sinv` is a
  private witness. `S` is at most 8,160, below the field modulus, so the
  constraint holds exactly when some byte of `override_hash` is non-zero.
- **O6. Remainder rule.** `F'` is built with `R_out` as a free private
  32-byte string. The prover chooses it: the input's rule, a rotated rule or
  the empty rule. The proof does not look at it.
- **O7. Bindings.** Constraint 7 of S1 uses the layout of section 4.2.
  `statement = 0x01`, `statement_version = 0x02`, `type = COIN`,
  `purpose = 0x01`, and the high 20 bytes of `out` and `fee` are zero.

What the cases mean:

| Case | `use_override` | What the prover must know | Public result |
|---|---|---|---|
| Plain coin | 0 | The coin's secrets (the words) | The ordinary reveal fields |
| Override | 1 | The coin's secrets and `override_secret` | The same fields, the same size, the same proof layout |
| A policy coin without the override | not possible | | Neither case opens its rule; only the policy class can spend it |

The two cases cannot be told apart from the transaction. The proof is
zero-knowledge, the AIR is one AIR, and every public value has the same
meaning in both.

### 4.4 Trace and budget

The hash schedule (spec 02's AIR is a schedule of Keccak permutations,
`proofs/src/schedule.rs`) becomes:

| Hash | Permutations | Note |
|---|---|---|
| `RIN` (the rule) | 2 | 215 bytes of input |
| `OV` (override) | 1 | 57 bytes of input |
| `F` | 2 | The rule bytes come from O3 |
| `C` | 1 | |
| `N0` to `N31` | 32 | Membership path, `N31 = root` |
| `M` | 1 | Marker |
| `F'` | 2 | The rule bytes are free |
| `C'` | 1 | Remainder |
| `B` (binding) | 5 | Section 4.2 |
| Total | 47 | Four more than the 43 of version 1 |

Two new kinds of byte source join the schedule of `proofs/src/schedule.rs`:

- **Gated carried bytes.** A block byte equals `sel * carried column` (degree
  2). It carries `RIN` into `F` under O3.
- **Gated links.** A digest byte of one hash equals a carried column, gated by
  `sel` (degree 2). It carries O4. An ungated link carries `RIN`.

New carried columns: `use_override` (1), `RIN` (32), the override hash (32),
`Sinv` (1). The carried columns go from 102 to 168. The trace is 47 * 24 =
1,128 rows, padded to 2,048 as today, and its width is the Keccak circuit
(2,633), the bit columns (1,088) and the direction column (1), 3,722 in all,
plus 168: **3,890 columns**. The highest constraint degree is 3, below the
blowup of 8, so the quotient is unchanged.

The proof budget (spec 07, section 3) changes in one number. `MAX_TRACE_WIDTH`
goes from 3,824 to 3,890. `MAX_TRACE_HEIGHT` stays 2,048. The proof-length
bound is the formula of `proofs/src/stark.rs`, `proof_length_bound`:

| Statement | Rows | Columns | `proof_length_bound` |
|---|---|---|---|
| S1 version 1 (today) | 2,048 | 3,824 | 1,056,723 |
| S1 version 2, ordinary class | 2,048 | 3,890 | 1,070,715 |
| Policy class (section 5.4) | 2,048 | 3,856 | 1,063,507 |
| Small statements (section 9) | 128 | 3,722 | 947,283 |

Both large bounds are below the 1,310,720-byte proof field, which does not
change. The batched-openings term of the security estimator depends on the
width through a logarithm; 3,890 over 3,824 moves it by about 0.025 bit. The
prover's gate re-runs the estimator on the new trace and refuses to prove if
any term falls under the rule of spec 09, section 4.1.

### 4.5 The added check

The ordinary reveal gains one state check, after the fee check (spec 03,
section 7, step 5) and before the binding: the `recipient` is not the address
of a registered policy (section 6.4).

## 5. The policy class

### 5.1 Payload and binding

Type `0x53`, `POLICY_VERSION = 0x0001`. The payload is fixed-length:

| Offset | Width | Field | Content |
|---|---|---|---|
| 0 | 2 | `version` | `0x0001` |
| 2 | 8 | `chain_id` | This chain's identifier |
| 10 | 32 | `marker` | The coin marker |
| 42 | 32 | `root` | A coin-tree root, eligible as in spec 05, section 5 |
| 74 | 32 | `remainder` | A zero-value remainder commitment `C'` |
| 106 | 32 | `out` | Amount word: the amount that goes to the escrow slot |
| 138 | 32 | `fee` | Amount word: the fee of the window (section 10.3) |
| 170 | 20 | `policy_address` | The frozen policy |
| 190 | 32 | `policy_codehash` | Its code hash |
| 222 | 32 | `params_hash` | |
| 254 | 32 | `action_tag` | |
| 286 | 32 | `action_salt` | |
| 318 | 32 | `instr` | A 32-byte payout instruction, bound but not read by the chain |
| 350 | 1,310,720 | `proof` | The serialized proof, zero padded to the field |
| 1,311,070 | 380 | `note` | The remainder's encrypted note |

Payload 1,311,450 bytes, envelope 1,311,451 bytes. There is no `recipient`:
the value goes to the slot, not to an address.

`binding = K("ghost/policy-reveal-binding/v1", fields)`:

| Offset | Width | Field | Value |
|---|---|---|---|
| 0 | 8 | `chain_id` | |
| 8 | 2 | `version` | `0x0001` |
| 10 | 32 | `domain` | Genesis block hash |
| 42 | 1 | `statement` | `0x04` |
| 43 | 1 | `statement_version` | `0x01` |
| 44 | 2 | `type` | `COIN` |
| 46 | 1 | `purpose` | `0x05` policy spend |
| 47 | 32 | `root` | |
| 79 | 32 | `marker` | |
| 111 | 32 | `remainder` | |
| 143 | 32 | `out` | |
| 175 | 32 | `fee` | |
| 207 | 20 | `policy_address` | |
| 227 | 32 | `policy_codehash` | |
| 259 | 32 | `params_hash` | |
| 291 | 32 | `action_tag` | |
| 323 | 32 | `action_salt` | |
| 355 | 32 | `instr` | |
| 387 | 380 | `remainder_note` | |

Total: 767 bytes after the tag, 798 with the 31-byte tag, six permutations.
Public values: 767 plus the 32-byte digest, 799 bytes.

### 5.2 Checks, in order

The order is that of spec 03, section 7, with the policy checks added. The node
stops at the first failure and runs the proof last.

1. Shape: type `0x53`, exact envelope length, version `0x0001`.
2. Encoding: `out` and `fee` are amount words; `policy_address` is 20 bytes.
3. Chain: `chain_id` is this chain's.
4. Fee: equal to the window fee for `G_POLICY` (section 10.3) of the including
   block's window or the window before, and the cover rule holds.
5. Binding: the node computes the digest itself.
6. Root: eligible, as in spec 03, section 7, step 7.
7. Marker: not in the spent set, and not used earlier in the block.
8. Backstop: `out + fee` is at most the hidden total.
9. Policy: `policy_address` is a frozen policy created in a block before the
   including block (section 6.1), and its `EXTCODEHASH` equals
   `policy_codehash`. `policy_address` is not a reserved address (section 6.5).
10. Tree room for the remainder.
11. Proof.

Check 9 can change when a reorganisation removes the policy. The pool repeats
it on every new head (section 11).

### 5.3 Effects

In one journaled state change that a reorganisation rewinds with the rest of
the block:

1. Record the marker as spent.
2. Append the zero-value remainder `C'` and its note, as spec 03, section 7,
   step 13 does, and write the policy reveal receipt (section 7.5).
3. If `out > 0`, open escrow slot `E[marker]` (section 7.1) with
   `remaining = out`. If `out = 0`, no slot opens; this is a fee-only spend.
4. Pay the fee as spec 07 does: burn `G_POLICY * max(price, beta)`, credit the
   rest to the block finder.
5. Add `out + fee` to `total_out`. Add `out` to `total_escrow`.

No account balance is credited and no code runs.

### 5.4 Constraints (statement S4)

S4 shares the membership, marker, range, conservation and binding gadgets of
S1.

- **P1. Rule opening.** `RIN` is the hash of section 4.3, O2. The five fields
  `policy_address`, `policy_codehash`, `params_hash`, `action_tag` and
  `action_salt` are read from the public values. `override_hash` is a private
  witness. Because the opened rule must be the one inside `F`, the published
  salt is the committed one (section 2, item 1).
- **P2. Input rule.** `F` is built with `R_in = RIN`, through an ungated carried
  copy.
- **P3. Zero remainder.** The six limbs of `v'` are constrained to zero, so
  `v = out + fee`. The remainder fingerprint `F'` is built with the empty rule
  (32 constant zero bytes) and free `s'`, `r'`, `b'` and salt.
- **P4. Membership, marker, ranges.** As S1, constraints 2, 3 and 5.
- **P5. Bindings.** `statement = 0x04`, `statement_version = 0x01`,
  `type = COIN`, `purpose = 0x05`. The high 20 bytes of `out` and `fee` are zero.

Hashes: `RIN` 2, `F` 2, `C` 1, `N0..N31` 32, `M` 1, `F'` 2, `C'` 1, `B` 6; 47
permutations. Carried columns: `r` (32), `b` (32), salt (16), `v` (6), `v'`
(6), carry bits (10) and `RIN` (32), 134 in all. Width 3,722 + 134 = **3,856**,
2,048 rows.

## 6. Frozen policies

### 6.1 The factory and the registry

A frozen policy is created only through the native factory at
`POLICY_FACTORY = 0x0000000000000000000000000000000000000062` (**Proposed**
address). Input: `salt (32) || initcode`, with `value = 0`. It does this, in
order:

1. Compute `addr = last 20 bytes of K("ghost/policy-address/v1", salt,
   keccak256(initcode))`. The address does not depend on the sender or on a
   nonce, so the same code and salt give the same address.
2. Fail if `addr` is a reserved address (section 6.5), or if an account exists
   at `addr` with a non-zero nonce, any code or any storage. If the account has
   only a balance (sent in advance by anyone), the factory burns it: it is set
   to zero and credited to nobody, and the burn counts with the burned base
   fees. A 1-wei transfer therefore cannot block a deployment, and the policy
   starts with a zero balance.
3. Write the registry entry `REG[addr] = {frozen = 1, height = current block
   number, codehash = 0}` in the native account `POLICY_REGISTRY`
   (`0x67686f7374000000000000000000000000000009`). The flag is set before
   any code runs.
4. Run `initcode` as a frozen context (section 6.2) with `ADDRESS = addr`,
   `CALLER = POLICY_FACTORY` and `value = 0`, under the gas the caller passed.
5. Deposit the returned code under the base client's rules (EIP-170 size
   limit, no `0xEF` first byte), set `REG[addr].codehash` to its Keccak-256,
   and return `addr`.

Any failure reverts the whole call, the registry entry included. The factory
charges the base client's CREATE2 gas (32,000, the init code word charge, the
execution and 200 gas per code byte) plus `REGISTRY_GAS = 40,000` for the two
registry words.

A **frozen policy created in an earlier block** (written *FP*) is an address
whose registry entry exists, whose `height` is below the current block number
and whose `codehash` is set. The code of an FP never changes: nothing in a
frozen context can destroy, replace or delegate it (section 6.2).

### 6.2 What a frozen context may do

A **frozen context** is any call frame whose executing account (the `ADDRESS`)
has a registry entry. The constructor is a frozen context. So is every frame
below it, because section 6.3 allows a frozen frame to call only other frozen
frames and natives. A non-frozen contract that calls an FP runs the FP's code
in a frozen frame; one that uses `DELEGATECALL` or `CALLCODE` on it runs the
code in its own non-frozen account, where natives refuse it (the natives check
the executing account, section 7.2).

**Forbidden** means the frame halts at once with an exceptional halt that
spends all of its gas, as the `INVALID` opcode does.

| Opcode | In a frozen context |
|---|---|
| `STOP`, `ADD`, `MUL`, `SUB`, `DIV`, `SDIV`, `MOD`, `SMOD`, `EXP`, `NOT`, `LT`, `GT`, `SLT`, `SGT`, `EQ`, `ISZERO`, `SIGNEXTEND`, `AND`, `OR`, `XOR`, `BYTE`, `SHL`, `SHR`, `SAR`, `ADDMOD`, `MULMOD`, `KECCAK256` | Allowed |
| `ADDRESS`, `CALLER`, `CALLVALUE`, `CALLDATALOAD`, `CALLDATASIZE`, `CALLDATACOPY`, `CODESIZE`, `CODECOPY`, `RETURNDATASIZE`, `RETURNDATACOPY` | Allowed. `CALLVALUE` is always zero (section 6.4). `CODESIZE` and `CODECOPY` read the frame's own code |
| `ORIGIN`, `GASPRICE` | Allowed. In an action (section 8.4) `ORIGIN` is `ACTION_CALLER` and `GASPRICE` is zero |
| `BALANCE`, `SELFBALANCE` | **Forbidden** |
| `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH` | Allowed only for the address of an FP. Forbidden for every other address, precompiles and natives included |
| `BLOCKHASH`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `DIFFICULTY`, `GASLIMIT`, `CHAINID`, `BASEFEE` | Allowed. These are the chain facts |
| `BLOBHASH`, `BLOBBASEFEE` | Invalid opcodes on Ghost already (the EVM profile) |
| `POP`, `MLOAD`, `MSTORE`, `MSTORE8`, `MCOPY`, `MSIZE`, `PUSH0` to `PUSH32`, `DUP1` to `DUP16`, `SWAP1` to `SWAP16`, `JUMP`, `JUMPI`, `PC`, `JUMPDEST`, `GAS` | Allowed |
| `SLOAD`, `SSTORE`, `TLOAD`, `TSTORE` | Allowed on the frame's own account. `SSTORE` and `TSTORE` fail in a static context, as the base client has it |
| `LOG0` to `LOG4` | Allowed (not in a static context) |
| `CALL`, `STATICCALL` | Allowed only with value zero and a target that is an FP or an allowlisted native or precompile (section 6.3). Otherwise **forbidden** |
| `CALLCODE`, `DELEGATECALL` | **Forbidden** |
| `CREATE`, `CREATE2` | **Forbidden** |
| `SELFDESTRUCT` | **Forbidden** |
| `RETURN`, `REVERT`, `INVALID` | Allowed |
| Every opcode not listed | Invalid, as in the EVM profile |

The check is made when the opcode runs, not when the code is deployed, so the
constructor and the runtime code follow one rule.

### 6.3 Call targets and the allowlist

The allowlist is checked first. A `CALL` or `STATICCALL` from a frozen context
to one of these addresses is a precompile or native call and follows its own
rules:

| Address | What | Notes |
|---|---|---|
| `0x02` | SHA-256 | |
| `0x03` | RIPEMD-160 | |
| `0x04` | Identity | |
| `0x51` | Signature verify (spec 09, section 7) | |
| `0x60` | The escrow natives (section 7.2) | |
| `0x61` | The statement checker (section 9.3) | |

Every other address that the base VM treats as a precompile, modexp (`0x05`)
and BLAKE2 (`0x09`) included, and every removed or failing precompile, is
forbidden in a frozen context. The factory (`0x62`) is also forbidden: a
frozen context cannot create. The reason is the same for all: each has a cost
or a security claim that is not fixed in this document. A later version can
add an address by changing this table.

A `CALL` or `STATICCALL` to an FP runs the target in a frozen frame. A call
to anything else is forbidden.

### 6.4 Frozen policies hold no balance

The chain refuses any value sent to the address of a registered policy, at
every place a balance can arrive:

- a `CALL` with value, and a transaction of any type whose recipient is the
  policy and whose value is not zero;
- `SELFDESTRUCT` of any contract with the policy as beneficiary (the
  `SELFDESTRUCT` fails);
- the `recipient` of an ordinary reveal (the added check of section 4.5);
- the `dest` of `pay` (section 7.2);
- the block header's `coinbase` (a block whose `coinbase` is a registered
  policy is invalid; tips are credited there);
- a balance that exists at the address before creation (it is burned, section
  6.1, step 2).

So `BALANCE` of a policy is always zero and `CALLVALUE` in its frame is always
zero. The registry is read from the state, so a reorganisation that removes a
policy removes the rule with it.

### 6.5 Reserved addresses

A policy cannot be created at, and `pay` cannot credit, a reserved address:
every address below `0x0000000000000000000000000000000000010000`, the tree,
marker, totals and commit-entry accounts of `params/ghost`
(`0x67686f7374000000000000000000000000000001` to `...07`) and the three
accounts this document adds (`...08` to `...0a`, section 7.1).

### 6.6 What a frozen policy acts on

- its immutable code;
- its own storage and the storage of older frozen policies (by calling them);
- its own escrow slots;
- the chain facts (number, timestamp, base fee, and so on);
- the transactions and actions sent to it.

Anyone can send a policy a transaction. No one can change its code, give it a
balance or alter what its slots hold. Roles that the policy's own code defines
stay possible and visible, and wallets show them before a coin commits. The
chain guarantees immutability and slot isolation. It does not guarantee that
the code is honest.

## 7. Escrow slots

### 7.1 Storage

Slots live in the native account `ESCROW_ACCOUNT`
(`0x67686f7374000000000000000000000000000008`), which holds no code and
rejects every EVM access (`CALL`, `BALANCE`, `EXTCODE*`), as the commit entries
do (`core/vm/evm.go`, `IsCommitEntry`). The word `i` of the slot for `marker`
is at storage key `K("ghost/escrow-slot/v1", marker, i as 1 byte)`.

| Word | Content | Width |
|---|---|---|
| 0 | `policy_address` (20), `open` (1), `action_nonce` (8) | 29 |
| 1 | `remaining` (12), `out` (12), `height` (8) | 32 |
| 2 | `timestamp` (8), `paid` (12), `recommitted` (12) | 32 |
| 3 | `action_debits` (12), `forfeited` (12) | 24 |
| 4 | `params_hash` | 32 |
| 5 | `action_tag` | 32 |
| 6 | `action_salt` | 32 |
| 7 | `instr` | 32 |

`height` and `timestamp` are the opening block's. All amounts are below `2^96`
and use 12 bytes. When a slot closes, words 4 to 7 are cleared and words 0 to 3
stay (`open = 0`). A closed slot is never reopened: a marker is spent once.

Opening a slot costs `SLOT_OPEN_GAS = 8 * 20,000 = 160,000` (the base client's
price of a new storage word), paid inside `G_POLICY`.

`POLICY_REGISTRY` (`...09`) holds the registry words of section 6.1 and
`ACTION_CALLER` (`...0a`) is the address an action call comes from (section
8.4). Neither holds code. Both reject every EVM access.

### 7.2 The native functions

The natives are at `ESCROW_NATIVES = 0x0000000000000000000000000000000000000060`
(**Proposed** address). Input is `op (1) || arguments`. Every function needs:

- the caller to be a frozen context (section 6.2) whose executing account is
  the slot's `policy_address`: the natives check `ADDRESS` of the calling
  frame, never `ORIGIN`, and never the code that runs;
- the slot to exist and be open;
- for `pay`, `recommit` and `close`, a non-static call.

A failure acts as `REVERT` with empty data: the flat gas is spent, the rest is
returned and the call changes nothing. Gas is flat per function and charged
before the work.

| Op | Function | Arguments | Output | Gas |
|---|---|---|---|---|
| `0x01` | `slot(marker)` | `marker (32)` | 15 words: `policy_address`, `open`, `remaining`, `out`, `paid`, `recommitted`, `action_debits`, `forfeited`, `action_nonce`, `height`, `timestamp`, `params_hash`, `action_tag`, `action_salt`, `instr`. A slot of another policy, or none, reads as absent: the call fails | 16,900 |
| `0x02` | `pay(marker, dest, amount)` | `marker (32)`, `dest (32, left-padded address)`, `amount (32)` | none | 56,000 |
| `0x03` | `recommit(marker, F, salt, note, amount)` | `marker (32)`, `F (32)`, `salt (16)`, `amount (32)`, `note (380)` | none | 31,000 |
| `0x04` | `close(marker)` | `marker (32)` | none | 20,000 |
| `0x05` | `actionMarker()` | none | the marker of the running action (32) | 200 |
| `0x06` | `actionSettle()` | none | `expected_remaining - debit` (32) | 200 |

The flat gases are the base client's warm access (100) plus its storage prices
for the words each function reads and writes, plus the bytes of a recommit at
16 gas each (6,848), rounded up. The build ticket tests that none of them is
less than that sum.

Rules of the writing functions. Each checks `amount <= remaining` and
`amount >= 1` (for `pay` and `recommit`), then lowers `remaining` by `amount`
**before** any other effect:

- **`pay`.** The top 12 bytes of `dest` must be zero; the low 20 bytes are the
  address. It may not be
  an FP or any registered policy (section 6.4) or a reserved address (section
  6.5). The effect is `AddBalance(dest, amount)`. No code runs, whatever the
  code at `dest` is or later becomes. `paid` grows by `amount`.
- **`recommit`.** `C = K("ghost/coin-commitment/v1", COIN_V2, F, amount)`. The
  call has the effects of commit step 10 (spec 03, section 6) without the
  burn: append `C` and the note, store the salt beside `F`, write the commit
  receipt, add `amount` to `total_in`. The note must be exactly `NOTE_BYTES`
  long. The coin tree must have room (commit step 8); if it is full the call
  fails and the policy must handle it. `recommitted` grows by `amount`.
- **`close`.** `forfeited` grows by `remaining`, `remaining` becomes zero, the
  value is credited to nobody (the rule for the data reserve, spec 04, section
  6). `total_escrow` falls by the same amount.
- **Closing.** A slot closes when `remaining` reaches zero or on `close`. A
  closed slot rejects every function.

`actionMarker()` and `actionSettle()` work only inside an action (section 8.4),
only for the policy the action is addressed to. Elsewhere they fail.

A policy can never move value from a slot to another slot or to itself, and
the natives hold no state of their own beyond the slot words.

### 7.3 Accounting

For every slot, at all times:

```text
out = remaining + paid + recommitted + action_debits + forfeited
```

Chain totals (`PrivTotalsAccount`, spec 03, section 9):

| Event | `total_in` | `total_out` | `total_escrow` |
|---|---|---|---|
| Slot opens with `out` (and fee) | | `+ out + fee` | `+ out` |
| `recommit(amount)` | `+ amount` | | `- amount` |
| `pay(amount)` | | | `- amount` (value moves to a balance) |
| Action debit | | | `- debit` (value burned and tipped) |
| `close` | | | `- remaining` (value forfeited) |

`total_escrow` is a third slot of `PrivTotalsAccount` (slot 2). It equals the
sum of `remaining` over open slots. Only `recommit` touches the hidden-set
totals. The hidden total, `total_in - total_out`, still means the value in
unspent commitments; escrow value is outside it. The supply reading of spec
03, section 9 gains a term:

```text
public supply = issuance - burned base fees - hidden total - total_escrow
```

where "burned base fees" now includes the burned part of every action debit,
and forfeited escrow stays out of supply for good, as the forfeited data
reserve does.

### 7.4 Two rollback boundaries

- A **policy-call revert** inside an action undoes the policy's storage
  writes, slot moves, tree appends, totals and logs from that call. It never
  undoes the action's debit or nonce (section 8.4).
- A **chain reorganisation** rewinds everything, debit and nonce included,
  with balances, trees, markers and totals (spec 05, section 7).

### 7.5 Logs

The native code writes these logs (address `ESCROW_ACCOUNT`, topic 0 the tag
hash `K(name)`, topic 1 the marker):

| Name | Data |
|---|---|
| `ghost/slot-opened/v1` | `policy_address (32)`, `out (32)`, `instr (32)` |
| `ghost/slot-paid/v1` | `dest (32)`, `amount (32)` |
| `ghost/slot-recommitted/v1` | `amount (32)` |
| `ghost/slot-closed/v1` | `forfeited (32)` |
| `ghost/action-result/v1` | `action_nonce (32)`, `success (32)`, `debit (32)` |

The policy reveal also writes a receipt from the coin tree account, topics
`K("ghost/policy-reveal-receipt/v1")` and the marker, data
`loc (8) || remainder (32) || note (380) || policy_address (20) || out (32) ||
instr (32)`.

## 8. Policy actions

### 8.1 The transaction

Type `0x54`, `ACTION_VERSION = 0x0001`. No sender, nonce, gas price or
signature: the proof is the authority and the slot pays.

| Offset | Width | Field | Content |
|---|---|---|---|
| 0 | 2 | `version` | `0x0001` |
| 2 | 8 | `chain_id` | |
| 10 | 32 | `marker` | The slot |
| 42 | 8 | `action_nonce` | Must equal the slot's |
| 50 | 32 | `expected_remaining` | Amount word: the slot's `remaining` |
| 82 | 32 | `debit` | Amount word charged from the slot |
| 114 | 8 | `expiry` | Last block height at which the action is valid |
| 122 | 2 | `calldata_len` | At most `ACTION_CALLDATA_MAX = 1,024` |
| 124 | 1,024 | `calldata` | Zero padded after `calldata_len` bytes |
| 1,148 | 948,224 | `proof` | `ACTION_PROOF_BYTES`, zero padded |

Payload 949,372 bytes, envelope 949,373 bytes. `ACTION_PROOF_BYTES` is the
bound of section 4.4 for the small statements, 947,283, rounded up to a
multiple of 1,024. Padding must be zero. The policy is not a field: it is the
slot's `policy_address`.

### 8.2 The statement KNOW_ACTION_v1

Statement code `0x05`, version `0x01`, purpose `0x06`.

Public inputs, set by the node from the slot and the transaction (the prover
supplies none): `chain_id`, `version`, `domain`, `policy_address`, `marker`,
`action_nonce`, `action_tag` and `action_salt` (both **read from the slot**,
never from the transaction), `expected_remaining`, `debit`, `expiry` and
`calldata_hash`.

`calldata_hash = K("ghost/action-calldata/v1", calldata_len (2), calldata
(calldata_len bytes))`.

The proof shows that the prover knows `action_root` with
`K("ghost/policy-action/v1", action_root, action_salt) = action_tag`.

`binding = K("ghost/action-binding/v1", fields)`:

| Offset | Width | Field |
|---|---|---|
| 0 | 8 | `chain_id` |
| 8 | 2 | `version` (`0x0001`) |
| 10 | 32 | `domain` |
| 42 | 1 | `statement` (`0x05`) |
| 43 | 1 | `statement_version` (`0x01`) |
| 44 | 1 | `purpose` (`0x06`) |
| 45 | 20 | `policy_address` |
| 65 | 32 | `marker` |
| 97 | 8 | `action_nonce` |
| 105 | 32 | `action_tag` |
| 137 | 32 | `action_salt` |
| 169 | 32 | `expected_remaining` |
| 201 | 32 | `debit` |
| 233 | 8 | `expiry` |
| 241 | 32 | `calldata_hash` |

Total: 273 bytes after the tag, 297 with the 24-byte tag, three permutations.
Constraints:

- **A1.** `A = K("ghost/policy-action/v1", action_root, action_salt)` with
  `action_root` free and private (one permutation, 87 bytes of input).
- **A2.** `A` equals the public `action_tag` byte by byte.
- **A3.** The binding (three permutations) is built over the public inputs.
- **A4.** `statement = 0x05`, `statement_version = 0x01`, `purpose = 0x06`.

The node has already refused a slot with `action_tag = 0` (check 4 of section
8.3), so the circuit does not test it.

Four permutations, 96 rows, padded to 128. No carried columns: width 3,722.

### 8.3 Checks, in order

The node (pool and block) makes them in this order and stops at the first
failure:

1. Shape: type `0x54`, exact length, version, zero padding, `calldata_len` at
   most 1,024.
2. Encoding: `expected_remaining` and `debit` are amount words.
3. Chain: `chain_id` is this chain's.
4. Slot: `E[marker]` exists, is open, belongs to an FP (the registry entry is
   still there) and has `action_tag != 0`.
5. Nonce: `E.action_nonce = action_nonce`.
6. Amount: `E.remaining = expected_remaining` and `debit <= expected_remaining`.
7. Expiry: the including block's height is at most `expiry`.
8. Price: `debit >= G_ACTION * baseFee`, with the including block's base fee.
9. Binding: the node computes the digest itself.
10. Proof.

If any check fails in a block, the block is invalid. If the base fee rises above
`debit / G_ACTION` before the action lands, it waits or expires. It is never
charged more than `debit`. If the slot changed, the action is invalid and
nothing is charged.

### 8.4 Execution

After the checks, in one journaled change:

1. **Charge.** `E.remaining -= debit`; `E.action_debits += debit`;
   `total_escrow -= debit`. `G_ACTION * baseFee` is burned (credited to
   nobody). The rest, `debit - G_ACTION * baseFee`, is credited to the block
   finder. `E.action_nonce += 1`. If `E.remaining = 0` the slot closes.
2. **Mark.** Take a snapshot.
3. **Call.** Call `policy_address` with `from = ACTION_CALLER`, value zero,
   input `calldata[0..calldata_len]` and gas `ACTION_CALL_GAS = 250,000`, in a
   non-static frozen context. In this context `actionMarker()` returns the
   marker and `actionSettle()` returns `expected_remaining - debit`. `ORIGIN`
   is `ACTION_CALLER`; `GASPRICE` is zero.
4. **Result.** If the call reverts or halts, restore the snapshot of step 2.
   The charge and the nonce stay. Write the `ghost/action-result/v1` log in
   both cases. The unused call gas is not refunded: an action always costs
   `G_ACTION`.

The receipt status is successful whenever the action was admitted. The result
log says whether the call succeeded. The action uses `G_ACTION` gas from the
block gas pool.

The debit is exact. The amount left for the policy is known when the proof is
made. The owner chooses `debit` with room above `G_ACTION * baseFee`: the
excess is the tip that outbids other private transactions for block space.

## 9. Native statements

A fixed list. Each has a pinned code, disjoint tags, a fixed proof size, fixed
trace dimensions, a fixed public-input length, its own security gate and a
measured gas constant.

| Statement | Code | Version | Purpose | Used by |
|---|---|---|---|---|
| `S1` version 2 (ordinary reveal) | `0x01` | `0x02` | `0x01` | Type `0x50` |
| `S4` (policy reveal) | `0x04` | `0x01` | `0x05` | Type `0x53` |
| `KNOW_ACTION_v1` | `0x05` | `0x01` | `0x06` | Type `0x54` only |
| `KNOW_PREIMAGE_v1` | `0x06` | `0x01` | `0x07` | The statement checker |

Arbitrary developer statements are deferred.

### 9.1 Domain separation

Each statement has its own binding tag, statement code and purpose code, so a
digest made for one cannot verify for another. `KNOW_PREIMAGE_v1` can never
stand in for `KNOW_ACTION_v1`: the action path accepts only statement
`0x05`, and the checker accepts only statement `0x06`.

### 9.2 KNOW_PREIMAGE_v1

The proof shows knowledge of `x` (32 bytes) with
`y = K("ghost/policy-preimage/v1", x)`. Public inputs: `chain_id`, `version`,
`domain`, `policy_address` (the calling policy), `y (32)` and `context (64)`,
a value the policy supplies. `binding = K("ghost/preimage-binding/v1",
fields)` over: `chain_id (8)`, `version (2)`, `domain (32)`, `statement (1)`,
`statement_version (1)`, `purpose (1)`, `policy_address (20)`, `y (32)`,
`context (64)`; 161 bytes, 187 with the tag, two permutations. One more
permutation computes `y`. Three permutations, 72 rows, padded to 128; width
3,722; proof field `ACTION_PROOF_BYTES`.

### 9.3 The statement checker

At `STATEMENT_CHECKER = 0x0000000000000000000000000000000000000061`
(**Proposed**). Input: `statement (1) || y (32) || context (64) || proof
(ACTION_PROOF_BYTES)`. Only a frozen context may call it, and only with
`statement = 0x06`. It returns 32 bytes, 1 or 0. Gas:
`PREIMAGE_VERIFY_GAS = 110,000` plus 3 per 32-byte word of input, charged
before verifying and whether or not the proof verifies. An input of any other
length fails.

A proof is about 0.93 MiB, so a transaction that carries one exceeds the
128 KiB per-transaction cap of the pool (spec 09, section 8.3). Section 15,
item 3 keeps the checker failing closed until the pool rule for such
transactions is specified.

## 10. Gas constants and fees

### 10.1 Rules

The rules of spec 07, section 4 hold for each class: a private transaction
does not choose its fee; the fee is the window fee for the class's gas; the
cover rule holds for the including block. The gas of each type is one fixed
figure.

```text
gas(type) = BYTE_GAS * ENVELOPE_BYTES(type) + BASE_TX_GAS + VERIFY_GAS(type) + extra(type)
```

`BYTE_GAS = 16` and `BASE_TX_GAS = 21,000`, unchanged. The verification
charge follows spec 07's rule, `GAS_PER_MS = 10,000` (30,000,000 gas over
3,000 ms), applied to the slowest recorded native verification at the shipped
configuration.

### 10.2 The verification charge

The recorded slowest verification of the budget trace is **10.61 ms** (nine
proofs at blowup 2^3 and 43 queries, `docs/benchmarks/reveal-parameters.md`,
"Verifying times"; the median is 8.08 ms). Verification cost grows with the
trace width and the number of queries, and hardly at all with the number of
permutations, because the verifier opens a fixed number of queries on rows of
that width. So:

```text
10.61 ms * (3,890 / 3,824) = 10.79 ms  ->  107,900 gas
VERIFY_GAS_ORD = VERIFY_GAS_POLICY = VERIFY_GAS_ACTION = 110,000   (rounded up)
```

The small statements (128 rows, 3,722 columns) are no larger than the
ordinary class in either dimension, so they take the same charge as an upper
bound. The build ticket of section 18 measures at least 1,000 verifications of
each statement in the node's own verifier on the reference hardware. If the
slowest exceeds 11.0 ms (110,000 gas) the constant is **raised** in that
change. A lower measured value does not lower it without a deliberate
consensus change. The data reveal keeps `VERIFY_GAS_DATA = 92,300`: its trace
has half the rows and its pricing does not change (section 10.5).

If the proof configuration changes under spec 09, section 4.1, every constant
of this section is recomputed from the formulas here with the new
`PROOF_BYTES`, bounds and measurements.

### 10.3 The constants

| Name | Value | Meaning |
|---|---|---|
| `NOTE_BYTES` | 380 | Encrypted note, every commitment (section 3.2) |
| `ORD_ENVELOPE_BYTES` | 1,311,291 | Ordinary reveal (section 4.1) |
| `POLICY_ENVELOPE_BYTES` | 1,311,451 | Policy reveal (section 5.1) |
| `ACTION_ENVELOPE_BYTES` | 949,373 | Policy action (section 8.1) |
| `VERIFY_GAS_ORD`, `_POLICY`, `_ACTION` | 110,000 each | Section 10.2 |
| `SLOT_OPEN_GAS` | 160,000 | Eight new storage words (section 7.1) |
| `ACTION_STATE_GAS` | 15,000 | Three storage word updates at 5,000: nonce, remaining, debits |
| `ACTION_CALL_GAS` | 250,000 | Cap on the policy call |
| `G_PRIV` | 21,111,656 | `16 * 1,311,291 + 21,000 + 110,000` |
| `G_POLICY` | 21,274,216 | `16 * 1,311,451 + 21,000 + 110,000 + 160,000` |
| `G_ACTION` | 15,585,968 | `16 * 949,373 + 21,000 + 110,000 + 15,000 + 250,000` |
| `FEE_WINDOW`, `FEE_STEPS`, `TIP_DIVISOR` | 4, 1, 10 | Unchanged (spec 07) |

Window fee for a class: `price_w` as in spec 07, section 4;
`base_part = G_class * price_w`; `tip = ceil(base_part / 10)`;
`fee = base_part + tip`. The burn is `G_class * max(price_w, beta)`. The three
classes have three fees in the same window.

Worked values at the genesis base fee of 1 gwei (`b_ref = 1,000,000,000`,
`price = 1,125,050,001`):

```text
[window-genesis-ordinary]
g = 21111656
base_part = 23751668603911656
tip = 2375166860391166
fee = 26126835464302822
cover_limit = 1237555001

[window-genesis-policy]
g = 21274216
base_part = 23934556732074216
tip = 2393455673207422
fee = 26328012405281638
cover_limit = 1237555001
```

The ordinary fee rises by 26,340,120,643,412 wei over version 1's
26,100,495,343,659,410 (about 0.1 percent). The lowest `debit` of an action at the same base fee is
`G_ACTION * 1,000,000,000 = 15,585,968,000,000,000` wei, about 0.0156 GHOST.

Other parameters of this document:

| Name | Value | Meaning |
|---|---|---|
| `ORD_TX_TYPE`, `ORD_TX_VERSION` | `0x50`, `0x0002` | Ordinary reveal |
| `POLICY_TX_TYPE`, `POLICY_VERSION` | `0x53`, `0x0001` | Policy reveal |
| `ACTION_TX_TYPE`, `ACTION_VERSION` | `0x54`, `0x0001` | Policy action |
| `ACTION_CALLDATA_MAX` | 1,024 | Bytes of calldata in an action |
| `ACTION_PROOF_BYTES` | 948,224 | `ceil(947,283 / 1,024) * 1,024` |
| `MAX_TRACE_WIDTH` | 3,890 | Raised from 3,824 (section 4.4) |
| `MAX_PARAMS_BYTES` | 64 | Policy parameters in a rule and a capsule |
| `HOLD_BLOCKS`, `HOLD_SECONDS` | 8,640, 259,200 | Guard's hold (section 12) |
| `REGISTRY_GAS` | 40,000 | Two new storage words for a registry entry |
| `ESCROW_NATIVES`, `STATEMENT_CHECKER`, `POLICY_FACTORY` | `0x60`, `0x61`, `0x62` | Native addresses (**Proposed**) |
| `ESCROW_ACCOUNT`, `POLICY_REGISTRY`, `ACTION_CALLER` | `0x6768...08`, `...09`, `...0a` | Native accounts (**Proposed**) |
| `PEER_FAIL_LIMIT` | 3 | Failed proofs per head before a peer is dropped (**Proposed**) |

### 10.4 Block space

The default gas limit is 30,000,000 (spec 05, question 1). `G_PRIV` and
`G_POLICY` are each more than half of it. `G_ACTION` is 15.6 million; it plus `G_PRIV` is 36.7 million and two actions
are 31.2 million. So a block holds at most one private
transaction of any type, as spec 07 already says for reveals. A cancel
competes with reveals and other actions for that space, and wins by paying a
larger tip in `debit`. This is the cost of proofs near a megabyte. Question 4
of section 17 asks whether to change it.

### 10.5 Data constants

The data reveal (type `0x51`) is separated from the coin reveals in every path
that shares a constant today, so that data pricing and the data envelope do
not change:

- `GhostDataRevealGas` in `core/types/tx_ghost_private.go` (line 167, now
  `= GhostRevealGas`) becomes its own constant, `G_DATA = 16 * 1,311,067 +
  21,000 + 92,300 = 21,090,372`.
- The data reveal's payload stays 1,311,066 bytes with a 156-byte note slot
  (`DATA_NOTE_SLOT = 156`). The slot carries `cf` in its first 32 bytes and 124
  zero bytes; `ghostpriv.DataReveal.Note` is `DATA_NOTE_SLOT - 32` bytes, not
  `NoteBytes - 32`.
- The gas pool and block accounting use the type's own gas at
  `core/state_processor.go` (line 198), `miner/worker.go` (line 1027, line 1055
  and line 1086 for the room check).
- `WindowFee`, the cover split and the pool's window fees take the gas of the
  class as an argument. `ghostpriv.GasPriv` (`ghostpriv.go`, lines 285 and 321)
  no longer serves every kind. A data reveal pays the window fee for `G_DATA`,
  within `DATA_RESERVE` as now.

## 11. Pool admission

Policy reveals and actions enter the pool the reveal pool already has
(`core/txpool/ghostpool`). Nothing is added to the pool of ordinary
transactions.

**Shared limits.** Applied to all four private types (`0x50`, `0x51`, `0x53`,
`0x54`), before any proof is verified:

- the per-peer token budget: `PeerRevealsPerBlock = 4` per head, charged to the
  peer for each delivery, announced or not;
- `PeerMaxInFlight = 4`, `PeerMaxHeld = 4`, one check slot per peer;
- the verification concurrency: `maxValidations = 4` checks, one kept for
  local transactions;
- a bound on the hashes of refused transactions (`maxRejected = 4,096`).

**Caps.** Reveals of all three coin kinds keep `MaxReveals = 16` and
`MaxBytes = 16 * 1,311,451 = 20,983,216`. Actions have their own:
`MaxActions = 8` and `MaxActionBytes = 8 * 949,373 = 7,594,984`. A flood of
one kind cannot fill the other's room.

**Keys.**

- A policy reveal is held under the coin marker, one per marker across all
  coin reveal types, first seen wins.
- An action is held under `(marker, action_nonce)`. The key is reserved only
  after the proof verifies. An unverified action reserves nothing, so it
  cannot hold a victim's slot. Only the holder of the action key can make two
  valid actions for one `(marker, nonce)`; the first to verify is kept, and
  the other is refused without a penalty.

**Cheap checks before the proof.** For a policy reveal: shape, chain, fee,
marker unused, and check 9 of section 5.2. For an action: checks 1 to 8 of
section 8.3. Each costs state reads only.

**Penalties.** A delivery whose proof fails is remembered by hash and refused
again without a check. A peer with `PEER_FAIL_LIMIT = 3` failed proofs at one
head is dropped (`DropPeer`). **Proposed.**

**Recheck on every new head.** All cheap checks run again for every held
transaction against the block that would come next, as for reveals
(`ghostpool.Reset`). A held action is not verified again: its public inputs
are exactly what the cheap checks read. Anything that no longer holds is
dropped: a slot that closed, a nonce that moved, a policy that a
reorganisation removed, a base fee that now exceeds `debit / G_ACTION`, an
expiry that passed.

**Order for a block.** The block builder takes the private transactions with
the highest tip per gas first, then by hash. A reveal's tip per gas is the
tip it pays divided by its gas. An action's is `(debit - G_ACTION * baseFee) /
G_ACTION`.

**Wire and RPC.** Types `0x53` and `0x54` travel and are fetched like `0x50`
and `0x51` (`FilterAnnounced`, the delivery path in `eth/handler_eth.go`). A
node's own RPC accepts them through `eth_sendRawTransaction`. A new method,
`ghost_escrowSlot(marker)`, returns the fifteen words of `slot()` for a wallet.

## 12. Ghost Guard

Guard is a frozen policy with fixed code, empty parameters, no balance and two
entry points. Its address and code hash are fixed by the build ticket of
section 18 in a constants-only change, after the code is final. They are the
`policy_address` and `policy_codehash` of every Guard rule.

**Commit.** The wallet makes a rule: `policy_address = GUARD_ADDRESS`,
`policy_codehash = GUARD_CODEHASH`, `params_hash = K("ghost/policy-params/v1")`
(empty parameters), `override_hash = K("ghost/policy-override/v1",
guard_secret)`, `action_tag = K("ghost/policy-action/v1", stop_root,
action_salt)`, a fresh `action_salt`. It commits a coin whose fingerprint
holds that rule and whose note holds the capsule. The `guard_secret` is held
by the app and the `stop_root` by the stop card. Neither comes from the
Phantom Key.

**Normal spend.** The ordinary class with `use_override = 1`. It is instant
and looks like every other spend. The remainder rule is the owner's choice.

**Words-only spend.** The policy class, a full sweep, `instr` set to the
recipient (12 zero bytes then the address). The coin's value goes to the slot.
Anyone with the words can do this, and the stop card can cancel it.

**Release.** `Guard.release(marker)` is an ordinary transaction that anyone
may send and that pays its own gas. It reads `slot(marker)`, and needs
`height >= E.height + HOLD_BLOCKS` and `timestamp >= E.timestamp + HOLD_SECONDS`
with `HOLD_BLOCKS = 8,640` and `HOLD_SECONDS = 259,200` (72 hours at 30
seconds a block), and the top 12 bytes of `instr` zero. Then it calls
`pay(marker, address(instr), remaining)`. There is no relay fee.

**Cancel.**

1. The stop card and the phone read `E` with `ghost_escrowSlot`.
2. They choose `debit` and `expiry`, compute `a = E.remaining - debit`, build
   a new key's `F_new` and note for the exact commitment
   `C = K("ghost/coin-commitment/v1", COIN_V2, F_new, a)`, with a fresh
   `action_salt` in the new coin's rule.
3. They sign `calldata = cancel(F_new, salt_new, note_new)` into a policy
   action.
4. Guard's `cancel` requires that `actionMarker()` succeeds, then calls
   `recommit(marker, F_new, salt_new, note_new, actionSettle())`.

The amount in the note matches the commitment, so a words-only restore finds
the new coin. Release and cancel share the slot's single closed state: the
first one to land closes it.

**Every amount.**

| Situation | Outcome |
|---|---|
| Coin value below the reveal fee | Unspendable, like any dust coin today |
| `out = 0` | A fee-only spend; no slot |
| Slot of any size, after the hold | Release pays all of `remaining` to `instr`; the sender pays gas |
| Slot with `remaining > debit` | Cancel re-commits `remaining - debit` |
| Slot with `remaining <= debit` at the current base fee | Cancel cannot run. The owner may wait for lower fees until the hold ends. Wallets advise Guard spends well above the action cost |
| `debit = remaining` | The action closes the slot and the cancel's `recommit` of zero fails: nothing is re-committed |

**Transfer.** The owner spends on the ordinary class with the override and
sets the remainder rule to the receiver's own Guard rule, with a fresh
capsule, or to empty. A coin handed over as words alone stays under the
giver's stop key. Wallets say so before they hand one over.

**Not promised.**

- A majority of miners that also holds the words can censor cancels. The hold
  floors are chain-height and chain-timestamp floors (spec 06, section 5.1),
  not wall-clock guarantees.
- A cancel needs a block with room (section 10.4) and a slot larger than the
  action cost.
- A full coin tree makes `recommit` fail (section 7.2), and the cancel with it.
  The tree rollover of spec 05 is the answer; this document does not specify
  a reserve of room.

## 13. Privacy and quantum claims

**Privacy.**

- The ordinary class hides whether a coin has a policy. It hides the use of
  the override. All ordinary transactions have one size and one proof layout.
- A policy-class reveal shows the policy, its code hash, `params_hash`, a
  per-coin `action_tag` and `action_salt`, `instr` and the amount `out`. It
  does not show which commit it spends.
- Slot activity is public: opening, actions, the debit, payment, re-commit and
  close. A cancel's new coin is as private as a fresh Vanish of its amount.
- Third-party policies leak what their parameters leak.
- The policy class is public by design. A holder who does not want that uses
  the ordinary class.

**Quantum safety.** Native authority, actions and statements are hash-based
and quantum-safe. The proofs follow spec 09, section 4.1. A frozen policy
cannot call the elliptic-curve or modexp precompiles. Cryptography that a
third party writes in bytecode is outside the chain's guarantee (spec 09,
section 7).

## 14. Properties

Each is numbered so that a build ticket's test can cite it. A test that still
passes with the check it names removed does not count (spec 03, section 10).

- **RP-1. One ordinary shape.** An ordinary transaction with `use_override = 0`
  and one with `use_override = 1` have the same length, the same public-value
  layout and the same proof field width; a verifier cannot tell them apart from
  the fields.
- **RP-2. The switch is boolean.** A witness with `use_override = 2` fails
  constraint O1.
- **RP-3. No override on an empty rule.** A coin with the empty rule cannot be
  spent with `use_override = 1`, and a coin with a non-empty rule cannot be
  spent with `use_override = 0`.
- **RP-4. The override needs the secret.** With `use_override = 1`, a wrong
  `override_secret` fails O4. An `override_hash` of zero fails O5.
- **RP-5. The remainder rule is private.** The remainder rule is in no public
  value, and changing it changes neither the transaction length nor the
  proof's public values.
- **RP-6. The published salt is the committed one.** A policy reveal whose
  `action_salt` differs from the rule's is rejected: the proof fails.
- **RP-7. A policy reveal cannot keep value.** A witness with `v' != 0` fails
  P3.
- **RP-8. Both classes share markers.** A coin spent by the ordinary class
  cannot be spent by the policy class, and the other way round.
- **RP-9. The policy must exist.** A policy reveal for an address that is not
  an FP, or whose `EXTCODEHASH` differs, is rejected before the proof; a
  reorganisation that removes the policy drops it from the pool.
- **RP-10. A frozen context cannot leave its sandbox.** Each forbidden opcode
  of section 6.2 halts the frame, in the constructor and at depth 3. Calls to
  `0x05` and `0x09` from a frozen context fail.
- **RP-11. No balance.** Every path of section 6.4 fails; the balance of a
  policy is zero after any sequence of transactions.
- **RP-12. Slot isolation.** Policy A cannot read, pay, recommit or close a
  slot of policy B, by a call, a `DELEGATECALL` from a non-frozen contract or
  an action.
- **RP-13. The accounting identity.** After any sequence of slot operations,
  `out = remaining + paid + recommitted + action_debits + forfeited` for every
  slot, `total_escrow` equals the sum of `remaining`, and the hidden total
  moves only on a policy reveal and a `recommit`.
- **RP-14. Decrement first.** A policy that calls `pay` for more than
  `remaining`, or twice for the whole of it, fails the second time.
- **RP-15. No recipient code.** A `pay` to a contract that would reenter runs
  no code.
- **RP-16. An action binds every field.** Changing the nonce,
  `expected_remaining`, `debit`, `expiry`, the calldata, the marker or the
  chain makes the proof fail.
- **RP-17. Tag and salt come from the chain.** An action built against a salt
  that differs from the slot's fails.
- **RP-18. The charge is exact.** An admitted action lowers `remaining` by
  exactly `debit`, burns `G_ACTION * baseFee` and credits the rest to the
  block finder.
- **RP-19. Revert keeps the charge.** A policy call that reverts leaves the
  debit and the nonce and undoes the call's other effects.
- **RP-20. A reorganisation rewinds the debit.** After a reorganisation that
  removes the action's block, the slot, the nonce, the balances and the totals
  equal their earlier values.
- **RP-21. A stale action is refused.** An action with the wrong nonce, the
  wrong `expected_remaining`, a passed `expiry` or a `debit` under
  `G_ACTION * baseFee` is rejected before the proof and charges nothing.
- **RP-22. Unverified actions hold nothing.** A flood of invalid actions for a
  slot does not stop a valid action for it from being admitted.
- **RP-23. Pool caps are separate.** Filling the action cap leaves room for
  reveals, and the other way round.
- **RP-24. Gas is fixed.** Each type takes exactly its gas from the block
  gas pool, and the data reveal still takes `G_DATA`.
- **RP-25. Guard release.** `release` fails before the hold in blocks or in
  time, and pays `remaining` after both.
- **RP-26. Guard cancel.** A cancel from the stop card re-commits
  `remaining - debit` to the new key; a words-only restore finds it; a
  release after it fails.
- **RP-27. Words alone are not enough.** A holder of the words, without the
  override secret and without `action_root`, cannot make an ordinary spend,
  and cannot cancel or alter a slot.
- **RP-28. Secrets are independent of the words.** No path derives
  `guard_secret` or `stop_root` from a Phantom Key.
- **RP-29. Notes round-trip.** A wallet restores a policy coin from its
  capsule, and discards a note whose capsule does not match the rule or the
  leaf.
- **RP-30. The checker fails closed.** The statement checker returns failure
  while section 15, item 3 is open.

## 15. Not settled: fail closed

1. **Verification constants.** `VERIFY_GAS_ORD`, `_POLICY` and `_ACTION` are set
   from the recorded 10.61 ms (section 10.2). Until the build ticket's
   measurement of at least 1,000 verifications per statement is recorded, a
   node uses these values, and it does not accept a lower one.
2. **Admission limits.** `PEER_FAIL_LIMIT`, `MaxActions` and `MaxActionBytes`
   are proposed. A node enforces them as written until the pool's flood
   tests set others.
3. **The statement checker.** A proof for `KNOW_PREIMAGE_v1` is about 0.93 MiB
   and does not fit the account transaction pool cap of 128 KiB. Until a rule
   admits such a transaction, the checker at `0x61` fails every call, and no
   policy may rely on it. `KNOW_ACTION_v1` is not affected: it travels in its
   own transaction type.
4. **Guard address and code hash.** Until the Guard code is final and audited,
   no node, wallet or test network treats any address as Guard.
5. **Tree room for a re-commit.** A full coin tree makes a cancel fail (section
   12). Until spec 05's rollover is built, a wallet treats a tree within
   `HOLD_BLOCKS` blocks of full as unsafe for a Guard commit.
6. **Reserved addresses.** The addresses `0x60`, `0x61`, `0x62` and the three
   accounts `...08` to `...0a` are proposed. They are replaced by the launch
   values in a constants-only change, like the existing tree accounts.
7. **Proof configuration.** All sizes and bounds are for blowup 2^3, 43
   queries. They follow spec 09, section 4.1 when the configuration changes.

## 16. What this supersedes

Changed with this document:

- **[Spec 01](01-commitments-and-keys.md), section 3 and section 9.** The rule
  is no longer always empty (section 3.1). The note is 380 bytes, note version
  `0x03` (section 3.2).
- **[Spec 02](02-proof-statements.md), section 4 and section 7.** S1 gains the
  switch and the override case; the coin reveal binding loses the `rule` field
  and carries a 380-byte note (section 4.2); S4, `KNOW_ACTION_v1` and
  `KNOW_PREIMAGE_v1` are new statements.
- **[Spec 03](03-coin-rules.md), section 7, step 11 and section 8.** "The rule
  is the empty rule" and "the rule carries over unchanged" no longer hold:
  on the ordinary class the remainder rule is the prover's choice. Section 9
  gains `total_escrow` (section 7.3). Section 8's "claim gives the new key sole
  control" holds for ordinary coins and for override reveals that rotate the
  rule; it does not hold for a policy coin handed over as words alone.
- **[Spec 07](07-private-transaction.md), sections 1 to 4, 6.** `TX_VERSION`,
  `NOTE_BYTES`, `PAYLOAD_BYTES`, `ENVELOPE_BYTES`, `VERIFY_GAS`, `G_PRIV` and the
  pool's byte cap change for the ordinary class (sections 4.1 and 10.3);
  the fee of the data reveal is no longer the coin reveal's fee but has its own
  gas (section 10.5); new types `0x53` and `0x54` are added.
- **[Spec 05](05-trees-and-headers.md).** The note store and the page layout
  use `NOTE_BYTES = 380`.
- **[Spec 09](09-quantum-safe-accounts.md), section 7.** The allowlist of
  section 6.3 is a use of the signature-verify precompile, not a change to it.
- **Locked decisions (founder, changed by the request of 2026-10-30):**

| Decision | Change |
|---|---|
| No rules on GHOST in the first milestone; later a short fixed list | Open-ended frozen policies |
| Empty rule; fixed S1 statement | Ordinary class with an override case; new policy class |
| Rule carries over unchanged (spec 03, section 8) | On the ordinary class the remainder rule is the prover's choice |
| Claim gives the new key sole control (spec 03, section 8) | True for ordinary coins and for override reveals that rotate the rule; not for a policy coin handed over as words alone |
| One private shape | Two classes: ordinary (all alike) and policy (public by design) |
| Note size 156 bytes | 380 bytes |
| Commit is top-level only | Unchanged for contracts; escrow slots re-commit natively |

## 17. Questions for the founder

Each has a default that this document already applies.

1. **Sixth rule field.** Put `action_salt` in the rule (section 2, item 1).
   Default: yes. Without it a thief with the words can disable the cancel.
2. **Verification charge.** 110,000 gas for each new statement, above the
   recorded 10.61 ms (section 10.2). Default: as written; the build ticket
   raises it if the measurement is higher.
3. **Modexp and BLAKE2 in frozen policies.** Forbidden (section 6.3), as the
   draft has it. Default: forbidden. A later version can allow BLAKE2.
4. **Block space.** One private transaction per block at 30,000,000 gas
   (section 10.4). Default: accept, as spec 07 does. A larger gas limit or a
   smaller proof would lift it.
5. **Policy actions versus reveals in the pool.** Separate caps and a shared
   peer budget (section 11). Default: as written.
6. **Version 1 reveals.** Not accepted after the change; the test networks
   restart (section 4). Default: yes, once, before genesis (spec 09, question
   4).

## 18. Build tickets

This document is cut into these pieces. Each has a behaviour a test can show.

1. **Ordinary reveal statement, version 2.** AIR, prover and verifier for
   section 4.3, binding v2, widths and bounds, vectors, the security gate on
   the new trace. Test: RP-1 to RP-5.
2. **Policy reveal statement.** S4 for section 5.4. Test: RP-6, RP-7.
3. **Action and preimage statements.** `KNOW_ACTION_v1` and `KNOW_PREIMAGE_v1`
   (sections 8.2, 9). Test: RP-16, RP-17.
4. **Note version 3 and the capsule.** Section 3.2 in the client, wallet,
   restore, node note store, pages, buckets and commit parsing. Test: RP-29.
5. **Policy reveal in the node.** Type `0x53`, checks, effects, slot opening,
   accounting, receipts, the separation of the constants (sections 5, 7.1,
   7.3, 10.5). Test: RP-8, RP-9, RP-13, RP-24.
6. **Frozen policies.** The factory, the registry, the opcode and call rules,
   the no-balance rules. Test: RP-10, RP-11.
7. **Escrow natives and policy actions in the node.** Section 7.2 and
   sections 8.3 and 8.4. Test: RP-12, RP-14, RP-15, RP-18 to RP-21.
8. **Pool admission.** Section 11 in `ghostpool` and the wire path. Test:
   RP-22, RP-23.
9. **Gas constants.** The measurement of section 10.2, the constants of 10.3
   and the checker script for this document. Test: the recomputed values equal
   section 10.3.
10. **Ghost Guard contract.** The code, its address and hash, tests of release
    and cancel (section 12). Test: RP-25, RP-26.
11. **Guard in the wallet.** Commit, normal spend, words-only spend, release,
    cancel, transfer and restore; independent secrets. Test: RP-27, RP-28.
12. **Lifecycle test.** Commit, words-only spend, cancel and release on the
    test network. Test: the milestone behaviour of section 12.
13. **Statement checker pool rule.** The rule of section 15, item 3.

## 19. Checking this document

The values of this document are recomputed from these formulas. They use
integers only.

```text
NOTE_BYTES       = 12 + (128 + 224) + 16 = 380
ORD_PAYLOAD      = 2+8+32+32+32+20+32+32 + 1,310,720 + 380 = 1,311,290
POLICY_PAYLOAD   = 2+8+32+32+32+32+32+20+32+32+32+32+32 + 1,310,720 + 380 = 1,311,450
ACTION_PAYLOAD   = 2+8+32+8+32+32+8+2+1,024 + 948,224 = 949,372
ordinary binding = 8+2+32+1+1+2+1+32+32+32+20+32+32+380 = 607
policy binding   = 8+2+32+1+1+2+1+32+32+32+32+32+20+32+32+32+32+32+380 = 767
action binding   = 8+2+32+1+1+1+20+32+8+32+32+32+32+8+32 = 273
permutations     = ceil((607+29)/136) = 5;  ceil((767+31)/136) = 6;  ceil((273+24)/136) = 3
trace width      = 2,633 + 1,088 + 1 + carried columns
capsule          = 1+20+32+32+32+32+1+64+10 = 224
G_PRIV           = 16*1,311,291 + 21,000 + 110,000 = 21,111,656
G_POLICY         = 16*1,311,451 + 21,000 + 110,000 + 160,000 = 21,274,216
G_ACTION         = 16*949,373 + 21,000 + 110,000 + 15,000 + 250,000 = 15,585,968
G_DATA           = 16*1,311,067 + 21,000 + 92,300 = 21,090,372
```

The proof-length bounds are `proof_length_bound(rows, columns)` of
`proofs/src/stark.rs`. A script that recomputes the formulas above, the worked
fee values of section 10.3 and the section structure is part of the gas
constants ticket (section 18, item 9). It must also fail when any table of
this document is damaged.

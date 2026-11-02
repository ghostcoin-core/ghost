# Reveal policies, version 4 (draft, 2026-10-30)

Status: research draft, not a specification. Version 3 (`reveal-policies-v3.md`) moved held deposits into native escrow slots and native authority. Its red team found:
1. A cancel did not bind the exact amount it settles (Critical).
2. `POLICY_MIN_OUT` could leave policy coins unspendable (Critical).
3. PolicyAction had no admission bounds against unpaid proof floods (High).

Version 4 fixes all three and writes in the review's other requirements. It is a complete document; version 3 is kept for comparison. Coins only.

## What changed from version 3

| Finding | Version 4 answer |
|---|---|
| 1. Settlement amount not bound | An action's proof binds `expected_remaining`, an exact `debit` and an `expiry` height. The chain checks all three before charging or incrementing the nonce, then moves exactly `remaining - debit`. Guard's new note is encrypted for that exact commitment. Section 6. |
| 2. `POLICY_MIN_OUT` freezes coins | Removed. There is no consensus minimum. Every amount has a defined outcome (section 8, table). Minimums are wallet advice. |
| 3. Unpaid proof flooding | PolicyAction is admitted under the reveal pool's peer budgets, verification concurrency, byte and count limits and failed-proof penalties, all applied before proof verification. A pending action reserves its `(marker, nonce)` only after its proof verifies. Section 6. |
| Frozen policies could see outside balance changes | Frozen policies can neither receive nor read balances. Section 5. |
| Stop card alone could not cancel | `action_salt` is published with the policy reveal and kept in the slot, so the stop card alone can prove. Section 1. |
| Accounting, revert boundaries, capsule on rotation, zero remainder, data constants | Stated exactly in sections 3, 4, 9 and 11. |

## 1. The rule

```text
rule = K("ghost/reveal-policy/v2",
         policy_address (20 bytes, left-padded to 32), policy_codehash (32),
         params_hash (32), override_hash (32), action_tag (32))

params_hash   = K("ghost/policy-params/v1", params)               params: 0 to 64 bytes
override_hash = K("ghost/policy-override/v1", override_secret)    or 0: no override
action_tag    = K("ghost/policy-action/v1", action_root, action_salt)  or 0: no actions
```

`K` is the tagged Keccak-256 of spec 01, section 2, and all fields are fixed width.

`action_salt` is fresh random for every coin. It is published by the policy-class reveal, alongside the tag. With the salt public, tags are still unrelated across coins, and `action_root` stays secret. Wallets never reuse a salt, including for a coin re-committed by a cancel.

## 2. Two transaction classes

The **class** is public: it is the private-transaction type.

**Ordinary class.** One AIR with fixed trace dimensions, public layout and proof encoding. Every transaction of this class looks the same.
- The **input rule** (the rule inside the membership-proven input fingerprint) and the **remainder rule** are separate witnesses. Today's AIR uses one public rule in both fingerprints and fixes it to zero (`proofs/src/reveal.rs:210-267`); that changes.
- A private boolean `use_override` in {0, 1}:
  - `0`: the input rule is the empty rule.
  - `1`: the input rule opens to the five fields, `override_hash != 0`, and the prover knows its preimage.
- The remainder rule is the prover's choice. A coin with no override and a non-empty rule satisfies neither case, so it can never use this class.

**Policy class.** A separate statement sharing the membership, marker, range and conservation gadgets. It:
- opens the input rule;
- proves `v' = 0`;
- publishes `policy_address`, `policy_codehash`, `params_hash`, `action_tag`, `action_salt` and `instr`, a 32-byte payout instruction.

All of these are bound in the binding digest. Both classes share one coin-marker set.

## 3. The native policy-class reveal

Checks run in today's order (`reveal.go:345`: shape, chain, fee, binding, root, marker and backstop before the proof). Added to the state checks: `policy_address` is a frozen policy, created in an earlier block, with `EXTCODEHASH = policy_codehash`. The pool rechecks this on every new head with its other reveal checks (`ghostpool.go:326`), because a reorg can remove it.

Effects, in one journaled state change that reorgs rewind:
- record the marker;
- append the zero-value remainder (spec 03, 346);
- if `out > 0`, open escrow slot `E[marker] = {policy_address, remaining = out, params_hash, action_tag, action_salt, action_nonce = 0, instr, height, timestamp, open = true}`. If `out = 0`, no slot opens; this is today's fee-only spend;
- pay the fee as today;
- add `out + fee` to `total_out`, as today.

No account balance is credited and no code runs.

## 4. Escrow slots

Escrow value has already left the hidden set: it was counted in `total_out` when the slot opened.

For every slot, at all times:

```text
out = remaining + paid + recommitted + action_debits + forfeited
```

Only `recommit` touches the hidden-set totals: it adds its amount to `total_in`. `pay`, action debits and forfeits move or destroy public value and never touch `total_out` again.

Native functions, callable only from a frozen policy for slots whose `policy_address` is the executing policy (not `tx.origin`), and rejected in a static context:
- `slot(marker)`: read the caller's own slot; any other slot reads as absent.
- `pay(marker, dest, amount)`: credit by `AddBalance`; no recipient code runs. `dest` may not be a frozen policy.
- `recommit(marker, F, salt, note, amount)`: `amount >= 1`. It appends `C = H(tag, COIN, F, amount)` with its note.
- `close(marker)`: forfeit `remaining`, credited to nobody.

Each needs `open` and `amount <= remaining`, and decrements `remaining` before any further effect. The slot closes at zero or on `close`, and every native function rejects a closed slot.

**Two rollback boundaries:**
- A policy-call revert undoes the policy's storage writes, slot moves, tree appends, totals and logs from that call. It never undoes the action's debit or nonce (section 6).
- A chain reorg rewinds everything, debit and nonce included, together with balances, trees, markers and totals (spec 05, 451).

## 5. Frozen policies

A frozen policy is created with the native freeze flag, which takes effect before its constructor runs. In a frozen context (constructor included, at every depth):
- **Forbidden:** DELEGATECALL, CALLCODE, SELFDESTRUCT, CREATE, CREATE2, any CALL carrying value, BALANCE and SELFBALANCE.
- **Forbidden on any address that is not a frozen policy created in an earlier block:** EXTCODESIZE, EXTCODEHASH and EXTCODECOPY, and CALL or STATICCALL to it.
- **Explicit precompile allowlist**, checked before the rules above: sha256 (`0x02`), ripemd160 (`0x03`), identity (`0x04`), signature verify (`0x51`), the escrow natives, and the native statement checker. Every other address the base VM treats as a precompile, modexp included, is forbidden in a frozen context.
- **Frozen policies hold no balance.** The chain refuses any value sent to one: value-carrying calls and transactions, reveal recipients, and `pay` destinations.

What a frozen policy acts on:
- its immutable code;
- the storage of itself and of older frozen policies;
- its own escrow slots;
- chain facts (number, timestamp, base fee);
- the transactions and actions sent to it.

Anyone can send it transactions, so a policy can be called by anyone. But no one can change its code, give it a balance, or alter what its slots hold. Roles its own code defines stay possible and visible, and wallets show them.

## 6. Policy actions

```text
PolicyAction {
  marker, statement = KNOW_ACTION_v1, proof,
  expected_remaining, debit, expiry,
  calldata (fixed maximum size)
}
```

**Admission** (pool and block building):
- PolicyAction shares the reveal pool's limits (`ghostpool.go:58, 435`). Before any proof verification, it is subject to:
  - per-peer budgets;
  - verification concurrency;
  - byte and count caps;
  - penalties for peers that send failed proofs.
- Cheap checks next: shape, chain, `E[marker]` exists, is open, belongs to a frozen policy, has `action_tag != 0`, `E.action_nonce` matches, `E.remaining == expected_remaining`, `height <= expiry`, `debit <= expected_remaining`, and `debit >= G_ACTION * base_fee`.
- Then the proof. An action reserves its `(marker, nonce)` only after its proof verifies, so an unverified action cannot hold a victim's slot. Only the key holder can produce competing valid actions.
- On every new head the pool rechecks all of the cheap checks, as it does for reveals.

**The proof** shows knowledge of `action_root` with `K(tag, action_root, E.action_salt) = E.action_tag`. The tag and salt are read from the chain, never supplied. Public inputs bind chain ID, genesis, the policy address, the marker, `action_nonce`, `expected_remaining`, `debit`, `expiry` and `H(calldata)`.

**Execution:**
1. Repeat the cheap checks against the actual block state.
2. Charge exactly `debit` from the slot: `G_ACTION * base_fee` is burned as an ordinary base fee and the rest goes to the miner. Increment `action_nonce`.
3. Call the policy with `calldata` under the fixed gas cap `G_ACTION`, in an action context where `actionMarker()` returns the marker and `actionSettle()` returns `expected_remaining - debit`.

The debit is exact, so the amount left for the policy is known when the proof is made. If the base fee rises above `debit / G_ACTION`, the action waits or expires, and is never charged more. If the slot changed, the action is invalid, and nothing is charged.

## 7. Native statements

Fixed list, each with a pinned ID and disjoint domain tags. Each has a fixed proof size, trace dimensions, public-input length and decode limits, its own security gate, and gas measured at worst case:
- `KNOW_ACTION_v1` (section 6). Only the native action path uses it.
- `KNOW_PREIMAGE_v1`, for policies: knowledge of `x` with `K(tag, x) = y`, bound to caller-supplied public inputs of fixed maximum length. It can never stand in for `KNOW_ACTION_v1`.

Arbitrary developer statements are deferred.

## 8. Ghost Guard

**Commit:**
- policy Guard, params empty;
- `override_hash = K(guard secret)`;
- `action_tag = K(stop_root, action_salt)`, with the stop card holding `stop_root`.

**Normal spend:** ordinary class with the override. It is instant and looks like every other spend.

**Words-only spend:** policy class, full sweep, `instr` = recipient.

**Release:** `Guard.release(marker)` is an ordinary transaction that anyone may send and that pays its own gas. It needs `height >= E.height + 8640` and `timestamp >= E.timestamp + 72 h`, and pays `remaining` to `E.instr`.

**Cancel:**
1. The stop card and phone read `E` from the chain.
2. They choose `debit` and `expiry`, compute `a = E.remaining - debit`, and build `F_new` and its note for the exact commitment `C = H(tag, COIN, F_new, a)`, with a fresh `action_salt` in the new coin's rule.
3. They sign `calldata = cancel(F_new, salt_new, note_new)` into a PolicyAction.
4. Guard requires `actionMarker() == marker` and then calls `recommit(marker, F_new, salt_new, note_new, actionSettle())`.

The amount matches the note, so words-only restore finds the new coin. Release and cancel share the slot's single closed state.

**Every amount:**

| Situation | Outcome |
|---|---|
| Coin value below the reveal fee | Unspendable, exactly like any dust coin today |
| `out = 0` | Fee-only spend; no slot |
| Slot of any size, after the hold | Release pays all of `remaining` to `instr`; the sender pays gas |
| Slot with `remaining > debit` | Cancel re-commits `remaining - debit` |
| Slot with `remaining <= debit` at the current base fee | Cancel can't run yet. The owner may wait for lower fees until the hold ends. Wallets advise Guard spends well above action cost |

**Transfer:** the owner spends on the ordinary class with the override and sets the remainder rule to the receiver's own Guard rule, with a fresh capsule, or to empty. A coin handed over as words alone stays under the giver's stop key, and wallets say so.

**Not promised:** a majority miner who also has the words can censor cancels. The hold floors are chain-height and chain-timestamp floors (spec 06, 312).

## 9. Policy capsule

Every coin note grows from 156 bytes (`note.rs`) to 380 by carrying a 224-byte capsule inside the same encryption:

```text
version (1) | policy_address (20) | policy_codehash (32) | override_hash (32) |
action_tag (32) | action_salt (32) | params_len (1) | params (64) | zero pad (10)
```

- Notes keep today's construction: fresh nonce, bound to chain and the exact leaf.
- A coin with the empty rule has a version 0 capsule, all fields zero. Any coin whose rule is not empty, whatever class created it, has a version 1 capsule for its own rule.
- A remainder or re-commit gets a capsule built for its own rule: the input's capsule when the rule is kept, a new one when it is rotated. It is then freshly encrypted, never copied.
- Restore rebuilds the rule from the capsule and discards a mismatch (`restore.rs:264`). The whole note is bound in the proof.
- Neither the override secret nor `action_root` is ever stored.

## 10. Privacy and quantum claims

**Privacy:**
- The ordinary class hides whether a coin has a policy.
- A policy-class reveal shows the policy, code hash, `params_hash`, a per-coin `action_tag` and `action_salt`, `instr` and the amount, but not which commit it spends.
- Slot activity is public. A cancel's new coin is as private as a fresh Vanish of its amount.
- Third-party policies leak what their parameters leak.

**Quantum safety:** native authority, actions and statements are hash-based and quantum-safe. Cryptography that third-party bytecode writes is outside the chain's guarantee.

## 11. Fees and constants

- The ordinary class's gas is re-derived from the spec 07 formula: about +3,584 byte-gas for the larger note, plus the new AIR's measured verification cost.
- The policy class and PolicyAction get their own constants.
- Data reveals get their own envelope and gas constants, separated in every path that now shares them (`tx_ghost_private.go:153`, `state_processor.go:198`, `worker.go:1027`), so data pricing does not change.

## 12. Locked decisions this changes

| Decision | Change |
|---|---|
| No rules on GHOST in the first milestone; later a short fixed list | Open-ended frozen policies (founder request, 2026-10-30) |
| Empty rule; fixed S1 statement | Ordinary class with an override case; new policy class |
| Rule carries over unchanged (spec 03, 365) | On the ordinary class the remainder rule is the prover's choice |
| Claim gives the new key sole control (spec 03, 362) | True for ordinary coins and for override reveals that rotate the rule; not for a policy coin handed over as words alone |
| One private shape | Two classes: ordinary (all alike) and policy (public by design) |
| Note size 156 bytes | 380 bytes |
| Commit is top-level only | Unchanged for contracts; escrow slots re-commit natively |

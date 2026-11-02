# Reveal policies, version 3 (draft, 2026-10-30)

Status: research draft, not a specification. Version 2 (`reveal-policies-v2.md`) kept the native reveal free of contract code and fixed V1's replay, partial-sweep and pool attacks. Its red team found five Critical gaps (V2-1 to V2-5), all in how a held deposit is authorised, paid out and funded. Version 3 closes them by moving value and authority for held deposits into the chain's own rules. A policy contract decides **what** happens to a deposit; only the chain moves the money, and only the chain checks who is allowed to act. Coins only.

## What changed from version 2

| Gap | Version 3 answer |
|---|---|
| V2-1 deposits not tied to the right policy or stop key | Each deposit is a **native escrow slot**, not part of the policy's balance. Only the slot's own policy can move it, through native calls. The authority to act is a native field of the coin's rule, checked by the chain. The policy never checks a key itself. |
| V2-2 deposits too small to settle | The policy branch requires `out >= POLICY_MIN_OUT`, a consensus constant checked by the node on a public value. Every exit path has defined behaviour for every amount, down to zero. Guard no longer charges a relay fee. |
| V2-3 payout address gains code | Payouts are native credits that run no recipient code, as reveal credits do today. Frozen policies cannot send value with CALL at all. |
| V2-4 previous holder keeps cancel power after a claim | On the ordinary and override paths the remainder's rule is the prover's choice, so a transfer rotates the rule. A coin with an override can only be fully handed over by an override reveal that rotates its rule. Claims of an ordinary coin are unchanged. |
| V2-5 cancel needs public GHOST | A native, account-less **policy action** transaction is paid from the escrow slot. It is admitted only after a native proof of the coin's action key, so only the key holder can spend escrow on gas. |
| General contract Commit, open developer checker | Both are dropped from this version. Re-committing happens only through the escrow slot. Proofs are limited to a fixed set of native statements with fixed, measured costs; arbitrary developer statements come later. |

## 1. The rule

```text
rule = K("ghost/reveal-policy/v2",
         policy_address (20 bytes, left-padded to 32), policy_codehash (32),
         params_hash (32), override_hash (32), action_tag (32))

params_hash   = K("ghost/policy-params/v1", params)          params: 0 to 64 bytes
override_hash = K("ghost/policy-override/v1", override_secret)   or 0: no override
action_tag    = K("ghost/policy-action/v1", action_root, action_salt)  or 0: no actions
```

`K` is the tagged Keccak-256 of spec 01, section 2. All fields are fixed width. `action_salt` is a fresh random 32 bytes for each coin, so two coins with the same `action_root` publish unrelated tags.

## 2. Two transaction classes, three cases

The **class** is public: it is the private-transaction type in the envelope.

**Ordinary class.** One AIR with fixed trace dimensions, public-input layout and proof encoding. A private boolean `use_override`, constrained to 0 or 1, selects between:
- `use_override = 0`: the coin's rule is the empty rule (as today).
- `use_override = 1`: the rule opens to the five fields, `override_hash != 0`, and the prover knows `override_secret` with `K(tag, override_secret) = override_hash`.

Public outputs, envelope, note size and fee class are identical in both cases. The remainder's rule is the prover's choice: keep it, rotate it to a new policy rule, or set it to empty. Both cases already have full authority over the coin.

**Policy class.** A separate statement that shares the same membership, marker, range and conservation gadgets. It:
- opens the rule;
- proves `v' = 0` (the one remainder that spec 03 section 8 always appends holds zero);
- publishes `policy_address`, `policy_codehash`, `params_hash`, `action_tag` and `instr`, a 32-byte payout instruction bound in the binding digest.

Both classes use one coin-marker set, so a coin is spent once whichever class spends it.

## 3. The native policy-class reveal

Checks, in today's order (spec 03 section 7 and `reveal.go:345`, keeping shape, chain, fee, binding, root, marker and backstop checks before the proof), with these additions:
- `out >= POLICY_MIN_OUT`;
- `policy_address` is a frozen policy (section 5), created in an earlier block, with `EXTCODEHASH = policy_codehash`.

These facts hold on any branch where the policy exists. A reorg can remove them, so the pool rechecks pending reveals on every new head, as it already does (`ghostpool.go:326`).

Effects, in one journaled state change that reorgs rewind:
- record the marker;
- open escrow slot `E[marker] = {policy_address, remaining = out, params_hash, action_tag, action_nonce = 0, instr, height, timestamp, open = true}`;
- pay the fee as today.

No account balance is credited and no code runs. `total_out` grows by `out + fee`, as today.

The policy class has its own gas and envelope constants. The data-reveal constants are kept separate, so data pricing does not change.

## 4. Escrow slots: the only way deposit value moves

Native functions callable only from inside a frozen policy, and only for slots whose `policy_address` is the caller:
- `slot(marker)`: read the caller's own slot. A slot of another policy reads as absent.
- `pay(marker, dest, amount)`: credit `dest` by `AddBalance`. No recipient code runs, whatever code `dest` has or later gets.
- `recommit(marker, F, salt, note, amount)`: append `C = H(tag, COIN, F, amount)` with its note. The amount-bound-at-commit rule holds and `total_in` grows by `amount`; the caller supplies the fingerprint `F`.
- `close(marker)`: the remainder is forfeited, credited to nobody (the same rule as the data-reveal reserve) and counted in the accounting.

Every call needs `amount <= remaining` and `open`, and decrements `remaining`. A slot closes when it reaches zero or on `close`. A policy can never move value from one slot to another, or from a slot to itself.

## 5. Frozen policies

A frozen policy is created with the native freeze flag, which takes effect before its constructor runs. In a frozen context (constructor included, at every call depth):
- **Forbidden:** DELEGATECALL, CALLCODE, SELFDESTRUCT, CREATE, CREATE2, and any CALL that carries value.
- **Forbidden on any address that is not a frozen policy created in an earlier block:** BALANCE, EXTCODESIZE, EXTCODEHASH and EXTCODECOPY, and CALL or STATICCALL to it.
- **Allowed:** precompile and native addresses, which are resolved before the rules above. The allowlist is the hash precompiles, signature verify `0x51`, the escrow functions, and the native statement checker (section 7). Modexp is unavailable. Chain facts (block number, timestamp, base fee) are readable.

Code is immutable, and no outside contract or account can change what a policy sees. Roles a policy defines in its own storage stay possible and visible; wallets show them before a coin commits. The chain guarantees immutability and slot isolation, not honesty.

## 6. Policy actions: paid from the slot, authorised by the chain

A native, account-less transaction:

```text
PolicyAction { marker, statement = KNOW_ACTION_v1, proof, calldata (fixed max size) }
```

1. Cheap checks first: shape, chain, and `E[marker]` exists, is open and has `action_tag != 0`.
2. The proof shows knowledge of `(action_root, action_salt)` with `K(tag, action_root, action_salt) = E.action_tag`. Its public inputs bind chain ID, genesis, the policy address, the marker, `E.action_nonce` and `H(calldata)`. An invalid proof is rejected unpaid, as an invalid reveal is today.
3. The chain charges `min(G_ACTION * base_fee, remaining)` from the slot to the miner, increments `action_nonce`, and calls the policy with `calldata` under a fixed gas cap. The call runs in an action context where `actionMarker()` returns the marker.
4. A revert keeps the gas charge (it was authorised and paid) and undoes the policy's other effects.

Only the action-key holder can make the slot pay gas, so nobody else can drain it. The nonce stops replays.

## 7. Native statements

Version 3 has a fixed list of native statements, each with a pinned ID, fixed proof size and trace dimensions, and gas measured from benchmarks:
- `KNOW_ACTION_v1` (section 6);
- `KNOW_PREIMAGE_v1`, for policies: knowledge of `x` with `K(tag, x) = y`, bound to caller-supplied public inputs.

Arbitrary developer statements are deferred until their bounds and pricing can be specified.

## 8. Ghost Guard

- **Commit:** policy Guard, params empty, `override_hash = K(guard secret)`, `action_tag = K(stop_root, action_salt)`. The stop card holds `stop_root`. The coin's capsule (section 9) holds `action_salt`, and the phone keeps a copy.
- **Normal spend:** ordinary class with `use_override = 1`, which is instant and looks like every other spend.
- **Words-only spend:** policy class, full sweep, `out >= POLICY_MIN_OUT`, `instr` = the recipient. The coins sit in escrow slot `E[marker]`.
- **Release:** `Guard.release(marker)` is an ordinary transaction that anyone may send, paying their own gas. It is allowed only when `height >= E.height + 8640` and `timestamp >= E.timestamp + 72 h`. It calls `pay(marker, E.instr, remaining)`. There is no relay fee.
- **Cancel:** a PolicyAction from the stop card with calldata `cancel(F_new, salt_new, note_new)`. Guard requires `actionMarker() == marker` and that the slot is open, then calls `recommit(marker, F_new, salt_new, note_new, remaining)`. If gas has used up the whole slot, which only an extreme fee spike can cause because `POLICY_MIN_OUT` covers `G_ACTION` at a high base fee, the slot is closed and forfeited. Release and cancel end in one terminal state: whichever lands first closes the slot.
- **Transfer:** to give away a Guard coin, the owner spends it on the ordinary class with the override, rotating the remainder's rule to the receiver's own Guard rule or to empty. A coin handed over as words alone stays under the giver's stop key; wallets say so.
- **Not promised:** a majority miner who also holds the words can censor cancels. The hold floors are chain-height and chain-timestamp floors (spec 06, 312), not wall-clock guarantees.

## 9. Policy capsule (recovery from the words)

Every coin note, ordinary or policy, carries a 224-byte capsule inside its encryption (note.rs construction, fresh nonce, bound to chain and leaf):

```text
version (1) | policy_address (20) | policy_codehash (32) | override_hash (32) |
action_tag (32) | action_salt (32) | params_len (1) | params (64) | zero pad (10)
```

- Ordinary coins use version 0 with all fields zero, so the ciphertext is the same size.
- Remainders carry the plaintext and re-encrypt it under the remainder's note key; ciphertext is never copied.
- Restore rebuilds the rule from the capsule and discards a mismatch, as it does for leaves today (`restore.rs:249`).
- The whole note is bound in the reveal proof.
- The override secret and `action_root` are never in the capsule: the words alone give only the policy class.

## 10. Privacy and quantum claims (narrowed)

**Privacy:**
- The ordinary class hides whether a coin has a policy.
- A policy-class reveal shows the policy, its code hash, `params_hash`, a per-coin `action_tag`, `instr` and the amount, but not which commit it spends.
- Everything a slot does afterwards is public. A Guard cancel's new coin is as private as a fresh Vanish of that amount.
- Third-party policies can leak what their parameters leak.

**Quantum safety:**
- Native authority, actions and statements are hash-based and quantum-safe.
- A frozen policy can't call the elliptic-curve or modexp precompiles. Cryptography a third party writes in bytecode is outside the chain's guarantee.

## 11. Fees

Every note grows by 224 bytes, so the ordinary class's gas constant is re-derived from the spec 07 formula; the window and cover rules are unchanged. The policy class and PolicyAction have their own constants. Data constants are separated and unchanged.

## 12. Locked decisions this changes

| Decision | Change |
|---|---|
| No rules on GHOST in the first milestone; later a short fixed list | Open-ended frozen policies (founder request, 2026-10-30) |
| Empty rule; fixed S1 statement | Ordinary class with an override case; new policy class |
| Rule carries over unchanged (spec 03, 365) | On the ordinary class the remainder's rule is the prover's choice |
| Claim gives the new key sole control (spec 03, 362) | True for ordinary coins and for override reveals that rotate the rule; not for a policy coin handed over as words alone |
| One private shape | Two classes: ordinary (all coins look the same) and policy (public by design) |
| Note size | Grows by 224 bytes |
| Commit is top-level only | Unchanged for contracts; escrow slots can re-commit natively |

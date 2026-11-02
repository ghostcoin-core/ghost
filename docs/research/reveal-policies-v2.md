# Reveal policies, version 2 (draft, 2026-10-30)

Status: research draft, not a specification. Version 1 was red-teamed and judged unsound. This version answers each Critical and High finding (F1 to F6) and the twelve review questions. Coins only; data policies come later.

## The change in principle

**A policy never decides whether a private spend is valid.** The native spend checks only the proof, the fee, the marker and two static facts about the policy, and runs no contract code. On the policy branch, the coin's whole value moves into the policy contract's custody with an authenticated deposit record. Everything the policy does after that happens in ordinary, paid transactions. This removes unpaid failure (F6), forged callbacks, and all the callback-context problems (review question 7).

## 1. The rule and its three cases

```text
rule = K("ghost/reveal-policy/v1", policy_address (20 bytes, left-padded to 32),
         policy_codehash (32), params_hash (32), override_hash (32))
override_hash = K("ghost/policy-override/v1", override_secret)   or 0 for "no override"
params_hash   = K("ghost/policy-params/v1", canonical params bytes)
```

`K` is the existing tagged hash (spec 01, section 2), with fixed widths and no variable-length fields inside the rule.

One reveal statement covers three cases. A boolean-constrained branch selector chooses between them, and the selector is never public.

| Case | What the proof shows | Public outputs |
|---|---|---|
| Ordinary coin | rule is the empty rule (as today) | today's reveal fields |
| Policy coin, override branch | the rule opens correctly, `override_hash != 0`, and the prover knows `override_secret` | **identical** to an ordinary reveal: same version, statement, fields, proof layout, padding and fee class |
| Policy coin, policy branch | the rule opens correctly; publishes `policy_address`, `policy_codehash`, `params_hash`, `instr`; **`v' = 0` (no remainder) is a constraint in the circuit** | a policy-reveal shape (below) |

- `override_hash = 0` disables the override. It never means "skip the check".
- Ordinary coins keep the canonical empty rule. There are no key-derived overrides, so rekeying a remainder or claim has no secret-transfer trap.
- On the override branch the remainder is allowed and carries the same rule (spec 03, 362). The override secret is held apart from the key, so a rekeyed remainder stays rescuable.
- The full sweep on the policy branch is proven, not assumed, and fixes F4. A thief who holds the words cannot leave value in a hidden remainder; all of it goes into the policy's custody.

## 2. The native policy-branch reveal

Checks, cheapest first:
1. The proof, the fee and the marker, exactly as today.
2. `EXTCODEHASH(policy_address) == policy_codehash`.
3. `policy_address` is a frozen policy (section 3) that was created in an earlier block.

Checks 2 and 3 cannot become false later: a frozen policy can never be destroyed or changed. So a reveal admitted to the pool cannot be invalidated by a cheap state change, and admission keeps today's model.

Effects, all in one journaled native state change:
- record the marker;
- credit `out = v - fee` to `policy_address`'s balance **without executing any code** (spec 03, 133 is kept);
- write the deposit record `D[marker] = {policy_address, amount, params_hash, instr, height, timestamp}`;
- pay the fee as today.

Reorgs rewind all of these together.

`instr` is a fixed 32-byte payout instruction bound in the binding digest, for example the recipient a Guard release pays.

The policy-reveal transaction has a fixed size and its own fixed gas constant, `G_PRIV_POLICY`, covering the deposit-record write. No execution budget is needed.

## 3. Frozen policies (fixes F1)

A contract is a **frozen policy** if it was created with the native freeze flag. The flag is permanent. Code running at a frozen address, at any call depth:
- cannot use DELEGATECALL, CALLCODE, SELFDESTRUCT, CREATE or CREATE2;
- cannot CALL or STATICCALL a contract that is not a frozen policy. Plain value transfers to accounts with no code are allowed: Ghost has no EIP-7702, so accounts never gain code;
- may call other frozen policies, which run under the same rules;
- may call the native functions: hashes, signature verify (0x51), the deposit-record reader, the proof checker (section 6) and Commit (section 5). The modexp precompile is unavailable in a frozen context.

What this gives:
- A frozen policy's behaviour depends only on its own code, its own storage, other frozen code, the native functions and the transactions sent to it.
- The code cannot change, and the policy cannot borrow mutable authority from a proxy or another contract.
- Storage roles the code itself defines (for example an "admin" variable) are visible in the code. Wallets show any privileged role before a coin commits to a policy. The chain guarantees immutability, not honesty.

A policy coin with no override whose policy can never pay out is frozen forever. This is a stated outcome. Wallets create policy coins with an override by default.

## 4. Recovery from the words alone (fixes F3)

The encrypted note of every coin commit and every remainder gains a fixed-size **policy capsule** under a key derived from the Phantom Key. The capsule holds `policy_address`, `policy_codehash`, params (up to a fixed maximum, 96 bytes proposed) and `override_hash`.
- Ordinary coins carry a capsule of the same size filled with encrypted random bytes, so all commits stay the same size.
- Restore rebuilds the rule from the capsule and checks it against the rule inside `F`; a mismatch is discarded, as `restore.rs` does today for leaves.
- The override secret is deliberately not in the capsule. The words alone always give the policy branch, never the override.
- Size: the note grows by about 192 bytes on every commit and remainder.

## 5. Policy processing and contract Commit

- **Unforgeable deposits.** A policy learns of deposits only through the native reader of `D[marker]`, which only the native reveal writes. Every policy function is an ordinary transaction that anyone may send and that pays its own gas; a failure is an ordinary revert paid by the sender. There is no callback. The policy keeps a one-way state machine per marker.
- **Contract Commit.** Only frozen policies may call Commit. It debits the calling contract's own balance (never `tx.origin`), is rejected in static or delegated contexts, and keeps the amount-bound-at-commit rule. The caller supplies the fingerprint `F_new`, salt and note; the node computes `C = H(tag, type, F_new, v)` as today.
- Public accounting stays exact: a policy reveal of `x` with fee `f` adds `x + f` to `total_out`, and a contract Commit of `y` debits the contract `y` and adds `y` to `total_in`.

## 6. The developer proof checker

A native function verifies a STARK against a **pinned program ID** and its public inputs, and returns a verdict for that `(program_id, public_inputs)` pair only.
- It enforces a minimum security level, maximum proof size, maximum trace dimensions and memory bounds.
- It charges gas from the declared size before decoding, and an invalid proof pays the full cost.
- Native issuance never consults it. Its transcript domains and tags are disjoint from the coin and data statements.

## 7. Ghost Guard as a frozen policy

- **Per-coin stop tag (fixes F5 for Guard):** `params = stop_tag_i = K("ghost/guard-stop/v1", stop_root, coin_salt_i)`. The stop card holds `stop_root`. Two Guard coins of one owner publish unrelated tags.
- **Hold:** release is allowed only when `height >= D.height + 8640` **and** `timestamp >= D.timestamp + 72 h`, so the wait has a block floor and a clock floor. The chain's timestamp assumptions (spec 06) apply.
- **Release:** anyone may submit it after the hold. It pays `D.amount` minus a fixed relay fee to the recipient in `D.instr`. The recipient was bound by the proof, so the relayer cannot change it.
- **Cancel (fixes F2):** a proof of program `GUARD_CANCEL_v1` shows knowledge of `stop_root` with `K(stop_root, coin_salt_i) = stop_tag_i`. Its public inputs bind chain ID, genesis, the Guard address, the program ID, the hold's marker, the amount, `F_new`, the new salt and the new note.
  - The Guard moves the hold from Held to Cancelled in one step that can never be undone, and Commits `F_new`.
  - A proof replayed against another hold fails because the marker differs; replayed against the same hold, it does nothing.
  - Anyone may submit the cancel. The Guard pays the submitter a fixed fee out of the held amount, so the owner needs no public GHOST.
- **Not promised:** a majority miner who also holds the words can censor cancels. Settlement stays probabilistic (threat model, 36).

## 8. Privacy claims (narrowed)

- Ordinary reveals and override-branch reveals are indistinguishable. Commits never show whether a coin has a policy.
- A policy-branch reveal publishes the policy, its code hash, `params_hash`, `instr` and the amount. It does not say which commit it spends.
- Everything a policy does afterwards is public. A Guard cancel's new coin is publicly created by the Guard with a known amount: it is as private as a fresh Vanish of that amount, and no more.
- Third-party policies can leak whatever their design leaks. Per-coin salted parameters are the recommended pattern.

## 9. Quantum safety (narrowed)

- Native authority stays quantum-safe.
- Frozen policies have no elliptic-curve precompiles and no modexp.
- Cryptography a third party writes in bytecode is outside the chain's guarantee (spec 09, 701).
- Ghost's standard policies use only hashes, ML-DSA and STARKs.

## 10. Fees

- Ordinary and override reveals are unchanged: window fee and cover rule.
- Policy-branch reveals have their own fixed constant, `G_PRIV_POLICY`, and are a public class by design.
- Policy functions pay ordinary gas.
- Data-reveal economics are untouched, because this is coins only.

## 11. Locked decisions this changes

| Decision | Change |
|---|---|
| No rules on GHOST in the first milestone; later a short fixed list | Open-ended frozen policies (founder request, 2026-10-30) |
| Empty rule and fixed S1 statement | One statement with three cases |
| Commit is top-level only | Frozen policies may Commit |
| One private shape | Ordinary and override reveals share one shape; the policy branch is a second, public shape |
| Digits are all you need | Still true for ordinary coins. For policy coins the digits give the policy branch, and the override needs its separate secret |
| Note size | Grows by about 192 bytes for the capsule |

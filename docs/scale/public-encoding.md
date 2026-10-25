# Public transaction encoding against the 10 MiB message cap

This page models the bytes of a block carrying 3,500 public transactions beside 3,500 private reveals, for two encodings of the public transactions' signatures, against the base client's 10 MiB message cap (modeled: the target and the cap, workload.md and spec 09, section 8.4). It is part of the first stage (feasibility and security) of the scale work and follows the rules and the public transaction requirements of designs.md. The target does not change here: 3,500 public transactions per block, 10 million a day (modeled: the founder's target).

Every figure carries one of the labels of workload.md: measured, modeled or not yet established. Nothing on this page is measured. The arithmetic is benchmarks/scale/public_encoding.py, whose `INPUTS` dict at the top holds every input, tested by benchmarks/tests/test_scale_public_encoding.py; the command below prints the table of this page:

```sh
python3 benchmarks/scale/public_encoding.py
python3 benchmarks/tests/test_scale_public_encoding.py
```

**Result.** Raw ML-DSA-44 signatures do not fit: 3,500 of them with the private non-proof parts need 14,283,500 bytes against a cap of 10,485,760, before any aggregate proof, body, header or framing (modeled). Replacing the signatures on chain by one verification proof that binds each account, signing key and transaction fits, with 3,734,380 bytes left for bodies, headers and framing (modeled), as long as that proof is no larger than 5,045,100 bytes (modeled). What that proof costs to make is not yet established: no figure for proving ML-DSA-44 verifications exists in the repository.

Counted in every block below (modeled):

- the private non-proof parts: 3,500 reveals of 347 bytes, 1,214,500 bytes (modeled from spec 07, section 3);
- the private aggregate proofs: three bundles a block, one root proof each, at 1,310,720 bytes (modeled: the stated input is the proof field of spec 07, section 2, and three is the number of independent aggregators of throughput.md; the size of a real recursive root proof is not yet established);
- not counted: transaction bodies (transfers, commits, contract calls), headers and RLP framing. The table reports the bytes left for them (modeled).

| Variant | Public bytes | With the private non-proof parts | With the aggregate proofs too | Fits under the cap | Headroom | Body bytes a transaction may add |
|---|---|---|---|---|---|---|
| raw ML-DSA-44 | 13,069,000 (modeled) | 14,283,500 (modeled) | 18,215,660 (modeled) | no (modeled) | -7,729,900 (modeled) | 0.00 (modeled) |
| signature replaced by a proof | 1,604,720 (modeled) | 2,819,220 (modeled) | 6,751,380 (modeled) | yes (modeled) | 3,734,380 (modeled) | 1,066.97 (modeled) |

## Raw encoding

Every public transaction carries its scheme ID, public key and signature: 2 + 1,312 + 2,420 = 3,734 bytes for ML-DSA-44, the smaller of the two schemes of spec 09, section 8 (modeled; SLH-DSA-SHAKE-128s carries 7,890, modeled in spec 09).

- 3,500 transactions: 13,069,000 bytes of scheme, key and signature (modeled: 3,500 x 3,734).
- With the 3,500 private non-proof parts: 14,283,500 bytes, 3,797,740 over the cap of 10,485,760 (modeled), before aggregate proofs, bodies, headers or framing.
- With the three private aggregate proofs as well: 18,215,660 bytes, 7,729,900 over the cap (modeled).
- Public transactions a block can carry beside the private parts and the aggregate proofs, before bodies: 1,429 (modeled: 5,339,100 bytes of room divided by 3,734), about 41 percent of the target's 3,500 (modeled). throughput.md runs the public stream at that capacity: the public backlog grows without bound and the public p99 delay passes the 2-minute ceiling of workload.md (modeled there).
- Gas: each ML-DSA-44 transaction costs at least 80,744 gas before its verification charge (modeled: spec 09, section 8.1), so 3,500 of them need at least 282,604,000 gas, over nine times the proposed 30,000,000 limit (modeled), while spec 09, section 8.4 keeps the limit below 41,943,040 so that a block of zero bytes still fits the cap (modeled there). Raising the gas limit alone cannot reach the target (modeled, as workload.md states).

So the raw encoding misses the cap at the target (modeled), whatever the gas limit.

## Signature replaced by a proof

The signatures leave the chain. Each transaction keeps only the bytes that bind it to an aggregate verification proof, and the block carries the proof (modeled from the inputs):

| Input | Value | Label |
|---|---|---|
| Account | 20 bytes | modeled: addresses stay 20 bytes (spec 09, section 4.3) |
| Signing key identity | 32 bytes | modeled: a stated input, a digest of the public key |
| Transaction hash | 32 bytes | modeled: a stated input, a digest of the signed transaction |
| Binding bytes a transaction | 84 | modeled: the sum |
| Verification proof | 1,310,720 bytes | modeled: a stated input, the proof field of spec 07; the size of such a proof is not yet established |
| Verifications a proof | 3,500 | modeled: a stated input, one proof a block |
| ML-DSA-44 verifications to prove a block | 3,500 | modeled: one per public transaction |
| Verification proofs a block | 1 | modeled: 3,500 / 3,500 |

Results (modeled):

- Public bytes: 3,500 x 84 + 1,310,720 = 1,604,720 (modeled).
- With the private non-proof parts and the three private aggregate proofs: 6,751,380 bytes, under the cap with 3,734,380 bytes of headroom (modeled).
- Bodies, headers and framing may then take 1,066.97 bytes a public transaction on average (modeled: the headroom over 3,500). Whether the public mix's bodies (2,450 transfers, 700 commits and 350 contract calls a block, modeled from the proposed shares of workload.md, themselves not yet established) fit that is not yet established: contract call bodies depend on which contracts launch.
- The largest verification proof that still fits: 5,045,100 bytes (modeled: the headroom plus the stated 1,310,720).
- Splitting the verifications over smaller proofs costs bytes: at 500 verifications a proof a block needs 7 proofs and no longer fits (modeled, tested).
- Public transactions a block could carry at the stated sizes, before bodies: 10,500 (modeled), three times the target's 3,500 (modeled).

What the proof must bind (designs.md, public transactions, requirement 2, no figure): each account, its signing key and the exact transaction it signs, so a valid proof for one transaction authorizes no other, and a key change is honoured from the block it takes effect. Nodes still run every state-dependent check (nonce, balance, code, gas) of every public transaction (rule 1). The proof's own hash construction must be named by rule 3 and carries the security gaps security.md lists for recursive proofs (not yet established). <!-- no-figure -->

## What is not yet established

- **The proving cost of the verification proof.** Proving 3,500 ML-DSA-44 verifications a block (modeled count) has no figure in the repository: not yet established. What would measure it: an AIR of ML-DSA-44 verification over BabyBear (its SHAKE-128 and SHAKE-256 expansions and hashes are Keccak-f\[1600\] permutations; its NTT arithmetic is modulo 8,380,417, a different prime from BabyBear's, so it must be emulated), proven with the pinned Plonky3 at the leaf parameters, timed for one proof of N verifications on named hardware and recorded with the CPU model, as benchmarks/reveal/tests/recursion_proxy.rs does for recursion (not yet established: a new Rust benchmark outside this piece). A cheaper lower bound, as in recursion.md: count the Keccak-f\[1600\] permutations one verification performs and prove that many with `p3-keccak-air` (not yet established).
- **The verification proof's size and its verification time at the node** (not yet established): the 1,310,720 bytes above are a stated input.
- **Who builds the signature proof, and inclusion when that builder disappears** (designs.md, public transactions, requirement 6): not yet established; until shown, a single proof a block is a single point of failure for every public transaction (modeled: one proof a block).
- **Bodies, headers and RLP framing** of the public mix and of the message that carries a block: not yet established, beyond the 1,066.97 bytes a transaction they may take (modeled).
- **Gas of a public transaction without its signature bytes**: spec 09, section 8.1 charges 16 gas a signature byte; the charge for a transaction whose signature is proven in aggregate is not yet established (a spec change outside this piece).
- **Propagation**: a pooled transactions message must still carry each transaction's signature to the builder of the proof, so the mempool path carries 3,734 bytes a transaction even when the block does not (modeled); its message budget and admission bounds (spec 09, section 8.3) at 3,500 a block are not yet established.

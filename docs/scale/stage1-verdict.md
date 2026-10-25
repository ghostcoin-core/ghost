# Stage 1 verdict: feasibility and security of the scale target

This page is the verdict of the first stage (feasibility and security) of the scale work. It is drawn from what the five pieces of the stage produced: workload.md (the target, ceilings and budgets), designs.md (the rules and design requirements), security.md (the proven-security argument), phone-protocol.md and phone-results.md (the phone reveal and wallet restore), recursion.md with docs/scale/recursion-proxy.jsonl (one reveal proof entering recursion), and throughput.md and public-encoding.md (fleet throughput, inclusion delay and the public encoding). The target does not change: 10 million private reveals and 10 million public transactions a day, about 3,500 of each per 30 s block (modeled: the founder's target, workload.md).

Every figure carries one of the labels of workload.md: **measured** (actually run, the machine named), **modeled** (a formula or stated inputs) or **not yet established** (with the command or hardware that would produce it). Every physical-phone figure and every real-recursion figure is not yet established: the sandbox the pieces were written in could reach no physical phone and build no recursive verifier, and no proxy stands in for either below.

Verdict: Not feasible as designed

Which decision rule applied. The rules are taken in order, and the first that holds decides: <!-- no-figure -->

- First rule, a ceiling or the 10 MiB cap missed for every design considered, by measured or modeled numbers: **holds.** Every wallet restore design considered (the baseline of spec 05, section 8, the buckets design and the checkpoint design) misses the proposed full-restore download ceiling, the restore time ceiling and the keeping-up ceiling of workload.md on a chain of one year or more at the target (modeled in phone-results.md, below). This rule decided the verdict, and the limiting constraint is wallet restore volume.
- Second rule, a missing proven security argument or a recursion cost that is only a proxy: would also hold, and is not what decided. security.md leaves the whole-bundle proven bound not yet established, and the only recursion cost is a proxy (modeled lower bounds in recursion.md). Each such gap is carried into stage 3 below.
- Third rule, every cryptographic requirement established and every budget met: does not hold on either count.

The restore ceilings are proposals for the founder (not yet established as final in workload.md). Had every restore design met them, the second rule would decide, never the third: the security argument and the real recursion cost are open whatever the restore ceilings are.

## Evidence

| Area | What the pieces found | Label | Where |
|---|---|---|---|
| Target and budgets | 3,500 private reveals and 3,500 public transactions a block; today's rule would charge 2,460.5434 block gas limits for the reveals; raw public signatures and private non-proof parts take 14,283,500 bytes against the 10,485,760-byte cap | modeled | workload.md, benchmarks/scale/budget.py |
| Proven security of the bundle | Whole-bundle proven bound not yet established: recursion with the hash inside the circuit, extraction over 12 layers, the proven extension-field terms and the cited theorem numbers are open; today's proven leaf figure is 80 classical and 40 quantum bits against 128 and 64, and with a 256-bit Keccak-256 digest the Keccak architectures reach at most 127.96 classical bits in the query phase | not yet established for the bound; the bits are modeled | security.md, benchmarks/scale/security_budget.py |
| Recursion cost, architecture (a), Keccak to Keccak | Misses the aggregator ceilings in the proxy: a merge at least 14.44 s on one 32-core machine against 0.3 s, its trace extension 164.875 GiB against 128 GiB, and 3,499 merges at least 1,263.03 s on 40 machines against a 30 s block | modeled from measured (proxy) records, a lower bound | recursion.md, docs/scale/recursion-proxy.jsonl |
| Recursion cost, architectures (b) and (c), Poseidon2 aggregation | No figure: an in-circuit Poseidon2 verifier is missing from the pinned dependencies | not yet established | recursion.md |
| Real recursive merge of any architecture, on named hardware | No run in the build sandbox | not yet established | recursion.md |
| Throughput, architecture (a)'s costs | The 40 machines of workload.md include none of 3,500 reveals a block; 2,780 machines keep up; no fleet tried up to 25,270 holds the 5-minute p99 delay ceiling, whose floor before the waits for blocks is 166.0 s; the best p99 is 356.2 s | modeled, from the proxy: lower bounds | throughput.md, benchmarks/scale/throughput.py |
| Aggregation cost | 21.6585 machine-seconds a reveal at full use: 1.2032 US cents a reveal at an illustrative 2 US dollars a machine-hour, against a 0.1-cent ceiling met only below 0.1662 US dollars a machine-hour | modeled; the price is not yet established | throughput.md |
| Independent operation | When the largest of three aggregators disappears, inclusion goes on at the remaining aggregators' capacity, about 2,310 a block at 3,500 offered | modeled | throughput.md |
| Denial of service | A reveal that fails only at execution costs up to 180.49 machine-seconds; late failures at a tenth of the target raise the p99 from 392.8 s to 1,046.7 s; invalid proofs that fail the check cost 0.000288 s each | modeled | throughput.md |
| Public encoding, raw ML-DSA-44 | 14,283,500 bytes a block with the private non-proof parts, over the cap before any aggregate proof; at most 1,429 public transactions a block fit beside the private parts and three aggregate proofs | modeled | public-encoding.md, benchmarks/scale/public_encoding.py |
| Public encoding, signatures replaced by a proof | 6,751,380 bytes a block with the private parts and the aggregate proofs, 3,734,380 under the cap, at a stated proof size of 1,310,720 bytes; 3,500 ML-DSA-44 verifications to prove a block | modeled | public-encoding.md |
| Proving cost of the public verification proof | No figure in the repository | not yet established | public-encoding.md |
| Reveal on a physical phone | No physical phone run; on the emulated mid-range phone, not a real device: 4.11 s warm median with eight threads, 13.15 s with one, 630.1 MiB of WebAssembly memory | not yet established on a phone; the emulated figures are measured, emulated | phone-results.md, workload.md |
| Wallet restore at one year of chain | Full-restore download 803.0 GB for the baseline, 248.8 GB for buckets and 803.0 GB for a checkpoint key made at genesis, against a proposed 500 MB; restore time 46.5, 15.2 and 46.5 hours against 10 minutes | modeled; the ceilings are not yet established proposals | phone-results.md, benchmarks/scale/restore_sim.py |
| Keeping a wallet up to date | 66.0 GB a month for the baseline and checkpoint and 20.4 GB for buckets, with markers, against a proposed 50 MB | modeled | phone-results.md |
| Headers for a clean device | 611.8 MB a year of chain, for every design, alone over the proposed 500 MB after about 298 days | modeled | phone-results.md |
| Restore on a real phone | No run against a chain of the target size | not yet established | phone-results.md |
| Fresh-node sync time and node operating cost | No run, no model | not yet established | workload.md |
| Storage growth of a full node | 686.2 GB a year of leaves and notes and 116.8 GB of spent markers, before receipts, against a proposed 2 TB a year | modeled | workload.md |

## Limiting constraint

**Wallet restore volume at the target.** At 10 million new leaves and spends a day (modeled: the target), a wallet restoring from its secret alone downloads, after one year of chain, 803.0 GB with the baseline, 248.8 GB with buckets, the best design considered, and 803.0 GB with a checkpoint for a key made at genesis, against a proposed full-restore ceiling of 500 MB; it needs 15.2 hours or more against a proposed 10 minutes, and keeping up takes 20.4 GB a month or more against a proposed 50 MB (all modeled in phone-results.md). Volume, not processing, sets the cost: the download is about 96 percent of the baseline's elapsed time at one year (modeled there). The headers a clean device must check grow 611.8 MB a year whatever the tree design (modeled), so no tree design alone can meet a 500 MB ceiling past about 298 days of chain (modeled).

What would have to change (any one route, and the target stays as it is):

- A restore design that cuts the year-one full-restore download about 500 times (modeled: 248.8 GB to 500 MB) and keeping up about 400 times (modeled: 20.4 GB to 50 MB a month) while keeping "the digits are all you need" and the privacy of designs.md (wallet restore requirement 3): for example private information retrieval for the note fetch, whose cost for these records is not yet established, an authenticated compact source of spent status (not yet established), and a check of the header chain smaller than every header from genesis, such as a succinct proof of the header chain (not yet established).
- A founder decision on the restore ceilings, which workload.md states as proposals (not yet established): a reference phone and data plan that allow hundreds of gigabytes a year (modeled from the figures above) would remove this constraint, and the verdict would then fall to the missing security argument.
- A founder decision to give up "the digits are all you need" for a stated trust assumption, such as a restore service, which the wallet restore requirements of designs.md rule out today (no figure).

Other ceilings missed, by modeled numbers, but not for every design considered, so not limiting on their own (each carried below): the aggregator ceilings of workload.md for architecture (a) (recursion.md), and with them the 40-machine fleet, the 5-minute p99 delay and, above 0.1662 US dollars a machine-hour, the cost ceiling (throughput.md); the 10 MiB cap for raw ML-DSA-44 signatures, which the proof encoding meets on bytes (public-encoding.md). Architectures (b) and (c) and the public verification proof have no cost figure (not yet established), so they could not be judged.

## Requirements carried into stage 3

Every integrated requirement not yet verified, each to be shown in the third stage before the design is chosen:

- **Propagation.** Every message that carries a block or its transactions (a new block, a block bodies response, a pooled transactions message) fits under 10,485,760 bytes with bodies, headers and RLP framing counted, at 3,500 public transactions and 3,500 reveals a block; the pooled transactions path still carries 3,734 bytes of signature a public transaction; block propagation time at those sizes (all not yet established; the block bytes are modeled in public-encoding.md).
- **State execution.** Nodes run every state-dependent check of every reveal (the sequential marker check against executed state, a canonical earlier root, the fee in force) and of every public transaction (nonce, balance, code, gas), in order, for 3,500 of each a block, inside the 3,000 ms verification budget of spec 07, section 4 (not yet established).
- **Real capacity.** A real recursive conversion and merge of the chosen architecture on named hardware, with its memory against the 128 GiB machine, replacing the proxy in throughput.md; the fleet, delay and cost at those real seconds (not yet established).
- **Reorganisation and marker rules.** Spent status follows the canonical chain exactly through pruning, sync and restore; a reorganisation undoes spends present only on disconnected blocks; two bundles carrying the same marker resolve by a stated rule in both orders; no marker is deleted for its age (designs.md, rule 2, and the markers and state requirements; not yet established).
- **Denial-of-service bounds.** Total verification work, memory, queue growth and honest-user delay under sustained traffic from many identities, with per-peer and total budgets, above all for reveals that fail late at up to 180.49 machine-seconds each (modeled in throughput.md) and malformed recursive proofs; whether a late failure pays a fee (not yet established).
- **Independent operation.** Anyone may bundle from public data with no key or permission of another aggregator, a single reveal is included when no aggregator takes it, inclusion continues when the largest aggregator disappears or censors (modeled for disappearance only in throughput.md), and who pays an aggregator and from which field (not yet established).
- **Proven security of the whole bundle.** At least 128 classical bits and NIST Category 1, every grinding site at half: the twelve gaps of security.md, among them recursion with the hash inside the circuit, extraction over 12 layers, round-by-round soundness of the Plonky3 IOP and the proven extension-field terms (not yet established).
- **Digest length.** A commitment and transcript digest longer than 256 bits in the Keccak architectures, which reach at most 127.96 classical bits with Keccak-256 (modeled in security.md), or a theorem in which the collision term does not add (not yet established; a founder decision).
- **Proof length at the bundle's parameters.** The leaf proof at 92 queries against the 1,310,720-byte proof field of spec 07 (not yet established).
- **Architectures (b) and (c).** An in-circuit Poseidon2 verifier and its costs, and an analysis of exactly Poseidon2 over BabyBear at width 24 (not yet established).
- **Bundle binding.** A bundle binds the approved Ghost statement and verifier, the exact ordered contents, the count, the chain and the versions, with tests that changing, reordering, adding or dropping any one fails (designs.md, private bundle requirement 1; not yet established).
- **Public verification proof.** Its proving cost for 3,500 ML-DSA-44 verifications a block, its size against the 5,045,100 bytes that still fit, its binding of account, key and transaction with key changes honoured, its builders and inclusion when one disappears, and the gas of a public transaction without signature bytes (not yet established; sizes modeled in public-encoding.md).
- **Wallet restore at scale.** A design that meets the restore ceilings, above (not yet established), and a restore timed on a real phone against a chain of the target size (not yet established).
- **Reveal on a physical phone.** Proving time and memory on named mid-range phones, with and without threads, against the 10 s and proposed 1 GiB ceilings (not yet established: phone-protocol.md, steps 4 to 7).
- **Fresh-node sync, storage and node cost.** Fresh-node sync time on the ordinary full node against 24 hours, storage growth against 2 TB a year, and node cost a transaction against 0.01 US cents (not yet established).
- **Fee windows and tree rollover.** How a bundle behaves across fee windows, and how a bundle near a tree's last leaves is split, rebuilt or deferred (designs.md, private bundle requirements 7 and 9; not yet established).

## Reproduce

Every figure above comes from these scripts and records (the scripts print their tables when run; the tests check them):

- `benchmarks/scale/budget.py` and `benchmarks/tests/test_scale_budget.py`: the target's byte, gas, storage and merge budgets.
- `benchmarks/scale/security_budget.py` and `benchmarks/tests/test_scale_security.py`: the security sums.
- `benchmarks/reveal/tests/recursion_proxy.rs`: the recursion proxy, which wrote `docs/scale/recursion-proxy.jsonl`.
- `benchmarks/scale/recursion_costs.py` and `benchmarks/tests/test_scale_recursion.py`: the fleet cost of the proxy records.
- `benchmarks/scale/restore_sim.py` and `benchmarks/tests/test_scale_restore.py`: wallet restore and catch-up.
- `benchmarks/scale/phone_records.py` and `benchmarks/tests/test_scale_phone_records.py`: the phone record format.
- `benchmarks/scale/throughput.py` and `benchmarks/tests/test_scale_throughput.py`: throughput, delay, bursts, failures and adversarial traffic.
- `benchmarks/scale/public_encoding.py` and `benchmarks/tests/test_scale_public_encoding.py`: the public encoding.
- `benchmarks/scale/labels.py` and `benchmarks/tests/test_scale_verdict.py`: the label check and this page's check.
- `docs/scale/workload.md`, `docs/scale/designs.md`, `docs/scale/security.md`, `docs/scale/phone-protocol.md`, `docs/scale/phone-results.md`, `docs/scale/recursion.md`, `docs/scale/throughput.md` and `docs/scale/public-encoding.md`: the pieces this verdict reads.

```sh
python3 benchmarks/scale/budget.py
python3 benchmarks/scale/security_budget.py
python3 benchmarks/scale/recursion_costs.py
python3 benchmarks/scale/restore_sim.py
python3 benchmarks/scale/throughput.py
python3 benchmarks/scale/public_encoding.py
python3 benchmarks/tests/test_scale_verdict.py
python3 benchmarks/scale/labels.py docs/scale/throughput.md docs/scale/public-encoding.md docs/scale/stage1-verdict.md
```

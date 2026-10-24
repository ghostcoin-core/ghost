# Workload, resource ceilings and budgets at the launch target

This page states what the launch target means as a workload, the resource ceilings later work is judged against, and the byte, gas, storage and restore budgets the target implies with today's encodings. It is the first of five pieces of the first stage (feasibility and security) of the scale work; later pieces measure and judge against what it defines. Whether the target is reachable is for those pieces to report, not this one.

Every figure carries one label:

- **measured**: actually run, with the machine named. Figures from the reveal benchmarks were measured on an emulated mid-range phone, not a real device, and stay labelled emulated.
- **modeled**: computed from a formula or from stated inputs, or quoted from a spec that computes it.
- **not yet established**: nobody has produced it yet; the entry names the command, hardware or decision that would.

Every ceiling and the public mix are inputs the founder may change. The arithmetic is in benchmarks/scale/budget.py, whose `INPUTS` dict at the top of the file holds the model's inputs; `python3 benchmarks/scale/budget.py` prints every modeled budget below, and benchmarks/tests/test_scale_budget.py checks each one.

Hash constructions. The repository has two Keccak constructions, and neither is NIST SHA3-256: <!-- no-figure -->

- The real reveal prover in proofs/ (used by benchmarks/reveal/) commits with the Keccak-f\[1600\] padding-free sponge of proofs/src/stark.rs, at Keccak-256's rate, and runs its transcript on Keccak-256 with its original padding. Every reveal figure on this page (proof size, gas, phone time and memory) comes from this construction. <!-- no-figure -->
- The benchmark statement in benchmarks/prover/ uses padded Keccak-256 (benchmarks/prover/src/keccak.rs checks it equals the library's Keccak-256). No figure on this page comes from it. <!-- no-figure -->

## Workload

The target is fixed: 10 million private reveals and 10 million public transactions a day, at the same time (modeled: a model input, the founder's target). It is never weakened because a measurement is hard.

| Input | Value | Label |
|---|---|---|
| Private reveals a day | 10,000,000 | modeled: the founder's target, a model input |
| Public transactions a day | 10,000,000 | modeled: the founder's target, a model input |
| Block time | 30 s on average | modeled: the chain's target block time, an average and not a proving window |
| Blocks a day | 2,880 | modeled: 86,400 / 30 |
| Private reveals per block | about 3,500 | modeled: 10,000,000 / 2,880 = 3,472.2, taken as 3,500 |
| Public transactions per block | about 3,500 | modeled: 10,000,000 / 2,880 = 3,472.2, taken as 3,500 |

Both streams run in the same blocks. Every budget below takes a block with 3,500 private reveals and 3,500 public transactions together (modeled).

### Public mix

The founder states the public mix. Nothing in the repository sets it yet, so each share is a proposal (not yet established), stated as a model input:

| Kind | Proposed share | Per block at the modeled 3,500 | Label |
|---|---|---|---|
| Plain transfers between accounts | 70% | 2,450 | not yet established: proposal for the founder; per-block count modeled from the share |
| Commits (Vanish), which add a commitment to the tree | 20% | 700 | not yet established: proposal for the founder; per-block count modeled from the share |
| Contract calls | 10% | 350 | not yet established: proposal for the founder; per-block count modeled from the share |

Every kind is signed by an account. The signature budget below takes every public transaction as ML-DSA-44, the smaller of the two schemes of spec 09, section 8 (modeled: the cheapest case; SLH-DSA-SHAKE-128s carries 7,890 bytes, modeled in spec 09). Contract call bodies and their gas are not yet established: they depend on which contracts launch, which the founder would state.

### Where the chain stands today

| Item | Value | Label |
|---|---|---|
| Private reveal envelope | 1,311,067 bytes | modeled: spec 07, section 2 |
| Proof field of a reveal | 1,310,720 bytes | modeled: spec 07, section 2 |
| Non-proof part of a reveal | 347 bytes | modeled: 1,311,067 - 1,310,720 (spec 07, section 3) |
| Gas of a reveal | 21,090,372 | modeled: spec 07, section 2 |
| Proposed block gas limit | 30,000,000 | modeled: the default of spec 05, question one |
| Reveals per block today | 1, about 2,880 a day | modeled: 30,000,000 // 21,090,372 = 1 |
| Aggregator payment field | none; the fixed tip goes to the block finder | modeled: spec 07 has no such field (no figure to measure) |
| Public scheme, key and signature, ML-DSA-44 | 3,734 bytes | modeled: 2 + 1,312 + 2,420 (spec 09, section 8) |
| Message cap of the base client's eth protocol | 10 MiB, 10,485,760 bytes | modeled: spec 09, section 8.4 |
| Leaf and note a wallet downloads | 188 bytes | modeled: 32-byte leaf and 156-byte note (spec 05, section 8) |
| Leaves a tree holds | 2^32 | modeled: spec 05, section 3 |

## Resource ceilings

Each ceiling is a model input with a proposed value. A proposal nothing in the repository supports is labelled not yet established, with what would set it. The phone figures below are the only ones measured so far, on an emulated phone.

### Reference phone

| Resource | Ceiling or known figure | Label and what would set it |
|---|---|---|
| Proving time, one reveal, single thread | 13.15 s warm median, 15.02 s cold median | measured on the emulated mid-range phone, not a real device (Mac Studio, Apple M5 Max, throttled Chrome), 2026-10-21, docs/benchmarks/reveal-results.md |
| Proving time, one reveal, eight threads | 4.11 s warm median, 5.20 s cold median | measured on the emulated mid-range phone, not a real device, 2026-10-23, docs/benchmarks/reveal-results.md |
| Proving time ceiling | 10 s for one reveal, cold or warm | modeled: the existing target of the reveal benchmarks, kept as the input |
| WebAssembly memory, single thread | 596.8 MiB | measured on the emulated mid-range phone, not a real device, 2026-10-21 |
| WebAssembly memory, eight threads | 630.1 MiB | measured on the emulated mid-range phone, not a real device, 2026-10-23 |
| Memory ceiling | proposed 1 GiB for the whole tab | not yet established: proposal for the founder; set by running benchmarks/web/drive-reveal.mjs on a real mid-range phone and reading the renderer's peak |
| Restore download ceiling | proposed 500 MB for a full restore, 50 MB a month to keep up | not yet established: proposal for the founder; set by a mobile data plan the founder chooses as reference |
| Restore time ceiling | proposed 10 minutes on the phone's network | not yet established: proposal for the founder; set by timing a restore on a real phone against a chain of the target size |
| Phone storage ceiling | proposed 200 MB for wallet data | not yet established: proposal for the founder |
| Real device | none run | not yet established: run benchmarks/web/drive-reveal.mjs against a real mid-range phone over remote debugging |

### Ordinary full node

| Resource | Proposed ceiling | Label and what would set it |
|---|---|---|
| CPU | 8 cores of a current desktop processor | not yet established: proposal for the founder; the node build names the reference node hardware (spec 09, section 8.2) |
| Memory | 32 GiB | not yet established: proposal for the founder |
| Bandwidth | 100 Mbit/s down, 50 Mbit/s up, sustained | not yet established: proposal for the founder |
| Storage | 4 TB solid-state disk, a year of growth with room to spare | not yet established: proposal for the founder; checked against the modeled growth in Storage and sync |
| Verification time per block | 3,000 ms | modeled: the budget spec 07 maps the 30,000,000 gas limit onto (spec 07, section 4) |

### Aggregator

| Resource | Proposed ceiling | Label and what would set it |
|---|---|---|
| Machines | 40 proving machines | not yet established: proposal; the merge budget below uses it as an input |
| CPU per machine | 32 cores | not yet established: proposal for the founder |
| Memory per machine | 128 GiB | not yet established: proposal for the founder |
| Bandwidth | 1 Gbit/s sustained | not yet established: proposal for the founder; at least the modeled private proof bytes per block divided by the block time |
| Storage | the full node's, plus proofs in flight | not yet established: proposal for the founder |
| Time for one merge | 0.3 s | not yet established for Ghost: the 0.303 s leanMultisig figure is leanVM merging its own proofs (192-bit binary field, Keccak as a placeholder), not Plonky3 proofs of the Ghost reveal; set by a recursion benchmark on named hardware in a later piece |

## Latency and backlog

| Input | Proposed value | Label and what would set it |
|---|---|---|
| Maximum transaction-to-inclusion delay, private | 5 minutes (10 blocks) at the 99th percentile under the target load | not yet established: proposal for the founder; measured by the throughput simulation of a later piece |
| Maximum transaction-to-inclusion delay, public | 2 minutes (4 blocks) at the 99th percentile | not yet established: proposal for the founder |
| Sustainable backlog | one hour of target load (about 417,000 private and 417,000 public) held without loss | not yet established: proposal; the count is modeled as 10,000,000 / 24 |
| Recovery after overload | back to the normal delay within one hour after a burst of twice the target for one hour | not yet established: proposal for the founder |
| Burst spare capacity | 50% above the target, sustained for an hour | not yet established: proposal for the founder |

Merge budget for one block (modeled, benchmarks/scale/budget.py, from the 0.3 s input above):

| Figure | Value | Label |
|---|---|---|
| Two-to-one merges to fold 3,500 proofs into one | 3,499 | modeled: n - 1 |
| Machine time | 1,049.7 machine-seconds | modeled: 3,499 x 0.3 s |
| Least wall time on 40 machines, all proofs at once | 26.2425 s | modeled: 1,049.7 / 40, a lower bound no schedule beats |
| Depth of a balanced merge tree | 12 levels, 3.6 s | modeled: ceil(log2 3,500) x 0.3 s |
| Wall time merging level by level on 40 machines | 28.2 s | modeled: 94 rounds of 0.3 s |

A 30 s block time is an average, not a proving window. Sustained throughput and transaction-to-inclusion delay are measured separately, with bursts, failures and backlog, in a later piece (rule 4 of designs.md); the 28.2 s above is modeled and leaves less than 2 s of a 30 s block for everything else (modeled).

## Storage and sync

Modeled from benchmarks/scale/budget.py at the target, with today's encodings:

| Figure | Value | Label |
|---|---|---|
| Private proof bytes per block | 4,587,520,000 (about 4.59 GB) | modeled: 3,500 x 1,310,720 |
| Private proof bytes per day | 13,107,200,000,000 (about 13.1 TB) | modeled: 10,000,000 x 1,310,720 |
| Private envelopes per day, today's encoding | 13,110,670,000,000 | modeled: 10,000,000 x 1,311,067 |
| Private non-proof bytes per block | 1,214,500 | modeled: 3,500 x 347 |
| Public scheme, key and signature bytes per block | 13,069,000 | modeled: 3,500 x 3,734 |
| Both together, before bodies, aggregate proofs or headers | 14,283,500 | modeled: 13,069,000 + 1,214,500 |
| Over the 10,485,760-byte message cap by | 3,797,740 | modeled |
| Gas per block under today's rule | 73,816,302,000 | modeled: 3,500 x 21,090,372 |
| Multiple of the 30,000,000 gas limit | 2,460.5434 | modeled |
| Leaves and notes a wallet downloads per day | 1,880,000,000 (1.88 GB) | modeled: 10,000,000 x 188 |
| Per year | 686,200,000,000 (686 GB) | modeled: x 365, before receipts, markers and public commits |
| Spent markers kept per year | 116,800,000,000 (116.8 GB) | modeled: 10,000,000 x 32 bytes x 365, kept forever (spec 05, "Who keeps what") |
| Days until a coin tree fills at 10,000,000 new leaves a day | 429.5 | modeled: 2^32 / 10,000,000 |

Raising the gas limit alone cannot reach the target: the public signatures alone are over the message cap (modeled above).

| Input | Proposed value | Label and what would set it |
|---|---|---|
| Sustained storage growth of a full node | at most 2 TB a year | not yet established: proposal for the founder; checked against the modeled growth of the chosen designs |
| Fresh-node sync time | at most 24 hours to a node that follows the tip, on the ordinary full node above | not yet established: proposal; measured by syncing a node from a peer on a chain of the target size |
| Wallet restore volume on the phone | the phone's restore download ceiling above | not yet established: see Reference phone |

## Cost

| Input | Proposed value | Label and what would set it |
|---|---|---|
| Aggregation cost per private reveal | at most 0.1 US cents | not yet established: proposal for the founder; set by the machine-seconds per reveal from a recursion benchmark times a named cloud price |
| Node cost per transaction | at most 0.01 US cents | not yet established: proposal; the ordinary full node's monthly cost divided by its monthly transactions |
| Machine-seconds per private reveal for merging | 0.29991 s | modeled: 1,049.7 / 3,500, from the unestablished 0.3 s merge |
| Spare capacity priced in | 50% above the target | not yet established: the burst input of Latency and backlog |
| Who pays the aggregator | no field today | not yet established: a requirement of the private bundle design in designs.md |

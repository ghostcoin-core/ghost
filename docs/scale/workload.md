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

The target is 1 million transactions a day in total (modeled: a model input, the founder's decision of 2026-11-08; Ethereum does about 2 million a day and Bitcoin about 500,000). It replaces the earlier target of 10 million of each kind, which the founder called an optimistic reach. Capacity can be raised later by a network upgrade (see Raising capacity later); the target is not weakened because a measurement is hard.

The 1 million is a total, not a pair of streams. The private path is sized for the worst case of all of them being private reveals, and the public path for the same 1 million total, so any mix between the two fits. The two rows below are alternatives for the same transactions and are not added together.

| Input | Value | Label |
|---|---|---|
| Private reveals a day | 1,000,000 | modeled: the founder's total, taken as the worst case where every transaction is a private reveal; a model input |
| Public transactions a day | 1,000,000 | modeled: the founder's total, taken as the worst case where every transaction is public; a model input |
| Block time | 30 s on average | modeled: the chain's target block time, an average and not a proving window |
| Blocks a day | 2,880 | modeled: 86,400 / 30 |
| Private reveals per block | about 350 | modeled: 1,000,000 / 2,880 = 347.2, taken as 350 |
| Public transactions per block | about 350 | modeled: 1,000,000 / 2,880 = 347.2, taken as 350 |

Per block, the private reveals and the public transactions together never exceed about 350 (modeled). Every budget below takes the worst case of each stream alone, and the byte budget also adds the two, which is a bound no real mix reaches (modeled).

### Public mix

The founder states the public mix. Nothing in the repository sets it yet, so each share is a proposal (not yet established), stated as a model input:

| Kind | Proposed share | Per block at the modeled 350 | Label |
|---|---|---|---|
| Plain transfers between accounts | 70% | 245 | not yet established: proposal for the founder; per-block count modeled from the share |
| Commits (Vanish), which add a commitment to the tree | 20% | 70 | not yet established: proposal for the founder; per-block count modeled from the share |
| Contract calls | 10% | 35 | not yet established: proposal for the founder; per-block count modeled from the share |

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
| Leaf and note a wallet downloads | 412 bytes | modeled: 32-byte leaf (spec 05, section 8) and 380-byte note (spec 10, section 3.2) |
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
| Machines | 40 proving machines | not yet established: proposal; the merge budget below uses it as an input. A rough first estimate is 9 to 18 machines of 32 cores for the whole network at 1 million a day, depending on the private share; the 40 is kept as headroom until the new aggregation shape is chosen (not yet established) |
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
| Sustainable backlog | one hour of target load (about 41,700 private and 41,700 public, each the worst case alone) held without loss | not yet established: proposal; the count is modeled as 1,000,000 / 24 = 41,666.7 |
| Recovery after overload | back to the normal delay within one hour after a burst of twice the target for one hour | not yet established: proposal for the founder |
| Burst spare capacity | 50% above the target, sustained for an hour | not yet established: proposal for the founder |

Merge budget for one block (modeled, benchmarks/scale/budget.py, from the 0.3 s input above):

| Figure | Value | Label |
|---|---|---|
| Two-to-one merges to fold 350 proofs into one | 349 | modeled: n - 1 |
| Machine time | 104.7 machine-seconds | modeled: 349 x 0.3 s |
| Least wall time on 40 machines, all proofs at once | 2.6175 s | modeled: 104.7 / 40, a lower bound no schedule beats |
| Depth of a balanced merge tree | 9 levels, 2.7 s | modeled: ceil(log2 350) x 0.3 s |
| Wall time merging level by level on 40 machines | 4.8 s | modeled: 16 rounds of 0.3 s |

A 30 s block time is an average, not a proving window. Sustained throughput and transaction-to-inclusion delay are measured separately, with bursts, failures and backlog, in a later piece (rule 4 of designs.md); the 4.8 s above is modeled and leaves most of a 30 s block for everything else (modeled).

### Ceilings judged again at 1 million a day

Against the figures on this page (modeled, each from benchmarks/scale/budget.py):

| Ceiling | At 1 million a day | Label |
|---|---|---|
| Block gas limit of 30,000,000 | not met under today's rule: 350 reveals cost 7,381,630,200 gas, 246.05434 times the limit; only 1 reveal fits | modeled; gas for aggregated proofs is for the aggregation design to set |
| Message cap of 10,485,760 bytes | met: public signatures plus private non-proof bytes come to 1,428,350 bytes, under the cap by 9,057,410 | modeled: a bound that adds both worst cases |
| Merge time on 40 machines | met: 4.8 s level by level, against a 30 s block | modeled from the unestablished 0.3 s merge |
| Tree capacity | met: one tree of 2^32 leaves lasts 4,294.967296 days, about 11.8 years | modeled |
| Restore volume | 150,380,000,000 bytes (about 150 GB) a year of leaves and notes; the restore, phone and storage ceilings stay as proposed | modeled; judged against the phone ceilings by the restore pieces |

The proof bytes per block (458,752,000, about 459 MB) are still far over the message cap, so private proofs must still be aggregated before they reach a block; this is unchanged by the lower target (modeled).

## Raising capacity later

The 1 million target is not a limit of the design. A later network upgrade that adds a larger aggregation bundle shape raises capacity without removing the old one: the new shape carries its own verifier key under a new statement or protocol version, and both shapes are accepted during the change, so bundles built for the old shape stay valid until the founder retires it. The constants that change are the reveals per bundle and bundles per root of the shape, the per-block counts above, and the verifier keys pinned for the bundle and root proofs; the reveal statement itself does not change. The shape for 1 million a day, with each layer's prover memory, machine count, cost and delay, and the same figures at 10,000 and 100,000 a day, are not yet established here: they are the next slice of this work, and the production keys wait on that shape.

## Storage and sync

Modeled from benchmarks/scale/budget.py at the target, with today's encodings:

| Figure | Value | Label |
|---|---|---|
| Private proof bytes per block | 458,752,000 (about 459 MB) | modeled: 350 x 1,310,720 |
| Private proof bytes per day | 1,310,720,000,000 (about 1.31 TB) | modeled: 1,000,000 x 1,310,720 |
| Private envelopes per day, today's encoding | 1,311,067,000,000 | modeled: 1,000,000 x 1,311,067 |
| Private non-proof bytes per block | 121,450 | modeled: 350 x 347 |
| Public scheme, key and signature bytes per block | 1,306,900 | modeled: 350 x 3,734 |
| Both together, before bodies, aggregate proofs or headers | 1,428,350 | modeled: 1,306,900 + 121,450 |
| Under the 10,485,760-byte message cap by | 9,057,410 | modeled |
| Gas per block under today's rule | 7,381,630,200 | modeled: 350 x 21,090,372 |
| Multiple of the 30,000,000 gas limit | 246.05434 | modeled |
| Leaves and notes a wallet downloads per day | 412,000,000 (412 MB) | modeled: 1,000,000 x 412 |
| Per year | 150,380,000,000 (150.4 GB) | modeled: x 365, before receipts, markers and public commits |
| Spent markers kept per year | 11,680,000,000 (11.7 GB) | modeled: 1,000,000 x 32 bytes x 365, kept forever (spec 05, "Who keeps what") |
| Days until a coin tree fills at 1,000,000 new leaves a day | 4,294.967296 | modeled: 2^32 / 1,000,000 |

Raising the gas limit alone still cannot carry the private proofs: they are about 459 MB a block against the message cap (modeled above), so the private path needs aggregation. The public signatures now fit under the cap.

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
| Machine-seconds per private reveal for merging | 0.299143 s | modeled: 104.7 / 350, from the unestablished 0.3 s merge |
| Spare capacity priced in | 50% above the target | not yet established: the burst input of Latency and backlog |
| Who pays the aggregator | no field today | not yet established: a requirement of the private bundle design in designs.md |

# Recursion layers: results

The stage 2 design (stage2-design.md, "Aggregation cost") chose architecture (c): a batch proof verifying 32 reveal proofs, a root proof over one aggregator's batches, and a shrink proof at blowup 2^5 with 56 queries. Its cost figures are modeled from cell counts and a guessed Poseidon2 permutation cost of 400 ns (modeled). This page records what the real layers in proofs/src/layers/ measure, on the machine named below, and says plainly what is not yet established.

Machine: a Lima virtual machine named by its hostname prefix lima- (the rest of the hostname is left off this page), with 16 cores (arm64, CPU implementer 0x61, no model name in /proc/cpuinfo) and 46.9 GiB of memory (measured from /proc/cpuinfo and /proc/meminfo). It is not an aggregator machine of the design; every figure below labelled measured was taken on it and on no other.

## What is built

- <!-- no-figure --> **Batch layer.** A verifier circuit for up to a fixed capacity of child proofs of one AIR and shape, proven as a batch STARK of five tables (wires, arithmetic, Poseidon2 permutation, bits, packing) routed by the LogUp argument of the pinned Plonky3 lookup crate over its batch STARK. It replays each child's transcript, checks its Merkle openings, its FRI folding and its constraints at the out-of-domain point, and exposes the running digest of the children's ordered public values before and after, and their count.
- **Binding.** Each layer's transcript absorbs, before any challenge, a tag naming the layer kind, its index, the protocol and statement versions, the chain identifier and the digest of its children's verifier key. That digest and the circuit's wiring are preprocessed columns, so the layer's verifier key fixes them. Anyone can batch from public reveals: the key is rebuilt from the circuit with no secret of any aggregator. No elliptic curve is used anywhere.
- **Root and shrink layers.** Not yet established: the in-circuit verifier of a batch STARK proof (a layer child, as opposed to a reveal child) is not built yet, so neither the root nor the shrink proves yet, and the 1,310,720-byte bound on the shrink proof is not yet established.

Permutation columns: the width-24 Poseidon2 permutation table has 450 columns a permutation (measured by counting the AIR written in proofs/src/layers/poseidon2.rs), against the modeled 451 of the design, which counted the library AIR's export flag; it is checked against the library's default_babybear_poseidon2_24.

## Poseidon2 permutation

Permutation cost: 897.1 ns per permutation (measured: one scalar width-24 permutation of the pinned library, one core of the machine above, a million permutations, timed by the test time_one_poseidon2_permutation in proofs/tests/layers.rs while no layer proved; repeated runs on the same machine gave 868.7 ns to 1129.3 ns, measured, so the figure moves by about a quarter from run to run on this virtual machine).

- Against the fleet threshold of 93 ns: missed (measured 897.1 ns, above the modeled 93 ns at which 40 machines suffice).
- Against the merge-budget threshold of 122 ns: missed (measured 897.1 ns, above the modeled 122 ns of the 0.3 s merge budget).
- Against the design's other modeled ceilings: the cost ceiling of 1,226 ns is met by every run (measured 868.7 ns to 1129.3 ns); the delay ceiling of 1,025 ns is met by the 897.1 ns run and missed by the slowest, 1129.3 ns (measured), so it is not yet established on this machine.
- Both thresholds of the design are missed by every run, the fastest included (measured 868.7 ns against 93 ns and 122 ns).

This is a scalar permutation on a virtual machine; the packed permutation a prover uses, and an aggregator core, are not yet established.

## Layers

All three stages are compared with the 128 GiB machine ceiling of the design (modeled ceiling).

Batch: not yet established at the real shape on this machine. The benchmark (proofs/tests/layers_bench.rs, run with -- --ignored --nocapture) proves 32 real version 2 coin reveals and their batch at blowup 2^3 with 96 queries and prints its seconds and peak memory (VmHWM); it has not been run here, whose sandbox holds 6 GiB (not yet established). At the test shape (blowup 2^3, 2 queries) a batch of 3 stand-in children proves in about 5.6 s with tables of 32,768, 4,096, 2,048, 64 and 1,024 rows and a proof of 104,596 bytes (measured on the machine above). A batch of 32 stand-in children (each at blowup 2^2 with one query, the batch at blowup 2^2 with two queries) has tables of 262,144, 32,768, 8,192, 128 and 8,192 rows and brings the test process's peak memory (VmHWM) to 3.55 GiB; a batch of one real version 2 coin reveal at the same batch shape has tables of 262,144, 131,072, 8,192, 64 and 8,192 rows and a peak of 4.50 GiB (both measured on the machine above, far under the 128 GiB ceiling, which is modeled).

Root: not yet established; the root over 44 batches needs the in-circuit verifier of a batch STARK proof, which is not built yet.

Shrink: not yet established, for the same reason; its proof size against the 1,310,720-byte proof field is therefore not yet established.

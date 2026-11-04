# Public signatures: ML-DSA-44 chunk proofs, results

The stage 2 design (stage2-design.md, "Public signature size") takes signatures out of the block: raw ML-DSA-44 signatures need 14,283,500 bytes a block against the 10,485,760-byte cap (modeled in public-encoding.md), so verifications are proven in chunks of 32 and folded by the batch, root and shrink layers into one public root. The design's cell count, 7,132,392 a verification (modeled), and its 101 permutations and 750,000 arithmetic cells (modeled) were models until the chunk AIR existed. This page records what the chunk AIR in proofs/src/mldsa/ counts and measures, on the machine named below, and says plainly what is not yet established.

Machine: the acceptance run's machine, a Lima virtual machine with 16 cores (arm64, CPU implementer 0x61, no model name in /proc/cpuinfo) and 46.9 GiB of memory (measured from /proc/cpuinfo and /proc/meminfo). It is the machine of the recursion layers' results (layers-results.md) and not an aggregator machine of the design. The acceptance run of this page's tests is held to 6 GiB of memory on it; every figure below labelled measured was taken on it, inside that limit, and on no other.

## What is built

- <!-- no-figure --> **Chunk AIR.** One batch STARK of the five layer tables (wires, arithmetic, Poseidon2 permutation, bits, packing) and ten ML-DSA tables, on the layers' LogUp bus: Keccak-f[1600] one round a row (the round constraints, columns and trace generation of the pinned p3_keccak_air AIR, the round constant preprocessed), for SHAKE-128 and SHAKE-256 with the absorbed lanes XORed in by a lane XOR table; NTT butterflies and the NTT-domain identity of w'_approx modulo q in 12-bit limbs over BabyBear with every limb range checked by its bits; RejNTTPoly (ExpandA); SampleInBall; the t1 and z unpacking with the z norm bound; UseHint with w1Encode. It verifies ML-DSA.Verify of FIPS 204 under the context ghost/tx/v1: tr, mu, the challenge, the matrix, the identity, the hint count and the final c~ comparison. The chunk is committed with Poseidon2, like the private layers.
- <!-- no-figure --> **Laid out for the layer above.** What the batch layer's verifier circuit pays for a chunk proof is every column a table opens (twice for a table that reads its next row), every bus column and every constraint, not the chunk's height. So no wide table reads its next row: a Keccak round's input and output lanes are wires, and the next round reads them back through the wire table; ExpandA carries its running count to the next row through a wire; the hint table takes eight coefficients a row and sends them, and its three limbs of w1Encode and its hint count, as packed wires of eight values; t1 sends its coefficients packed eight to a wire; SampleInBall is a narrow step table, one squeezed byte a row, that checks its memory of the 256 coefficients on a bus of its own (address, value, time, every read before the row's time) against a position table, instead of carrying the whole polynomial on every row. The constraints of the ML-DSA tables are folded in the batch's circuit with their sums kept linear until a product needs them.
- <!-- no-figure --> **Public inputs.** For each transaction in block order: its account, its key identity (the first half of tr, which the circuit computes from the key) and its transaction hash (the message signed), one byte a value. The chunk's public values are a layer's: the binding (chain and versions), the Poseidon2 running digest of those inputs before and after, and the count, so reordered, added or dropped transactions change the digest or the count.
- <!-- no-figure --> **Folding.** chunk_batch_key gives a batch layer over chunk proofs; the root and shrink are the recursion ticket's own layers. A chunk's index is its slot in its batch; chunks in different batches are ordered by the running digest, each batch starting where the one before it ended.
- <!-- no-figure --> **Chunk size.** A parameter: the tests use chunks of 2, the benchmark (proofs/tests/mldsa_chunk_bench.rs, run with -- --ignored --nocapture) the design's 32.

## Known-answer vectors

The vectors in proofs/tests/data/ml_dsa_44_vectors.txt come from the pinned implementation (RustCrypto ml-dsa 0.1.1, by client/tests/ml_dsa_vectors.rs), not NIST's own files: whether they match NIST's files is not yet established, since NIST's files were not read here. Each is a public key, a message and a deterministic signature; the messages are of 0, 32 and 77 bytes (measured from the file). All of them verify inside a chunk proof in proofs/tests/mldsa_chunk.rs, and a changed signature is refused: the 32-byte ones in the two chunks of 2 that the fold below folds, the 0-byte and 77-byte ones each in a chunk of 1 of its own message length, so that its key and the shared chunk key fit the acceptance run's memory together.

## Per verification

Counted from the built tables (measured: the difference between circuits of two and one slots, by verification_cost):

- Keccak-f[1600] permutations: 99 a verification (measured), against the modeled 101: ten for tr over the 1,312-byte key, one for mu, one for SampleInBall, 80 for ExpandA (five SHAKE-128 blocks for each of 16 entries), seven for c~'. Native verification of the vectors runs at most as many (measured).
- Cells: 8,639,439 main-trace cells a verification (measured: rows times each table's main width, one lane), against the modeled 750,000 cells of arithmetic and 7,132,392 cells of the design's proving model, so above both (measured against modeled). The rows a verification fills (measured): 97,932 wires, 1,227 arithmetic, 7 Poseidon2, 69 bits, 506 packing, 2,376 Keccak rounds (24 a permutation), 238 lane XORs, 13,312 butterflies (13 NTTs), 1,024 NTT-domain checks, 560 ExpandA, 128 SampleInBall steps, 256 SampleInBall positions, 32 t1, 1,024 z and 128 hint rows. The Keccak rounds, each 2,508 columns wide, are most of the cells; the wires between Keccak rounds (25 lanes after each of a permutation's first 23 rounds) are most of the wires (measured from these rows and widths).

## Chunk

Chunk of 2 at the test shape (blowup 2^2, one query): 21.14 s to 26.50 s to prove over the runs of this change, a proof of 342,556 bytes, with tables of 262,144 wire rows, 8,192 Keccak rows and 32,768 butterfly rows (measured on the machine above, by the tests in proofs/tests/mldsa_chunk.rs).

Chunk of 32 at blowup 2^3 with 96 queries: not yet established. The benchmark is written but was not run on this machine in this change, so seconds per chunk at 32 are not yet established.

Seconds per block of 3,500 transactions: not yet established. It is 110 chunks times the measured seconds per chunk plus the measured fold seconds of the recursion benchmark, a sum of measured figures, and neither part is measured at the real shape on this machine (the recursion benchmark's batch and root do not fit this machine's memory, layers-results.md, not yet established).

## Fold and size

Test-shape fold (measured on the machine above, by the test chunks_fold_into_one_public_root_proof, in the acceptance run under its 6 GiB limit): two chunks of 2, one batch over each chunk at blowup 2^2 with one query, a root over both batches and a shrink of the root at blowup 2^2 with two queries.

The batch circuit over one chunk proof fills 240,901 wires, 91,100 arithmetic rows, 5,990 Poseidon2 rows and 9,224 packing rows (measured, by batch_entries), so its tables are 262,144, 131,072, 8,192, 64 and 16,384 rows and its prover is modeled at 3,618,042,112 bytes (modeled). Before this layout (a Keccak table reading its next row, a hint table of 32 coefficients reading its next row, SampleInBall carrying 1,024 columns a row) the same circuit filled 448,000 wires and 154,824 arithmetic rows, tables of 524,288 and 262,144 rows, a prover modeled at 7,235,170,560 bytes, and the batch's prover was stopped by the 6 GiB limit (measured, the acceptance run killed for memory).

| Stage | Tables (rows) | Proof | Seconds | Peak memory of the test process (VmHWM) |
|---|---|---|---|---|
| Chunk of 2 (each of two) | 262,144 wires, then the other fourteen | 342,556 bytes (measured) | 21.14 to 26.50 s (measured) | 4.13 GB to 4.14 GB (measured) |
| Batch key over a chunk | 262,144, 131,072, 8,192, 64, 16,384 | none | not timed | 1.53 GB to 1.73 GB (measured) |
| Batch over one chunk (each of two) | 262,144, 131,072, 8,192, 64, 16,384 | 90,353 bytes (measured) | 22.52 s to 26.72 s (measured) | 4.97 GB to 5.16 GB (measured) |
| Root key over two batches | 131,072, 65,536, 4,096, 64, 8,192 | none | not timed | 1.85 GB to 2.04 GB (measured) |
| Root over two batches | 131,072, 65,536, 4,096, 64, 8,192 | 107,072 bytes (measured) | 11.93 s to 11.98 s (measured) | 3.57 GB to 3.75 GB (measured) |
| Shrink key | 131,072, 32,768, 4,096, 64, 4,096 | none | not timed | 1.96 GB to 2.14 GB (measured) |
| Shrink of the root | 131,072, 32,768, 4,096, 64, 4,096 | 106,244 bytes (measured) | 9.18 s to 9.90 s (measured) | 2.99 GB to 3.17 GB (measured) |

Each range is over the last two acceptance runs of this change on the machine above (measured); the proof sizes and table heights were the same in both (measured). The fold test is not ignored: it runs in the acceptance command, and in the last run its seven tests passed in 221.69 s (measured).

Peak memory is per layer (measured: the test resets the process's peak resident memory before each stage and reads it after), and it counts what the process holds besides the stage itself: the chunk key throughout, and during a batch the batch key too. Every stage stays under the 6 GiB limit (measured). The batch proofs and the batch key are dropped before the shrink. The known-answer test, which holds a second chunk key while it proves, peaked at 3.33 GB proving the 0-byte vector and 3.36 GB proving the 77-byte one in the last run (measured, reset before each).

Size: the design's public root proof is 859,736 bytes (modeled). The test-shape public root proof after the shrink is 106,244 bytes (measured), within its computed bound of 107,900 bytes (measured bound) and the 859,736 the size test asserts, and within the 1,310,720-byte proof field (modeled limit). The recursion layers' recorded shrink bound at the real shape on main is 1,185,685 bytes at blowup 2^5 with 56 queries (measured bound, layers-results.md), above 859,736 by 325,949 bytes (measured gap); whether the real shrink over chunk proofs at that shape meets 859,736 bytes is not yet established, since the real batch and root do not fit this machine (layers-results.md, not yet established).

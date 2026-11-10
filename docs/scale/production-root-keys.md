# Production root keys

A release node verifies a block's bundle root proof and its public root proof against two verifier keys, each written by `root_key_to_bytes` (proofs/src/ffi.rs) from a shrink key. This page states the shapes those keys are derived at, what deriving them holds in memory, where their bytes and digests are committed, and how CI derives them again after every merge. Deriving a key builds the real-shape circuits and commits their preprocessed columns; nothing is proven.

## How a key is derived and checked

- <!-- no-figure --> **Derivation.** `layers::production_bundle_root_key` and `mldsa::production_public_root_key` build each stage's key for verifying alone from its blank circuit: the circuit's wire values are dropped before its preprocessed columns are written, the circuit once they are, each table's columns become their coefficients in place, and the commitment is made one block of their extension at a time, nothing of a block kept once it is hashed. The key below is dropped once the next is made, and the shrink key is returned. `ffi::production_root_key_bytes` writes the node's bytes from it, and the C call `ghost_production_root_key` (proofs/include/ghost_proofs.h) does the same for the node. The derivation is deterministic: the preprocessed commitment uses the all-zero salt seed of the library's key generation.
- <!-- no-figure --> **Pin.** Each key's SHA-256 digest is committed as lower-case hex text in proofs/keys/bundle-root-key.sha256 and proofs/keys/public-root-key.sha256. `ffi::is_production_root_key` and the C call `ghost_root_key_is_production` accept a key only when its digest is the pinned one.
- <!-- no-figure --> **Bytes.** Each key's bytes, the `root_key_to_bytes` output of a real derivation, are committed as lower-case hex text on one line in proofs/keys/bundle-root-key.hex and proofs/keys/public-root-key.hex, for the node to embed.
- <!-- no-figure --> **Test.** proofs/tests/production_root_keys.rs plans each derivation stage by stage, prints its figures and refuses any stage planned above the derivation budget `layers::KEY_DERIVATION_BUDGET_BYTES` (the 6,144 MiB of the sandboxed check), checks the digest files under proofs/keys/ are the pinned ones, and checks each committed hex file decodes to a root key of its path, at the shrink's shape and planned tables, whose SHA-256 is the digest in its `.sha256` file; these tests build no key and run with the other tests. The tests that build a key are ignored by default so the normal tests stay fast: `derive_production_bundle_root_key` and `derive_production_public_root_key` each derive one key and check its bytes against the committed hex file and its digest against the pinned one. Run them with `-- --ignored --nocapture`.
- <!-- no-figure --> **CI.** The ignored tests run after every merge to main, never on a pull request, in two jobs of .github/workflows/ci.yml on `ubuntu-24.04`, one key a job so each fits its 10-minute limit, each built with AVX2 (`RUSTFLAGS: -C target-feature=+avx2`, as the ML-DSA fold jobs are) because, built scalar, the build and a derivation together run past that limit: rust-proofs-root-key-bundle runs every ignored test but the public root's derivation, and rust-proofs-root-key-public runs that derivation. A change that alters a key without committing its new bytes and digest turns main red. scripts/check-production-root-keys-job.sh, run by the production-root-keys-job job on every pull request, fails if those jobs stop running after merge only, leave the hosted image, the 10-minute limit or AVX2, drop `-- --ignored --nocapture`, or leave an ignored test of the file unrun.

## Shapes

- <!-- no-figure --> **Bundle root key.** A batch of `layers::REVEALS_PER_BATCH` version 2 coin reveals and a root of `layers::BATCHES_PER_ROOT` such batches, both at `LayerShape::WIDE`, and the root's shrink at `LayerShape::SHRINK` (stage2-design.md, "The shape for 1 million a day").
- <!-- no-figure --> **Public root key.** A chunk of `mldsa::DESIGN_CHUNK` ML-DSA-44 verifications, folded by the private bundles' layers: a batch of `layers::REVEALS_PER_BATCH` chunks and a root of `layers::BATCHES_PER_ROOT` batches at `LayerShape::WIDE`, and the root's shrink at `LayerShape::SHRINK` (stage2-design.md, "Public signature size").

## Memory of each stage

The peak of a stage is the largest of its blank circuit as it is built, its rows (the circuit without its wire values) with its preprocessed columns, and its columns (then, in their place, their coefficients) with one block of their extension, the block's rows before and after salting and its Merkle subtree (modeled, `layers::KeyMemory`). The test prints these figures for every stage and fails if any stage plans above the budget.

| Stage (all modeled) | Table heights | Lanes | Circuit | Its rows | Preprocessed columns | Block | Peak |
|---|---|---|---|---|---|---|---|
| Bundle: batch (modeled) | 8388608, 8388608, 524288, 1024, 131072 | 2, 1, 1, 1, 1 | 0.71 GiB | 0.25 GiB | 1.84 GiB | 2.28 GiB | 4.12 GiB |
| Bundle: root (modeled) | 8388608, 8388608, 2097152, 4096, 524288 | 8, 1, 1, 1, 1 | 2.24 GiB | 0.85 GiB | 3.98 GiB | 0.56 GiB | 4.83 GiB |
| Bundle: shrink (modeled) | 262144, 262144, 131072, 256, 16384 | 8, 2, 1, 1, 1 | 0.08 GiB | 0.03 GiB | 0.15 GiB | 2.60 GiB | 2.75 GiB |
| Public: chunk (modeled) | fifteen tables, the tallest 4194304 | 1 each | 1.01 GiB | 0.92 GiB | 0.72 GiB | 1.81 GiB | 2.52 GiB |
| Public: batch (modeled) | 8388608, 8388608, 1048576, 1024, 131072 | 4, 2, 1, 1, 1 | 1.32 GiB | 0.47 GiB | 2.70 GiB | 1.58 GiB | 4.28 GiB |
| Public: root (modeled) | 8388608, 8388608, 2097152, 4096, 524288 | 8, 2, 1, 1, 1 | 2.29 GiB | 0.86 GiB | 4.14 GiB | 0.57 GiB | 5.00 GiB |
| Public: shrink (modeled) | 262144, 262144, 131072, 256, 16384 | 8, 2, 1, 1, 1 | 0.08 GiB | 0.03 GiB | 0.15 GiB | 2.60 GiB | 2.75 GiB |

Both derivations fit the 6.00 GiB budget (modeled): the bundle root key peaks at 4.83 GiB and the public root key at 5.00 GiB, each at its root stage.

## Digests

Both keys were derived to the end by the derivation test, then a single test for both keys, one after the other in one process, under the 6,144 MiB cap of the sandboxed check (measured on one machine, two runs):

- <!-- no-figure --> **Bundle root key.** Derived in 172 to 176 s; the process's peak resident memory was 5.35 to 5.36 GiB, reached at the root stage (measured). SHA-256 `5a230c8f019c3f9b707ebea174149cef74488bd17aee21214ef77c0b689ddec0`, pinned in proofs/keys/bundle-root-key.sha256.
- <!-- no-figure --> **Public root key.** Derived in 215 to 217 s; the process's peak resident memory was 5.57 to 5.61 GiB, reached at the root stage (measured). SHA-256 `d00492b05e4513aed78b20a4291d2696bc8e112792490c3f423f398f2a5a93f5`, pinned in proofs/keys/public-root-key.sha256.

The committed key bytes (proofs/keys/bundle-root-key.hex and proofs/keys/public-root-key.hex) come from a third such run, one after the other in one process under the same cap, each written only once its SHA-256 matched the pinned digest: the bundle root key in 211 s at a peak of 5.41 GiB, the public root key in 230 s at a peak of 5.78 GiB (measured).

The measured peaks are above the modeled ones by up to 0.61 GiB: the model counts the key's data, not the allocator's slack or the threads' working buffers. Both stay under the cap. A change to a layer's circuit, its shape or the commitment changes the derived key, and the derivation tests then fail until the new key's bytes and digest are committed.

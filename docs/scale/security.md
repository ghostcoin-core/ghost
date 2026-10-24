# Proven security of the recursive bundle

This page is the security argument for the whole recursive bundling construction: the leaf proof, every layer of the recursion, the transcript, the verifier binding and the losses of composing them. It is part of the first stage (feasibility and security) of the scale work and follows the rules of designs.md. The arithmetic is in benchmarks/scale/security_budget.py, tested by benchmarks/tests/test_scale_security.py.

Every figure carries one of the labels of workload.md: measured, modeled or not yet established. Nothing on this page is measured: the sandbox that wrote it could not run the prover, so a figure that needs a run is not yet established and names the command or change that would produce it.

**Result.** The whole-bundle proven bound is **not yet established**. Three steps of the argument are missing (listed in "What is not yet established"): a proof that soundness survives recursion when the verifier circuit computes the hash it is modeled by, the proven extension-field terms at the parameters below, and the exact theorems of the two cited papers for each term. Where the argument is complete, the modeled figures already show two things: today's proven figures fall short by 48 classical and 24 quantum bits (modeled), and with Keccak-256's 256-bit digest the sum of terms stays just under 128 classical bits for every parameter set (modeled), so the Keccak architectures need a longer digest to reach the requirement.

## Requirement

Before mainnet, the whole bundled proof is proven to at least 128 bits classically and to NIST Category 1 against a quantum attacker (64 quantum bits, spec 09, section 3), with every grinding site counted at half its proof-of-work bits. This is a hard requirement, recorded in decision 0003 and in spec 09, section 4.1. It is not met today and is not changed to fit a result. (Labels: the 128, 64 and half are the target, modeled from spec 09.)

What "proven" means here: a bound that follows from a stated theorem, in the random oracle model classically and the quantum random oracle model against a quantum attacker, with the hash as the oracle. That each concrete hash behaves as a random oracle is an assumption no candidate can prove; it is stated per hash in "Primitive evidence". A figure that rests on any further conjecture, such as the conjectured FRI estimate, is conjectured, never proven, on this page. <!-- no-figure -->

Today's figures from decision 0003, at `keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk` (modeled: the pinned estimator's output, quoted, not recomputed):

| Figure | Classical | Quantum | Kind |
|---|---|---|---|
| Queries alone, `log2(1/rate) * queries` | 129 (modeled) | | Conjectured |
| Whole leaf proof | 128 (modeled) | 64 (modeled) | Conjectured |
| Whole leaf proof | 80 (modeled) | 40 (modeled) | The estimator's proven figure, one proof, no recursion |
| Earlier configuration, blowup 2^2 with 57 queries | 72 (modeled) | | The estimator's proven figure |
| Shortfall of the proven figure against the requirement | 48 (modeled) | 24 (modeled) | One proof, before any recursion loss |

The proven 80 matches the Johnson-regime query term with the query grinding counted in full: 43 queries at 1.5 bits each (rate 1/8) is 64.5, plus 16 is 80.5 (modeled). Counted at half, as the requirement says, the same term is 72.5 classical and 40.25 quantum (modeled). Which term the estimator's 80 comes from is not yet established from its source; the command that would print every proven term is a run of `ProvenSecurity::compute_from_proof` in benchmarks/prover/src/security.rs (`estimate`) at these parameters, for example through `cargo test --release --locked --manifest-path proofs/Cargo.toml shipped_configuration_meets_quantum_rule -- --nocapture` extended to print the proven terms (a Rust change outside this piece; not yet established).

## Construction

The bundle folds the reveals of one block into one proof by a two-to-one tree of recursive proofs, with no elliptic-curve wrap anywhere. At the target (3,500 reveals a block, modeled from workload.md) the tree has 3,500 leaf proofs, 12 merge layers of 1,750, 875, 437, 219, 109, 55, 27, 14, 7, 3, 2 and 1 merges (an odd proof is carried up unmerged), and 6,999 proofs in all (modeled). Nodes verify only the root proof, natively, and still run every state-dependent check of every reveal (designs.md, rule 1). Recursion aggregates proof verification only; it authorizes nothing by itself.

### Leaf proof

The leaf is today's reveal STARK (proofs/src/stark.rs): an IOP made of the AIR of the statement, DEEP-ALI and the FRI low-degree test over BabyBear with a degree-5 extension for challenges (154 bits, modeled), compiled by the BCS transformation with Merkle commitments and a Fiat–Shamir transcript. Hiding FRI and a hiding Merkle commitment give zero knowledge; zero knowledge is not a soundness term.

Soundness error terms of one leaf proof (each is a term of the sum; grinding at half; labels per figure): <!-- no-figure -->

1. FRI query phase: `rate^(q/2)` per proof in the proven (Johnson) regime against `rate^q` conjectured, plus the query grinding at half. Today 72.5 proven classical bits with grinding at half (modeled) against 129 conjectured from the queries alone (modeled).
2. FRI commit phase: one folding challenge per round from the extension field; its proven term depends on the field size, the codeword length and the proximity-gap bound used. Not yet established at any parameter set on this page.
3. Batching of the openings into one FRI instance (7,716 functions over a 2^15 codeword, modeled from docs/benchmarks/reveal-parameters.md), plus the batch grinding at half. The conjectured term is 134 (modeled); the proven term is not yet established.
4. DEEP out-of-domain point and constraint composition (ALI): field terms. The conjectured term is at least 138 (modeled); the proven term is not yet established.
5. Hash: a collision in the Merkle commitment hash, counted once for the whole bundle (a single event for the attacker, not one per proof). Keccak-256 gives 128 classical bits and about 85.3 quantum bits by the `t^3 / 2^L` term (modeled).

Transcript and domain separation: the challenger is `SerializingChallenger32` over `HashChallenger<u8, Keccak256Hash, 32>`, started from an empty input (`Challenger::from_hasher(Vec::new(), ...)` in proofs/src/stark.rs). The public inputs enter as one field element per byte (`public_field`). The library at the pinned revision observes the commitments, the public values and the proof's sizes before drawing each challenge; the exact list and order of what it absorbs is not yet established on this page (read `p3_uni_stark::prove` and `verify` at revision `f98331687e47`). No Ghost-specific domain-separation tag, statement identifier, chain identifier or version enters the transcript today. <!-- no-figure -->

What binds the verifier and statement identity: the node's verifier, not the proof. `verify` picks the AIR from the `Statement` the transaction type names, rebuilds the public inputs from the transaction itself, checks their count and checks `degree_bits` against the AIR's height. A proof made for one statement fails another statement's AIR only because the constraints differ, which is a property of the code, not a probability. This suffices for a single reveal verified natively; inside a bundle the statement identity must become an input of the proof (next sections). <!-- no-figure -->

### Conversion layer

When the leaf hash and the aggregation hash differ (Keccak leaves to Poseidon2 aggregation), the first merge layer is a conversion layer: each of its 1,750 proofs (modeled) runs, inside an AIR over BabyBear, the full verifier of two Keccak leaf proofs, Keccak-f\[1600\] arithmetized, and is itself committed and transcribed with Poseidon2. Its soundness terms are its own STARK terms (items 1 to 4 above, at its own parameters, over its own trace), plus the leaves' terms carried through extraction (see "Composition losses"). The Keccak collision term stays in the sum, because the leaf commitments it checks are Keccak commitments; the Poseidon2 collision term is added.

Transcript and domain separation: the conversion proof's own transcript, plus, as an input to the in-circuit leaf verifier, every leaf's transcript recomputed with Keccak-256 exactly as the native verifier does. The layer's transcript must absorb, before any challenge, a tag naming the layer kind, the layer index, the protocol and statement versions and the chain identifier, and the digest of the child verifier key; none of this exists yet (not yet established). <!-- no-figure -->

What binds the verifier: the child verifier key (the leaf AIR, its configuration string, the statement identifier) is fixed in the conversion AIR as a constant or a preprocessed commitment, and the leaf's public inputs are exposed as the conversion proof's public inputs or folded into a digest that is. <!-- no-figure -->

### Merge layers

Every merge proof verifies two child proofs of the layer below inside its AIR and outputs one proof of the same kind. Its soundness terms are its own STARK terms at the layer parameters, plus its children's terms through extraction. Its transcript absorbs the same tag as the conversion layer with its own layer index and the digest of the child verifier key. Its public inputs are the ordered concatenation, or a running digest, of its children's transaction-content digests and their counts.

### Root and the node

The node verifies the root proof natively against public inputs it builds itself: the digest of the approved Ghost statement and verifier key, the digest of the exact ordered transaction contents of the bundle, the count, the chain identifier and the protocol and statement versions. A change, reordering, addition or removal of any one makes the root fail (designs.md, private bundle requirement 1). <!-- no-figure -->

### The verifier-binding assumption

Stated as an assumption, because no recursion circuit exists yet: every layer's AIR fixes the verifier key of its children, and every layer's public inputs carry, unchanged or under a collision-resistant digest, the statement identity, the ordered contents, the count, the chain and the versions of every leaf below it. It is enforced in two places: inside each layer's constraints (a child proof against any other verifier key does not satisfy them) and at the node (the root's public inputs must equal the node's own constants and the block's contents). Plonky3-recursion is not evidence that it holds: its compatibility check is shape-only and binds no child proving keys, statements or public claims, and it is Poseidon-only, unaudited and "not recommended for production". The leanMultisig merge time (0.303 s, not yet established for Ghost) is leanVM verifying its own proofs over a 192-bit binary field with Keccak as a placeholder, not Plonky3 proofs.

## Composition losses

The bound for the whole bundle is the sum of every proof's error terms over the tree (a union bound), with each hash collision term counted once:

`bits(bundle) = -log2( sum over proofs p of 2^-bits(p) + sum over hashes h of 2^-collision(h) )` <!-- no-figure -->

Classically each `bits(p)` is the proof's own terms combined the same way, grinding at half. Against a quantum attacker each proof's round-by-round bits are halved and grinding is counted at half (`quantum_bits` in the module; for a figure whose grinding share is unknown the whole figure is halved, which can only understate it), and the hash term is `L/3` for an `L`-bit digest. Both come from the bound `t^2 * e + t^3 / 2^L` of Chiesa, Manohar and Spooner (ePrint 2019/834; spec 09, section 4.1). <!-- no-figure -->

For 6,999 proofs of equal strength the sum costs `log2(6,999)`, about 12.77 bits (modeled): each proof needs about 140.77 classical and 76.77 quantum bits for the sum to reach 128 and 64 (modeled). Each added layer adds its proofs to the sum, so a deeper tree only lowers the bound (tested in the module; modeled).

What each step of this sum rests on, and whether it is proven:

| Step | Source | Status |
|---|---|---|
| One proof, classical: BCS soundness `t * e` from round-by-round soundness | Spec 09, section 4.1; neither named paper | Proven for an IOP with round-by-round error `e`; that `e` for Plonky3's IOP at these parameters is the estimator's proven figure is not yet established |
| One proof, quantum: `t^2 * e + t^3 / 2^L` | ePrint 2019/834, the BCS-from-IOP result with round-by-round soundness | Proven by that paper for BCS in the QROM; the theorem number is not yet established on this page (the paper's text could not be retrieved where this was written) |
| Grinding at half | Grover's search, spec 09, section 4.1 | Modeled, and the requirement's own rule |
| Union over the 6,999 proofs of the tree | The sum above | Proven only if each layer's argument is knowledge sound with an extractor that composes over 12 layers without loss beyond the sum; not yet established |
| Recursion when the verifier circuit computes the hash | ePrint 2025/2166 (Chiesa, Di, Hu and Zheng: hash-based succinct non-interactive reductions from interactive oracle reductions are secure in the QROM when the reduction has post-quantum state-restoration security) | Not yet established: whether its theorems cover a tree of depth 12 whose layers evaluate the oracle inside their constraints, and with what loss, has not been read from the paper's text; the theorem numbers are not yet established |
| The verifier-binding assumption | This page | An assumption on a circuit that does not exist yet; not yet established |

The gap in the fifth row is the main one. In the random oracle model the hash is a black box, but a merge layer's AIR computes the hash to verify its children, so the statement it proves refers to the oracle itself; a random-oracle proof of one STARK does not by itself cover that. Until a theorem covers it, the whole-bundle figure is conditional on it, and so is every bundle figure on this page.

## Parameters

Leaf and layer parameters that meet the requirement in the query phase, for each of the three architectures. Blowup 2^3 is kept for the leaves (Keccak's constraint degree of 3 needs it in zero-knowledge mode, decision 0003) and used for the layers; 16 grinding bits at the queries and 16 before the batching challenge, as today; BabyBear with the degree-5 extension (154 bits). The queries are the fewest whose Johnson-regime term, in each of the 6,999 proofs, brings the sum to 128 classical and 64 quantum: 92 (modeled, `johnson_queries_needed`). Each proof's query phase then gives 146 classical and 77 quantum bits (modeled). The whole-proof proven figure of each leaf and layer is not yet established, because the proven extension-field terms are not computed; the query-phase figures are an upper bound on it.

| Architecture | Leaf | Conversion and merge layers | Hash terms counted once | Whole bundle, classical | Whole bundle, quantum | Against 128 / Category 1 (modeled) |
|---|---|---|---|---|---|---|
| Keccak leaves to Keccak aggregation | Blowup 2^3, 92 queries, grinding 16 + 16, BabyBear ext-5 | The same, Keccak-256 commitments and transcript | Keccak-256, 256-bit digest: 128 classical, 85.3 quantum (modeled) | 127.96 (modeled) | 64.23 (modeled) | Short by 0.04 classical bits (modeled) |
| Keccak leaves to Poseidon2 aggregation | The same | Blowup 2^3, 92 queries, grinding 16 + 16, BabyBear ext-5, Poseidon2 width 24 | Keccak-256 and a 9-element Poseidon2 digest (279 bits: 139.5 classical, 93 quantum, modeled) | 127.96 (modeled) | 64.23 (modeled) | Short by 0.04 classical bits (modeled) |
| Poseidon2 leaves to Poseidon2 aggregation | Blowup 2^3, 92 queries, grinding 16 + 16, BabyBear ext-5, Poseidon2 width 24 | The same | 9-element Poseidon2 digest only (modeled) | 133.21 (modeled) | 64.23 (modeled) | Met in the query phase and hash terms only (modeled); the whole bound is not yet established |

So no parameter set reaches 128 classical bits in a Keccak architecture while the commitments use a 256-bit Keccak-256 digest: its collision term is exactly 128 (modeled) and any other term in the sum leaves the total below it. What would be needed: a commitment and transcript digest longer than 256 bits, for example 320 bits squeezed from the same Keccak-f\[1600\] sponge, whose capacity of 512 bits allows it, giving a 160-bit collision term and a Keccak-to-Keccak bundle of about 133.2 classical bits in the query phase (modeled). That is a change of the proof configuration and of spec 09, section 4.1, item 3, which is a founder decision outside this piece.

With today's leaf parameters (43 queries) in the same tree, the query phase gives about 59.7 classical bits for the whole bundle (modeled), a shortfall of more than 68 (modeled). At 92 queries the proof is longer than today's; whether it still fits the 1,310,720-byte proof field of spec 07 is not yet established (the command is the proof-length bound of `proof_length_bound` in proofs/src/stark.rs at 92 queries, a Rust change outside this piece).

The proven extension-field terms at these parameters are not yet established; they are expected to bind before the query term, because proven proximity-gap errors grow with the codeword length and the number of batched functions while the conjectured ones do not. If they fall below the bits each proof needs, the remedy is a larger extension of BabyBear or independent batching challenges (spec 09, section 4.1, item 2), not a smaller target. The command is the estimator run named under "Requirement", at blowup 2^3, 92 queries and each candidate extension degree (not yet established).

## Primitive evidence

Each hash candidate exactly as Ghost uses it, and which published record applies to exactly that primitive (designs.md, rule 3). Industry adoption and unrelated reduced-round results do not decide the comparison. No record in this table proves a hash is a random oracle; that assumption is what "proven" rests on for every candidate. <!-- no-figure -->

| Primitive and role | Field and encoding | Width, rate and capacity | Rounds | Records that apply | Records that do not |
|---|---|---|---|---|---|
| Keccak-f\[1600\] in a padding-free sponge: Merkle leaf hash and two-to-one compression of the reveal proof | BabyBear elements in Montgomery form, two to a 64-bit lane; each block overwrites the rate, a short last block overwrites only the lanes it fills; no padding, no length, an empty row hashes to zero; safe only because every row of a matrix has a fixed width | 25 lanes of 64 bits (1,600 bits), rate 17 lanes (1,088 bits), capacity 512 bits, 4-lane (256-bit) digest (modeled: read from proofs/src/stark.rs) | 24, the full permutation (modeled) | Cryptanalysis of the Keccak-f\[1600\] permutation itself; the generic sponge bound at capacity 512 for fixed-length inputs. Whether a published proof covers this overwrite, padding-free mode exactly is not yet established | Results on NIST SHA3-256, whose padding and domain suffix differ; results on Keccak with fewer rounds; adoption |
| Keccak-256 (original Keccak padding): Fiat–Shamir transcript of the reveal proof, `HashChallenger<u8, Keccak256Hash, 32>` | Bytes of the serialized transcript | Keccak-f\[1600\], rate 1,088 bits, capacity 512 bits, 256-bit output (modeled: read from proofs/src/stark.rs) | 24 (modeled) | Keccak-256 as specified by its designers, the one spec 01 uses | NIST SHA3-256 (a different padding and domain suffix, so a different function); reduced-round results |
| Poseidon2 over BabyBear, width 24: commitments and duplex transcript of a Poseidon2 leaf or layer, as in the benchmark harness | BabyBear elements | Width 24; sponge rate 15 and capacity 9 for commitments, 9-element (279-bit) digest; duplex challenger rate 15. The reveal AIR's in-circuit hash uses rate 16 with an 8-element digest (248 bits, about 124 bits of collision) and could not carry a 128-bit collision term (all modeled: read from benchmarks/prover/src/zk.rs and benchmarks/prover/src/poseidon2.rs) | `BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS` full rounds on each side and `BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_24` partial rounds of the pinned library, S-box `x^7` | Only analysis of Poseidon2 over BabyBear at width 24 and these round numbers; which published record covers exactly this instance is not yet established | The CICO and zero-test records: they are Poseidon1 over KoalaBear with t=16, a different permutation, field and width; Poseidon1 or Poseidon2 results at other widths or fields; adoption |

Keccak-f\[1600\] arithmetized inside a BabyBear AIR (the conversion layer, or Keccak aggregation) is the same permutation computed by constraints; its security as a hash does not change, but the AIR's correctness is a code property that a test must hold (not yet established, no such AIR exists). <!-- no-figure -->

## What is not yet established

Every gap, by name, with what would close it. Conjectured security is never counted as proven here; the figures that close a gap are labelled where they appear.

1. **Recursion with the hash inside the circuit (not yet established).** No theorem read for this page proves that soundness survives a tree of recursive STARKs whose layers compute the oracle in their constraints, classically or in the QROM. Closed by a theorem, with its number and its loss, that covers exactly this composition (ePrint 2025/2166 is the candidate to read in full), or a written proof in this repository.
2. **Extraction over 12 layers (not yet established).** The union bound is valid only if every layer is knowledge sound with an extractor that composes over the depth of the tree without extra loss. Closed by the same theorem, or by a proof that the per-layer extractor is straight-line, classically and against a quantum attacker.
3. **Theorem numbers of the cited sources.** The exact theorem of ePrint 2019/834 used for the quantum conversion, and the theorems of ePrint 2025/2166 for recursion, are not yet established on this page: their text could not be retrieved where it was written. Closed by citing the theorem and section beside each term in "Composition losses".
4. **Round-by-round soundness of the Plonky3 IOP (not yet established).** The quantum conversion needs round-by-round soundness, not only soundness. Closed by a proof, or a published one for the pinned revision's IOP, that the estimator's proven terms are round-by-round errors.
5. **Proven extension-field terms.** Not computed at any parameter set on this page. Closed by the estimator run named under "Requirement" at blowup 2^3, 92 queries and each candidate extension degree, recorded as measured.
6. **Which term gives today's proven 80.** The reading that it is the query term with grinding in full is modeled. Closed by the same run printing every proven term.
7. **Digest length in the Keccak architectures.** A 256-bit Keccak-256 digest caps the sum at 128 classical bits and every other term leaves it below (a shortfall of 0.04 bits at the parameters above, modeled). Closed by a longer commitment and transcript digest (a founder decision changing the proof configuration), or by a theorem in which the collision term does not add to the soundness terms.
8. **Domain separation and verifier binding.** The transcript has no Ghost tag, statement identifier, chain identifier, version or verifier-key digest today, and no recursion circuit fixes a child verifier key. Closed by the bundle design, with tests that a child proof under any other verifier key, statement, chain or version fails, and that changing, reordering, adding or dropping a reveal fails.
9. **Proof length at 92 queries (not yet established).** Closed by the proof-length bound at those parameters against the 1,310,720-byte proof field, or a new transaction version (spec 07).
10. **The padding-free Keccak sponge (not yet established).** Closed by a published or written proof that the overwrite, padding-free mode at fixed input length meets the sponge bound at capacity 512.
11. **Poseidon2 over BabyBear width 24 (not yet established).** Closed by naming the published analysis that covers exactly this instance and its round numbers; the Poseidon1 KoalaBear t=16 records do not.
12. **The leanMultisig and Plonky3-recursion figures for Ghost.** Neither is evidence for a Ghost bundle; a Ghost merge time and a binding recursion verifier are not yet established and are other pieces of this work.

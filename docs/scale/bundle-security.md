# Whole-bundle security: the estimator run and the proof obligations

The stage 2 design (stage2-design.md, "Whole-bundle proven security bound") reaches 135.80 classical and 66.05 quantum bits for a bundle only as a modeled sum, and calls it a proven bound only once its proof obligations are discharged. This page is the write-up for the outside review: it runs the pinned library's estimator at the real shape of every proof in a bundle, evaluates the design's formulas at those same shapes, checks the formulas' constants against the paper text that could be read, and gives the status of each obligation. Every figure is labelled. Here "measured" means the output of running code on the built circuits: their shapes counted, and the estimator run on them. It is not a measured attack cost, and a bit count labelled measured is still only what the estimator or the formula computes (not yet established as a proven bound).

**Result.** At the real shapes, the design's formulas give 135.80 classical and 66.05 quantum bits for a bundle of 3,612 proofs, above 128 and 64 (modeled; the formula's inputs measured). The library's own proven figure is lower in two ways, stated plainly in "The two side by side": the library caps every proof at the digest's 139-bit collision resistance, so its figures added over the bundle give 127.18 classical and 57.18 quantum bits, below the requirement (measured and modeled); with the cap lifted and the digest counted once, the library gives 138.33 classical bits, above the formula, but 63.18 quantum bits under the crate's convention of halving the whole figure, below 64 and below the formula (measured and modeled). None of these sums is a proven bound: all five proof obligations below are open (not yet established), and no theorem read here covers recursion with the hash inside the circuit in the quantum random oracle model.

## How to rerun

```sh
scripts/bundle-security.sh
```

The script runs proofs/tests/bundle_security.rs with `--nocapture`, which prints every table of this page from a fresh run, and fails when a row of a table on this page differs from the run, when the page has a table the run does not produce (other than the hand-written tables of constants and obligations), or when the formula's whole-bundle sum is below the requirement of 128 classical or 64 quantum bits (modeled there as the target, benchmarks/scale/security_budget.py). benchmarks/scale/labels.py checks the labels of this page, and with `--obligations` its obligations table.

## The bundle and its parameters

- **The bundle.** As in the design, the largest bundle: one aggregator holding all reveals of a block, so 3,500 reveal proofs (the leaves), 110 batch proofs of 32 reveals, one root and one shrink, 3,612 proofs (modeled: the design's bundle).
- **The parameters.** Those of the prover and the layers as built: the scale configuration of proofs/src/scale.rs (a 279-bit Poseidon2 digest whose collision resistance the estimator takes as 139 bits, challenges from the degree-8 extension of BabyBear taken as 247 bits, blowup 2^3 with 96 queries, 16 bits of grinding on the queries and 16 before the batching challenge, hiding FRI), and the shapes of proofs/src/layers/: the batch and root at blowup 2^3 with 96 queries, the shrink at 2^5 with 56; FRI folds by 2 down to a final polynomial of one coefficient (measured: read from the code the run uses).
- **The shapes.** The reveal's from its AIR, as the scale gate derives them (the test checks that the leaf's estimate equals scale_coin_reveal_v2_estimate). The layers' from their real circuits, planned without proving by estimate_pipeline in proofs/src/layers/mod.rs, the same planning as plan_pipeline of the layers work: a batch's circuit built for one, two and three reveal slots and extended to 32, a root's for one, two and three batch slots and extended to 110, the shrink's built whole (measured). The layers results page planned a root over 44 batches, the largest aggregator's share; this page plans the 110 of the design's bundle (measured).
- **How a layer enters the estimator.** The library's estimator takes one AIR; a layer is a batch STARK of five tables sharing one transcript, one out-of-domain point and one FRI instance. Its parameters are folded into one set (proofs/src/layers/security.rs): the batched functions summed over the tables with the library's own count for a batch-STARK instance (main, preprocessed, quotient, randomizing and LogUp columns at every point they are opened at), the constraints summed, the largest constraint degree and quotient chunk count, the tallest table's domain, two out-of-domain points.
- **The shared out-of-domain point.** Five tables tested at one point can make the DEEP error up to five times that of the largest table. The run repeats the uncapped estimate with the challenge field taken three bits smaller, which charges more than that factor to every field-size term, and the figure does not move (measured: the last column of the estimator table).

## The shapes

| Proof (measured: the shapes of the built circuits, as the estimator takes them) | Proofs in the bundle | Log blowup, queries, grinding on queries and batching | Tables | Degree bits | FRI rounds | Constraints | Largest constraint degree | Quotient chunks | Batched functions |
|---|---|---|---|---|---|---|---|---|---|
| leaf, a reveal (measured) | 3,500 | 3, 96, 16 and 16 | 1 | 12 | 12 | 5,882 | 3 | 8 | 7,940 |
| batch (measured) | 110 | 3, 96, 16 and 16 | 5 | 24 | 24 | 890 | 4 | 8 | 2,685 |
| root (measured) | 1 | 3, 96, 16 and 16 | 5 | 24 | 24 | 1,154 | 4 | 8 | 3,905 |
| shrink (measured) | 1 | 5, 56, 16 and 16 | 5 | 19 | 19 | 866 | 4 | 8 | 2,483 |

Degree bits are the log of the tallest committed trace with the zero-knowledge doubling; the tested codeword is that times the blowup (measured).

## The estimator's output

The estimator is the pinned library's ProvenSecurity and ConjecturedSecurity of p3-uni-stark, as the scale gate of proofs/src/scale.rs already runs it. It reports whole bits, each the smallest of its terms: algebraic composition, DEEP, the low-degree test, the batching of the openings, and a cap at the commitment hash's collision resistance (its output below measured, in the sense above).

| Proof (measured: the pinned estimator's output, whole bits) | Conjectured | Conjectured, grinding at half | Proven, unique decoding | Proven, list decoding | Proven, the library's figure | Proven, grinding at half | Proven, grinding at half, collision cap lifted | The same, field three bits smaller |
|---|---|---|---|---|---|---|---|---|
| leaf, a reveal (measured) | 139 | 139 | 95 | 139 | 139 | 139 | 151 | 151 |
| batch (measured) | 139 | 139 | 95 | 139 | 139 | 139 | 151 | 151 |
| root (measured) | 139 | 139 | 95 | 139 | 139 | 139 | 151 | 151 |
| shrink (measured) | 139 | 139 | 69 | 139 | 139 | 139 | 147 | 147 |

- Every proof's proven figure, and every conjectured one, is the collision cap of 139 bits (measured): the library charges the digest's collision term to each proof, where the design charges it once to the bundle.
- With the cap lifted, the smallest algebraic term is 151 bits for a reveal, a batch and a root and 147 for the shrink, grinding at half (measured).
- The unique-decoding regime gives 95 and 69 bits (measured); the list-decoding regime is the one every figure above rests on.

## The design's formulas at the real shapes

The formulas are the design's ("Whole-bundle proven security bound"), with m = 16 (modeled): a query gives -log2(sqrt(rho)(1 + 1/(2m))) bits; the commit-phase and batching term is ((m + 1/2)^7 / (3 rho^(3/2))) n^2 (M - 1) / |F| plus (2m + 1)(n + 1) R / (sqrt(rho) |F|), with M the batched functions, n the codeword length, R the folding rounds and |F| the degree-8 extension; each term gets its grinding at half; against a quantum attacker each proof's round-by-round bits are halved, grinding kept at half, and the digest's term is a third of its 279 bits; proofs and the digest are added as probabilities (modeled). The run evaluates them at the measured shapes above. The test also checks the formula against the design's own leaf: at its modeled codeword of 2^15, 7,716 functions and 12 rounds it gives the design's 147.74 and 77.87 bits (modeled).

| Proof (modeled: the design's formulas at the measured shapes) | Proofs in the bundle | Query term, classical | Proximity term, classical | Classical bits each | Quantum bits each |
|---|---|---|---|---|---|
| leaf, a reveal (modeled) | 3,500 | 147.74 | 181.07 | 147.74 | 77.87 |
| batch (modeled) | 110 | 147.74 | 158.64 | 147.74 | 77.84 |
| root (modeled) | 1 | 147.74 | 158.10 | 147.74 | 77.83 |
| shrink (modeled) | 1 | 145.51 | 161.75 | 145.51 | 76.75 |
| Poseidon2 digest of 279 bits, counted once (modeled) | 1 | | | 139.50 | 93.00 |
| Whole bundle, 3,612 proofs (modeled) | | | | 135.80 | 66.05 |
| Whole bundle, the round terms as Lemma 8.2 of BCIKS states them (modeled) | | | | 135.80 | 66.05 |

The real shapes give the design's sums to the second decimal: the query term binds every proof, and the proximity term, the one the real shapes change, stays at least ten bits above it (modeled). The last row takes the folding rounds and the batching coefficient as Lemma 8.2 states them (see "Constants checked against the paper text"), and the sum does not move (modeled).

## The two side by side

| Figure (measured: the library; modeled: the formula) | The library's proven figure, grinding at half | The design's formula | The library's figure below the formula |
|---|---|---|---|
| leaf, a reveal, classical, as the library caps it (measured and modeled) | 139.00 | 147.74 | yes, by 8.74 bits |
| leaf, a reveal, quantum, as the library caps it (measured and modeled) | 69.00 | 77.87 | yes, by 8.87 bits |
| leaf, a reveal, classical, collision cap lifted (measured and modeled) | 151.00 | 147.74 | no |
| leaf, a reveal, quantum, collision cap lifted (measured and modeled) | 75.00 | 77.87 | yes, by 2.87 bits |
| batch, classical, as the library caps it (measured and modeled) | 139.00 | 147.74 | yes, by 8.74 bits |
| batch, quantum, as the library caps it (measured and modeled) | 69.00 | 77.84 | yes, by 8.84 bits |
| batch, classical, collision cap lifted (measured and modeled) | 151.00 | 147.74 | no |
| batch, quantum, collision cap lifted (measured and modeled) | 75.00 | 77.84 | yes, by 2.84 bits |
| root, classical, as the library caps it (measured and modeled) | 139.00 | 147.74 | yes, by 8.74 bits |
| root, quantum, as the library caps it (measured and modeled) | 69.00 | 77.83 | yes, by 8.83 bits |
| root, classical, collision cap lifted (measured and modeled) | 151.00 | 147.74 | no |
| root, quantum, collision cap lifted (measured and modeled) | 75.00 | 77.83 | yes, by 2.83 bits |
| shrink, classical, as the library caps it (measured and modeled) | 139.00 | 145.51 | yes, by 6.51 bits |
| shrink, quantum, as the library caps it (measured and modeled) | 69.00 | 76.75 | yes, by 7.75 bits |
| shrink, classical, collision cap lifted (measured and modeled) | 147.00 | 145.51 | no |
| shrink, quantum, collision cap lifted (measured and modeled) | 73.00 | 76.75 | yes, by 3.75 bits |
| Whole bundle, classical, each proof as the library caps it (measured and modeled) | 127.18 | 135.80 | yes, by 8.62 bits |
| Whole bundle, quantum, each proof as the library caps it (measured and modeled) | 57.18 | 66.05 | yes, by 8.87 bits |
| Whole bundle, classical, collision cap lifted, the digest once (measured and modeled) | 138.33 | 135.80 | no |
| Whole bundle, quantum, collision cap lifted, the digest once (measured and modeled) | 63.18 | 66.05 | yes, by 2.87 bits |

Where the library's figure is below the formula, plainly:

- **Every proof, as the library reports it.** The library's proven figure, 139 bits a proof, is below the formula's 147.74 for a reveal, a batch and a root and 145.51 for the shrink (measured and modeled). The reason is the cap: the library's figure is the 139-bit collision term of the digest, not an algebraic term.
- **The whole bundle from the library's figures.** Added over 3,612 proofs, the capped figures give 127.18 classical and 57.18 quantum bits, below the requirement of 128 and 64 and below the formula's 135.80 and 66.05 (measured and modeled). This sum charges the digest's collision once a proof, 3,612 times; the design charges it once, as one collision breaks every proof that uses the hash at once.
- **The quantum figure, cap lifted.** Under the crate's convention, a quantum figure is half the classical one, grinding included (proofs/src/stark.rs, SecurityEstimate). That gives 75 bits for a reveal, against the formula's 77.87, and 63.18 for the whole bundle, below 64 and below the formula's 66.05 (measured and modeled). The convention halves the grinding a second time, which only understates. The design halves the round-by-round bits and counts grinding at half once. The library reports no split between its query and grinding bits, so its own figure under the design's rule is not given here (not yet established).
- **Where it is not below.** With the cap lifted, the library's classical figure is above the formula: 151 bits against 147.74 for a reveal, a batch and a root, 147 against 145.51 for the shrink, and 138.33 for the whole bundle against 135.80 (measured and modeled). The library picks its own list-decoding parameter where the design fixes m = 16, and it rests on its own sources' bounds, not on the design's formula.

## Constants checked against the paper text

Read in this run: Ben-Sasson, Carmon, Ishai, Kopparty and Saraf, "Proximity Gaps for Reed–Solomon Codes", the full version of the FOCS 2020 paper, as ECCC report TR20-083, revision 3 of 2021-07-03 (BCIKS below). The FOCS 2020 proceedings text was not read, so whether it numbers its theorems the same way is not yet established. ePrint 2021/582 (ethSTARK), ePrint 2022/1216 (Haböck's FRI summary) and ePrint 2019/834 (Chiesa, Manohar and Spooner) could not be read from the sandbox: the ePrint server answered HTTP 403 to every request, so every check that rests on them stays not yet established, for that reason.

| Term | Source and its number, as read in this run | Constant on the design's page | Check | Label |
|---|---|---|---|---|
| A query, -log2(sqrt(rho)(1 + 1/(2m))) bits | BCIKS, Theorem 8.3 (batched FRI soundness): error epsilon_C + alpha^s with alpha = sqrt(rho)(1 + 1/2m), integer m at least 3, s query invocations; Lemma 8.2 defines alpha^(0)(rho, m) the same way | The same per query, m = 16 | Matches the paper text; m = 16 meets m at least 3, and the rate is a power of two as the theorem asks, 2^-3 and 2^-5 | modeled; the constant checked against the paper text |
| Batching M functions with the powers of one challenge, ((m + 1/2)^7 / (3 rho^(3/2))) n^2 (M - 1) / F | BCIKS, Theorem 7.2 (weighted correlated agreement over curves, version II), Eq. (7.1): S larger than the greater of ((1 + 1/2m)^7 m^7 / (3 rho^(3/2))) n^2 l and ((2m + 1) / sqrt(rho)) (M' n + 1) l, for a curve of degree l and weights of common denominator M' (the paper writes M; it is 1 for unweighted agreement) | (m + 1/2)^7 / (3 rho^(3/2)) times n^2 (M - 1) | Matches with l = M - 1, since (1 + 1/2m)^7 m^7 is (m + 1/2)^7; the paper bounds by the greater of its two arguments and the design adds them, which can only cost bits. Lemma 8.2 and Theorem 8.3 batch with independent coefficients (Eq. (8.3)) and bound that step by Eq. (8.8) through Theorem 7.4; using Theorem 7.2 there instead, for powers of one challenge, is the design's composition, and no theorem of BCIKS states it whole | modeled; the composition not yet established |
| Folding rounds, (2m + 1)(n + 1) R / (sqrt(rho) F) | BCIKS, Lemma 8.2 (batched FRI error bound): epsilon_C = (m + 1/2)^7 D^2 / (2 rho^(3/2) F) + ((2m + 1)(D + 1) / sqrt(rho)) times the sum of the folding arities over F, D the first domain's size | R rounds, at arity 2 | Lemma 8.2 states the sum of the arities, 2R at arity 2, where the design has R; R is the bound inside the proof of Lemma 8.2 (the sum of the arities less one) before the lemma loosens it, and that proof's rounds also add less than half of the Eq. (8.8) term, which the design leaves out. The last formula row takes both as Lemma 8.2 states them, and the sum does not move | modeled |
| Quantum: round-by-round bits halved, the digest's term a third of its bits | ePrint 2019/834: text not read in this run (HTTP 403); no theorem number for it is recorded in this repository | Each proof's bits halved, grinding at half; 279 / 3 bits for the digest | Not checked: the paper text could not be read | not yet established |
| The Johnson-regime form as ethSTARK and Haböck state it | ePrint 2021/582 and ePrint 2022/1216: text not read in this run (HTTP 403) | The two terms above | Not checked against these two; the same constants are found in BCIKS above | not yet established |
| The library's own proven terms | The pinned library's p3-security crate names its sources in its code; none of them was read in this run, and no theorem number is given for them here | Not on the design's page | Not checked | not yet established |

## Proof obligations

| Obligation | Status | Theorem and number, or what would close it | Label |
|---|---|---|---|
| Recursion with the hash inside the circuit | open | Would close it: a theorem, with its number and its loss, that a recursive STARK whose batch, root and shrink compute Poseidon2 in their own constraints keeps the soundness of its layers, classically and in the quantum random oracle model. Candidates to read in full, from the design: ePrint 2025/2166, and the arithmetized random oracle model of Chen, Chiesa, Gur, O'Connor and Spooner (Eurocrypt 2023), which is classical only. Neither was read in this run. | not yet established |
| Extraction over three layers | open | Would close it: a straight-line or otherwise composable knowledge extractor for each of the batch, root and shrink, with its loss, whose losses compose over the three layers into the bundle's bound, classically and in the quantum random oracle model. | not yet established |
| Round-by-round soundness of the Plonky3 IOP | open | Would close it: a proof that each term above is a round-by-round soundness error of the IOP the pinned Plonky3 runs (a batch STARK with LogUp lookups, preprocessed columns, hiding FRI, the batching challenge as powers of one value), so that the Fiat–Shamir and quantum conversions apply to it; BCIKS bounds the low-degree test only. | not yet established |
| Theorem numbers of the cited sources | open | Would close it: the theorem beside each term from the text of ePrint 2021/582, ePrint 2022/1216 and ePrint 2019/834, which the sandbox could not read (HTTP 403), and a theorem for the batching by powers of one challenge composed into Lemma 8.2's argument. BCIKS's are recorded above (Theorem 7.2, Lemma 8.2, Theorem 8.3, read in this run). | not yet established |
| A published analysis of Poseidon2 over BabyBear, width 24 | open | Would close it: a published cryptanalysis of exactly this instance with its round numbers: Poseidon2 over BabyBear at width 24 with 8 full rounds (4 at each end), 21 partial rounds and the S-box x^7, the default_babybear_poseidon2_24 of the pinned library (proofs/src/layers/poseidon2.rs), as a sponge of rate 15 and capacity 9 with a 9-element digest; the CICO and zero-test records of Poseidon1 over KoalaBear do not count. None is known to this repository. | not yet established |

## Obligations no theorem covers

Said plainly: no theorem read in this run, and none recorded in this repository, covers any of the five obligations above (not yet established).

- **Recursion in the quantum random oracle model** has no candidate at all: the one model named for the hash inside the circuit is classical only. Without such a theorem, no recursive design can claim a proven NIST Category 1 bound for the bundle, and the design passes that to the founder; that decision is not this page's (not yet established).
- **Extraction over three layers** has no candidate named anywhere in the repository.
- **The Plonky3 IOP as built.** No round-by-round analysis read here covers it. The batch STARK's LogUp terms are not among the terms of the design's sum at all (not yet established).
- **Batching by powers of one challenge.** BCIKS proves the pieces (Theorem 7.2 and Lemma 8.2) but no theorem of BCIKS states the whole (not yet established).
- **Poseidon2 over BabyBear, width 24.** No published analysis of this instance is known to this repository (not yet established).

## What is not yet established

- A proven whole-bundle bound: every sum on this page is the formula's or the estimator's, conditional on the five open obligations (not yet established).
- The theorem numbers of ePrint 2021/582, ePrint 2022/1216 and ePrint 2019/834 and their constants against the design's: the papers could not be read from the sandbox (not yet established).
- The library's quantum figure under the design's rule, which needs its split between query and grinding bits (not yet established).
- Whether the FOCS 2020 proceedings number BCIKS's theorems as the ECCC revision does (not yet established).

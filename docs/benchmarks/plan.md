# Browser proof benchmark plan

This document fixes what the browser proof benchmark measures, on what, and how
the result is read, before anything is measured. Its purpose is to make the
10-second target in [the outline](../ghost-outline.md) mean something. It is a
specification only. A later change implements the benchmark harness against it.

Everything taken from the outline is stated as fact. Where the outline is
silent and a choice had to be made, the choice is marked **Default** and
listed again in [Defaults chosen here](#defaults-chosen-here). A later decision
may change any of them. If one changes, this document is edited first and the
benchmark is run against the edited version.

## What the outline fixes

- The reveal is one private transaction shape: one commitment in, an optional
  public amount out, and one remainder commitment.
- The coin tree has room for about four billion commitments, which is a tree
  of depth 32.
- A reveal proves membership in a recent tree state, opens one commitment,
  publishes a one-time marker, creates the remainder commitment, proves
  conservation of value including the fee, and is bound to its purpose.
- Proofs are hash-based, need no trusted setup, and come from an existing
  open-source library. The starting pick is Plonky3.
- The proof is never wrapped inside an elliptic-curve proof.
- The library's zero-knowledge mode must be on in the shipped configuration.
- The hash inside the proof is also the tree hash. It is chosen from the
  measurements below: the most-studied candidate that meets the speed target.
- The target is 10 seconds or less to prove, in a browser, on named reference
  hardware. The proof system is revisited if it is not met.
- Proofs are made in the browser in a background worker. Nothing is downloaded
  as a proving key.
- The design aims at post-quantum security within a defined threat model.

## Reference hardware and browser

One machine, measured in two configurations: as it is, and with its CPU
throttled to stand in for a mid-range phone. No real phone is measured.

| | Mac Studio | Emulated mid-range phone |
|---|---|---|
| Machine | Apple Mac Studio, Apple M5 Max, 64 GB memory | The same Mac Studio |
| CPU | Not throttled | Chrome DevTools CPU throttling at 4x, Lighthouse's calibration for a mid-tier mobile device |
| Operating system | The latest macOS release on the day of the run, recorded | The same |
| Browser | Google Chrome stable; the full build string is recorded at run time | The same Chrome build |
| Label in every record, table and report | Mac Studio | Emulated mid-range phone, not a real device |

Why these:

- The Mac Studio is the reference machine the project owner has. It is a
  high-end machine, so a pass on it alone says little; that is why the target
  must also be met in the emulated phone configuration.
- The emulated phone is the same Chrome on the same Mac with DevTools CPU
  throttling at 4x, Lighthouse's calibration for a mid-tier mobile device. It
  is labelled "emulated mid-range phone, not a real device" wherever it
  appears. It slows the CPU only; it does not reproduce a phone's memory,
  thermal limits or browser build. The results check that the throttling
  reached the benchmark's worker: the emulated runs must be slower than the
  unthrottled ones by roughly the throttling factor.
- Chrome is the most used browser and has the best WebAssembly support,
  including threads and SIMD.
- **Default:** the Chrome build is the stable release on the day of the run,
  pinned for the whole run and recorded. The machine and the throttling factor
  are decisions made for this plan, not outline decisions. Replace the machine
  only with one in the same class, and say so in the results.

Rules for the machines:

- Chrome is pinned to one build for the whole run. Automatic updates are off
  while the benchmark runs, and the full build string is recorded.
- A fresh browser profile with no extensions is used. Only the benchmark tab is
  open, and it stays in the foreground with the display on.
- Mac Studio: no other applications running, display awake.
- Emulated phone: DevTools is open on the benchmark tab with CPU throttling set
  to 4x before the session starts; nothing else is throttled or changed.
- Thermal state is part of the result, not a nuisance. Each session starts
  after the machine has rested for at least 3 minutes, in both configurations,
  and the harness records every run's start time so heat build-up shows in the
  series.
- Sessions of the two configurations, the hash candidates and the blowups are
  interleaved (see [Method](#method)).

## The statement being proved

The statement is the coin reveal: the largest and most representative of the
outline's statements. It has the one fixed private shape, so every reveal costs
the same. A full reveal, a zero-amount claim and a fee that uses the whole
balance are the same statement with different witness values; they are not
separate statements.

This section fixes the size and cost shape of the statement. It does not
decide the lifecycle specification. Where the layout below (the exact fields,
their order and which values feed the marker) differs from what the lifecycle
specification later settles, the benchmark is re-run only if the number of hash
calls, the input lengths or the constraint counts change.

### Field and encoding

- **Default:** the proof field is BabyBear (prime 2^31 - 2^27 + 1), with a
  degree-5 extension field for challenges, in Plonky3's STARK stack with FRI
  as the polynomial commitment scheme.
- For candidate A, a digest is 8 field elements (about 248 bits). For
  candidate B, a digest is the full 256-bit Keccak output, held as 32 bytes
  (256 bits in the trace) and carried as 256 bits in the public inputs. It is
  never reduced into field elements, because that would lose bits. Every size
  below given in "elements" is for A; B uses 32 bytes for the same item.
- **Default:** an amount is 96 bits, held as four limbs of 24 bits, each limb
  range-checked. This holds about 7.9 x 10^10 whole GHOST at 18 decimals,
  well above the 21 million main emission plus any tail.
- Secrets and blinding values are 8 field elements each for A and 32 bytes
  each for B.

### Hash used inside the statement

- **Default (candidate A):** Poseidon2 over BabyBear, state width 24, rate 16,
  capacity 8, output the first 8 elements of the state. Plonky3 ships this
  permutation.
- **Default (candidate B):** Keccak-256, byte-oriented, using Plonky3's Keccak
  permutation circuit.
- Both are measured. The outline chooses the most-studied hash that meets the
  speed target, and Keccak is the more studied of the two. If B meets the
  target on both the Mac Studio and the emulated phone it is chosen over A;
  otherwise A is chosen if it meets the target. The decision itself is made
  after the measurements, not here.
- Every use of the hash carries its own explicit tag, as the outline requires.
  For A, a tag is placed in the capacity part of the state (one element for the
  use, one for the tree level where relevant). For B, a one-byte tag and, for
  tree nodes, a one-byte level are the first input bytes. The tags are:
  commitment, marker, tree node. (The note key is derived outside the
  statement.)
- A tree node is one permutation of the left and right child digests plus the
  tag and level. A longer input (a commitment, a marker) is absorbed 16
  elements at a time for A, and in 136-byte blocks for B.

### Public inputs

The verifier supplies or recomputes all of these. The proof is bound to them
because the library places the public values in the Fiat-Shamir transcript.

| Name | Size | Meaning |
|---|---|---|
| Tree root | 8 elements | A recent, widely shared state of the coin tree, taken from a block header |
| Marker | 8 elements | The one-time marker published by this reveal |
| Remainder commitment | 8 elements | The new commitment holding what is left |
| Public amount out | 4 limbs | The amount sent to the public destination (may be zero) |
| Fee | 4 limbs | The total fee (base fee plus the fixed private tip) as set by the chain's formula for this block. The chain checks it equals the formula; the user never chooses it |
| Binding digest | 8 elements | A tagged hash, computed by the verifier outside the proof, over the chain identifier, transaction type and version, destination address, public amount out, fee, remainder commitment and tree root |
| Type tag | 1 element | The commitment type and version; fixed to the coin type and the current version |

Purpose binding is the last two rows. The binding digest is a public value,
so a proof cannot be reused with a different destination, amount, chain or
transaction. The benchmark must include it as a real public input, because
public inputs cost transcript work and proof size.

### Witness (private inputs)

- Secret `s`, reveal secret `r`, blinding `b` of the commitment being opened.
- Secret `s'` and reveal secret `r'` of the remainder commitment. By default
  of the outline these equal `s` and `r`, but the statement must also allow
  new, independent values so that a claim to a new key is possible. The
  statement does not require them to be equal. The benchmark runs both cases;
  the cost is the same.
- The commitment's version and type, content fingerprint, rule field, and
  amount `v` (four limbs).
- A Merkle path: 32 sibling digests and 32 direction bits.
- Fresh blinding `b'` for the remainder commitment, and the remainder amount
  `v'` (four limbs).

### Constraints

1. **Opening.** The input commitment `C` equals the tagged hash of
   `(s, r, b, version and type, fingerprint, rule, v)`. For the benchmark
   layout this is 8 + 8 + 8 + 1 + 8 + 4 + 4 = 41 elements plus the tag:
   3 permutations for A, 2 for B.
2. **Membership.** Starting from `C` as the leaf, apply the tagged node hash
   32 times along the path, selecting left or right by the direction bits.
   The result must equal the public tree root: 32 permutations for A and for B.
   Direction bits are range-checked to be 0 or 1.
3. **Marker.** The public marker equals the tagged hash of `(r, b)`: 16
   elements for A (1 permutation), 65 bytes for B (1 permutation). Which
   values feed the marker is the lifecycle specification's decision; what is
   fixed here is that the marker costs one short hash and is different for the
   remainder commitment, which has its own blinding (and, by default, the same `s` and `r`).
4. **Remainder commitment.** The public remainder commitment equals the tagged
   hash of `(s', r', b', version and type, fingerprint, rule, v')`. The
   version and type, fingerprint and rule are constrained to equal those of
   the input. `s'` and `r'` are free witness values: equal to `s` and `r` when
   the same Phantom Key keeps control of the remainder (the outline's default),
   and new values for a claim to a new key. 3 permutations for A,
   2 for B.
5. **Conservation.** `v = out + v' + fee`, limb by limb with carries, with all
   amounts range-checked to 96 bits. Because `v'` cannot be negative, the fee
   plus the amount out cannot exceed the balance.
6. **Type.** The type tag is the coin type, so a data commitment can never
   satisfy this statement.

Total hash cost: 39 Poseidon2 permutations for A, and 37 Keccak permutations
for B. The remaining constraints are small (range checks, limb arithmetic,
bit selection). The trace is therefore short, but the zero-knowledge mode
raises the minimum trace height and adds random rows, so the benchmark
measures the real configuration instead of estimating from the constraint
counts.

### Witness data for the runs

- The tree is conceptual: 2^32 leaves are never built. The harness generates
  a path with pseudo-random sibling digests, a random leaf position, and the
  consistent root. Sibling values and direction bits do not change the cost but
  must differ between runs so nothing degenerate (such as all-empty subtrees)
  is measured. Seeds are recorded.
- The input amount, the amount out and the fee are fixed for the primary
  measurement: input 1,000.000000000000000000 GHOST, amount out
  250.000000000000000000 GHOST, fee 0.001000000000000000 GHOST, remainder the
  rest. These are arbitrary but realistic and use the full width of the
  limbs.
- Zero-knowledge randomness (blinding rows, salts) is freshly drawn from the
  browser's secure random source on every run. It is never seeded.

## Security level and zero-knowledge mode

- **Default target:** 128 bits of security for soundness, for the complete
  configuration actually used, counted under the library's conjectured
  security estimate.
- The estimate comes from the library's own security analysis (the security
  estimator that ships with the pinned revision), applied to the actual
  parameters, and must account for all of: the FRI queries and folding, the
  grinding bits, the opening batching, the composition of the constraints (the
  number and degree of the constraints and the size of the challenge field),
  and the collision resistance of the commitment hash.
- If the pinned revision ships no security estimator, the harness's own
  estimator is used instead, with the same 128-bit conjectured floor. It is
  documented in the harness code and computes, from the actual parameters, both
  the conjectured (ethSTARK-style) and the best proven FRI soundness, including
  the grinding, the opening batching, the constraint composition, the size of
  the challenge field and the collision resistance of the commitment hash.
  Results name which estimator produced their figures. (The revision pinned at
  the time of writing ships one, `p3-security`, used through
  `p3-uni-stark`'s security parameters, so the harness uses it.)
- Either way, a configuration whose total conjectured estimate is below 128
  bits is rejected before any timing is recorded. The simple rule of counting
  each query of a code of rate 2^-k as k bits is only a starting point for
  choosing the number of queries; it is not accepted as evidence of the level.
- The commitment hash counts at its collision resistance. For candidate A the
  proof's own Merkle commitments use digests of 9 elements (about 279 bits),
  because 8 elements give only about 124 bits of collision resistance;
  Keccak-256 gives 128. The statement's 8-element digests for candidate A (the
  tree, the commitments and the marker) also give only about 124 bits of
  collision resistance; that is recorded for the threat-model work and does not
  change the cost shape.
- A configuration that cannot be built in zero-knowledge mode is reported as
  not buildable and is not measured. In particular, zero-knowledge mode adds one
  to the degree of the quotient, so the constraint degree must be at most the
  blowup: a circuit of degree 3 cannot run at a blowup of 2^1.
- Grinding is allowed up to 16 bits. The harness computes the number of
  queries from the estimate and does not use a hard-coded count. The extension
  degree is chosen so that the challenge field is large enough for the target
  (degree 5 above is the default).
- The primary run uses a blowup of 2^1 (rate 1/2). The harness also runs
  blowups of 2^2 and 2^3 as a sweep, because a higher blowup needs fewer
  queries (smaller proof, slower prover) and the best trade is a result, not an
  assumption.
- The result also records, next to the conjectured figure, the figure under
  the best proven bound for the same parameters, so a reader can see the gap.
  The target is the conjectured figure, and this is stated plainly wherever the
  number is quoted.
- Post-quantum: the design aims at security within the defined threat model
  in the outline. This benchmark does not prove that. It records the digest
  size, hash and field so the threat-model work can be done against exactly
  what was measured. The benchmark never uses a pairing or elliptic-curve
  step, and its proof is not wrapped.
- **Zero-knowledge mode is on for every measured configuration.** Plonky3 does
  this with a hiding polynomial commitment scheme paired with a hiding Merkle
  commitment; both must be selected, and the library does not check at compile
  time that they are. The harness therefore must:
  1. build the configuration through one function used by both the prover and
     the verifier, which uses the hiding commitment scheme and the hiding Merkle
     commitment, and fails to start if the library reports that the
     configuration is not zero-knowledge;
  2. print the library revision, the configuration name and the zero-knowledge
     flag into every result record;
  3. pass a check that two proofs of the same statement and witness, made with
     different randomness, differ in their commitments and that both verify;
  4. pass a check that the trace height used is at or above the library's
     required minimum for zero-knowledge for the number of openings and queries
     in use, and record the actual height.
- Measurements made without zero-knowledge mode are labelled "diagnostic, not
  zero-knowledge" and never count towards the target.
- The library is pinned to one exact revision for the benchmark, and the
  revision is recorded. Known problems in the zero-knowledge code of any
  revision (for instance a locking fault that can hang the prover, or a trace
  that is too short to hide its contents) are checked against the revision
  chosen before it is pinned.

## What is recorded

For every proof, in the browser, on the Mac Studio and on the emulated phone:

| Quantity | Definition |
|---|---|
| Proving time | Wall-clock milliseconds, taken inside the worker with `performance.now()`, from the call that receives the witness inputs to the return of the finished proof bytes. It includes witness and trace generation, the zero-knowledge randomness, FRI commitment and queries, and grinding. It excludes page load, downloading and compiling the WebAssembly module, and moving the result to the page. These are recorded separately (below) |
| Module start-up time | Milliseconds to fetch, compile and instantiate the module in the worker, recorded for the cold run |
| Peak memory | The high-water mark of the WebAssembly linear memory in the worker (pages grown multiplied by 64 KiB), read by the harness after each proof. Also recorded, for both the Mac Studio and the emulated phone: the browser's own process-level peak, the macOS footprint of the renderer process that runs the benchmark tab (`footprint` on that process, the peak kept) |
| Proof size | Bytes of the proof in the library's standard serde encoding with the postcard format, public inputs excluded. Also recorded: the public inputs' size and the total |
| Verification time | Wall-clock milliseconds to verify the proof, in the same worker in the same configuration, from receiving the proof and public inputs to a yes or no. Also recorded once natively on the Mac Studio, because the chain verifies natively |
| Outcome | Whether the run completed, was killed by the browser, or ran out of memory |

Also recorded on every result:

- Device configuration (Mac Studio, or emulated mid-range phone with the CPU
  throttling factor), operating system, Chrome build, number of logical cores
  reported by the browser, whether threads and SIMD were available and used.
- Library revision, Rust compiler version, build flags, the hash candidate,
  the blowup, the number of queries, grinding bits, the extension degree, the
  trace height and width, the security figures (conjectured and proven) and
  the estimator that produced them.
- Start time of the run, so thermal drift is visible, and the CPU pressure
  state the browser reports, where available.

### Builds

- **Primary build:** WebAssembly with SIMD and threads (shared memory, with
  the page served cross-origin isolated). Our own web application is able to
  ship that, so this is what a user gets.
- **Fallback build:** WebAssembly, single thread, SIMD on. Measured as well,
  because the application must still work where threads are unavailable.
- **Native reference:** the same prover built natively on the Mac Studio, for
  context only. It does not count towards the target.

## Method

1. **Correctness before speed.** Before any timing counts, in every
   configuration and build, the harness verifies that: a good proof verifies;
   the proof fails when any public input is changed (root, marker, remainder commitment,
   amount, fee, binding digest); a witness that breaks conservation (value out
   exceeds value in, or the sum is off by one at a limb boundary) does not
   produce a proof that verifies; and a witness with a wrong Merkle path is
   rejected. A speed number from a build that fails any of these is discarded.
2. **Sessions.** Five sessions on the Mac Studio and five on the emulated
   phone, per build, per hash candidate, per blowup. A session is a fresh
   browser tab opened on the page, so every session has a real cold start.
3. **Runs per session.** One cold run (the first proof after the tab opens),
   then ten warm runs back to back in the same worker. 55 proofs per
   configuration.
4. **Rest.** At least 3 minutes between sessions, in both configurations, so
   one session's heat does not carry into the next. The back-to-back warm runs
   inside a session are kept as they are, because a user who makes several
   reveals in a row meets the same heat.
5. **Order.** Configurations are interleaved rather than run one after another,
   so drift in room temperature does not favour one. This includes the Mac
   Studio and emulated phone sessions.
6. **Primary configuration.** Hash candidate A, blowup 2^1, primary build. The
   others are the sweep and are reported beside it.

## Reading the result

For every configuration the report gives, for the Mac Studio and for the
emulated phone:

- Cold proving time: the median and the slowest of the five cold runs.
- Warm proving time: the median, the 90th percentile, and the slowest of the
  fifty warm runs.
- Peak memory, proof size and verification time: the median and the largest.
- Whether any run failed.

**Default:** the 10-second target is met for a configuration on the Mac Studio,
or on the emulated phone, when **both** the median warm proving time **and** the
slowest cold proving time are 10 seconds or less, and no run failed. The target
applies to proving time as defined above and is met only when it is met on both
the Mac Studio and the emulated phone. The Mac Studio is a high-end machine, so
a pass there alone says little: the Mac Studio meeting it while the emulated
phone does not is reported as "met on the Mac Studio only", not as a pass. A
configuration that has zero-knowledge mode off does not count, and neither does
the native reference.

The report then states, in plain words, which hash candidates meet the target,
which one the outline's rule picks, and the proof size and verification time
that result in. It ends with one verdict: met, met on the Mac Studio only, or
not met. If no candidate meets the target on both the Mac Studio and the
emulated phone, the report says so, and the proof system is revisited as the
outline requires. Results from the emulated phone are always labelled
"emulated mid-range phone, not a real device".

## Where the results go

- The harness and the raw results (one JSON record per proof, with every field
  above) are committed together with a short written report in this folder.
  Raw results are committed so anyone can recompute the summary.
- **Default:** the harness lives under `benchmarks/` at the repository root and
  the results under `docs/benchmarks/results/`. The harness has one command that
  builds, runs the correctness checks, and prints the summary.
- Every result file names the commit of this repository and the library
  revision it was produced from.

## Defaults chosen here

The outline leaves these open. Each is a default chosen for this plan that a
later decision may change.

1. Reference machine: the project owner's Mac Studio (Apple M5 Max, 64 GB).
2. Phone class: the same Chrome on the same Mac Studio with DevTools CPU
   throttling at 4x (Lighthouse's mid-tier mobile calibration), labelled
   everywhere as "emulated mid-range phone, not a real device".
3. Browser: Google Chrome stable, the build recorded at run time and pinned for
   the whole run.
4. Field: BabyBear with a degree-5 extension; digests of 8 elements.
5. Hash: Poseidon2 (width 24) as candidate A and Keccak-256 as candidate B;
   both measured, chosen by the outline's rule.
6. Amounts: 96 bits in four 24-bit limbs.
7. Security: 128 bits conjectured, up to 16 grinding bits, blowup 2^1 as the
   primary and 2^2 and 2^3 as a sweep; the proven figure reported beside it.
8. Benchmark layout of the commitment (41 elements plus tag) and which values
   feed the marker, used only to fix the cost shape.
9. Statistics: five sessions, one cold and ten warm runs each; the target is
   judged on the median warm time and the slowest cold time.
10. Builds: threaded and single-thread WebAssembly, both with SIMD.
11. Machine rules: a fresh browser profile, a pinned Chrome build, at least 3
    minutes' rest between sessions, and interleaved configurations, the same for
    the Mac Studio and the emulated phone.
12. Process-level memory: the macOS footprint of the renderer process, in both
    configurations.
13. Security estimator: the library's own; if the pinned revision ships none,
    the harness's documented estimator, with the same 128-bit conjectured floor.
14. Where the harness and results live in the repository.

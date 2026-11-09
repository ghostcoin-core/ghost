# Stage 2 design: restore, aggregation, proven security and public signatures at the scale target

This page is the design of the second stage of the scale work. The first stage's verdict (stage1-verdict.md) found the target not feasible as designed and named the limits: wallet restore volume first, then the aggregation cost, the whole-bundle proven security bound and the size of public signatures in a block. This page picks one design for each of those limits and judges it against the same ceilings of workload.md, which do not change here, under the rules of designs.md. The target is that of workload.md: 1 million transactions a day in total, the private path sized for all of them being private reveals and the public path for all of them being public, about 350 of each per 30 s block (modeled: the founder's target of 2026-11-08, which replaced the earlier 10 million of each kind). The aggregation figures are also given at 10,000 and 100,000 a day, for the quieter chain before the target is reached (modeled). Nothing here is built; the build tickets are listed at the end, and the independent outside review that mainnet needs reviews the code and parameters they produce.

Every figure carries one of the labels of workload.md: **measured** (actually run, the machine named), **modeled** (a formula or stated inputs) or **not yet established** (with what would produce it). Nothing on this page was run: the only measured inputs are the recursion proxy records of docs/scale/recursion-proxy.jsonl, the Poseidon2 permutation timed in docs/scale/layers-results.md, and the timings quoted from docs/benchmarks/reveal-parameters.md and docs/research/recovery-cost.md, and every figure built on them is modeled. The arithmetic is benchmarks/scale/stage2.py, whose `INPUTS` dict at the top holds every input with its source; benchmarks/tests/test_scale_stage2.py checks that every table row on this page is exactly what the model prints, and that each ceiling comparison turns when its input crosses the ceiling.

**Result.** Each limit has a chosen design whose modeled figures meet the ceilings it is judged against at 1 million a day, with three exceptions stated plainly and passed to the founder below (all modeled): the 0.3 s merge budget of workload.md holds only if a Poseidon2 permutation costs at most 91 ns, where the measured cost is 897.1 ns (measured in layers-results.md), though the fleet and the cost ceilings it stood for are met; under the fixed-shape keys the cost ceiling of 0.1 US cents a reveal is met at 1 million a day and missed at 10,000 and 100,000 a day, where each aggregator proves padded layers for few reveals; and the whole-bundle bound reaches 138.59 classical and 69.82 quantum bits only as a modeled sum, proven once the proof obligations listed under its section are discharged (not yet established). The network runs on 26 aggregator machines at 1 million a day, 37 with the 50 percent spare, within the 40 workload.md proposes (modeled). Every ceiling of the reference phone is still a proposal (not yet established in workload.md).

| Limit the first stage named | Chosen design | Against its ceilings (all modeled) | Label |
|---|---|---|---|
| Wallet restore volume | Private lookups by key-derived lookup tags, by single-server lattice PIR, checked against header-committed indexed trees; a work-sampled proof of the header chain | Full restore 81.8 MB at one year and 138.5 MB at five against a proposed 500 MB; 264 s and 462 s against a proposed 10 minutes; keeping up within 50 MB a month at five checks a month at one year, three at five; full-node growth 241.4 GB a year against a proposed 2 TB, met | modeled; every ceiling a proposal, not yet established |
| Aggregation cost | Architecture (c) of security.md, Poseidon2 leaves and layers, with wide layers under fixed-shape keys: batches of 8 reveals, a root over up to 29 batches, a shrink | 0.0870 US cents a reveal against 0.1; p99 delay 237.4 s against 5 minutes; 26 machines across the network against the proposed 40, 37 with the spare; every layer's prover peak at most 58.1 GiB against 128 GiB | modeled, at the measured 897.1 ns Poseidon2 permutation |
| Whole-bundle proven security bound | A 279-bit Poseidon2 digest, a degree-8 extension of BabyBear, 96 queries in the Johnson regime, three recursive layers | 138.59 classical and 69.82 quantum bits against 128 and 64, the proven extension-field terms included | modeled; proven only with the obligations below, not yet established |
| Public signature size | Signatures leave the block: ML-DSA-44 verifications proven in chunks and folded by the same layers into one public root a block | 3,595,394 bytes a block before bodies against the 10,485,760-byte cap, 6,890,366 bytes of headroom; at 1 million a day raw signatures would fit too, 2,083 a block | modeled |

## Wallet restore volume

**Chosen:** private lookups by key-derived lookup tags, served by single-server lattice PIR over databases any full node can build from public data, every answer checked against header-committed indexed trees, with a work-sampled proof of the header chain in place of every header from genesis (all figures below modeled).

Why this one. The first stage found that volume, not processing, sets the cost, and that no scan of the whole chain fits: the best design it considered downloads 249.5 GB at one year of the earlier target of 10 million a day against a proposed 500 MB (modeled in phone-results.md), and a tenth of that volume is still far above it. A wallet that knows what to ask for and asks privately downloads in proportion to its own coins and the logarithm of the chain, not to the chain. It can know: a key's commitments are numbered 0, 1, 2 and on with no gaps, each a remainder of the one before (spec 01, section 8), so the wallet can compute an identifier for each of them from the digits before it asks (modeled: no figure beyond the counts below). What is left to hide is which record is fetched, which PIR does; what is left to check is that every answer belongs to the canonical chain, which header roots do; and the header chain itself is checked by sampling, so the phone no longer downloads 611.8 MB of headers a year of chain (modeled in phone-results.md).

### What changes on the chain

Each of these is a format change, and so a founder decision (listed at the end). No figure on this page depends on a change that is not listed here.

- **Lookup tag.** Every new leaf (a commit, a remainder, a claim's new commitment) carries a 16-byte lookup tag, the first 16 bytes of `S("ghost/note-lookup/v1", k_note, i as 8 bytes)` for its commitment number `i`, written by whoever writes the note, as the note's 3-byte nonce tag is today (modeled: 16 bytes a leaf). Consensus cannot check a tag and does not try. It replaces the bucket path of spec 01, section 8, whose reads of tag prefixes would let an endpoint that logged them link a later reveal's new leaf, whose tag falls in a bucket it saw requested, to the restoring wallet (not yet established as a measured attack; the reason PIR is chosen here).
- **Lookup index.** For each tree type, an append-only indexed Keccak-256 tree of depth 40 over (tag, position) pairs, the construction of the data marker-set tree of spec 05, section 6, whose root after the block's last transaction is a new header field (`coinLookupRoot`, `dataLookupRoot`). It gives a membership or an absence witness for any tag against a header (modeled: 47 bytes a leaf).
- **Coin spent-marker set tree.** The same construction over the coin spent markers, root `coinMarkerRoot`, which spec 05 has today only for data. Each leaf also records the position of the leaf the same reveal appended (its remainder, or a claim's new commitment), or none, so a spent marker leads to the next commitment with a witness and no request names it (modeled: 74 bytes a leaf). The data set needs no such field: data commitments have no remainder in version one (spec 04, question 3; no figure).
- **Header MMR.** Every header commits to a Merkle mountain range over all earlier headers and their cumulative work, as FlyClient does (Bünz, Kiffer, Luu and Zamani, IEEE S&P 2020), so a sampled header is checked against the tip with one path (modeled: 48 bytes a node, a 32-byte hash and 16 bytes of work).
- **Block lookup digest.** Every header commits to the ordered lookup tags and spent markers of its block, so the blocks after a PIR snapshot are read in bulk and checked against their headers (modeled: 350 times 48 bytes a block).

The header grows by these five 32-byte fields, from 582 to 742 bytes (modeled).

### What a wallet does

1. Derive the note key and the lookup tags from the digits alone (spec 01, section 7); nothing else is needed or stored. <!-- no-figure -->
2. Check the header chain, beside everything else: the last 64 headers in full, and headers sampled from genesis by cumulative work with the wallet's own randomness, each with its RandomX seal, its key block and an MMR path to the tip (modeled: 599 samples at one year of chain, 702 at five). The sampling density over the chain's work `x` is `1 / ((1 - x) ln(1/delta))` on `[0, 1 - delta]`, `delta` the share of the 64-header tail; against an attacker whose valid work after its fork is at most a ratio `c` of the honest work, every fork point leaves an invalid stretch that one sample hits with probability at least `ln(1/c) / ln(1/delta)` (modeled: the FlyClient argument, derived for this page; the bound for Ghost's difficulty rule is not yet established).
3. Probe the lookup hints by PIR: the tag of number zero, then numbers 1, 2, 4 and on, doubling until a tag is absent, then halving between the last present and the first absent; every restore makes exactly 22 probes, padded, which covers up to 1,023 hops (modeled). A probe returns at most a position: the hint table is not authenticated, and nothing is believed from it until the checks of step 5.
4. Fetch, for the highest number found, by PIR from the snapshot: its note; its coin-tree witness (64 leaves and a page's witness records); the hint, the leaf and the witness of its spent marker in the coin marker-set tree; and the leaf and witness of the lookup index, which proves "no first commitment" when nothing was found and is padding otherwise; plus one query to the hint overflow table for the bucket of the first tag (modeled: 31 queries in all, the same for every restore). The level-20 nodes of each tree and the blocks after the snapshot are read in bulk (modeled: 350 tags and markers a block for at most 20 blocks).
5. Check everything before use: the note decrypts under the note key with the leaf as associated data and recomputes the leaf (spec 01, section 8, step 4); the coin witness takes the leaf at its position to the snapshot header's coin root; the marker's absence witness (a low leaf whose value and next value bracket the marker) or membership witness takes it to the snapshot's `coinMarkerRoot`; the snapshot header is one of the 64 tail headers on the wallet's checked chain; and the bulk lists of the later blocks match each block's lookup digest (modeled: no figure). A missing or wrong item fails one of these checks and is rejected, never guessed.
6. Decide: an unspent marker, absent from the later blocks, makes that commitment the current one. A spent marker leads, through its leaf's recorded position, to the next leaf; a note there that decrypts under the key is the next number and the wallet continues from it in a second session, and one that does not means the value was claimed into another key or fully revealed. Nothing found, with the lookup index's absence witness, means the key never made a commitment by the snapshot (modeled: no figure).

Privacy. Every query is a single-server PIR query, which hides which record is fetched under the lattice assumption of the chosen scheme (Learning With Errors or its ring form, quantum-safe; the scheme and its parameters at 128 classical bits and NIST Category 1 are not yet established), so no endpoint learns a tag, a position, a marker or a note (designs.md, wallet restore requirement 3). Every restore makes the same 31 queries to the same databases in the same order, padded whatever the key's coins, and reads the same bulk data (modeled; tested in the model, which gives the same queries for a key of one hop and of 500). Two restores of one key make fresh, unrelated queries, so an endpoint cannot intersect them, and a later reveal's public tag or marker matches nothing it logged, because it logged no index: this closes the linking that prefix buckets allow (not yet established beyond the PIR scheme's own proof). The header samples depend only on the wallet's randomness. What an endpoint still sees: that a restore or a check happened, when, and from which network address; a wallet runs its status checks on its own schedule, never just before a spend, and sends reveals by another path (no figure). A second session after a stale hint shows that the key's coin moved since the snapshot, at most 20 blocks before (modeled).

Spent status follows the canonical chain exactly (designs.md, rule 2). The snapshot's roots are those of a header on the wallet's checked chain, and the later blocks come from the same chain; a reorganisation that removes the snapshot header removes its roots, the server rebuilds from the new canonical chain, and the wallet runs again (no figure). A spend only on a disconnected block is absent from every root of the new chain, so the coin shows unspent again; a spend kept on the new chain is in its marker set (no figure).

Denial of service. The hint tables can be wrong only to the wallet's cost in queries, never its result, because nothing in them is believed before step 5 (no figure). An attacker who copies a key's public tag into commits pays one commit's gas and burned amount for each copy (spec 03), and gains at most a second session for the victim: copies made after the victim's leaf sort after it, and a copy that front-runs the victim's pending reveal from the pool leads to a note that does not decrypt, after which the marker-set witness of the previous number leads to the right leaf (modeled: no figure). Filling a bucket past its 16 slots moves the extra entries to the overflow table, which every restore queries for the bucket of its first tag; its size is set by what the attacker spends (modeled: an input of 1 GB, not yet established). A spent marker cannot be aimed at before it is spent, because an unspent marker is known only to its holder (spec 01, section 3; no figure). PIR server work a query is the whole database read once, a cost a restore server bounds per client and in total like any request budget (modeled below; the budgets themselves are not yet established).

What a full node and a restore server keep. Every full node keeps the three new indexed trees and the header MMR, because the header roots are consensus fields (modeled below). A restore server is a full node that also keeps the two hint tables and runs the PIR engine; it needs no key or permission from anyone and builds everything from public chain data, so restore works from any honest full node that chooses to serve it, and a wallet can use any of them (designs.md, wallet restore requirement 6; the hint tables are modeled below). It rebuilds its snapshot every 20 blocks (modeled: an input; the PIR scheme's preprocessing cost per rebuild is not yet established).

### Figures against the reference phone

Inputs (all from the repository or stated here; labels as given): a phone link of 5 MB a second and a phone four times slower than the build machine, the assumptions of recovery-cost.md (not yet established on a phone); a RandomX hash every 128 ms over eight threads and a 2.08 s cache build per key block, those of recovery-cost.md section 3.3, measured on the build machine, times four (not yet established on a phone); PIR communication of 2.5 MB a query and server reading at 12.1 GB a second a core, the YPIR figures recovery-cost.md quotes for a 32 GB database (not yet established for these records), communication taken to grow with the square root of the database above that size and never to fall below it (modeled: an assumption); a restore server of 32 cores, the aggregator machine of workload.md (not yet established); 52 hops a year, the assumption of phone-results.md (not yet established). The restore time takes the header check beside the download and the server's work, because neither needs the other's result until the last check (modeled).

| Figure (all modeled) | One year of chain | Five years of chain | Ceiling (workload.md) |
|---|---|---|---|
| Header proof: sampled headers, tail headers, RandomX keys (modeled) | 599, 64, 86 | 702, 64, 175 | none |
| Header proof bytes (modeled) | 1.2 MB | 1.7 MB | none |
| PIR queries and their bytes (modeled) | 31 queries, 80.2 MB | 31 queries, 136.3 MB | none |
| Bulk tree tops and the blocks after the snapshot (modeled) | 0.4 MB | 0.5 MB | none |
| Full-restore download (modeled) | 81.8 MB, met | 138.5 MB, met | proposed 500 MB (not yet established) |
| Restore time: the header check beside the download and the server's work (modeled) | 264 s (header 264 s; download 16 s and server 2 s), met | 462 s (header 462 s; download 28 s and server 9 s), met | proposed 10 minutes (not yet established) |
| Server work a restore (modeled) | 55 core-seconds | 273 core-seconds | none |
| Phone memory at its peak (modeled) | 257.9 MiB, met | 258.1 MiB, met | proposed 1 GiB (not yet established) |
| Phone storage (modeled) | 2.0 MB, met | 2.2 MB, met | proposed 200 MB (not yet established) |
| Keeping up, 2 status checks a month (modeled) | 17.0 MB (8.5 MB a check), met | 26.3 MB (13.1 MB a check), met | proposed 50 MB a month (not yet established) |
| Most status checks a month within 50 MB (modeled) | 5 | 3 | none |

Against the first stage (both modeled): the full-restore download falls from 249.5 GB at one year with buckets, at the earlier target of 10 million a day, to 81.8 MB at 1 million a day, and the restore time from 15.2 hours to 264 s. Keeping up is no longer a download of the chain: a wallet's witness against an old root stays valid, because historical roots stay valid forever (spec 05, section 5), so keeping up is only learning whether another holder of the digits spent the coin, one authenticated check at a time, with the headers since the last check sampled the same way (modeled: about 8.5 MB a check at one year). The ceiling of 50 MB a month then fixes how often a wallet may check, which is a decision for the founder: five checks a month at one year of chain, three at five (modeled). The restore time is dominated by the RandomX cache builds of the sampled headers' key blocks: 86 caches at one year and 175 at five (modeled), single-threaded Argon2d at the assumed 2.08 s each (not yet established on a phone).

Header sampling against a stronger attacker. The samples are set for an attacker whose valid work after its fork is at most half the honest work, about a third of the hashrate before luck (modeled: the input). Against a stronger attacker the same samples give less (all modeled):

| Attacker's valid work against the honest chain's (all modeled) | Bits a sample, one year | Assurance of the restore's samples, one year |
|---|---|---|
| 0.25 (modeled) | 0.2223 | 133.2 bits |
| 0.50 (modeled) | 0.1069 | 64.0 bits |
| 0.75 (modeled) | 0.0434 | 26.0 bits |
| 0.90 (modeled) | 0.0157 | 9.4 bits |

A wallet that checks every header resists any attacker below half the hashrate; a sampling wallet resists one below about a third with 64 bits of assurance a restore, and less above it (modeled). The threat model already records that a majority of Ghost's hashrate can be rented for about a dollar an hour at launch (threat-model.md, section 9; an estimate there, not yet established), and a majority defeats a full header check too. Whether a phone may sample, how many bits it must reach and whether a full check stays offered for large amounts are founder decisions (listed below).

Growth of a full node, and what a restore server keeps beyond it:

| Full-node growth a year (all modeled) | Bytes |
|---|---|
| Leaves, notes and spent markers, as the first stage counted (modeled) | 162.1 GB |
| Lookup tags (modeled) | 5.8 GB |
| Lookup index tree (modeled) | 34.7 GB |
| Coin spent-marker set tree (modeled) | 38.7 GB |
| Header MMR (modeled) | 0.1 GB |
| Total, against the proposed 2 TB a year (modeled) | 241.4 GB, met |
| A restore server's hint tables at one year of chain, beyond a full node (modeled) | 40.3 GB |

The trees are counted with every inner node stored (modeled: 64 bytes a leaf), the most a node keeps; receipts are left out, as the first stage left them out (spec 05, section 12; not yet established). The 4 TB disk of the ordinary full node holds about 16.6 years of this growth (modeled: 4 TB over 241.4 GB a year).

Full-node growth meets the proposed 2 TB a year with room (modeled): the 380-byte note of spec 10, section 3.2 makes the first stage's own count of leaves, notes and markers 162.1 GB a year, and this design's lookup tags, trees and header MMR add 79.3 GB (all modeled). At the 156-byte note the total would be 159.6 GB (modeled). The ceiling is a proposal of workload.md (not yet established).

### What is not yet established for restore

- The PIR scheme, its parameters at 128 classical bits and NIST Category 1, and its real communication, server time and preprocessing for these databases at the target's size (not yet established: a PIR server built from these databases and timed on named hardware; the 2.5 MB and 12.1 GB a second are published figures for another database).
- The phone's RandomX hash and cache build (not yet established: the restore timed on named mid-range phones; the 128 ms and 2.08 s are build-machine measurements times an assumed four).
- The sampling bound for Ghost's difficulty rule, the attacker ratio a phone must assume and the sample count it must reach (not yet established: a written proof from the FlyClient analysis for Ghost's difficulty adjustment, and a founder decision).
- The PIR client's memory and time on the phone (not yet established; the phone memory above counts one RandomX cache, the bulk data and 2 MB).
- A restore and a keep-up check timed on a real phone against a chain of the target size (not yet established).

## Aggregation cost

**Chosen:** architecture (c) of security.md, Poseidon2 leaves and Poseidon2 layers, with wide layers in place of a two-to-one tree, under fixed-shape verifier keys: each batch proof verifies up to 8 reveal proofs, one root proof verifies up to 29 of an aggregator's batches (232 reveals), and a shrink layer at blowup 2^5 makes the proof the block carries; a layer with empty slots is proven padded under the same key (all figures below modeled).

Why this one. The first stage's own lower bounds rule out the other two architectures against the fleet of workload.md, whatever the machine price: 40 machines in a 30 s block have 3.4286 machine-seconds for each of 350 reveals (modeled), while architecture (a) needs at least 21.6585 machine-seconds a reveal and architecture (b)'s conversion layer alone at least 7.2194 (modeled in throughput.md, lower bounds from the measured (proxy) records). Both re-prove Keccak-f\[1600\] inside a trace, 13,070 permutations a reveal proof at 24 rows of 2,633 columns each (modeled in recursion.md). Architecture (c) verifies a Poseidon2 proof inside a Poseidon2 trace, one row of a width-24 Poseidon2 AIR a permutation (modeled: 451 columns, read from the layout of the pinned library's Poseidon2 AIR; not yet established until counted from the crate), so the hashing that dominated (a) shrinks by two orders of magnitude and the verifier's arithmetic becomes a comparable part.

The design (every parameter an input of the model; no figure on this list beyond those labelled):

- **Leaf.** The reveal statement is unchanged, including its own Keccak-256 hashes of commitments and markers (spec 01). Only its proof's commitments and transcript move to Poseidon2 over BabyBear, width 24, sponge rate 15 and capacity 9, a 9-element digest (modeled: 279 bits), with challenges from the degree-8 extension of BabyBear, 96 queries at blowup 2^3, grinding 16 and 16 bits (modeled: the security section's parameters).
- **Batch.** One proof verifies up to 8 reveal proofs in its constraints and exposes a running digest of their ordered contents and their count (modeled: a 600-column trace of 2^19 rows, its size fixed by the key whatever it holds).
- **Root.** One proof verifies up to 29 of an aggregator's batches of the block (modeled: the largest aggregator's 141 reveals fill 18; at the 50 percent burst spare its 211 fill 27; a 600-column trace of 2^20 rows).
- **Shrink.** One proof verifies the root at blowup 2^5 with 56 queries, so the proof the block carries is short (modeled: 859,736 bytes, under the 1,310,720-byte proof field of spec 07).
- **Binding.** Each layer fixes the digest of its children's verifier key in a preprocessed column, and absorbs into its transcript, before any challenge, a tag naming the layer kind, its index, the protocol and statement versions, the chain identifier and that digest; the node builds the root's public inputs itself from the block's ordered reveals, the count, the chain and the versions (security.md, "Root and the node"; designs.md, private bundle requirement 1; no figure). Plonky3-recursion is not used and is not evidence for any of this. <!-- no-figure -->
- **Independent operation.** Anyone can batch from the public reveals with no key of another aggregator (designs.md, rule 6). A reveal no aggregator takes is still included: any party, or its own wallet's server, can make a bundle of one, and the direct path of one reveal verified natively stays, which needs a proof field of at least 2,330,908 bytes for a reveal proof at 96 queries (modeled: above today's 1,310,720, so a new transaction version of spec 07, a founder decision).
- **No elliptic-curve wrap anywhere** (designs.md, private bundle requirement 13; no figure). <!-- no-figure -->

How the seconds are modeled. The cells a verifier circuit spends on one child proof are its Poseidon2 permutations (every compression and leaf hash of a fixed-shape verifier and the transcript of its out-of-domain values) at 451 cells each, plus its arithmetic: the DEEP combination of every opened function at every query at 17 cells a term, the folding at 200 cells a round a query, and the child's constraints at the out-of-domain point, 3,000,000 cells for a reveal proof and 1,000,000 for a layer proof (modeled: the counts derived from the shapes; the cells a step are assumptions, not yet established). Single-thread seconds a cell are those of the measured (proxy) Keccak records, 167.4 ns past the smaller proxy (modeled from the medians of docs/scale/recursion-proxy.jsonl), less their Keccak-f\[1600\] leaf hashing of the extension at the 131 ns a permutation measured in reveal-parameters.md, plus the same extension hashed with Poseidon2 at 897.1 ns a permutation (measured in layers-results.md: one scalar width-24 permutation of the pinned library on one core of the build machine named there, a million permutations; runs gave 868.7 ns to 1129.3 ns, measured; not yet established on an aggregator core). Every 32-core machine is taken as perfectly parallel, as the first stage took it (modeled). Unlike the first stage's proxy, these figures are estimates, not lower bounds: the Poseidon2 cost and the arithmetic cells can move them either way (modeled).

| Figure (all modeled) | Value | Ceiling (workload.md) |
|---|---|---|
| Cells to verify one reveal proof inside a layer (modeled) | 36,484,124 | none |
| Single-thread seconds a cell, Poseidon2 commitments (modeled) | 1,062.6 ns | none |
| Batch proof of 8 reveals on one machine (modeled) | 10.4 s | none |
| Root over up to 29 batches (the largest aggregator fills 18), then the shrink (modeled) | 20.9 s and 5.2 s | none |
| Machine-seconds a private reveal (modeled) | 1.5669, missed | 0.299143, the 0.3 s merge budget (not yet established) |
| Machine-seconds a block, private (modeled) | 548.4 | none |
| Machine-seconds a block, public signature proofs (modeled) | 155.4 | none |
| Machines a block needs, and with 50 percent spare (modeled) | 24 and 36, met | 40 machines (not yet established) |
| The network's aggregator machines: each of the 3 aggregators and the public root's builder on whole machines of its own, and with 50 percent spare (modeled) | 26 and 37 | 40 machines (not yet established) |
| Cost a private reveal at 2 US dollars a machine-hour (modeled) | 0.0870 US cents, met | 0.1 US cents (not yet established) |
| p99 transaction-to-inclusion delay, largest aggregator (modeled) | 237.4 s (38.3 s proving and filling, the rest two block waits), met | 5 minutes (not yet established) |
| Reveal proofs into the largest aggregator (modeled) | 0.09 Gbit/s, met | 1 Gbit/s sustained (not yet established) |
| Highest Poseidon2 permutation cost that meets each ceiling (modeled) | 40 machines: 1,599 ns; with 50 percent spare: 1,033 ns; merge budget: 91 ns; cost: 1,045 ns; delay: 2,602 ns | the input is 897.1 ns (measured) |

Against the first stage (both modeled): 1.5669 machine-seconds a reveal against at least 21.6585 for architecture (a). The private machine-seconds a reveal are more than double the 0.6781 this page modeled before the permutation was timed, at an assumed 400 ns (modeled), and miss the 0.3 s merge budget of workload.md, which holds only at 91 ns or less; that budget was a proxy for the fleet and cost ceilings, and both of those are met at the measured cost (modeled). The fleet of 40 machines holds up to 1,599 ns a permutation and with the 50 percent burst spare up to 1,033 ns, the cost ceiling up to 1,045 ns and the delay ceiling up to 2,602 ns (modeled). The measured runs range from 868.7 ns to 1129.3 ns (measured in layers-results.md), so the slowest run would miss the cost ceiling and the spare fleet of 40 (modeled): the permutation timed on an aggregator core decides both. The delay is the time to fill a batch, the batch, root and shrink proofs, and two waits for proof-of-work blocks with a 30 s mean, whose 99th percentile is about 199 s alone (modeled), so it falls only a little with faster proving.

The delay model: a reveal waits for its batch to fill and be proven, or for at most 30 s after the batch opened, when the aggregator proves it padded (modeled: an input, one mean block time); then for the next block, at which its aggregator starts a root over the batches done; once the root and shrink are proven, it waits for the next block again (modeled: the waits are exponential with a 30 s mean, as throughput.md models block times). Late failures follow a stated rule (designs.md, private bundle requirement 3): a reveal in a bundle whose state-dependent checks fail at execution, its marker already spent or its root not canonical, is skipped and the rest of the bundle executes in order, because the bundle proves proof validity only (designs.md, rule 1). So a late failure costs the fleet its share of one batch, one root and one shrink, about the 1.5669 machine-seconds of an honest reveal (modeled), and nothing is re-proven, against up to 180.49 machine-seconds in the first stage's tree (modeled in throughput.md). Whether a skipped reveal pays a fee is not yet established (designs.md, private bundle requirement 10). Invalid proofs are refused at the aggregator's native check, as in throughput.md (modeled there: 0.000288 machine-seconds each).

### The shape for 1 million a day

Settled on 2026-11-08, at the 1 million a day of workload.md and the measured Poseidon2 permutation.

A verifier key is made for one shape: a batch circuit with a fixed number of child slots and a root circuit with a fixed number of batch slots (proofs/src/layers, `batch_key` and `root_key`). A layer with fewer children fills the rest with padding and costs the prover the same as a full one (modeled: the model's bundle proves every batch at its full arity and every root at its full capacity). The shape is then a trade: wider layers waste more on the slots a block leaves empty, narrower ones need a larger root, and every layer must fit one aggregator machine. `choose_shape` in benchmarks/scale/stage2.py takes, of every reveals-per-batch from 4 to 128 and every batches-per-root from 1 to 64, the admissible shape with the fewest machine-seconds a block at the target; a shape is admissible when every layer's peak prover memory is within 128 GiB, the largest aggregator's reveals at the 50 percent burst spare fit one root, and the p99 delay is within 5 minutes; of shapes that cost the same, it takes the larger root (modeled). It takes 8 reveals a batch and 29 batches a root: 27 batches are the fewest that hold the burst, and 29 cost the same, because the root's trace is 2^20 rows for both, so the two more give a little more burst room (modeled).

Each layer's peak prover memory is the streamed prover's peak planned from the built circuits at the shape the layers plan today, a batch of 32 reveals, a root over 44 batches and its shrink (modeled in layers-results.md: 93.3, 116.3 and 8.0 GiB), scaled by the layer's padded trace at this shape against its trace at that one (modeled: every part of the plan grows with the tables; the plan at this shape is not yet established until the layers' constants move to it).

| Layer of the chosen shape (all modeled) | Trace rows | Extension, the cell model | Streamed prover at its peak, scaled from the plan | Ceiling (workload.md) |
|---|---|---|---|---|
| Batch of 8 reveals (modeled) | 524,288 | 18.8 GiB | 23.3 GiB, met | 128 GiB a machine (not yet established) |
| Root over 29 batches (modeled) | 1,048,576 | 37.5 GiB | 58.1 GiB, met | 128 GiB a machine (not yet established) |
| Shrink of the root (modeled) | 65,536 | 9.4 GiB | 8.0 GiB, met | 128 GiB a machine (not yet established) |

For each reveals-per-batch, the fewest batches a root that hold the burst (all modeled):

| Reveals per batch (all modeled) | Fewest batches per root that hold the burst | Largest peak | Machine-seconds a block | Network machines | Admissible |
|---|---|---|---|---|---|
| 4 (modeled) | 53 | 116.3 GiB | 756.0 | 27 | yes |
| 8 (modeled) | 27 | 58.1 GiB | 703.8 | 26 | yes |
| 16 (modeled) | 14 | 58.1 GiB | 712.9 | 27 | yes |
| 32 (modeled) | 7 | 93.3 GiB | 723.4 | 26 | yes |
| 64 (modeled) | 4 | 186.6 GiB | 833.1 | 29 | no |
| 128 (modeled) | 2 | 373.2 GiB | 984.5 | 35 | no |

The machine-seconds include the public signature proofs, whose batches take the same reveals-per-batch (modeled). A batch of 64 or more does not fit one machine (modeled: 186.6 GiB for 64). Of the shapes that fit, 8 a batch wastes the fewest padded slots on the three aggregators' 141, 122 and 87 reveals, while 4 a batch needs a root over 53 batches as large as the planned one (modeled). The difference between 8, 16 and 32 is under 3 percent of the machine-seconds and at most one machine (modeled), so the choice is not sensitive; 8 also keeps the batch, the layer every reveal waits for, the shortest to prove (modeled: 10.4 s).

The network's aggregator machines. Aggregators are independent (designs.md, rule 6), so each runs whole machines of its own: at 1 million a day the three aggregators and the public root's builder run 26 machines in all, 37 with the 50 percent spare, against the 40 workload.md proposes (modeled; a pooled fleet would need 24 and 36). workload.md's first estimate of 9 to 18 machines (not yet established there) counted neither the public proofs, nor the padding, nor whole machines for each aggregator.

### At 10,000, 100,000 and 1,000,000 a day

The same shape and keys at lower daily totals, the reveals a block scaled from the target's 350 and rounded up, split among the three aggregators as above (all modeled):

| Figure at the chosen shape (all modeled) | 10,000 a day | 100,000 a day | 1,000,000 a day | Ceiling (workload.md) |
|---|---|---|---|---|
| Reveals a block, and each aggregator's (modeled) | 4: 2, 1, 1 | 35: 15, 12, 8 | 350: 141, 122, 87 | none |
| Batches the largest aggregator proves, padded to its arity (modeled) | 1 | 2 | 18 | none |
| Machine-seconds a block, private and public (modeled) | 109.7 and 26.1 | 130.6 and 37.9 | 548.4 and 155.4 | none |
| The network's aggregator machines, and with 50 percent spare (modeled) | 7 and 8 | 8 and 10 | 26 and 37 | 40 machines (not yet established) |
| Machine-seconds a private reveal (modeled) | 27.4205 | 3.7307 | 1.5669 | none |
| Cost a private reveal at 2 US dollars a machine-hour (modeled) | 1.5234 US cents, missed | 0.2073 US cents, missed | 0.0870 US cents, met | 0.1 US cents (not yet established) |
| p99 delay, largest aggregator (modeled) | 265.7 s, met | 251.7 s, met | 237.4 s, met | 5 minutes (not yet established) |

Every layer's peak memory is the same at every volume, because the keys fix the layers' size (modeled: the shape table above). What a quiet chain pays for is the padding: every aggregator with a reveal proves at least one full batch, one full root of 29 slots and one shrink each block, 36.6 machine-seconds however few reveals it holds (modeled), so the cost a reveal at 10,000 a day is about 18 times that at the target, and at 100,000 a day about 2.4 times; both miss the 0.1 US cent ceiling (modeled). The delay holds at every volume, because a batch that does not fill is proven padded 30 s after it opened (modeled).

### Quiet blocks

A near-empty block, all its reveals taken by one aggregator or sent on the direct path (all modeled):

| A quiet block (all modeled) | Reveals | Machine-seconds | Cost a reveal | p99 delay | Block bytes |
|---|---|---|---|---|---|
| One bundle under the fixed-shape keys, 8 a batch and 29 batches a root, padded (modeled) | 1 | 36.6 | 2.0311 US cents, missed | 265.7 s | 860,099 |
| One bundle under a smaller shape's keys, 4 a batch and 1 batch a root (modeled) | 1 | 9.1 | 0.5078 US cents, missed | 238.3 s | 808,095 |
| Direct path, each reveal proof verified natively (modeled) | 1 | 0.0 | 0.0000 US cents, met | 138.2 s | 2,331,271 |
| One bundle under the fixed-shape keys, 8 a batch and 29 batches a root, padded (modeled) | 4 | 36.6 | 0.5078 US cents, missed | 265.7 s | 861,188 |
| One bundle under a smaller shape's keys, 4 a batch and 1 batch a root (modeled) | 4 | 9.1 | 0.1269 US cents, missed | 238.3 s | 809,184 |
| Direct-path reveals a block holds: under the 10,485,760-byte cap alone, and under today's gas rule (modeled) | | | | | 4 and 1 |

The direct path should serve quiet blocks, not a smaller bundle (modeled). A block's single reveal sent directly costs no aggregator time, waits one block instead of two (modeled: a p99 of 138.2 s), and needs no second set of verifier keys; its cost is 2,331,271 block bytes and a node's native verification, and a proof field of at least 2,330,908 bytes in a new transaction version of spec 07, which the direct path already needs (Independent operation, above; a founder decision below). Today's gas rule lets one such reveal into a block and the byte cap four (modeled), so the direct path serves a block of one reveal and the fixed-shape bundle serves anything more. A smaller bundle shape would cut a lone reveal's proving from 36.6 to 9.1 machine-seconds, but it still misses the cost ceiling, at 0.5078 US cents for one reveal and 0.1269 a reveal for four, and it doubles the keys every node pins and every audit reviews (modeled; the key count no figure). With one aggregator taking all of a 10,000-a-day block's four reveals the fixed shape costs 0.5078 US cents a reveal, against 1.5234 when three aggregators each prove a padded bundle (modeled); at quiet volumes the cost ceiling is missed by every bundled path, and whether it applies before the chain reaches its target is listed for the founder below.

### Proof library for the layers

Settled on 2026-11-03, before the layers are built.

- **Why the layers need it.** Every layer checks its children's proofs in its own constraints, so it needs a lookup or permutation argument: columns committed after a challenge. `p3-uni-stark` has none. <!-- no-figure -->
- **Chosen:** every Plonky3 crate in the repository moves to one upstream revision, `0d803737b681774186cd283b1fd2d8e493655c82` (main of 2026-10-26), and the layers take their argument from its `p3-lookup` (LogUp) and `p3-batch-stark` crates. `proofs/src/lookup_check.rs` proves and verifies a range-lookup AIR with them in the shipped configuration (Keccak-256 commitments and transcript, hiding FRI, zero knowledge on) and checks that a value outside the table is refused. Decision 0003, "Revision", records what moved with it. <!-- no-figure -->
- **Not Plonky3-recursion.** It depends on the Plonky3 release candidate from crates.io, not a revision of the repository, so it would bring a second copy of every Plonky3 crate beside the pinned one; it is Poseidon-only, unaudited and not recommended for production by its authors, and its compatibility check binds no child keys or statements (recursion.md, architecture (b)). The design above already does not use it. <!-- no-figure -->
- **Not the earlier pin with the same crates added.** The earlier pin, `f98331687e47` of 2026-10-13, already had `p3-lookup` and `p3-batch-stark`, which would have been the smaller change. Upstream has since fixed soundness bugs in exactly the code the layers use: lookup tuples and the hiding chunk count, periodic-column lookups, selectors in lookup counts, FRI openings at a zero point, grinding bounds, and hiding FRI now requires a hiding Merkle commitment. A lookup argument for the layers should not start from a revision with known, fixed soundness bugs. <!-- no-figure -->
- **Not a release tag.** The newest, 0.9.0-rc.2 of 2026-10-16, predates those fixes. <!-- no-figure -->
- **Hash-based only.** The new crates commit with hashes and Merkle trees alone; they bring no curve-based or pairing commitment, and no layer encloses a proof in one, so the layers stay quantum safe. <!-- no-figure -->
- **Zero knowledge of the lookup terminals: no statement relies on it, so the pin stays** (settled on 2026-11-04). At this revision `p3-batch-stark` publishes each AIR's LogUp terminal in the proof unmasked, even under the hiding PCS; the upstream branch that masks them (`robin/batch-stark-zk-lookup-blinding`) has not reached main. A single AIR's local lookups close to a zero terminal and reveal nothing, but an AIR's share of a lookup across several AIRs (the `wire` bus every layer and chunk routes its values on) is a partial sum over its own trace, so it can leak what that trace is computed from. Every statement proven with the batch STARK computes its trace from public data alone, as the table below states for each, so its terminals need no hiding. The reveal and every other statement with a secret witness are uni-STARK proofs, which have no lookups, and the one test-only use, `proofs/src/lookup_check.rs`, has local lookups only. <!-- no-figure -->
- **Before a statement may rely on hiding them.** A statement whose witness is secret (a reveal's digits, a note key, a holding) must not prove lookups across AIRs under the hiding configuration at this revision. Before one does, every Plonky3 crate moves together to a revision with the masking on main, and a test shows a cross-AIR terminal masked under the shipped hiding configuration. `benchmarks/scale/layer_witness.py` holds the repository to this: it fails when a statement below has no row, when a statement's prover takes an input the check does not list (so the table must say whether it is public), when any other file proves with the batch STARK or sends on a bus across AIRs, when any crate but `proofs/` depends on `p3-batch-stark` or `p3-lookup`, and when a row relies on hiding while the pin is still this revision or no such test exists. <!-- no-figure -->

| Statement | Prover | Its witness | Cross-AIR terminals |
|---|---|---|---|
| Batch over reveal proofs | `prove_batch_of` (`layers::prove_batch`) | The reveal proofs it verifies, each with its public values, and what its verifier circuit computes from them. A reveal proof is itself a zero-knowledge uni-STARK proof (hiding FRI, no lookups) made to be published: the direct path carries it in a transaction, and anyone can batch from the public reveals (Independent operation, above). The reveal's digits and note never reach the batch. | public witness, no hiding needed |
| Batch over chunk proofs | `prove_layer_of` (`layers::prove_layer`) | The chunk proofs it verifies, each with its claim (binding, running digests, count), and what its verifier circuit computes from them; a chunk proof is made from public data alone (the last row). | public witness, no hiding needed |
| Root | `prove_layer_of` (`layers::prove_layer`) | An aggregator's batch proofs with their claims. A batch proof is computed from public data and its prover's own hiding randomness, which protects nothing secret; the claims are what the node rebuilds from the block. | public witness, no hiding needed |
| Shrink | `prove_layer_of` (`layers::prove_layer`) | One root proof with its claim, made from public data the same way. | public witness, no hiding needed |
| ML-DSA-44 chunk | `prove_chunk_of` (`mldsa::prove_chunk`) | Each transaction's account, public key, key identity, message (the transaction hash) and signature, and what the verification computes from them (the SHAKE states, the NTTs, `w'_approx` and the hint). The pooled transaction carries all of them to every builder and the raw-signature fallback puts them in a block; a signature and its public key are public by design. | public witness, no hiding needed <!-- no-figure --> |

### Layer prover memory at the real shape

Settled on 2026-11-07, after the layers were built.

The layers were built and planned at the shape this page chose for the earlier target, a batch of 32 reveals and a root over 44 batches; the figures of this section are at that shape, and the scaled peaks of the chosen shape above are taken from them. The layers' constants and the real-shape memory test move to the chosen 8 reveals a batch and 29 batches a root in a later step, still checked against the 128 GiB ceiling (not yet established). The cell model counts each layer's extension once (modeled: 75.0 GiB for a batch of 32). The built layers' tables, planned from their circuits at the real shape (docs/scale/layers-results.md), are larger: a batch of 32 reveals fills tables of up to 8,388,608 rows in 8 and 4 lanes, and the library's prover, which holds every committed matrix over its extended domain with its Merkle tree and salts until the last opening, would need about 580.5 GiB for it, 733.5 GiB for a root over 44 batches and 78.3 GiB for the shrink (all modeled). No real-shape shrink proof could then be made on a 128 GiB aggregator machine (modeled ceiling).

The layers keep this design whole: three layers at the real shape, every layer's blowup and queries, the whole-bundle bound of the next section and the 1,310,720-byte proof field (modeled). Only the prover changes, in this repository's own code (proofs/src/layers/stream.rs), the pinned Plonky3 crates unchanged: each committed matrix is kept as its polynomials' coefficients over the zero-knowledge doubled domain, and its extension is evaluated one block of rows at a time, a block at most 2 GiB with its salts and its Merkle subtree (modeled), to commit, to batch the openings and to answer the queries, each block a query falls in evaluated again; the quotient is computed one chunk at a time on a coset the size of the trace. The proofs and the verifier are the library's byte for byte: proofs/tests/layers_memory.rs proves a small circuit of all five tables with the library's `prove_batch` and with the streamed prover at every block size down to single rows and requires the same bytes (measured by that test; the result does not depend on the machine).

| Layer at the real shape (modeled) | Tables, rows | Holding every extension whole | Streamed prover at its peak | Ceiling (workload.md) |
|---|---|---|---|---|
| Batch of 32 reveals (modeled) | 8,388,608, 8,388,608, 2,097,152, 4,096 and 524,288 | 580.5 GiB, missed | 93.3 GiB, met | 128 GiB a machine (not yet established) |
| Root over 44 batches (modeled) | 8,388,608, 8,388,608, 4,194,304, 8,192 and 524,288 | 733.5 GiB, missed | 116.3 GiB, met | 128 GiB a machine (not yet established) |
| Shrink of the root (modeled) | 262,144, 262,144, 131,072, 256 and 16,384 | 78.3 GiB, met | 8.0 GiB, met | 128 GiB a machine (not yet established) |

The streamed peak is the circuit, the key (each table's preprocessed columns and their coefficients), the largest block, and the batched openings with the folding layers of the opening argument above every committed matrix's coefficients: for the root 3.4, 20.9, 3.4 and 88.6 GiB, of which the coefficients are 62.9 GiB (modeled; layers-results.md gives every layer's parts). `the_real_shape_batch_and_root_fit_the_128_gib_ceiling` fails when a layer plans above the ceiling. A real-shape proof on an aggregator machine, its seconds and its measured peak memory, and the root's verification time against the 3,000 ms budget of spec 07, section 4, are not yet established.

### What is not yet established for aggregation

- The seconds of a Poseidon2 permutation of the pinned library on an aggregator core, where the 897.1 ns was measured on the build machine of layers-results.md, and of a real batch, root and shrink proof on named hardware (not yet established: the permutation test of proofs/tests/layers.rs on an aggregator core, then the real layers).
- The planned prover memory of the layers at the chosen 8 reveals a batch and 29 batches a root, against the scaled 23.3, 58.1 and 8.0 GiB above (not yet established: the layers' constants and proofs/tests/layers_memory.rs moved to that shape).
- The arithmetic cells of the verifier circuit and the out-of-domain constraint evaluation of the reveal statement (not yet established: counted from the first real layer).
- The streamed layer prover's seconds and measured peak memory at the real shape, against its modeled 93.3, 116.3 and 8.0 GiB for the batch, root and shrink (not yet established: proofs/tests/layers_bench.rs on an aggregator machine).
- The reveal's proving time and memory on the phone with Poseidon2 commitments, the degree-8 extension and 96 queries, against the 10 s and proposed 1 GiB ceilings (not yet established: phone-protocol.md, steps 4 to 7, rerun with the new prover).
- The price of an aggregator machine-hour (not yet established; the 2 US dollars is the illustrative input of throughput.md).
- Who pays an aggregator, from which field (designs.md, private bundle requirement 6; not yet established).

## Whole-bundle proven security bound

**Chosen:** close the bound by parameters and structure: a 279-bit Poseidon2 digest in every proof's commitments and transcript, challenges from the degree-8 extension of BabyBear, 96 queries at blowup 2^3 (56 at blowup 2^5 in the shrink) in the Johnson regime with parameter `m = 16`, and three recursive layers in place of eight, so that every term of the sum is computed, the union covers 263 proofs and extraction composes over three layers (all figures below modeled).

What changes against security.md, and why (all modeled):

- **Digest.** The Keccak architectures cannot reach 128 classical bits with a 256-bit Keccak-256 digest, whose collision term alone is 128 (modeled in security.md). A 9-element Poseidon2 digest is 279 bits, 139.50 classical and 93.00 quantum bits for its collision term, counted once for the bundle (modeled).
- **Extension field.** The proven commit-phase and batching term was the missing one. It is computed here with the Johnson-regime proximity-gap bound of Ben-Sasson, Carmon, Ishai, Kopparty and Saraf (FOCS 2020), in the form the ethSTARK documentation (ePrint 2021/582) and Haböck's FRI summary (ePrint 2022/1216) state it: `((m + 1/2)^7 / (3 rho^(3/2))) n^2 (M - 1) / |F|` for `M` functions batched with the powers of one challenge over a codeword of length `n`, plus `(2m + 1)(n + 1) R / (sqrt(rho) |F|)` for `R` folding rounds (modeled; the constants checked against the papers' text: not yet established). With the degree-5 extension of today (about 154 bits) that term alone leaves the whole bundle at 69.92 classical bits; with the degree-8 extension (about 247 bits) it no longer binds (modeled, the table below).
- **Queries.** In the Johnson regime with `m = 16` a query gives `-log2(sqrt(rho)(1 + 1/(2m)))`, 1.4556 bits at blowup 2^3 and 2.4556 at blowup 2^5 (modeled), a little under the 1.5 security.md used with the slack taken to zero. With 16 bits of grinding counted at half, 96 queries at blowup 2^3 and 56 at blowup 2^5 bring the quantum sum over the bundle to 69.82 bits, about six bits over 64, and the classical sum to 138.59, about ten over 128 (modeled); the quantum sum binds first.
- **Depth.** Wide layers make three recursive layers above the leaves, batch, root and shrink, where a two-to-one tree over the same reveals has eight, and 263 proofs in the largest bundle of 232 reveals instead of 463 (modeled). The extraction the union bound needs composes over three layers.
- **DEEP and constraint terms.** With the degree-8 extension the out-of-domain and constraint-combination terms are of order the constraint degree times the codeword length over the field, below 2^-200 for every proof here (modeled), and are not counted.

| Proof (all modeled) | Proofs in a bundle of 232 | Classical bits each | Quantum bits each |
|---|---|---|---|
| leaf (modeled) | 232 | 147.74 | 77.87 |
| batch (modeled) | 29 | 147.74 | 77.87 |
| root (modeled) | 1 | 147.74 | 77.87 |
| shrink (modeled) | 1 | 145.51 | 76.76 |
| Poseidon2 digest of 279 bits, counted once (modeled) | 1 | 139.50 | 93.00 |
| Whole bundle, 263 proofs (modeled) | | 138.59 | 69.82 |
| The same with the degree-5 extension of today (modeled) | | 69.92 | 36.41 |

The bundle is taken at its largest, one root with every one of its 29 batches and 232 reveal slots filled, the most one key admits (modeled); smaller bundles have fewer proofs and more bits. The quantum figures follow security.md: each proof's round-by-round bits halved, grinding at half, the hash term a third of the digest (modeled from ePrint 2019/834 as security.md uses it). The requirement is unchanged: 128 classical bits and NIST Category 1 for the whole bundle, grinding at half (spec 09, section 4.1; modeled there as the target).

Proof obligations. The sum above is a proven bound only when each step it rests on is proven for this construction. Where each of the twelve gaps of security.md stands under this design:

| Gap of security.md | Status under this design | Label |
|---|---|---|
| Recursion with the hash inside the circuit | Still open, now for three layers: a theorem with its number and loss covering recursive STARKs whose layers compute the oracle in their constraints, classically and in the QROM; candidates to read in full are ePrint 2025/2166 and the arithmetized random oracle model of Chen, Chiesa, Gur, O'Connor and Spooner (Eurocrypt 2023), which is classical only | not yet established |
| Extraction over the layers | Still open, now over three layers: a straight-line or composable extractor for each layer | not yet established |
| Theorem numbers of the cited sources | Still open: the theorem and section beside each term | not yet established |
| Round-by-round soundness of the Plonky3 IOP | Still open: a proof that the terms above are round-by-round errors | not yet established |
| Proven extension-field terms | Computed by the stated formula at every proof's parameters, the table above; to be confirmed by the estimator run of security.md at these parameters | modeled; the run not yet established |
| Which term gives today's proven 80 | Superseded: today's parameters are not used | modeled in security.md; no longer used |
| Digest length in the Keccak architectures | Closed by the 279-bit Poseidon2 digest | modeled |
| Domain separation and verifier binding | Designed under Aggregation cost, binding; closed by the build's tests that a child under any other verifier key, statement, chain or version fails, and that changing, reordering, adding or dropping a reveal fails | not yet established until built |
| Proof length at the bundle's parameters | Answered: 2,330,908 bytes a reveal proof, 859,736 a root after the shrink | modeled |
| The padding-free Keccak sponge | No longer used for proof commitments; the statement's own Keccak-256 is unchanged | no figure <!-- no-figure --> |
| Poseidon2 over BabyBear, width 24 | Now load-bearing: a published analysis of exactly this instance and its round numbers, with the CICO and zero-test records of Poseidon1 over KoalaBear not counted | not yet established |
| The leanMultisig and Plonky3-recursion figures | Not used anywhere | no figure <!-- no-figure --> |

If no theorem covers recursion with the hash inside the circuit in the quantum random oracle model before mainnet, no recursive design can claim a proven NIST Category 1 bound for the whole bundle, and the requirement becomes a decision for the founder rather than a parameter (not yet established; listed below).

## Public signature size

**Chosen:** public signatures leave the block. Each block carries one public root proof that proves every ML-DSA-44 verification of its public transactions, made in chunks of 32 verifications and folded by the batch, root and shrink layers of the private bundles; each transaction keeps 84 binding bytes (a 20-byte account, a 32-byte key identity and a 32-byte transaction hash), and a transaction with its raw signature stays valid as a fallback (all figures below modeled).

Why this one. At the earlier target raw ML-DSA-44 signatures could not fit: 3,500 of them with the private parts needed 14,283,500 bytes against the 10,485,760-byte cap before any proof (modeled in public-encoding.md), and no other scheme of spec 09 is smaller. At 1 million a day they do: 350 of them with the private parts come to 1,428,350 bytes (modeled in workload.md), and beside the three private roots a block carries 2,083 raw-signature transactions (modeled below). The proof encoding stays the chosen design because it is what lets a later, larger bundle shape carry more public transactions than raw signatures allow, and it costs 155.4 machine-seconds a block at the target, about 6 of the network's 26 machines (modeled); whether to launch with raw signatures in the block until then is listed for the founder below. The proof encoding of public-encoding.md fits on bytes; what it lacked was a proving cost and a builder, and the chosen aggregation gives both (modeled below).

- **What the proof binds.** Its public inputs are, for every transaction in block order, the account, the key identity the node reads from that account's state at this block, and the transaction hash; the node builds them itself, so a proof for one transaction authorizes no other, and a key change is honoured from the block it takes effect (designs.md, public transactions, requirement 2; no figure). Nodes still run every state-dependent check, nonce, balance, code and gas (rule 1; no figure). <!-- no-figure -->
- **What is proven.** ML-DSA-44 verification as specified in FIPS 204, its SHAKE-128 and SHAKE-256 work as Keccak-f\[1600\] permutations of the pinned Keccak AIR and its arithmetic modulo 8,380,417 emulated over BabyBear (modeled: 101 permutations and 750,000 cells of arithmetic a verification, both counts not yet established until the chunk AIR exists), inside chunks committed with Poseidon2 as the private layers are.
- **Who builds it.** Anyone, from the pooled transactions, which still carry their signatures to the builders (3,734 bytes a transaction, modeled in public-encoding.md). If no builder publishes a root for a block, the block carries public transactions with their raw signatures, up to the capacity below, so public transactions keep being included when every builder disappears (designs.md, public transactions, requirement 6; modeled).
- **Admission.** The pool keeps the admission bounds of spec 09, section 8.3 for raw signatures; an invalid public root costs a node one native verification and is refused (modeled: no figure for its time yet; not yet established).

| Figure (all modeled) | Value |
|---|---|
| Cells to prove one ML-DSA-44 verification (modeled) | 7,132,392 |
| Chunk proofs a block, 32 verifications each, extension of one (modeled) | 11, 21.1 GiB |
| Machine-seconds a block, and a public transaction (modeled) | 155.4 and 0.4440 |
| Root proof after the shrink, every bundle (modeled) | 859,736 bytes |
| Private non-proof parts with lookup tags (modeled) | 127,050 bytes |
| Three private roots (modeled) | 2,579,208 bytes |
| Public binding bytes and the public root (modeled) | 889,136 bytes |
| Block before bodies, headers and framing (modeled) | 3,595,394 bytes, under the 10,485,760-byte cap: yes |
| Headroom, and a public transaction's share of it (modeled) | 6,890,366 bytes, 19,686.8 bytes |
| Raw-signature transactions a block carries when no public proof is built (modeled) | 2,083 |
| A reveal proof at 96 queries, sent to an aggregator (modeled) | 2,330,908 bytes |

Against the first stage (both modeled): the block before bodies is 3,595,394 bytes, and the bodies, headers and framing of the public mix may take 19,686.8 bytes a transaction on average against 1,066.97 in public-encoding.md's proof variant at the earlier target. The public proofs cost 155.4 machine-seconds a block, more a transaction than the 0.2105 of the earlier target, mostly from the measured permutation cost and partly because a block's 11 chunks fill one batch of 8 slots and part of a second, padded, which the fleet figures under Aggregation cost already include (modeled).

### What is not yet established for public signatures

- The chunk AIR of ML-DSA-44 verification, its real permutation and arithmetic counts, and its proving seconds on named hardware (not yet established).
- The gas of a public transaction without its signature bytes, and the fee that pays the builder of the public root (not yet established: a change of spec 09, section 8.1).
- The bodies, headers and RLP framing of the public mix against the 1,566.4 bytes a transaction (modeled) left for them (not yet established: contract call bodies depend on which contracts launch).
- The node's native verification time of four root proofs a block inside the 3,000 ms budget of spec 07, section 4 (not yet established).

## Decisions for the founder

None of these changes the target. Each is needed for the design above, and each figure it rests on is labelled where it appears:

- **Move the proof system's hash off the Keccak baseline.** Commitments and transcripts of every proof move to Poseidon2 over BabyBear width 24, and challenges to the degree-8 extension; the statement's Keccak-256 stays. designs.md records Keccak-256 as the provisional baseline with no automatic Poseidon2 fallback, so this is a deliberate choice: the first stage's lower bounds rule out the Keccak architectures against the fleet budget (modeled), and Poseidon2's evidence for exactly this instance is an open obligation (not yet established).
- **The format changes of the restore design:** a 16-byte lookup tag with every new leaf, the lookup index and coin marker-set trees, the header MMR and the block lookup digest, five header fields and 742-byte headers (modeled), before the note and header formats are frozen; and withdrawing the bucket path of spec 01, section 8 in favour of PIR (no figure).
- **Header sampling on phones:** the attacker ratio to assume (half the honest work, about a third of the hashrate, is this page's input) and the assurance a restore must reach (64 bits is the input), with a full header check kept for large amounts (modeled: the table under Wallet restore volume).
- **How often a wallet checks its coin:** the 50 MB a month of workload.md allows five authenticated checks a month at one year of chain and three at five (modeled); a larger keep-up ceiling or fewer checks are the two choices.
- **The aggregation shape and the fleet:** fixed-shape keys of 8 reveals a batch and 29 batches a root, and 26 aggregator machines across the network at 1 million a day, 37 with the 50 percent spare, within the 40 workload.md proposes (modeled at the measured 897.1 ns permutation); the spare fleet of 40 holds up to 1,033 ns a permutation and the cost ceiling up to 1,045 ns, both below the slowest measured run of 1129.3 ns (modeled; the permutation on an aggregator core not yet established).
- **The 0.3 s merge budget:** missed at 1.5669 machine-seconds a reveal (modeled), while the fleet and cost ceilings it stood for are met; retire it in favour of those two, or keep it, which no shape meets above 91 ns a permutation (modeled).
- **The cost ceiling on a quiet chain:** under the fixed-shape keys a reveal costs 1.5234 US cents at 10,000 a day and 0.2073 at 100,000 a day against 0.1 (modeled), because every aggregator with a reveal proves padded layers each block; whether the ceiling applies before the chain reaches its target, or quiet blocks are left to the direct path and to fewer aggregators, is the founder's choice.
- **The direct path of a single reveal:** a proof field of at least 2,330,908 bytes in a new transaction version of spec 07, which also lets the direct path serve quiet blocks of one reveal at no aggregator cost (modeled, under Quiet blocks), or a single reveal always bundled by someone, at 36.6 machine-seconds a block under the fixed shape (modeled).
- **Raw public signatures at launch:** at 1 million a day a block carries 2,083 raw-signature transactions beside the private roots, against 350 needed (modeled), so the public proof could wait for the upgrade that raises capacity, saving 155.4 machine-seconds a block (modeled); this page keeps the proof as the chosen design.
- **Proven quantum security of recursion:** if no theorem covers recursion with the hash inside the circuit in the quantum random oracle model before mainnet, whether the requirement of spec 09, section 4.1 stays a launch condition (not yet established).
- **The restore ceilings themselves** stay proposals of workload.md; this design meets the download, time, memory and phone storage proposals on a chain of one and five years at the target (modeled), so none of them needs to change for it.
- **Full-node storage growth:** at the 380-byte note of spec 10, section 3.2, an ordinary full node grows 241.4 GB a year with this design's trees, within the 2 TB a year workload.md proposes, and its 4 TB disk holds about 16.6 years of it (modeled); the proposal needs no change for it (the proposal itself not yet established).

## Carried into the third stage

The requirements the first stage carried into the third stage still stand (stage1-verdict.md), with these changes from this design:

- **Real capacity** is now of architecture (c): a real batch, root and shrink on named hardware with memory against the 128 GiB machine (not yet established), replacing the cell model above.
- **Wallet restore at scale** now has a design: what remains is the PIR scheme and its costs at the target's size, the sampling proof for Ghost's difficulty rule, and a restore and a check timed on real phones (not yet established).
- **Proven security of the whole bundle** now has every term computed (modeled) and five open proof obligations (not yet established), listed under its section.
- **Digest length** and **proof length at the bundle's parameters** are answered by this design (modeled).
- **Public verification proof** now has a design and a proving cost (modeled), and keeps its gas, admission and builder payment (not yet established).
- **State execution** gains the inserts of three indexed trees and the header MMR for every block, inside the 3,000 ms budget of spec 07, section 4 (not yet established).

## Build tickets

These build the chosen design; none is part of this page. Each lists what closes it.

1. **Poseidon2 reveal prover.** The reveal statement proven with Poseidon2 commitments and transcript, the degree-8 extension, 96 queries at blowup 2^3; its proof size against 2,330,908 bytes (modeled) and its proving time and memory on the emulated and named physical phones (not yet established).
2. **Poseidon2 recursion layers.** The batch, root and shrink layers with the verifier binding and domain separation of Aggregation cost, and their failure tests; their constants and the real-shape memory test moved to 8 reveals a batch and 29 batches a root; a Poseidon2 permutation timed on an aggregator core and real layer proofs on named hardware, recorded as measured, replacing the cell model (not yet established).
3. **Security write-up.** The estimator run at every layer's parameters, the theorems and their numbers for each term, and the five proof obligations of the security section, ready for the outside review (not yet established).
4. **ML-DSA-44 verification proofs.** The chunk AIR, the public root, the node's binding of account, key and transaction, the raw-signature fallback and the gas of a transaction without its signature (not yet established).
5. **Header MMR and sampled header proof.** The header field, the node's MMR, the wallet's sampler and its proof for Ghost's difficulty rule, and the RandomX hash and cache times on named phones (not yet established).
6. **Lookup tags, lookup index and coin marker-set tree.** The leaf and header format changes of spec 01 and spec 05 with their golden vectors, reorganisation tests and the node's storage measured at a chain of the target's daily volume (not yet established).
7. **PIR restore server.** The hint tables, the overflow table, the snapshot every 20 blocks (modeled: an input) and a named lattice PIR scheme at 128 classical bits and Category 1, with its communication and server time measured at the target's database sizes (not yet established).
8. **Wallet restore and keep-up.** The probes, follow-ups and checks of this page in the client, with tests that two keys with different coins make the same requests, that a wrong or missing item is refused, and that a spend only on a disconnected block shows unspent (not yet established).

## Reproduce

Every figure above comes from these scripts and records (the script prints every table of this page; the test checks it against the page):

- `benchmarks/scale/stage2.py` and `benchmarks/tests/test_scale_stage2.py`: every figure of this page and its checks.
- `benchmarks/scale/budget.py`, `benchmarks/scale/security_budget.py` and `benchmarks/scale/recursion_costs.py`: the inputs and sums it reuses.
- `docs/scale/recursion-proxy.jsonl`: the measured (proxy) records its seconds a cell come from.
- `docs/scale/layers-results.md`: the measured Poseidon2 permutation and the layers' planned prover memory its peaks are scaled from.
- `benchmarks/scale/labels.py`: the label check.
- `benchmarks/scale/layer_witness.py` and `benchmarks/tests/test_scale_layer_witness.py`: the check that every statement proven with the batch STARK has a row in the table of "Proof library for the layers", that its prover takes only the inputs that row accounts for, and that no row relies on hiding the lookup terminals at a pin that publishes them.
- `docs/scale/stage1-verdict.md`, `docs/scale/workload.md`, `docs/scale/designs.md`, `docs/scale/security.md`, `docs/scale/phone-results.md`, `docs/scale/recursion.md`, `docs/scale/throughput.md`, `docs/scale/public-encoding.md` and `docs/research/recovery-cost.md`: the pages this design reads.

```sh
python3 benchmarks/scale/stage2.py
python3 benchmarks/tests/test_scale_stage2.py
python3 benchmarks/scale/labels.py docs/scale/stage2-design.md
python3 benchmarks/scale/layer_witness.py
python3 benchmarks/tests/test_scale_layer_witness.py
```

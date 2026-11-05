# Stage 2 design: restore, aggregation, proven security and public signatures at the scale target

This page is the design of the second stage of the scale work. The first stage's verdict (stage1-verdict.md) found the target not feasible as designed and named the limits: wallet restore volume first, then the aggregation cost, the whole-bundle proven security bound and the size of public signatures in a block. This page picks one design for each of those limits and judges it against the same ceilings of workload.md, which do not change here, under the rules of designs.md. The target does not change either: 10 million private reveals and 10 million public transactions a day, about 3,500 of each per 30 s block (modeled: the founder's target, workload.md). Nothing here is built; the build tickets are listed at the end, and the independent outside review that mainnet needs reviews the code and parameters they produce.

Every figure carries one of the labels of workload.md: **measured** (actually run, the machine named), **modeled** (a formula or stated inputs) or **not yet established** (with what would produce it). Nothing on this page was run: the only measured inputs are the recursion proxy records of docs/scale/recursion-proxy.jsonl and the timings quoted from docs/benchmarks/reveal-parameters.md and docs/research/recovery-cost.md, and every figure built on them is modeled. The arithmetic is benchmarks/scale/stage2.py, whose `INPUTS` dict at the top holds every input with its source; benchmarks/tests/test_scale_stage2.py checks that every table row on this page is exactly what the model prints, and that each ceiling comparison turns when its input crosses the ceiling.

**Result.** Each limit has a chosen design whose modeled figures meet the ceilings it is judged against, with four exceptions stated plainly and passed to the founder below (all modeled): an ordinary full node grows 2,412.8 GB a year with the restore design's trees at the 380-byte note of spec 10, section 3.2, over the proposed 2 TB (it met the proposal at the 156-byte note); the 40-machine aggregator fleet that workload.md proposes is enough only if a Poseidon2 permutation costs at most 93 ns on an aggregator core, and the 0.3 s merge budget behind it only at 122 ns, where this page's input is 400 ns (not yet established); keeping a wallet up to date within 50 MB a month allows two authenticated status checks a month at one year of chain and one at five; and the whole-bundle bound reaches 135.80 classical and 66.05 quantum bits only as a modeled sum, proven once the proof obligations listed under its section are discharged (not yet established). Every ceiling of the reference phone is still a proposal (not yet established in workload.md).

| Limit the first stage named | Chosen design | Against its ceilings (all modeled) | Label |
|---|---|---|---|
| Wallet restore volume | Private lookups by key-derived lookup tags, by single-server lattice PIR, checked against header-committed indexed trees; a work-sampled proof of the header chain | Full restore 193.6 MB at one year and 417.6 MB at five against a proposed 500 MB; 264 s and 462 s against a proposed 10 minutes; keeping up within 50 MB a month at two checks a month at one year, one at five; full-node growth 2,412.8 GB a year against a proposed 2 TB, missed | modeled; every ceiling a proposal, not yet established |
| Aggregation cost | Architecture (c) of security.md, Poseidon2 leaves and layers, with wide layers: batches of 32 reveals, a root, a shrink | 0.0377 US cents a reveal against 0.1; p99 delay 244.3 s against 5 minutes; 104 machines against the proposed 40, which suffice only at 93 ns a Poseidon2 permutation or less | modeled; the Poseidon2 cost not yet established |
| Whole-bundle proven security bound | A 279-bit Poseidon2 digest, a degree-8 extension of BabyBear, 96 queries in the Johnson regime, three recursive layers | 135.80 classical and 66.05 quantum bits against 128 and 64, the proven extension-field terms included | modeled; proven only with the obligations below, not yet established |
| Public signature size | Signatures leave the block: ML-DSA-44 verifications proven in chunks and folded by the same layers into one public root a block | 5,003,444 bytes a block before bodies against the 10,485,760-byte cap, 5,482,316 bytes of headroom | modeled |

## Wallet restore volume

**Chosen:** private lookups by key-derived lookup tags, served by single-server lattice PIR over databases any full node can build from public data, every answer checked against header-committed indexed trees, with a work-sampled proof of the header chain in place of every header from genesis (all figures below modeled).

Why this one. The first stage found that volume, not processing, sets the cost, and that no scan of the whole chain fits: the best design it considered downloads 249.5 GB at one year against a proposed 500 MB (modeled in phone-results.md). A wallet that knows what to ask for and asks privately downloads in proportion to its own coins and the logarithm of the chain, not to the chain. It can know: a key's commitments are numbered 0, 1, 2 and on with no gaps, each a remainder of the one before (spec 01, section 8), so the wallet can compute an identifier for each of them from the digits before it asks (modeled: no figure beyond the counts below). What is left to hide is which record is fetched, which PIR does; what is left to check is that every answer belongs to the canonical chain, which header roots do; and the header chain itself is checked by sampling, so the phone no longer downloads 611.8 MB of headers a year of chain (modeled in phone-results.md).

### What changes on the chain

Each of these is a format change, and so a founder decision (listed at the end). No figure on this page depends on a change that is not listed here.

- **Lookup tag.** Every new leaf (a commit, a remainder, a claim's new commitment) carries a 16-byte lookup tag, the first 16 bytes of `S("ghost/note-lookup/v1", k_note, i as 8 bytes)` for its commitment number `i`, written by whoever writes the note, as the note's 3-byte nonce tag is today (modeled: 16 bytes a leaf). Consensus cannot check a tag and does not try. It replaces the bucket path of spec 01, section 8, whose reads of tag prefixes would let an endpoint that logged them link a later reveal's new leaf, whose tag falls in a bucket it saw requested, to the restoring wallet (not yet established as a measured attack; the reason PIR is chosen here).
- **Lookup index.** For each tree type, an append-only indexed Keccak-256 tree of depth 40 over (tag, position) pairs, the construction of the data marker-set tree of spec 05, section 6, whose root after the block's last transaction is a new header field (`coinLookupRoot`, `dataLookupRoot`). It gives a membership or an absence witness for any tag against a header (modeled: 47 bytes a leaf).
- **Coin spent-marker set tree.** The same construction over the coin spent markers, root `coinMarkerRoot`, which spec 05 has today only for data. Each leaf also records the position of the leaf the same reveal appended (its remainder, or a claim's new commitment), or none, so a spent marker leads to the next commitment with a witness and no request names it (modeled: 74 bytes a leaf). The data set needs no such field: data commitments have no remainder in version one (spec 04, question 3; no figure).
- **Header MMR.** Every header commits to a Merkle mountain range over all earlier headers and their cumulative work, as FlyClient does (Bünz, Kiffer, Luu and Zamani, IEEE S&P 2020), so a sampled header is checked against the tip with one path (modeled: 48 bytes a node, a 32-byte hash and 16 bytes of work).
- **Block lookup digest.** Every header commits to the ordered lookup tags and spent markers of its block, so the blocks after a PIR snapshot are read in bulk and checked against their headers (modeled: 3,500 times 48 bytes a block).

The header grows by these five 32-byte fields, from 582 to 742 bytes (modeled).

### What a wallet does

1. Derive the note key and the lookup tags from the digits alone (spec 01, section 7); nothing else is needed or stored. <!-- no-figure -->
2. Check the header chain, beside everything else: the last 64 headers in full, and headers sampled from genesis by cumulative work with the wallet's own randomness, each with its RandomX seal, its key block and an MMR path to the tip (modeled: 599 samples at one year of chain, 702 at five). The sampling density over the chain's work `x` is `1 / ((1 - x) ln(1/delta))` on `[0, 1 - delta]`, `delta` the share of the 64-header tail; against an attacker whose valid work after its fork is at most a ratio `c` of the honest work, every fork point leaves an invalid stretch that one sample hits with probability at least `ln(1/c) / ln(1/delta)` (modeled: proved for Ghost's difficulty rule under "Written sampling bound for Ghost's difficulty rule" below, with an ancestry and a parent check that the client does not make yet, not yet established until built).
3. Probe the lookup hints by PIR: the tag of number zero, then numbers 1, 2, 4 and on, doubling until a tag is absent, then halving between the last present and the first absent; every restore makes exactly 22 probes, padded, which covers up to 1,023 hops (modeled). A probe returns at most a position: the hint table is not authenticated, and nothing is believed from it until the checks of step 5.
4. Fetch, for the highest number found, by PIR from the snapshot: its note; its coin-tree witness (64 leaves and a page's witness records); the hint, the leaf and the witness of its spent marker in the coin marker-set tree; and the leaf and witness of the lookup index, which proves "no first commitment" when nothing was found and is padding otherwise; plus one query to the hint overflow table for the bucket of the first tag (modeled: 31 queries in all, the same for every restore). The level-20 nodes of each tree and the blocks after the snapshot are read in bulk (modeled: 3,500 tags and markers a block for at most 20 blocks).
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
| PIR queries and their bytes (modeled) | 31 queries, 188.6 MB | 31 queries, 410.9 MB | none |
| Bulk tree tops and the blocks after the snapshot (modeled) | 3.7 MB | 5.0 MB | none |
| Full-restore download (modeled) | 193.6 MB, met | 417.6 MB, met | proposed 500 MB (not yet established) |
| Restore time: the header check beside the download and the server's work (modeled) | 264 s (header 264 s; download 39 s and server 17 s), met | 462 s (header 462 s; download 84 s and server 85 s), met | proposed 10 minutes (not yet established) |
| Server work a restore (modeled) | 546 core-seconds | 2,732 core-seconds | none |
| Phone memory at its peak (modeled) | 258.2 MiB, met | 259.5 MiB, met | proposed 1 GiB (not yet established) |
| Phone storage (modeled) | 2.3 MB, met | 3.7 MB, met | proposed 200 MB (not yet established) |
| Keeping up, 2 status checks a month (modeled) | 38.3 MB (19.1 MB a check), met | 73.7 MB (36.8 MB a check), missed | proposed 50 MB a month (not yet established) |
| Most status checks a month within 50 MB (modeled) | 2 | 1 | none |

Against the first stage (both modeled): the full-restore download falls from 249.5 GB at one year with buckets to 193.6 MB, and the restore time from 15.2 hours to 264 s. Keeping up is no longer a download of the chain: a wallet's witness against an old root stays valid, because historical roots stay valid forever (spec 05, section 5), so keeping up is only learning whether another holder of the digits spent the coin, one authenticated check at a time, with the headers since the last check sampled the same way (modeled: about 19.1 MB a check at one year). The ceiling of 50 MB a month then fixes how often a wallet may check, which is a decision for the founder: two checks a month at one year of chain, one at five (modeled). The restore time is dominated by the RandomX cache builds of the sampled headers' key blocks: 86 caches at one year and 175 at five (modeled), single-threaded Argon2d at the assumed 2.08 s each (not yet established on a phone).

Header sampling against a stronger attacker. The samples are set for an attacker whose valid work after its fork is at most half the honest work, about a third of the hashrate before luck (modeled: the input). Against a stronger attacker the same samples give less (all modeled):

| Attacker's valid work against the honest chain's (all modeled) | Bits a sample, one year | Assurance of the restore's samples, one year |
|---|---|---|
| 0.25 (modeled) | 0.2223 | 133.2 bits |
| 0.50 (modeled) | 0.1069 | 64.0 bits |
| 0.75 (modeled) | 0.0434 | 26.0 bits |
| 0.90 (modeled) | 0.0157 | 9.4 bits |

A wallet that checks every header resists any attacker below half the hashrate; a sampling wallet resists one below about a third with at most 64 bits of assurance a restore, less the luck that Ghost's rule leaves an attacker who raises its difficulty (the luck table under "Written sampling bound for Ghost's difficulty rule"), and less above it (modeled). The threat model already records that a majority of Ghost's hashrate can be rented for about a dollar an hour at launch (threat-model.md, section 9; an estimate there, not yet established), and a majority defeats a full header check too. Whether a phone may sample, how many bits it must reach and whether a full check stays offered for large amounts are founder decisions (listed below).

Growth of a full node, and what a restore server keeps beyond it:

| Full-node growth a year (all modeled) | Bytes |
|---|---|
| Leaves, notes and spent markers, as the first stage counted (modeled) | 1,620.6 GB |
| Lookup tags (modeled) | 58.4 GB |
| Lookup index tree (modeled) | 346.8 GB |
| Coin spent-marker set tree (modeled) | 386.9 GB |
| Header MMR (modeled) | 0.1 GB |
| Total, against the proposed 2 TB a year (modeled) | 2,412.8 GB, missed |
| A restore server's hint tables at one year of chain, beyond a full node (modeled) | 403.3 GB |

The trees are counted with every inner node stored (modeled: 64 bytes a leaf), the most a node keeps; receipts are left out, as the first stage left them out (spec 05, section 12; not yet established). The 4 TB disk of the ordinary full node holds about 1.7 years of this growth (modeled: 4 TB over 2,412.8 GB a year).

Full-node growth misses the proposed 2 TB a year by 412.8 GB (modeled). The 380-byte note of spec 10, section 3.2 makes the first stage's own count of leaves, notes and markers 1,620.6 GB a year, under 2 TB on its own, and this design's lookup tags, trees and header MMR add 792.2 GB (all modeled). At the 156-byte note the total was 1,595.2 GB and met the proposal (modeled). The ceiling is a proposal of workload.md (not yet established), and what to do about it is listed for the founder below.

### Written sampling bound for Ghost's difficulty rule

This is the proof that step 2 rests on, written for Ghost's own rule, ASERT anchored at genesis with each header's own timestamp (spec 06, sections 4.3 and 5.1), in place of the FlyClient argument step 2 quoted (modeled: a proof from the checks and assumptions stated here; nothing in it was run on a chain). Its arithmetic is `benchmarks/scale/header_sample_bound.py`. `benchmarks/tests/test_header_sample_bound.py` checks that the first slice's table above, as `benchmarks/scale/header_sample_bits.py` prints it, is the bound's, figure for figure, and `client/tests/header_sample_bound.rs` checks Lemma B against the client's own difficulty rule and counts the header proof's bytes.

```text
Honest chain   headers 0 .. N-1, each of work D_i (its difficulty), total W
The proof      a tip and its range: n' leaves of (header hash, work), claimed total W';
               the last 64 headers (the tail) checked in full, then m samples
Shares         a point x of the claimed work as a share of W', 0 <= x < 1
delta          the tail's share of W', which the wallet reads from the tail's paths
Density        f(x) = 1 / ((1 - x) ln(1/delta)) on [0, 1 - delta], drawn as x = 1 - delta^u
Fork point a   the last leaf such that the range's leaves 0 .. a are the honest chain's
R, H           the claimed work after the fork, W' - W_a, and the honest work after it, W - W_a
I, V           the claimed work of the invalid and of the valid leaves after the fork, I + V = R
c              the attacker's input: V <= c H
```

A leaf is **valid** when its header passes every check the wallet makes of a sample, and **invalid** otherwise; a sample that lands on an invalid leaf refuses the whole proof. The checks are the client's (the header hashes to its leaf with its own `difficulty` as the leaf's work; it carries exactly the difficulty the rule requires of its own height and timestamp; it is sealed under its key block; the key block is the range's leaf at its seed height and passes the same checks; every path reaches the tip's root) and two the client does not make yet:

- **Ancestry.** The sample's own `headerMmrRoot` is the root of the range's leaves before it, as FlyClient checks. A leaf's path holds exactly the nodes of that shorter range (its left siblings and the peaks to its left), so the check costs no bytes (modeled: no more than the path). An honest header copied after the fork commits to the honest leaf after the fork, not to the range's, so it is invalid there unless Keccak-256 collides: every valid leaf after the fork was sealed on the attacker's own branch (modeled: proved here).
- **Parent.** With each sample the server sends the header before it with its path, and the wallet checks that the sample names it as its parent and is stamped after it, and that it carries the difficulty the rule requires of it; its seal is not checked. The client already checks the header before the tail in this way, and its seal too (modeled: one more header and path a sample, counted below).

Two assumptions stand beside the checks. The proof claims at least the honest chain's total work, `W' >= W`, the least a chain needs to be kept by a wallet that compares the tips it is offered and keeps the heaviest; a wallet that hears only one server has nothing to compare (not yet established: how many servers a wallet asks). And the attacker's input: `V <= cH`, whose cost in hashrate Lemma C gives.

**Theorem (sampling).**

```text
If the invalid leaves carry a share iota = I / R of the claimed work after the fork, one sample
lands on an invalid leaf with probability at least

    p(iota) = ln(1 / (1 - iota)) / ln(1/delta),

whatever the fork point and however the invalid leaves are placed. If V <= cH and W' >= W, then
iota >= 1 - c, so

    p >= ln(1/c) / ln(1/delta),

and m samples drawn after the tail is checked all miss with probability at most (1 - p)^m = 2^(-m b),
b = -log2(1 - p) bits a sample.
```

*Proof.* Let `x_a = W_a / W'` be the claimed work before the first leaf after the fork, so the work after the fork is the stretch `[x_a, 1)` of length `r = 1 - x_a = R / W'` (modeled: proved here). The tail is valid, so a fork inside the tail leaves no invalid leaf and nothing to prove; otherwise the invalid leaves after the fork form a set `S` inside `[x_a, 1 - delta]` of length `iota r`, a union of the leaves' stretches of work (modeled). The density `f` rises on `[0, 1 - delta]`, so of all such sets the leftmost interval `J = [x_a, x_a + iota r]` is the least likely: `S` and `J` share `S ∩ J`; the rest of `S` lies right of `J`'s end, where `f` is at least its value there, and the rest of `J` lies left of it, where `f` is at most that value; and the two rests have the same length (modeled: proved here). So

```text
P(S) >= P(J) = integral from x_a to 1 - (1 - iota) r of dx / ((1 - x) ln(1/delta))
             = ln(r / ((1 - iota) r)) / ln(1/delta)  =  ln(1 / (1 - iota)) / ln(1/delta),
```

which does not depend on the fork point. If `V <= cH` and `W' >= W`, then `H <= R` and `I = R - V >= (1 - c) R`, so `iota >= 1 - c` and `p >= ln(1/c) / ln(1/delta)` (modeled: proved here). The wallet draws its points with its own generator after it has checked the tail against the root, so the range is fixed before the points exist and each sample misses with probability at most `1 - p`, independently: all `m` miss with probability at most `(1 - p)^m` (modeled). The wallet takes `m = ceil(target / b)` from the `delta` it reads, so the assurance reaches the target whatever `delta` the attacker's tail gives it; a lighter tail only costs more samples (modeled). This ends the proof.

The bound at the page's settings, `delta` the share of 64 tail headers of 2,880 a day, the hit chance the least over fork points of the density integrated numerically over the leftmost invalid stretch (all modeled):

| Valid work after the fork against the honest work, `c` (all modeled) | Hit chance a sample, one year | Bits a sample, one year | Bits a sample, five years |
|---|---|---|---|
| 0.25 (modeled) | 0.1428 | 0.2223 | 0.1885 |
| 0.50 (modeled) | 0.0714 | 0.1069 | 0.0912 |
| 0.75 (modeled) | 0.0296 | 0.0434 | 0.0372 |
| 0.90 (modeled) | 0.0109 | 0.0157 | 0.0135 |

Its bits a sample at one year are the first slice's table above, figure for figure, and the test of this bound fails if they differ (modeled). At five years 702 samples of 0.0912 bits give the same 64 bits (modeled).

**Lemma A (a leaf's work is what its seal cost, checked from the header alone).** Spec 06, section 4.3 makes the required difficulty a function of the header's own height `n` and timestamp `ts` only, `D = g(lag)` with `lag = ts - G - 30 n`, and of no earlier header (modeled: proved here; the client test checks that the rule gives one difficulty for one lag at any height). So the wallet checks a sampled header's difficulty exactly from the header alone, and the leaf commits to that difficulty as its work (decision 0005), so a valid leaf's work is the difficulty its seal was checked at. A hash meets the target `M // D` with probability `(M // D + 1) / 2^256`, at most `(1 + 2^-128) / D` below the 2^128 cap on work of decision 0005, so a valid leaf costs whoever sealed it at least `D / (1 + 2^-128)` hashes on average (modeled: proved here). Rules whose difficulty depends on earlier headers need more in the tree to check a sampled difficulty, as Zcash's ZIP 221 puts timestamps and targets in its nodes; Ghost's rule needs nothing more than decision 0005's node of a hash and a work (modeled: proved here).

**Lemma B (difficulty rises at most `rho = 1.0059` from a header to its child).** `g` never rises as `lag` grows: the target `T_START x factor x 2^(shifts - 16)` grows with the exponent, BCH's cubic `factor` grows with `frac` and stays below twice its value at zero, and `D = max(D_MIN, M // target)` (modeled: proved here, and checked by the client test at every lag below). A child is stamped after its parent (spec 06, section 5.1), `ts' >= ts + 1`, one block further, `n' = n + 1`, so `lag' >= lag - 29` and `D' <= g(lag - 29)`. The cubic is within 0.013% of `2^x` (spec 06, section 4.3), so `g(lag - 29) / g(lag) <= 2^(29/3600) x 1.00013 / 0.99987 = 1.00586`; the floor `D_MIN` only lowers the ratio, and the rounding of `M // target` is below 2^-128 of it, so `D' <= rho D` (modeled: proved here). The client's rule meets it at every lag from past the floor to a difficulty of 2^81, and its largest rise there is within 0.026% of 2^(29/3600), so the bound is close to tight; over two blocks, 58 seconds of lag, the rise exceeds `rho`, so the bound holds header by header, where a child is checked against its parent (measured: client/tests/header_sample_bound.rs over every lag of that range; a computation, the same on any machine).

**Lemma C (luck along a linked chain).** Let the attacker hash `A = qH` times while the honest chain gains `H`, and let its valid leaves after the fork form one chain from the fork, each a child of the one before it and the first a child of the fork point, whose difficulty is `D_a`. For `q < c` it reaches `V >= cH` with probability at most

```text
exp(-(H / cap) (c ln(c/q) - c + q)),    cap = rho D_a + (rho - 1) c H.
```

*Proof.* By Lemma B each header is at most `rho` times its parent, so by induction `D_j <= rho D_a + (rho - 1)(D_(a+1) + ... + D_(j-1))`: it holds for the first, and `D_j <= D_(j-1) + (rho - 1) D_(j-1)` carries it on (modeled: proved here). So every header the attacker seals while `V < cH`, the one that crosses `cH` included, has `D < cap`. Count `V` over the headers it seals with `D <= cap`, on any branch it tries; a hash on such a header adds `D` with probability at most `(1 + 2^-128) / D` (Lemma A), and `(e^(lambda D) - 1) / D` grows with `D`, so `exp(lambda V - k t)` after `t` hashes, with `k = (1 + 2^-128)(e^(lambda cap) - 1) / cap`, never rises in expectation; hashes on other headers only lower it. Markov's inequality after `A` hashes, at `lambda = ln(c/q) / cap`, gives the bound with `2^-128` dropped (modeled: proved here). This ends the proof.

With the honest difficulty steady at `D_a`, so that a fork of `K` honest headers has `H = K D_a`, the bound in bits (all modeled):

| Attacker's hashrate against the honest hashrate, at `c` = 0.5 (all modeled) | Luck bound, fork of one day | Luck bound, fork of one year |
|---|---|---|
| 0.250, 20.0% of all hashrate (modeled) | 42.2 bits | 47.2 bits |
| 0.333, 25.0% of all hashrate (modeled) | 15.8 bits | 17.6 bits |
| 0.400, 28.6% of all hashrate (modeled) | 5.1 bits | 5.7 bits |
| 0.500, 33.3% of all hashrate (modeled) | 0.0 bits | 0.0 bits |

An attacker that kept its difficulty steady would face the luck of about `cK` headers. Ghost's rule lets it stamp its headers a second apart and raise its difficulty by up to 0.56% a header, which bunches its work into about `1 / ((rho - 1) c)` headers, some 339 at `c` = 0.5, and that is the luck which remains (modeled). So an attacker of a third of the hashrate, `q = c`, is the edge of the input, and below it a restore's assurance is the smaller of the sampling bound's 64 bits and the luck bound's (modeled). Together: an attacker whose valid work after the fork is a chain linked from the fork fools a sampled restore at the page's settings with probability at most `2^-64 + 2^-L`, `L` the luck bound above, because either `V < cH` and the theorem applies, or `V >= cH`, which is the luck (modeled: proved here).

**Difficulty raised on a lone header.** Without the parent check nothing ties a sample to the header before it, and Lemma B does not apply. An attacker can stamp one header far ahead of the schedule, where the rule requires the whole honest work after the fork, seal it with its hashes, and build a range of valid leaves only, cheap headers at the floor before it and its own tail after it, which no sample refuses. This is the difficulty-raising attack of Bahack ("Theoretical Bitcoin Attacks with less than Half of the Computational Power", arXiv 1312.7013, 2013). With hashes `q` times the honest work after the fork it seals that header with probability `1 - e^(-q)`, 39.3% at a third of the hashrate, whatever the fork's depth (modeled). The parent check refuses the lone header: a valid sample needs a parent stamped before it that claims at least `1/rho` of its work, so a raised header ends either a chain the attacker sealed from the fork, which Lemma C covers, or a run that starts on an invalid parent, whose claimed work is invalid work the sampler can hit (modeled: proved here for the lone header).

What the bound leaves open. A run of valid headers that starts on an invalid parent may start at up to `rho` times that parent's claimed work (Lemma B), so an attacker can turn invalid work into valid work by luck and lower the invalid share below `1 - c`. The theorem's general form `p(iota)` still holds for whatever share is left, but how far such runs let an attacker of a given hashrate lower it is not yet established: a bound for runs raised on invalid parents, or a check that refuses them. Until then the assurance against a share of the hashrate is the one above, for attackers that do not raise on invalid parents (not yet established beyond that).

What the client credits. The client's sampled check makes neither the ancestry nor the parent check yet, and credits only the tail's work, never the work the range claims below it (client/src/header_sample.rs), so nothing in the client rests on this bound or on what it leaves open.

**Header proof bytes.** `client/tests/header_sample_bound.rs` builds the proof the client's sampler checks on a chain of one and of five years at the target, every header on schedule at the start difficulty: each sample, the tail and the header before it, each with its key block and every path in the client's layout, the points drawn by the client's sampler from eight seeded generators, and every header spec 05's block-one example at its own height with all 24 items of decision 0005, whose first 19 decode with the client. It records the largest of the eight proofs (measured: a count, the same on any machine; the chain it counts on is modeled):

| Header proof bytes (modeled and measured) | One year of chain | Five years of chain |
|---|---|---|
| Modeled: the stage 2 model's header proof, the figure of the table above | 1,247,246 bytes (1.2 MB) | 1,667,534 bytes (1.7 MB) |
| Measured: the client's proof with every header and path entry sent once, the largest of seeds 1 to 8 | 873,346 bytes, under the model | 1,170,360 bytes, under the model |
| Measured: the same with the parent check's header before each sample and its key block, sent once | 1,349,331 bytes, over the model | 1,732,518 bytes, over the model |
| Measured: the client's proof as its structures hold it, each sample with its own key block and every path in full | 2,243,658 bytes, over the model | 2,806,770 bytes, over the model |

The model's bytes hold for the client's proof only when a transport sends each header and each shared path entry once, which decision 0005 allows; the parent check's header a sample then puts the proof 8.2% over the model at one year and 3.9% over at five, and the client's structures as they are, with a key block in every sample and every path in full, are 1.8 and 1.7 times the model (measured). The largest of these moves the full-restore download of 193.6 MB and 417.6 MB by at most 1.1 MB, and turns no ceiling (modeled).

### What is not yet established for restore

- The PIR scheme, its parameters at 128 classical bits and NIST Category 1, and its real communication, server time and preprocessing for these databases at the target's size (not yet established: a PIR server built from these databases and timed on named hardware; the 2.5 MB and 12.1 GB a second are published figures for another database).
- The phone's RandomX hash and cache build (not yet established: the restore timed on named mid-range phones; the 128 ms and 2.08 s are build-machine measurements times an assumed four).
- What the written sampling bound for Ghost's difficulty rule leaves open, and the attacker ratio a phone must assume and the sample count it must reach (not yet established: the ancestry and parent checks built into the client's sampled check, a bound for runs of valid headers raised on invalid parents or a check that refuses them, and a founder decision; the bound itself is written above, modeled).
- The PIR client's memory and time on the phone (not yet established; the phone memory above counts one RandomX cache, the bulk data and 2 MB).
- A restore and a keep-up check timed on a real phone against a chain of the target size (not yet established).

## Aggregation cost

**Chosen:** architecture (c) of security.md, Poseidon2 leaves and Poseidon2 layers, with wide layers in place of a two-to-one tree: each batch proof verifies 32 reveal proofs, one root proof verifies an aggregator's batches, and a shrink layer at blowup 2^5 makes the proof the block carries (all figures below modeled).

Why this one. The first stage's own lower bounds rule out the other two architectures against the fleet of workload.md, whatever the machine price: 40 machines in a 30 s block have 0.3429 machine-seconds for each of 3,500 reveals (modeled), while architecture (a) needs at least 21.6585 machine-seconds a reveal and architecture (b)'s conversion layer alone at least 7.2194 (modeled in throughput.md, lower bounds from the measured (proxy) records). Both re-prove Keccak-f\[1600\] inside a trace, 13,070 permutations a reveal proof at 24 rows of 2,633 columns each (modeled in recursion.md). Architecture (c) verifies a Poseidon2 proof inside a Poseidon2 trace, one row of a width-24 Poseidon2 AIR a permutation (modeled: 451 columns, read from the layout of the pinned library's Poseidon2 AIR; not yet established until counted from the crate), so the hashing that dominated (a) shrinks by two orders of magnitude and the verifier's arithmetic becomes a comparable part.

The design (every parameter an input of the model; no figure on this list beyond those labelled):

- **Leaf.** The reveal statement is unchanged, including its own Keccak-256 hashes of commitments and markers (spec 01). Only its proof's commitments and transcript move to Poseidon2 over BabyBear, width 24, sponge rate 15 and capacity 9, a 9-element digest (modeled: 279 bits), with challenges from the degree-8 extension of BabyBear, 96 queries at blowup 2^3, grinding 16 and 16 bits (modeled: the security section's parameters).
- **Batch.** One proof verifies 32 reveal proofs in its constraints and exposes a running digest of their ordered contents and their count (modeled: a 600-column trace of 2^21 rows).
- **Root.** One proof verifies all of an aggregator's batches of the block (modeled: 44 for the largest aggregator's 1,400 reveals).
- **Shrink.** One proof verifies the root at blowup 2^5 with 56 queries, so the proof the block carries is short (modeled: 859,736 bytes, under the 1,310,720-byte proof field of spec 07).
- **Binding.** Each layer fixes the digest of its children's verifier key in a preprocessed column, and absorbs into its transcript, before any challenge, a tag naming the layer kind, its index, the protocol and statement versions, the chain identifier and that digest; the node builds the root's public inputs itself from the block's ordered reveals, the count, the chain and the versions (security.md, "Root and the node"; designs.md, private bundle requirement 1; no figure). Plonky3-recursion is not used and is not evidence for any of this. <!-- no-figure -->
- **Independent operation.** Anyone can batch from the public reveals with no key of another aggregator (designs.md, rule 6). A reveal no aggregator takes is still included: any party, or its own wallet's server, can make a bundle of one, and the direct path of one reveal verified natively stays, which needs a proof field of at least 2,330,908 bytes for a reveal proof at 96 queries (modeled: above today's 1,310,720, so a new transaction version of spec 07, a founder decision).
- **No elliptic-curve wrap anywhere** (designs.md, private bundle requirement 13; no figure). <!-- no-figure -->

How the seconds are modeled. The cells a verifier circuit spends on one child proof are its Poseidon2 permutations (every compression and leaf hash of a fixed-shape verifier and the transcript of its out-of-domain values) at 451 cells each, plus its arithmetic: the DEEP combination of every opened function at every query at 17 cells a term, the folding at 200 cells a round a query, and the child's constraints at the out-of-domain point, 3,000,000 cells for a reveal proof and 1,000,000 for a layer proof (modeled: the counts derived from the shapes; the cells a step are assumptions, not yet established). Single-thread seconds a cell are those of the measured (proxy) Keccak records, 167.4 ns past the smaller proxy (modeled from the medians of docs/scale/recursion-proxy.jsonl), less their Keccak-f\[1600\] leaf hashing of the extension at the 131 ns a permutation measured in reveal-parameters.md, plus the same extension hashed with Poseidon2 at 400 ns a permutation (not yet established: no Poseidon2 permutation of the pinned library has been timed on an aggregator core). Every 32-core machine is taken as perfectly parallel, as the first stage took it (modeled). Unlike the first stage's proxy, these figures are estimates, not lower bounds: the Poseidon2 cost and the arithmetic cells can move them either way (modeled).

| Figure (all modeled) | Value | Ceiling (workload.md) |
|---|---|---|
| Cells to verify one reveal proof inside a layer (modeled) | 36,484,124 | none |
| Single-thread seconds a cell, Poseidon2 commitments (modeled) | 532.4 ns | none |
| Batch proof of 32 reveals on one machine (modeled) | 20.9 s, extension 75.0 GiB | 128 GiB a machine (not yet established) |
| Root over the largest aggregator's 44 batches, then the shrink (modeled) | 20.9 s and 2.6 s, extensions 75.0 and 9.4 GiB | 128 GiB a machine (not yet established) |
| Machine-seconds a private reveal (modeled) | 0.6781, missed | 0.29991, the 0.3 s merge budget (not yet established) |
| Machine-seconds a block, private (modeled) | 2,373.4 | none |
| Machine-seconds a block, public signature proofs (modeled) | 736.6 | none |
| Machines a block needs, and with 50 percent spare (modeled) | 104 and 156, missed | 40 machines (not yet established) |
| Cost a private reveal at 2 US dollars a machine-hour (modeled) | 0.0377 US cents, met | 0.1 US cents (not yet established) |
| p99 transaction-to-inclusion delay, largest aggregator (modeled) | 244.3 s (45.2 s proving and filling, the rest two block waits), met | 5 minutes (not yet established) |
| Reveal proofs into the largest aggregator (modeled) | 0.87 Gbit/s, met | 1 Gbit/s sustained (not yet established) |
| Highest Poseidon2 permutation cost that meets each ceiling (modeled) | 40 machines: 93 ns; with 50 percent spare: 29 ns; merge budget: 122 ns; cost: 1,226 ns; delay: 1,025 ns | the input is 400 ns (not yet established) |

Against the first stage (both modeled): 0.6781 machine-seconds a reveal against at least 21.6585 for architecture (a), and 104 machines a block, public proofs included, against at least 2,780 that kept up with the private stream alone. The cost ceiling holds with room at any Poseidon2 cost up to 1,226 ns a permutation and the delay ceiling up to 1,025 ns (modeled). The fleet of 40 machines holds only at 93 ns or less, and with the 50 percent burst spare of workload.md only at 29 ns or less (modeled). The delay is the time to fill a batch, the batch, root and shrink proofs, and two waits for proof-of-work blocks with a 30 s mean, whose 99th percentile is about 199 s alone (modeled), so it falls only a little with faster proving.

The delay model: a reveal waits for its batch to fill and be proven, then for the next block, at which its aggregator starts a root over the batches done; once the root and shrink are proven, it waits for the next block again (modeled: the waits are exponential with a 30 s mean, as throughput.md models block times). Late failures follow a stated rule (designs.md, private bundle requirement 3): a reveal in a bundle whose state-dependent checks fail at execution, its marker already spent or its root not canonical, is skipped and the rest of the bundle executes in order, because the bundle proves proof validity only (designs.md, rule 1). So a late failure costs the fleet its share of one batch, one root and one shrink, about the 0.6781 machine-seconds of an honest reveal (modeled), and nothing is re-proven, against up to 180.49 machine-seconds in the first stage's tree (modeled in throughput.md). Whether a skipped reveal pays a fee is not yet established (designs.md, private bundle requirement 10). Invalid proofs are refused at the aggregator's native check, as in throughput.md (modeled there: 0.000288 machine-seconds each).

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

### What is not yet established for aggregation

- The seconds of a Poseidon2 permutation of the pinned library on an aggregator core, and of a real batch, root and shrink proof on named hardware (not yet established: the Poseidon2 proxy command of recursion.md, architecture (b), then the real layers).
- The arithmetic cells of the verifier circuit and the out-of-domain constraint evaluation of the reveal statement (not yet established: counted from the first real layer).
- The reveal's proving time and memory on the phone with Poseidon2 commitments, the degree-8 extension and 96 queries, against the 10 s and proposed 1 GiB ceilings (not yet established: phone-protocol.md, steps 4 to 7, rerun with the new prover).
- The price of an aggregator machine-hour (not yet established; the 2 US dollars is the illustrative input of throughput.md).
- Who pays an aggregator, from which field (designs.md, private bundle requirement 6; not yet established).

## Whole-bundle proven security bound

**Chosen:** close the bound by parameters and structure: a 279-bit Poseidon2 digest in every proof's commitments and transcript, challenges from the degree-8 extension of BabyBear, 96 queries at blowup 2^3 (56 at blowup 2^5 in the shrink) in the Johnson regime with parameter `m = 16`, and three recursive layers in place of twelve, so that every term of the sum is computed, the union covers 3,612 proofs and extraction composes over three layers (all figures below modeled).

What changes against security.md, and why (all modeled):

- **Digest.** The Keccak architectures cannot reach 128 classical bits with a 256-bit Keccak-256 digest, whose collision term alone is 128 (modeled in security.md). A 9-element Poseidon2 digest is 279 bits, 139.50 classical and 93.00 quantum bits for its collision term, counted once for the bundle (modeled).
- **Extension field.** The proven commit-phase and batching term was the missing one. It is computed here with the Johnson-regime proximity-gap bound of Ben-Sasson, Carmon, Ishai, Kopparty and Saraf (FOCS 2020), in the form the ethSTARK documentation (ePrint 2021/582) and Haböck's FRI summary (ePrint 2022/1216) state it: `((m + 1/2)^7 / (3 rho^(3/2))) n^2 (M - 1) / |F|` for `M` functions batched with the powers of one challenge over a codeword of length `n`, plus `(2m + 1)(n + 1) R / (sqrt(rho) |F|)` for `R` folding rounds (modeled; the constants checked against the papers' text: not yet established). With the degree-5 extension of today (about 154 bits) that term alone leaves the whole bundle at 64.21 classical bits; with the degree-8 extension (about 247 bits) it no longer binds (modeled, the table below).
- **Queries.** In the Johnson regime with `m = 16` a query gives `-log2(sqrt(rho)(1 + 1/(2m)))`, 1.4556 bits at blowup 2^3 and 2.4556 at blowup 2^5 (modeled), a little under the 1.5 security.md used with the slack taken to zero. With 16 bits of grinding counted at half, 96 queries at blowup 2^3 and 56 at blowup 2^5 bring the quantum sum over the bundle to 66.05 bits, about two bits over 64, and the classical sum to 135.80, about eight over 128 (modeled); the quantum sum binds first.
- **Depth.** Wide layers make three recursive layers above the leaves, batch, root and shrink, where the two-to-one tree had twelve, and 3,612 proofs in a bundle of 3,500 reveals instead of 6,999 (modeled). The extraction the union bound needs composes over three layers.
- **DEEP and constraint terms.** With the degree-8 extension the out-of-domain and constraint-combination terms are of order the constraint degree times the codeword length over the field, below 2^-200 for every proof here (modeled), and are not counted.

| Proof (all modeled) | Proofs in a bundle of 3,500 | Classical bits each | Quantum bits each |
|---|---|---|---|
| leaf (modeled) | 3,500 | 147.74 | 77.87 |
| batch (modeled) | 110 | 147.74 | 77.86 |
| root (modeled) | 1 | 147.74 | 77.85 |
| shrink (modeled) | 1 | 145.51 | 76.76 |
| Poseidon2 digest of 279 bits, counted once (modeled) | 1 | 139.50 | 93.00 |
| Whole bundle, 3,612 proofs (modeled) | | 135.80 | 66.05 |
| The same with the degree-5 extension of today (modeled) | | 64.21 | 32.61 |

The bundle is taken at its largest, one aggregator holding all 3,500 reveals of a block (modeled); smaller bundles have fewer proofs and more bits. The quantum figures follow security.md: each proof's round-by-round bits halved, grinding at half, the hash term a third of the digest (modeled from ePrint 2019/834 as security.md uses it). The requirement is unchanged: 128 classical bits and NIST Category 1 for the whole bundle, grinding at half (spec 09, section 4.1; modeled there as the target).

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

Why this one. Raw ML-DSA-44 signatures cannot fit: 3,500 of them with the private parts need 14,283,500 bytes against the 10,485,760-byte cap before any proof (modeled in public-encoding.md), and no other scheme of spec 09 is smaller. The proof encoding of public-encoding.md fits on bytes; what it lacked was a proving cost and a builder, and the chosen aggregation gives both (modeled below).

- **What the proof binds.** Its public inputs are, for every transaction in block order, the account, the key identity the node reads from that account's state at this block, and the transaction hash; the node builds them itself, so a proof for one transaction authorizes no other, and a key change is honoured from the block it takes effect (designs.md, public transactions, requirement 2; no figure). Nodes still run every state-dependent check, nonce, balance, code and gas (rule 1; no figure). <!-- no-figure -->
- **What is proven.** ML-DSA-44 verification as specified in FIPS 204, its SHAKE-128 and SHAKE-256 work as Keccak-f\[1600\] permutations of the pinned Keccak AIR and its arithmetic modulo 8,380,417 emulated over BabyBear (modeled: 101 permutations and 750,000 cells of arithmetic a verification, both counts not yet established until the chunk AIR exists), inside chunks committed with Poseidon2 as the private layers are.
- **Who builds it.** Anyone, from the pooled transactions, which still carry their signatures to the builders (3,734 bytes a transaction, modeled in public-encoding.md). If no builder publishes a root for a block, the block carries public transactions with their raw signatures, up to the capacity below, so public transactions keep being included when every builder disappears (designs.md, public transactions, requirement 6; modeled).
- **Admission.** The pool keeps the admission bounds of spec 09, section 8.3 for raw signatures; an invalid public root costs a node one native verification and is refused (modeled: no figure for its time yet; not yet established).

| Figure (all modeled) | Value |
|---|---|
| Cells to prove one ML-DSA-44 verification (modeled) | 7,132,392 |
| Chunk proofs a block, 32 verifications each, extension of one (modeled) | 110, 21.1 GiB |
| Machine-seconds a block, and a public transaction (modeled) | 736.6 and 0.2105 |
| Root proof after the shrink, every bundle (modeled) | 859,736 bytes |
| Private non-proof parts with lookup tags (modeled) | 1,270,500 bytes |
| Three private roots (modeled) | 2,579,208 bytes |
| Public binding bytes and the public root (modeled) | 1,153,736 bytes |
| Block before bodies, headers and framing (modeled) | 5,003,444 bytes, under the 10,485,760-byte cap: yes |
| Headroom, and a public transaction's share of it (modeled) | 5,482,316 bytes, 1,566.4 bytes |
| Raw-signature transactions a block carries when no public proof is built (modeled) | 1,777 |
| A reveal proof at 96 queries, sent to an aggregator (modeled) | 2,330,908 bytes |

Against the first stage (both modeled): the block before bodies is 5,003,444 bytes against 14,283,500 with raw signatures, and the bodies, headers and framing of the public mix may take 1,566.4 bytes a transaction on average against 1,066.97 in public-encoding.md's proof variant. The public proofs cost 736.6 machine-seconds a block, which the fleet figures under Aggregation cost already include (modeled).

### What is not yet established for public signatures

- The chunk AIR of ML-DSA-44 verification, its real permutation and arithmetic counts, and its proving seconds on named hardware (not yet established).
- The gas of a public transaction without its signature bytes, and the fee that pays the builder of the public root (not yet established: a change of spec 09, section 8.1).
- The bodies, headers and RLP framing of the public mix against the 1,566.4 bytes a transaction (modeled) left for them (not yet established: contract call bodies depend on which contracts launch).
- The node's native verification time of four root proofs a block inside the 3,000 ms budget of spec 07, section 4 (not yet established).

## Decisions for the founder

None of these changes the target. Each is needed for the design above, and each figure it rests on is labelled where it appears:

- **Move the proof system's hash off the Keccak baseline.** Commitments and transcripts of every proof move to Poseidon2 over BabyBear width 24, and challenges to the degree-8 extension; the statement's Keccak-256 stays. designs.md records Keccak-256 as the provisional baseline with no automatic Poseidon2 fallback, so this is a deliberate choice: the first stage's lower bounds rule out the Keccak architectures against the fleet budget (modeled), and Poseidon2's evidence for exactly this instance is an open obligation (not yet established).
- **The format changes of the restore design:** a 16-byte lookup tag with every new leaf, the lookup index and coin marker-set trees, the header MMR and the block lookup digest, five header fields and 742-byte headers (modeled), before the note and header formats are frozen; and withdrawing the bucket path of spec 01, section 8 in favour of PIR (no figure).
- **Header sampling on phones:** the attacker ratio to assume (half the honest work, about a third of the hashrate, is this page's input) and the assurance a restore must reach (64 bits is the input), with a full header check kept for large amounts (modeled: the table under Wallet restore volume). The written bound adds what the hashrate input costs under Ghost's rule: at a third of the hashrate the luck of a raised difficulty leaves no assurance, and at a quarter the luck bound is 15.8 bits on a fork of one day (modeled: the luck table under "Written sampling bound for Ghost's difficulty rule").
- **How often a wallet checks its coin:** the 50 MB a month of workload.md allows two authenticated checks a month at one year of chain and one at five (modeled); a larger keep-up ceiling or fewer checks are the two choices.
- **The aggregator fleet:** 104 machines a block at the stated Poseidon2 cost, 156 with the 50 percent spare, against the 40 workload.md proposes; or keep 40, which holds only if a Poseidon2 permutation measures at 93 ns or less (modeled; the cost not yet established).
- **The direct path of a single reveal:** a proof field of at least 2,330,908 bytes in a new transaction version of spec 07, or a single reveal always bundled by someone (modeled).
- **Proven quantum security of recursion:** if no theorem covers recursion with the hash inside the circuit in the quantum random oracle model before mainnet, whether the requirement of spec 09, section 4.1 stays a launch condition (not yet established).
- **The restore ceilings themselves** stay proposals of workload.md; this design meets the download, time, memory and phone storage proposals on a chain of one and five years at the target (modeled), so none of them needs to change for it.
- **Full-node storage growth:** at the 380-byte note of spec 10, section 3.2, an ordinary full node grows 2,412.8 GB a year with this design's trees, against the 2 TB a year workload.md proposes, and its 4 TB disk holds about 1.7 years of it (modeled); whether to raise the proposal to fit it is the founder's decision (the proposal itself not yet established).

## Carried into the third stage

The requirements the first stage carried into the third stage still stand (stage1-verdict.md), with these changes from this design:

- **Real capacity** is now of architecture (c): a real batch, root and shrink on named hardware with memory against the 128 GiB machine (not yet established), replacing the cell model above.
- **Wallet restore at scale** now has a design: what remains is the PIR scheme and its costs at the target's size, the ancestry and parent checks of the written sampling bound and what it leaves open, and a restore and a check timed on real phones (not yet established).
- **Proven security of the whole bundle** now has every term computed (modeled) and five open proof obligations (not yet established), listed under its section.
- **Digest length** and **proof length at the bundle's parameters** are answered by this design (modeled).
- **Public verification proof** now has a design and a proving cost (modeled), and keeps its gas, admission and builder payment (not yet established).
- **State execution** gains the inserts of three indexed trees and the header MMR for every block, inside the 3,000 ms budget of spec 07, section 4 (not yet established).

## Build tickets

These build the chosen design; none is part of this page. Each lists what closes it.

1. **Poseidon2 reveal prover.** The reveal statement proven with Poseidon2 commitments and transcript, the degree-8 extension, 96 queries at blowup 2^3; its proof size against 2,330,908 bytes (modeled) and its proving time and memory on the emulated and named physical phones (not yet established).
2. **Poseidon2 recursion layers.** The batch, root and shrink layers with the verifier binding and domain separation of Aggregation cost, and their failure tests; a timed Poseidon2 permutation and real layer proofs on named hardware, recorded as measured, replacing the cell model (not yet established).
3. **Security write-up.** The estimator run at every layer's parameters, the theorems and their numbers for each term, and the five proof obligations of the security section, ready for the outside review (not yet established).
4. **ML-DSA-44 verification proofs.** The chunk AIR, the public root, the node's binding of account, key and transaction, the raw-signature fallback and the gas of a transaction without its signature (not yet established).
5. **Header MMR and sampled header proof.** The header field, the node's MMR, the wallet's sampler with the ancestry and parent checks its written bound needs, a bound for runs raised on invalid parents, and the RandomX hash and cache times on named phones (not yet established; the bound itself is written under Wallet restore volume, modeled).
6. **Lookup tags, lookup index and coin marker-set tree.** The leaf and header format changes of spec 01 and spec 05 with their golden vectors, reorganisation tests and the node's storage measured at a chain of the target's daily volume (not yet established).
7. **PIR restore server.** The hint tables, the overflow table, the snapshot every 20 blocks (modeled: an input) and a named lattice PIR scheme at 128 classical bits and Category 1, with its communication and server time measured at the target's database sizes (not yet established).
8. **Wallet restore and keep-up.** The probes, follow-ups and checks of this page in the client, with tests that two keys with different coins make the same requests, that a wrong or missing item is refused, and that a spend only on a disconnected block shows unspent (not yet established).

## Reproduce

Every figure above comes from these scripts and records (the script prints every table of this page; the test checks it against the page):

- `benchmarks/scale/stage2.py` and `benchmarks/tests/test_scale_stage2.py`: every figure of this page and its checks.
- `benchmarks/scale/budget.py`, `benchmarks/scale/security_budget.py` and `benchmarks/scale/recursion_costs.py`: the inputs and sums it reuses.
- `docs/scale/recursion-proxy.jsonl`: the measured (proxy) records its seconds a cell come from.
- `benchmarks/scale/labels.py`: the label check.
- `benchmarks/scale/header_sample_bound.py`, `benchmarks/tests/test_header_sample_bound.py` and `client/tests/header_sample_bound.rs`: the written sampling bound's tables, its check against the first slice's `benchmarks/scale/header_sample_bits.py`, Lemma B on the client's rule and the counted header proof bytes.
- `benchmarks/scale/layer_witness.py` and `benchmarks/tests/test_scale_layer_witness.py`: the check that every statement proven with the batch STARK has a row in the table of "Proof library for the layers", that its prover takes only the inputs that row accounts for, and that no row relies on hiding the lookup terminals at a pin that publishes them.
- `docs/scale/stage1-verdict.md`, `docs/scale/workload.md`, `docs/scale/designs.md`, `docs/scale/security.md`, `docs/scale/phone-results.md`, `docs/scale/recursion.md`, `docs/scale/throughput.md`, `docs/scale/public-encoding.md` and `docs/research/recovery-cost.md`: the pages this design reads.

```sh
python3 benchmarks/scale/stage2.py
python3 benchmarks/tests/test_scale_stage2.py
python3 benchmarks/scale/labels.py docs/scale/stage2-design.md
python3 benchmarks/scale/layer_witness.py
python3 benchmarks/tests/test_scale_layer_witness.py
python3 benchmarks/scale/header_sample_bound.py
python3 -m unittest tests.test_header_sample_bound -v
cargo test --manifest-path client/Cargo.toml --test header_sample_bound
```

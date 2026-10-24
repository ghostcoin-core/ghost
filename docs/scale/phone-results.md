# Phone results: the reveal on a physical phone, and wallet restore at scale

This page holds the phone side of the feasibility work of the first stage of the scale work: the private reveal on named physical phones, and wallet restore and catch-up of an old key against a simulated mature chain. It follows the rules of designs.md and judges against the reference phone ceilings of workload.md, which do not change here.

Every figure carries one of the labels of workload.md: **measured** (actually run, the machine named), **modeled** (a formula or stated inputs) or **not yet established** (with the command or hardware that would produce it). No physical phone was reachable where this page was written: every physical-phone figure is not yet established, and the emulated figures below stay labelled emulated. The restore side is a tested model, benchmarks/scale/restore_sim.py, tested by benchmarks/tests/test_scale_restore.py; none of its figures was run on a phone.

## Reveal on a physical phone

Parameters: the chosen leaf parameters are not yet established (security.md finds 92 queries at blowup 2^3 for the query phase, modeled, but leaves the whole bound and the proof length at those parameters not yet established). Every row below is the shipped configuration, `keccak-256/hiding-fri/blowup-2^3/queries-43/grinding-q16-b16-o0/ext-5/zk` for the real reveal (blowup 2^3, 43 queries, modeled in security.md), except the benchmark statement rows, whose own configuration is blowup 2^3 with 38 queries (measured in docs/benchmarks/results.md).

The commands are those of phone-protocol.md; "step" names its step. Every emulated figure is the Mac Studio's Chrome with its renderer throttled, not a real device.

| Hash candidate and exact construction | Statement | Thread mode | Physical phone | Emulated mid-range phone, not a real device |
|---|---|---|---|---|
| Keccak-256; Keccak-f\[1600\] padding-free sponge of proofs/src/stark.rs | coin reveal | eight threads (`wasm-threads`) | not yet established: protocol step 4 on a named mid-range phone | measured, emulated, 2026-10-23: cold median 5.20 s, warm median 4.11 s, WebAssembly memory 630.1 MiB; the renderer's total memory was not read |
| Keccak-256; the same sponge | coin reveal | threads unavailable (no cross-origin isolation, `wasm-single`) | not yet established: protocol step 5 | not yet established: no emulated run without isolation exists |
| Keccak-256; the same sponge | coin reveal | one thread, threads available (reveal.html, `wasm-single`) | not yet established: protocol step 6 | measured, emulated, 2026-10-21: cold median 15.02 s (slowest 17.39 s), warm median 13.15 s, WebAssembly memory 596.8 MiB, renderer peak median 935.0 MiB (macOS footprint of the throttled Mac tab, not a phone's) |
| Keccak-256; the same sponge | salted coin reveal | eight threads (`wasm-threads`) | not yet established: protocol step 6 | measured, emulated, 2026-10-23: cold median 5.51 s, warm median 4.20 s, WebAssembly memory 632.5 MiB |
| Poseidon2 over BabyBear, width 24 (benchmarks/prover) | the benchmark statement, the Poseidon2 equivalent statement | one thread (`wasm-single`) | not yet established: protocol step 7 | measured, emulated, date not recorded in docs/benchmarks/results.md: cold median 1.93 s, warm median 1.71 s, WebAssembly memory 10.7 MiB, process memory median 73.9 MiB |
| Keccak-256; padded Keccak-256 of benchmarks/prover/src/keccak.rs | the benchmark statement | one thread (`wasm-single`) | not yet established: protocol step 7 | measured, emulated, as the row above: cold median 4.91 s, warm median 4.47 s, WebAssembly memory 260.0 MiB, process memory median 321.7 MiB |
| Poseidon2 over BabyBear, width 24 | coin reveal | any | not yet established: no Poseidon2 prover of the real reveal exists (a Rust change outside this piece) | not yet established |

Against the ceilings of workload.md (proving at most 10 s cold or warm, modeled as the input; at most a proposed 1 GiB for the whole tab, not yet established): whether any physical phone meets them is not yet established. The emulated rows are not judged as phones. Two of them bear on what to look for (both measured, emulated): the single-thread reveal misses the time ceiling on the emulation, and the emulated renderer's 935.0 MiB is already close to the proposed 1 GiB, so the threads-unavailable run and the browser memory of step 3 are the likeliest failures on a real phone.

The Poseidon2 comparison above is on the benchmark statement only (both of its rows, measured, emulated): its shape is the same for both hashes, but it is lighter than the real reveal and its Keccak is the padded construction, not the reveal's sponge. Poseidon1 or KoalaBear records do not apply to it.

## Restore and catch-up

A clean restore today downloads every leaf and note from page 0, 188 bytes each (modeled: spec 05, section 8), trial-decrypts every note and checks notes and markers against bulk receipts; at 10 million new leaves a day that is 1.88 GB a day and 686.2 GB a year before receipts, markers and public commits (modeled, workload.md). Below are the baseline and two candidate alternatives, simulated on a chain of 100,000 leaves and extrapolated to one and five years at the target (all modeled). None of them is chosen here.

### The designs

- **Baseline.** Spec 05, section 8 as written: the page-root list, every page from page 0, every note trial-decrypted, every spent marker from the scan start read in bulk. Its requests are the same for every wallet (tested), so an endpoint learns nothing about which commitment is the wallet's: the privacy set is the whole chain. <!-- no-figure -->
- **Buckets: note tags with fixed decoy pages.** The design C of docs/research/recovery-cost.md, a candidate. A 4-byte tag, bound to the leaf, takes the first bytes of the note's nonce, so the note stays 156 bytes (modeled). The wallet reads the leaf and the tag of every leaf in bulk (36 bytes a leaf, modeled), finds its hits, then fetches the other 152 bytes of the notes only by whole pages (modeled): each hit page together with 15 decoy pages derived from the key and the page number, and at least 64 pages in all (both model inputs, modeled), in one request in page order. It needs a tag column with its own header root, a change to the note and header formats (a founder decision). It never downloads more than the baseline: it skips 152 bytes of each note it does not fetch (tested).
- **Checkpoint: scan from the key's birth epoch.** Design F of the same page, a candidate. The wallet holds a coarse birth epoch with the key (30 days of leaves at the target, a model input, modeled) and scans whole pages from the start of that epoch. It needs the epoch carried with the key: inside the digits it changes the key format (spec 01); outside them, "the digits are all you need" holds only with a fallback to the baseline when the epoch is lost.

Why these two: they are the two candidates of recovery-cost.md that cut volume or processing with no new trust in a service and no elliptic-curve part. Single-server PIR (design H there) hides the fetch better than decoys, but its cost for these records is not yet established, so it is not modeled here.

Privacy argument:

- Baseline: no request names a commitment, a position or a marker (spec 05, section 8); an endpoint learns only the scan start.
- Buckets: the bulk columns name nothing. The note fetch names pages: each hit page hides among its 15 decoys, so a coin is narrowed to the requested pages and no further (65,536 commitments a hit, modeled). The decoys are fixed by the key and the page, so a later restore asks for the same pages and an endpoint cannot intersect two requests to find the real one; padding to 64 pages hides the number of hits up to four (both modeled from the inputs). What it gives up: the request size tells an endpoint roughly how many hits a wallet has beyond four, and the fixed decoys link a key's restores to each other. Recovery-cost.md calls decoys a weak shield and PIR the target.
- Checkpoint: an endpoint learns the epoch the key was made in, the same kind of fact spec 05 already accepts for a scan start ("roughly when the wallet last synced"). A coin is narrowed to the leaves from that epoch on.

The privacy measure in the tables is the smallest set of commitments an endpoint can narrow the wallet's coins to, and the fraction of the chain it learns the wallet did not need.

Spent status: every design reads every canonical spent marker from its scan start in bulk, never one marker, and takes status only from the canonical chain (designs.md, rule 2). The tests show that a coin spent only on a disconnected block is unspent, that a restore which skips the check or takes status from unchecked marker hints is flagged, and that a status not checked is "unknown". Markers are counted at 32 bytes each, one per new leaf at the target (10 million spends and 10 million leaves a day, modeled). The receipt framing that authenticates notes and markers is not counted: its layout is open (spec 05, section 12), and recovery-cost.md models about 285 bytes a leaf more for it (modeled there).

### Inputs

| Input | Value | Label |
|---|---|---|
| Leaf and note | 32 + 156 = 188 bytes | modeled: spec 05, section 8 |
| Page and page root | 4,096 leaves, 32 bytes | modeled: spec 05, section 8 |
| New leaves and spends a day | 10,000,000 each | modeled: the target, workload.md |
| Phone link | 5,000,000 bytes a second (50 Mbit/s at 80 percent) | not yet established: workload.md states no phone link speed; the assumption of recovery-cost.md |
| Trial decryption of one note on the phone | 1,148 ns | not yet established on a phone: 287 ns measured on the build machine (the slowest of three runs of the client crate's real `restore_coins`, an aarch64 Linux virtual machine on the Mac Studio, 2026-10-20, recovery-cost.md) times its assumed phone slowdown of 4 |
| One hash a leaf (page root, tag check) on the phone | 680 ns | not yet established on a phone: 170 ns a leaf measured on the same machine for the page root (the client's tagged Keccak-256), times 4 |
| Notes of the key | 52 a year, each on its own page, the key one year old | not yet established: the assumption of recovery-cost.md (one a week) |
| Simulated chain | 100,000 leaves, 8 notes of the key on 8 pages from leaf 50,000, epoch of 16,384 leaves | modeled: the module's test chain, seed fixed |

The 131 ns Keccak-f\[1600\] permutation of docs/benchmarks/reveal-parameters.md (measured there) is the reveal prover's Merkle leaf hash in the padding-free sponge, not the note's decryption, so it is not used. The simulation's own hashes are stand-ins and are evidence about no primitive.

Elapsed time is the download at the phone link plus the processing, one after the other (modeled, an upper bound). Peak memory is the page-root list, one page of leaves and notes and one of markers, and the leaves of the key's own pages for its witnesses (modeled); storage is the page-root list and those leaves (modeled). Neither is measured.

### Results

| Design and chain (all modeled) | Leaf and note bytes | Total download, with page roots and markers | Trial decryptions | Elapsed time | Peak memory | Storage | Privacy: smallest set, fraction learned not needed |
|---|---|---|---|---|---|---|---|
| Baseline, simulated 100,000 leaves (modeled) | 18,800,000 | 22,000,800 (22.0 MB) | 100,000 | 4.58 s | 1.95 MB | 1.05 MB | the whole chain, 0 |
| Buckets, simulated (modeled) | 18,800,000: the request covers all 25 pages | 22,000,800 (22.0 MB) | 8 found, at most 9 | 4.54 s | 1.95 MB | 1.05 MB | the whole chain, 0 |
| Checkpoint, simulated (modeled) | 9,559,424 | 11,187,360 (11.2 MB) | 50,848 | 2.33 s | 1.95 MB | 1.05 MB | 50,848 leaves, 49.2 percent |
| Baseline, one year (modeled) | 686,200,000,000 (686.2 GB) | 803,028,515,648 (803.0 GB) | 3,650,000,000 | 167,278 s (46.5 hours) | 36.2 MB | 35.3 MB | the whole chain, 0 |
| Buckets, one year (modeled) | 131,927,958,016 (131.9 GB) | 248,756,473,664 (248.8 GB) | 53 | 54,715 s (15.2 hours) | 36.2 MB | 35.3 MB | 3,473,408 leaves (848 pages), 99.9 percent |
| Checkpoint, one year, key made at genesis (modeled) | 686,200,000,000 (686.2 GB) | 803,028,515,648 (803.0 GB) | 3,650,000,000 | 167,278 s (46.5 hours) | 36.2 MB | 35.3 MB | the whole chain, 0 |
| Baseline, five years (modeled) | 3,431,000,000,000 (3.43 TB) | 4,015,142,578,144 (4.02 TB) | 18,250,000,000 | 836,390 s (9.7 days) | 150.3 MB | 149.4 MB | the whole chain, 0 |
| Buckets, five years (modeled) | 657,567,803,904 (657.6 GB) | 1,241,710,382,048 (1.24 TB) | 57 | 273,162 s (75.9 hours) | 150.3 MB | 149.4 MB | 3,735,552 leaves (912 pages), 99.98 percent |
| Checkpoint, five years, key one year old (modeled) | 723,800,000,000 (723.8 GB) | 847,142,578,144 (847.1 GB) | 3,850,000,000 | 176,466 s (49.0 hours) | 150.3 MB | 149.4 MB | 3,850,000,000 leaves, 78.9 percent |

The buckets design's trial decryptions are its tag hits: the key's notes plus the expected false hits of a 4-byte tag, one in 2^32 leaves, rounded up (modeled). The simulated rows of the baseline and the checkpoint equal the simulation exactly; the buckets row is the analytic upper bound, and the simulation stays at or under it (tested). At the simulated size the buckets design gains nothing: 16 pages for each of 8 hits is more than the chain's 25 pages, so it fetches every note (modeled); with one decoy a hit and at least four pages it fetches 16 pages or fewer and saves bytes (tested).

Catch-up and headers (modeled):

| Item | Baseline | Buckets | Checkpoint |
|---|---|---|---|
| Keeping up for 30 days: leaf and note bytes (modeled) | 56,400,000,000 (56.4 GB) | 10,849,807,360 (10.8 GB), with 5 hit pages | 56,400,000,000: an up-to-date wallet already scans from its last page |
| Keeping up for 30 days: marker bytes (modeled) | 9,600,000,000 (9.6 GB) | the same | the same |
| Headers from genesis on a clean device, one year (modeled) | 611,798,400 (611.8 MB): 2,880 blocks a day of 582 bytes, for every design alike | the same | the same |
| The same, five years (modeled) | 3,058,992,000 (3.06 GB) | the same | the same |

Headers are outside every tree design: a clean device can trust no header but genesis (recovery-cost.md, section 3.3), so it downloads and checks all of them, and checking their seals takes days a year of chain on a phone (modeled there). On their own they are over the proposed restore download ceiling after about 298 days (modeled: 500 MB at 1,676,160 bytes a day).

### Against the reference phone ceilings

The ceilings are the proposals of workload.md, each not yet established; the target does not change.

| Ceiling (workload.md) | Baseline | Buckets | Checkpoint |
|---|---|---|---|
| Full restore download, proposed 500 MB (not yet established) | met on the simulated chain; missed at one year (803.0 GB) and five (4.02 TB), modeled | met on the simulated chain; missed at one year (248.8 GB) and five (1.24 TB), modeled | met on the simulated chain; missed at one year (803.0 GB) and five (847.1 GB), modeled |
| Keeping up, proposed 50 MB a month (not yet established) | missed: 66.0 GB a month with markers, modeled | missed: 20.4 GB a month with markers, modeled | missed, as the baseline, modeled |
| Restore time, proposed 10 minutes (not yet established) | met on the simulated chain; missed at one year (46.5 hours) and five (9.7 days), modeled | met on the simulated chain; missed at one year (15.2 hours) and five (75.9 hours), modeled | met on the simulated chain; missed at one year (46.5 hours) and five (49.0 hours), modeled |
| Memory, proposed 1 GiB for the whole tab (not yet established) | met at every size: at most 150.3 MB, modeled | met, as the baseline, modeled | met, as the baseline, modeled |
| Storage, proposed 200 MB of wallet data (not yet established) | met at one year (35.3 MB) and five (149.4 MB), modeled; the page-root list grows 28.5 MB a year, so it passes 200 MB at about 6.8 years (modeled) | the same, modeled | the same, modeled |

So, modeled: no candidate keeps "the digits are all you need" within the proposed download and time ceilings on a chain of a year or more at the target. Volume, not processing, sets the cost: the download is about 96 percent of the baseline's elapsed time at one year (modeled: 160,606 s of 167,278 s). The buckets design cuts the full-restore download about 3.2 times at one year (modeled: 803.0 GB to 248.8 GB) and leaves the spent markers as the larger part; the checkpoint helps only a key much younger than the chain. Meeting the download ceiling needs a further cut of about 500 times (modeled: 248.8 GB against 500 MB), which none of these designs gives; what to do about it is for the later verdict, not this page.

### What is not yet established

- Every restore figure on a real phone: download, time and memory on the reference phone against a chain of the target size (workload.md names the command: timing a restore on a real phone). The client crate's restore against a generated chain at the target's daily volume would replace the processing inputs above.
- The phone's trial-decryption and hashing cost (the inputs above are a build-machine measurement times an assumed slowdown of 4, not yet established).
- The receipt layout and its bytes (spec 05, section 12), and an authenticated compact source of spent markers; the totals above are before receipts.
- The cost and fit of PIR for the note fetch, the design that would hide the fetch better than decoys.

## How the figures were produced

The modeled restore figures are the output of benchmarks/scale/restore_sim.py (`analytic` and `restore`), checked figure by figure by benchmarks/tests/test_scale_restore.py:

```sh
python3 benchmarks/tests/test_scale_restore.py
python3 benchmarks/scale/restore_sim.py
python3 benchmarks/tests/test_scale_phone_records.py
```

The phone records format and its validator are benchmarks/scale/phone_records.py, tested with synthetic records only; no phone record exists yet.

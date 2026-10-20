# Research: what it costs a holder to recover a coin without a service

Status: research plus measurements, 2026-10-20. Write-up only; no program code
is added to this repository. Every measured number comes from one machine
(section 2) and from code already in this repository; every number that needs a
phone or a real network is an assumption and is marked as one. Nothing here
changes a specification. The recommendation in section 6 is for the founder to
accept or change.

## 1. Summary

The question: if honest self-recovery costs hundreds of GB, holders will use a
few big service operators in practice, and the trust and privacy exposure that
the protocol removes comes back. [Specification 05](../spec/05-trees-and-headers.md)
(section 9, and section 14, question 4) puts a full scan at 188 bytes per leaf, about 807 GB
for a full tree. This write-up measures that and compares ways to cut it.

What we found:

1. **The spec 05 figure is too low.** A restore must also fetch the block
   receipts that authenticate every note and marker (spec 05, section 8,
   item 5). With the receipt layout spec 05 requires, that adds about 285 bytes
   per leaf, so a scan as written costs about 470 bytes per leaf, not 188: about
   2.0 TB for a full tree, not 807 GB (section 3.2).
2. **The pages are not needed for the scan.** The receipts already carry the
   leaf, its position and its note. A wallet that scans receipts only, and
   fetches pages only for the witness, pays about 285 bytes per leaf (1.2 TB
   per full tree). This needs no change to any consensus format and no change to
   what an endpoint can see (section 5, design B).
3. **Cost follows the number of leaves, and an attacker sets that number.**
   Commits cost only gas and 1 wei (spec 03), so under a sustained flood of
   cheap commits a tree can fill in about 3.3 years (assumption: commit gas at
   its floor, section 3.4). Honest use cannot fill one (a block holds at most
   one private transaction, spec 07), so the 945 GB figure is a bound set by
   whoever pays to fill the tree, not by honest use.
4. **Headers set the time, and on a clean device often the bytes.** A wallet
   that kept its checked headers resumes from the last one. A wallet on a clean
   device has no header it can trust except genesis (fork choice is the
   heaviest chain, and checkpoint overrides are forbidden), so it downloads and
   checks every header from genesis, however recent the key's scan start is.
   That is 612 MB per year of the chain's age (746 MB with the tag design's
   longer headers), and checking every seal costs 6.8 hours per year on one
   core with the reference RandomX library and about 73 hours with the Rust
   port the client crate uses (section 3.3). On a 10-year-old chain the headers
   alone are 6.1 GB (7.5 GB with tags). In time this is the larger part of a
   clean-device restore at every load; in bytes it is the larger part with the
   tag design. It is outside the tree format and is listed as an open item
   (section 7).
5. **One design cuts the per-leaf cost about 8 times against receipts-only
   scanning, and it holds against an attacker who copies tags: a 4-byte note
   tag bound to the leaf, with a header-committed root over the tags.** The
   wallet reads 36 bytes per leaf (the leaf and its tag) instead of 285, and
   then pays a private fetch for every note it finds: about 2.5 MB each with
   PIR (an assumption from published figures) or about 20 MB each with 16
   decoys (section 4.1). It uses
   only hashing (quantum-safe), adds no bytes to the 156-byte note, and keeps
   the bulk-scan privacy of spec 05. It must be decided before the note layout
   and the header are frozen (section 5, design C; section 6). A cheaper
   variant with no leaf in the column (4 bytes per leaf) was found to break
   under an attacker who copies a victim's tag, and is not recommended
   (design C4).
6. **The time to check the headers is not solved by any tree design** and is
   the largest part of a clean-device restore in time: 12 days of seal checks
   per year of the chain's age on the assumed phone with the Rust port
   (section 3.3).
   The targets below are on bytes downloaded, not on time to finish, and a
   restore is not "5 minutes" until that is solved (section 7).

Recommended target (section 6), on bytes, with the header chain counted
separately because no tree design changes it: for a key at most one year old
at the busy load of section 3.4, the scan downloads at most 1 GB and each note
found costs at most 5 MB more to fetch privately; any scan downloads at most
50 GB per year of history, headers included, even under a flood at the gas
floor. On a clean device the headers from genesis come on top: 612 to 746 MB
per year of the chain's age. Receipt-only scanning (design B) meets none of
the scan targets; the tag design (C) meets them with PIR, and with decoys it
meets the scan targets but not the per-note one. **No design meets an all-in
figure such as "2 GB" on a chain older than about a year**: a one-year-old key
with 52 notes on a 10-year-old chain costs about 8.0 GB with C and PIR, 8.8 GB
with 365 notes (section 4.3). An all-in target needs a shorter header proof,
which is an open item (section 7).

## 2. What was measured, what was computed, what is assumed

| Kind | Item | Source |
|---|---|---|
| Measured | Trial decryption of notes, the real `restore_coins` of the client crate (section 3.1) | Run on this machine, 2026-10-20 |
| Measured | Page-root recomputation with the client's tagged Keccak-256 (section 3.1) | Run on this machine, 2026-10-20 |
| Measured | RandomX light-mode hash of the Rust port in the client crate (section 3.3) | Run on this machine, 2026-10-20 |
| Measured earlier | RandomX light-mode hash, C++ reference with JIT, 23.4 ms | [RandomX survey](../surveys/randomx.md) |
| Measured | Header size, 582 bytes | Vector `header-block-one-example`, spec 05, section 11 |
| Computed | Receipt sizes of the layout spec 05 requires, by RLP encoding (section 3.2) | Layout is an assumption: spec 05, section 12, item 5, leaves it open |
| Computed | Bytes and download time for every design, from the parameters of specs 05 and 07 | Section 4 |
| Assumption | A phone is 4 times slower than one core of this machine | The browser benchmark in `docs/benchmarks/results.md` uses the same factor (4x CPU throttle) |
| Assumption | A 50 Mbit/s link at 80 percent use, so 5 MB/s; 1 GB takes 3.3 minutes | Chosen here; no real phone or network was available |
| Assumption | Load levels: 0.1, 10 and 1,240 leaves per block (section 3.4) | Chosen here; no usage data exists |
| Assumption | A commit costs 24,200 gas at the floor (21,000 base plus 200 bytes at 16 gas) | Chosen here; the commit's gas is not fixed by any specification |
| Assumption | A key receives 12, 52 or 365 notes a year (one a month, a week, a day), each on a different page (section 4.1) | Chosen here; no usage data exists |
| Assumption | A private fetch of one note by PIR, with its receipt and the receipt's proof, costs 2.5 MB (section 4.1) | The YPIR figure as published for a 32 GB database; not measured here and not for these records |
| Assumption | No header after genesis is trusted without checking it; a clean device holds none (section 3.3) | Spec 05 fork choice (heaviest chain, spec 06); release builds carry no checkpoint override (decision 0001) |

**Machine.** The reference machine is the Mac Studio (Apple silicon, aarch64),
measured inside its 16-core Linux virtual machine with 46 GB of memory, as the
other benchmarks of this repository were. Rust 1.99.1, release build,
portable code: the `tiny-keccak` and `chacha20poly1305` crates the client
already uses, with no use of the processor's SHA-3 instructions, so the figures
are conservative for hardware that has them. **No phone was available.** Every
phone figure below is the reference figure times 4, stated as an assumption, and
no phone figure is a measurement.

## 3. Measurements

### 3.1 Compute per leaf is small

A synthetic coin tree of 1,048,576 random leaves with random 156-byte notes (so
every note is a miss, the case that dominates a restore) was run through the
client crate's real `restore_coins`, and the page root of 64 pages of 4,096
leaves was recomputed with the client's `hash::k` and the coin tree node tag.

| Step | One thread | Notes |
|---|---|---|
| Trial decryption, miss | 279 to 287 ns per leaf (about 3.5 million leaves per second) | Three runs |
| Same, 2 / 4 / 8 / 16 threads | 6.9 / 13.1 / 26.2 / 34.6 million leaves per second | One run each |
| Page root, 4,095 node hashes per page | 0.68 to 0.70 ms per page (about 170 ns per leaf) | Three runs |
| Both together | about 450 ns per leaf | |

At 450 ns per leaf a full tree of 2^32 leaves takes 32 minutes on one thread
and about 3 minutes on 16. On the assumed phone (4 times slower, one thread) it
is 2.2 hours. Next to the download times in section 4 (days) compute is not the
limit. **The cost of recovery is bandwidth.**

### 3.2 Bytes per leaf

Spec 05 counts the pages: 32 bytes of leaf plus 156 bytes of note is 188 bytes,
plus 32 bytes of page root per 4,096 leaves (0.008 per leaf). It does not count
the receipts that spec 05, section 8, item 5 requires for every block from the
scan start. A receipt of a transaction that appends a leaf must carry the leaf,
its tree index, its position and its note, and the receipt of a reveal also its
marker (section 12, item 5). The layout is not fixed. This write-up takes the
smallest honest one: one log per leaf with one topic, data of 32 (leaf) + 8
(tree index) + 8 (position) + 156 (note) = 204 bytes, and one more log of 32
bytes for a marker, encoded in RLP as the base client encodes receipts.

| Receipt of | Without logs bloom | With the 256-byte bloom |
|---|---|---|
| A commit (one leaf) | 276 bytes | 535 bytes |
| A reveal (one leaf and one marker) | 366 bytes | 625 bytes |

The bloom can be left off the wire because a receiving node rebuilds it from
the logs before checking `receiptsRoot`; the figures below use the smaller
column. In a mix of nine commits to one reveal a leaf's receipt is 285 bytes on
average. Ordinary transfers in the same blocks add their own receipts, which
are not counted here.

| Scan design | Bytes per leaf | Full tree of 2^32 leaves |
|---|---|---|
| Spec 05 as written (pages plus receipts), A | 188 + 0.008 + 285 = about 473 | 2.0 TB |
| Receipts only, B | 285 + 0.008 = about 285 | 1.2 TB |
| Pages only, notes authenticated by a header root (section 5, design D) | 188 + 0.008 | 807 GB |
| Leaf column plus tag column, C | 32 + 4 = 36 | 154.6 GB |

Spec 05's own 807 GB is the third row and holds only if a header carries a root
over the notes, which spec 05 does not have (review F3 is why the receipts are
fetched instead).

### 3.3 Headers

A header-only wallet checks every note, root and receipt against headers it
holds, so it needs a header at its scan start that it knows is on the
canonical chain. Two cases differ here:

- **Resync from cached headers.** A wallet that kept the headers it already
  checked continues from the last one. It downloads and checks only the headers
  since then; its scan start and its header start are the same point.
- **Clean-device recovery.** A wallet that holds only the key (and perhaps a
  scan-start hint, design F) has no checked header. A hint bounds where the
  note search begins; it does not authenticate a header at that point, nor the
  work of the chain before it, and a peer can serve a well-sealed but
  non-canonical branch that starts there. Canonical means heaviest total
  difficulty from genesis (spec 05, section 2; spec 06), and release builds
  carry no checkpoint override (decision 0001), so the only starting point the
  wallet can authenticate on its own is genesis. **A clean-device restore
  therefore downloads and checks every header from genesis**, whatever its
  scan start. No independently authenticated later starting point exists
  today; a header the holder wrote down by hand, or a succinct proof of the
  chain's work, would be one, and both are open items (section 7).

At 582 bytes per header and 1,051,200 blocks per year that is 612 MB per year,
12 MB per week, counted over the chain's age on a clean device and over the
time since the last sync on a resync. With the four extra roots of design C a
header is 710 bytes, 746 MB per year. The wallet also checks each header's
RandomX seal (spec 08).

| Seal check, one header | Time | Source |
|---|---|---|
| C++ reference, light mode, JIT, one thread | 23.4 ms | RandomX survey, 5 runs |
| Same, interpreter | 92 ms | RandomX survey |
| Rust port in the client crate, one thread | 250.5 ms (200 hashes); 32 ms per hash aggregate over 8 threads | This write-up |
| Cache build per key block (once per 8,192 blocks) | 0.52 s | This write-up |

| Headers to check (chain age, or time since last sync) | Headers | Download at 50 Mbit/s | Seal checks, C++ JIT, 1 thread | Seal checks, Rust port, 1 thread | Rust port, assumed phone (x4) |
|---|---|---|---|---|---|
| 1 week | 20,160 | 12 MB, 2 s | 7.9 min | 84 min | 5.6 hours |
| 1 year | 1,051,200 | 612 MB, 2 min | 6.8 hours | 73 hours (3.0 days) | 12 days |
| 10 years | 10,512,000 | 6.1 GB, 20 min | 68 hours | 30 days | 122 days |

The Rust port is interpreted and unoptimised (the survey measured the same
class of implementation, a Go port, at 316 ms). It is what a browser or phone
wallet built from the client crate would run today, which is why it is shown.
These times are about the chain's design, not the tree's, and no choice in
this write-up changes them (section 7).

### 3.4 How fast trees fill

A block holds at most one private transaction: `G_PRIV` is 21,090,372 gas
against a gas limit of 30,000,000 (spec 07, section 2). So reveals append at
most one leaf per block, 1,051,200 a year. Commits and data commits are public
transactions with no minimum amount above 1 wei (spec 03, section 6, step 6),
so the gas is the only brake. At the floor of 24,200 gas, a block holds 1,239
commits.

| Load | Leaves per block | Leaves per year | Time to fill one tree of 2^32 |
|---|---|---|---|
| Low (early network) | 0.1 | 105,120 | about 41,000 years |
| Busy (assumption) | 10 | 10.5 million | about 408 years |
| Flood at the gas floor | 1,240 | 1.30 billion | 3.3 years |
| Flood if a commit costs 100,000 gas | 300 | 0.32 billion | 13.6 years |

Only the base fee of the chain's own fee market stands between a flood and
these numbers; it is not analysed here. The point for recovery is that the
scan cost of every holder is set by the number of leaves other people pay to
add, not by anything the holder does.

## 4. Cost for a holder

Three holders, as the ticket asks, at the three loads of section 3.4. A is
the scan as spec 05 is written (pages plus receipts plus headers); B scans
receipts only (plus headers); C is the tag design of section 5 (36 bytes per
leaf, headers that are 128 bytes longer for four more roots, and one 32-byte
marker per block at most). A completed recovery has three parts, and this
section counts all three:

1. **The scan** of the key's span, from its scan start (section 4.2).
2. **The retrieval** of every note the scan finds, genuine or false, with
   what authenticates it (section 4.1). In A and B this is free: the scan has
   already downloaded every note of the span with its receipt. In C it is a
   separate private fetch per hit.
3. **The headers**: since the last sync on a resync, and from genesis on a
   clean device (section 3.3).

Times are downloads only, at 50 Mbit/s (5 MB/s).

- **Kept their scan start and their device:** a resync from cached headers;
  the rows "1 week" and "1 month" of section 4.2, which count headers over the
  same span. Retrieval adds one or a few notes.
- **Lost the device but kept a scan-start hint** (design F): the scan covers
  the key's age, but the headers cover the chain's age (section 4.3).
- **Lost both:** the scan and the headers both start at genesis (section 4.3,
  and the "10 years" rows of section 4.2 on a 10-year-old chain).
- **Worst case:** from genesis, through a tree that filled and the next ones;
  the end of section 4.2.

### 4.1 Retrieving what the scan finds

The tag scan of design C finds a hit's position but not its note. The note
must be fetched, authenticated and checked, without the fetch naming the
position (spec 05, section 8). Per hit:

- **Authentication.** The note is checked against the receipt that appended
  the leaf, and that receipt against the block's `receiptsRoot` in a header the
  wallet already holds (spec 05, section 8, item 5). The witness needs nothing
  more: the leaf column already holds every leaf of the span. Marker status
  comes from the marker roots design C assumes, already in the scan.
- **With PIR (design H), the target.** One query returns one record, the
  receipt with its proof in the block's receipt trie (a few KB). The cost per
  query is taken as **2.5 MB, an assumption**: it is the published YPIR figure
  for a 32 GB database, not measured here and not for records of this size.
- **With decoys, the interim.** A request for one receipt names the
  transaction, so the wallet instead fetches the block receipts of the hit's
  whole page together with those of a fixed set of decoy pages (section 5,
  design C, privacy). The receipts of one page are 4,096 x 285 = 1.17 MB, so
  one hit with 16 decoys costs 17 x 1.17 = **19.8 MB**, and with 256 decoys
  300 MB. The decoy set of a page is fixed, so two hits on the same page cost
  one fetch; the figures below assume every note is on a different page.
- **False hits.** A 32-bit tag matches a stranger's leaf with chance 2^-32: a
  year at the busy load (10.5 million leaves) gives 0.002 false hits, a year of
  flood (1.30 billion) 0.30, a full tree about 1. Each costs one fetch as above
  and is then discarded when its note fails to open the leaf (spec 01,
  section 8, step 4). Under a flood at the gas floor this adds about 0.8 MB a
  year with PIR or 6 MB with 16 decoys; elsewhere it is negligible.

Neither the target nor the protocol can cap how many notes a holder receives,
so retrieval is stated per note, under three usage assumptions:

| Notes found in the span | A, B | C with PIR | C with 16 decoys | C with 256 decoys |
|---|---|---|---|---|
| One | 0 (in the scan) | 2.5 MB | 19.8 MB | 300 MB |
| 12 (a month for a year) | 0 | 30 MB | 238 MB | 3.6 GB |
| 52 (a week for a year) | 0 | 130 MB | 1.03 GB | 15.6 GB |
| 365 (a day for a year) | 0 | 913 MB | 7.24 GB | 110 GB |

With 256 decoys, retrieval is larger than the scan for any regular use, and
even 16 decoys cost more than a year's busy scan (412 MB) once a key has more
than about 20 notes. Decoys are a stopgap for a few hits; PIR is required for
design C to keep its advantage.

### 4.2 The scan of a span

These tables count the scan with the headers of the same span: the cost of a
resync from cached headers, or of a clean-device restore on a chain no older
than the span. They leave out retrieval (section 4.1) and, for a clean device
on an older chain, the headers before the span (section 4.3).

#### Low load, 0.1 leaf per block

| History | Leaves | A | B | C | A time | C time |
|---|---|---|---|---|---|---|
| 1 week | 2,016 | 13 MB | 12 MB | 15 MB | 3 s | 3 s |
| 1 month | 8,640 | 54 MB | 53 MB | 64 MB | 11 s | 13 s |
| 1 year | 105,120 | 662 MB | 642 MB | 784 MB | 2 min | 3 min |
| 5 years | 525,600 | 3.3 GB | 3.2 GB | 3.9 GB | 11 min | 13 min |
| 10 years | 1,051,200 | 6.6 GB | 6.4 GB | 7.8 GB | 22 min | 26 min |

At this load the headers are 92 to 96 percent of every total, and C is slightly
worse than B because its headers are longer. The tags pay off above about 0.65
leaf per block.

#### Busy load, 10 leaves per block (assumption)

| History | Leaves | A | B | C | A time | C time |
|---|---|---|---|---|---|---|
| 1 week | 201,600 | 107 MB | 69 MB | 22 MB | 21 s | 4 s |
| 1 month | 864,000 | 459 MB | 297 MB | 95 MB | 2 min | 19 s |
| 1 year | 10,512,000 | 5.6 GB | 3.6 GB | 1.2 GB | 19 min | 4 min |
| 5 years | 52,560,000 | 27.9 GB | 18.0 GB | 5.8 GB | 1.6 hours | 19 min |
| 10 years | 105,120,000 | 55.8 GB | 36.1 GB | 11.6 GB | 3.1 hours | 39 min |

#### Flood at the gas floor, 1,240 leaves per block (assumption)

| History | Leaves | A | B | C | A time | C time |
|---|---|---|---|---|---|---|
| 1 week | 25.0 million | 11.8 GB | 7.1 GB | 915 MB | 39 min | 3 min |
| 1 month | 107 million | 50.7 GB | 30.6 GB | 3.9 GB | 2.8 hours | 13 min |
| 1 year | 1.30 billion | 617 GB | 372 GB | 47.7 GB | 34 hours | 2.7 hours |
| 5 years | 6.52 billion | 3.1 TB | 1.9 TB | 239 GB | 7.1 days | 13 hours |
| 10 years | 13.0 billion | 6.2 TB | 3.7 TB | 477 GB | 14 days | 26 hours |

**Worst case, one full tree of 2^32 leaves from page 0 (a lost key, in a
flooded network):** A is 2.0 TB (4.6 days at 50 Mbit/s), B is 1.2 TB (2.8
days), C is 154.6 GB (8.6 hours). The page-root list of a full tree is 34 MB
(1,048,576 roots of 32 bytes) in every design. Headers for the 3.3 years that
fill such a tree are another 2.0 GB (2.6 GB with C's longer headers and its
markers), more on a clean device if the chain is older, and their seal checks
are in section 3.3. C then retrieves about one false hit and every note found
(section 4.1).

Reading the tables: at the busy load, on a chain one year old, a one-year-old
key costs 5.6 GB under the spec as written (19 minutes) and 1.2 GB with tags
(4 minutes) before retrieval; with retrieval by PIR the tag design is 1.29 GB
for 52 notes and 2.07 GB for 365 (section 4.3). Under a flood the tag design is
8 times smaller than B but still tens of GB a year: the leaf column cannot be
skipped when the tag is bound to the leaf (section 5).

### 4.3 Completed clean-device recovery

All three parts together, for a holder on a clean device: headers from genesis
(chain age), the scan from the scan start (key age with a hint, chain age
without), and the retrieval of every note found plus the expected false hits.
Busy load unless the row says flood; in the flood row the key's one year is
flooded and the nine years before it are not scanned. Usage is the assumption
of section 4.1.

| Chain age, scan span, notes found | A | B | C with PIR | C with 16 decoys |
|---|---|---|---|---|
| 1 year, 1 year, 52 | 5.6 GB | 3.6 GB | 1.29 GB | 2.19 GB |
| 1 year, 1 year, 365 | 5.6 GB | 3.6 GB | 2.07 GB | 8.4 GB |
| 10 years, 1 year (hint kept), 52 | 11.1 GB | 9.1 GB | 8.0 GB | 8.9 GB |
| 10 years, 1 year (hint kept), 365 | 11.1 GB | 9.1 GB | 8.8 GB | 15.1 GB |
| 10 years, 10 years (hint lost), 52 | 55.8 GB | 36.1 GB | 11.7 GB | 12.6 GB |
| 10 years, 1 year of flood (hint kept), 52 | 623 GB | 378 GB | 54.6 GB | 55.5 GB |

How the C cells add up, for the third row: headers 10 x 746 MB = 7.46 GB,
scan 378 MB of leaves and tags plus 34 MB of markers, retrieval 52 x 2.5 MB =
130 MB, total 8.0 GB. On a 10-year-old chain the headers are half or more of
every busy-load total of C (93 percent in that row), and a hint saves the scan
but not them. The
time to check those headers' seals (68 hours with the C++ library, 30 days
with the Rust port, section 3.3) is on top of every row.

## 5. Designs compared

All designs keep the rule of spec 05, section 8: no request names a commitment,
a position, a marker, a note or a transaction, except where the row says what
changes. "Quantum-safe" means the design uses only hash-based or lattice-based
parts (the project rule); a design that needs an elliptic-curve or pairing
group is shown as excluded.

| Design | Bytes per leaf (restore) | What an endpoint can learn | Quantum-safe | Needs a format change before freeze | Bounds a flood |
|---|---|---|---|---|---|
| A. Spec 05 as written | about 473 | Block or page range of the scan start | Yes | No | No |
| B. Receipts only, pages for the witness only | about 285 | The same | Yes | No | No |
| C. 4-byte note tag bound to the leaf, tag root in the header | 36 (leaf and tag), plus per hit 2.5 MB by PIR or 19.8 MB with 16 decoys | The scan start; then a fetch for the hits, hidden by PIR or by a fixed set of decoys | Yes (SHA3-256) | Yes: the note's nonce layout, two header roots (four with marker roots) | Partly: 8 times less than B, and a copied tag gains nothing |
| C4. 4-byte tag by commitment number, no leaf column | 4, plus the hits | The same | Yes | Yes, as C | No: a copied tag forces fetches (see notes) |
| D. Header root over the notes (pages only) | about 188 | The same as A | Yes | Yes: two header roots, a second frontier | No |
| E. Smaller trees or epochs | The same per leaf; totals unchanged | Nothing new | Yes | Yes: depth is frozen at 32 (TH-1) | No (see below) |
| F. Birth hint with the key | Cuts the span, not the per-leaf cost | The age bucket of the key | Yes | No, if the hint stays outside the key digits | No |
| G. Detection key given to a service | Near 0 on the phone | The service sees every hit of the key | Yes (hash tag) | Same as C | Yes, by moving it to the service |
| H. Single-server PIR (lattice) | Does not find a leaf, only fetches a known one | Nothing, for the fetch | Yes (LWE) | No | Not alone |
| I. Oblivious message retrieval (lattice) | Phone near 0; server per message | Nothing | Yes (RLWE) | Yes: about 2.2 KB clue per message on the chain | Moves it to the server |
| J. Fuzzy message detection (pairing or curve groups) | Small | A fuzzy set of hits | **No: excluded** | | |

### Notes on each design

**A and B (receipts).** The receipt of every transaction that appends a leaf
already carries the leaf, its tree index, its position and its note (spec 05,
section 8, item 5; section 12, item 5), authenticated by `receiptsRoot`. A
wallet that scans the receipts of every block from its scan start therefore
holds every leaf and note in that span without a single page. It also holds
every leaf of its own page, as long as the scan start is the block of the first
leaf of a page (the spec lets a wallet start earlier, never later). It then
needs only the page-root list (32 bytes per 4,096 leaves) for the 20 levels
above the pages, and a page only for the part of the tree below its scan
start. A fetch by block range names no commitment, exactly as the receipt fetch
of spec 05 already does. This removes the 188-byte page download from the
scan with no change to any consensus rule or to what an endpoint learns. It
leaves the receipts, which are most of the cost.

**C (note tag bound to the leaf).** Each note carries a short tag that only
the key can recognise. Proposed form: a new derived key `k_tag =
S("ghost/note-tag-key/v1", key bytes)` (spec 01, section 7 style) and, for the
leaf `C` a note is stored with, `tag` = the first 4 bytes of
`S("ghost/note-tag/v1", k_tag, C)`. The 12-byte nonce of the note becomes the
4 tag bytes at offsets 0 to 3 followed by 8 random bytes, so the note stays 156
bytes and the tag costs the chain nothing. The writer knows `C` when it writes
the note, so it can compute the tag. Consensus takes bytes 0 to 3 of the note
as the tag, with no check (it cannot check a key it does not have), and appends
it to a third incremental tree per type whose root is a new header field.

The restore is: fetch the leaf column (32 bytes per leaf, authenticated by the
page-root list and the header root) and the tag column (4 bytes per leaf,
authenticated by the tag root); compute the tag of each leaf under `k_tag` and
compare; fetch the notes and receipt proofs only for the hits. That is 36 bytes
per leaf, 154.6 GB for a full tree, plus the retrieval of every hit (section
4.1). A 32-bit tag gives about one false hit per
full tree (tags of other keys are random), and a hit's note is authenticated as
today (by its receipt and a Merkle proof for that one receipt, checked against
`receiptsRoot`) and its contents opened against the leaf (spec 01, section 8,
step 4), so a false hit costs one fetch. A peer that hides or changes a tag
fails the tag root check, so the columns cannot be tampered with unseen.

Why the tag is bound to the leaf: a tag that depends only on the key (and the
commitment number) can be copied by anyone who reads the chain. Consensus
cannot check a tag, so an attacker can post any number of commits that carry a
victim's tag; every one is a hit the victim must fetch and discard, each paid
for by the attacker with 24,200 gas and the victim with a PIR query of several
MB. Bound to `C`, a copied tag fits only the victim's own leaf, and a copy of
that leaf costs the attacker the burned amount (spec 01, section 8, step 6).

- *Privacy:* the bulk download of both columns names nothing. The follow-up
  fetch of the hits names the positions of the key's leaves, which spec 05
  forbids today. It must be hidden by PIR (design H) or, until then, by
  fetching the block receipts of the hit's page together with those of decoy
  pages (a single receipt would name the transaction). The receipts of a page
  are about 1.17 MB, so one hit with 16 decoys costs 19.8 MB and with 256
  costs 300 MB (section 4.1). **Decoys must be a fixed set**, derived from `k_tag` and the page number, so that every later fetch
  asks for the same pages. Fresh random decoys on each request would let an
  endpoint intersect two requests: the real page is in both and the decoys
  almost never are (two sets of 256 out of 1,048,576 pages share about 0.06
  pages by chance). A fixed set links a key's fetches to each other, not to the
  key, and is still a weak shield (1 in 17, or 1 in 257), so decoys are the
  interim and PIR the target. A tag is 32 bits of a pseudorandom function under
  a key the endpoint does not have, so the tags of one key cannot be linked to
  each other or to the key.
- *Quantum-safety:* SHA3-256 and a 256-bit key only; Grover halves the key
  strength, the same as for the note key (spec 01, section 9).
- *Cost on the chain:* two more roots in every header (64 bytes, 67 MB per year;
  with the two marker roots below, 128 bytes and 134 MB per year, which is what
  column C of section 4 counts), one more frontier and one more tree
  update per appended leaf, 4 bytes per leaf in history. The marker problem is
  separate: a wallet still needs spent markers, one per reveal and at most one
  reveal per block (spec 07), 32 MB per year, but the status rule of spec 05
  (take it only from receipts) would pull in every receipt again. A
  spent-marker-set root in the header (spec 04, question 2, undecided) fixes
  that; column C assumes it, with two more roots (128 bytes per header in all).
  Without it, tag recovery is fast but status stays "unknown" until the
  receipts of the span are checked.
- *Break-even:* worse than B below about 0.65 leaf per block, better above.

**C4 (tag by commitment number, no leaf column).** The same, with `tag_i` the
first 4 bytes of `S("ghost/note-tag/v1", k_tag, i as 8 bytes)` for the key's
commitment number `i` (numbers have no gaps, so the wallet derives `i = 0, 1,
2, ...` until one is absent). The wallet then needs the tag column only: 4 bytes
per leaf, 17.2 GB for a full tree, and 6.0 GB a year under the flood. It is
shown because it is the smallest scan that is possible, and it is **not
recommended**: the tag can be copied (above), and the attacker pays gas only.
The wallet could cap the hits it will follow per tag, but then an attacker who
posts that many copies forces the wallet back to design B for that range, and a
flood of copies degrades every victim to B's cost. A copy made after the
victim's note is visible always comes after it, but a copy made while the
victim's transaction waits in the pool can come first, so "take the earliest"
is not a rule that holds.

**D (header root over the notes).** If the header carried a root over (leaf,
note) records, the pages alone would authenticate the notes and the receipts
would be needed only for markers. That reaches spec 05's 188 bytes per leaf and
no further, 1.5 times better than B, for two header roots and a second
frontier. Not worth it alone; C includes the same property (a root over what
the wallet reads).

**E (smaller trees or epochs).** A tree of depth 20 holds 1,048,576 leaves
(197 MB of leaves and notes), depth 24 holds 16.7 million (3.2 GB), depth 28 holds
268 million (50 GB). A smaller tree does not cut a restore: the holder still
scans every tree from its first (the sum is the same), and a flood fills more
of them (1,240 trees a year at depth 20). It helps only together with a hint
that names the first tree of the key, and then it is the same as design F with
coarser steps. Forcing coins to move out of old trees would end spec 05's rule
that a full tree's root stays valid forever (section 3), and with it the
bearer property. It also gives up the frozen depth of 32 (TH-1) for no
saving in the worst case. Not recommended.

**F (birth hint).** The wallet shows, next to the key, the date bucket in which
the key was made, for example a quarter. On restore it scans from the start of
that bucket, earlier by one bucket for safety. This cuts the span (a new key
scans months, not the whole chain) and nothing else. Costs: the endpoint learns
the age bucket of a restoring key, about the same as spec 05 already accepts
for an up-to-date wallet's scan start ("roughly when the wallet last synced");
at the busy load a quarter holds 2.6 million leaves and at the low load 26,000.
Spec 01 says the key carries the secret digits and the checksum and nothing
else. A hint put inside the digits would need a 13th group and a changed
checksum; kept outside (printed with the key, not part of any derivation) it
needs no change to spec 01. The risk of a hint is a date typed too late, which
would hide coins; the wallet therefore scans one bucket earlier, never treats
"nothing found" as final, and offers "scan from the start". Recommended outside
the digits.

**G (detection key).** Given a separate `k_tag`, a service can find the key's
tagged leaves for it without being able to read the notes. The service learns
every leaf that belongs to the key and when each appeared. With a 32-bit tag
that is exact, with an 8-bit tag it is fuzzy but costs far more in false hits.
It brings back the trust this write-up is meant to remove. Offer it, if at all,
as an opt-in for a holder who accepts it; never as the default.

**H (PIR).** Single-server PIR with lattice parts (SimplePIR and YPIR, based on
LWE and ring-LWE) fetches one record from a large database without the server
learning which. The YPIR paper reports 12.1 GB/s per server core and 2.5 MB of
total communication for a 32 GB database (figures as published, not measured
here, and not for records of 770 KB). A page database of a full tree is 807 GB,
which at that speed is about 67 core-seconds per query. PIR hides which page
holds the hit, so it is the right partner to design C. It cannot find the hit:
the wallet does not know the position, which is why tags are needed.

**I (oblivious message retrieval).** Lattice-based schemes (OMR, and its
faster PerfOMR) let a server pick out a recipient's messages from a large set
without learning which they are. As published, the server cost is about 7.3
thread-milliseconds per message for the first PerfOMR variant, so one full tree of
4.29 billion messages costs one recipient about 31 million thread-seconds (a
year of one core is 31.5 million), and each message needs a clue of about 2.2
KB on the chain, 14 times the 156-byte note. Usable for a window of recent
messages; not for a full history, and far heavier than a tag. Not recommended
for the core.

**J (fuzzy message detection).** The published scheme of Beck, Len, Miers and
Green works in elliptic-curve groups. Excluded by the quantum-safe rule.

The sources for H and I are the papers: [YPIR (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-menon.pdf),
[Oblivious Message Retrieval (ePrint 2021/1256)](https://eprint.iacr.org/2021/1256)
and [PerfOMR (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-liu-zeyu.pdf).
The figures quoted for them came from summaries of the papers and were not
re-derived or re-measured; check them against the papers before relying on them.

## 6. Recommendation

**Target (for the founder to accept), on bytes downloaded.**

1. *Typical scan:* for a key at most one year old, at the busy load (10 leaves
   per block), the scan of the key's span downloads at most **1 GB, about
   3 minutes at 50 Mbit/s**, the headers before the span not included.
2. *Retrieval:* each note found, genuine or false, costs at most **5 MB** more
   to fetch privately and authenticate. The number of notes is the holder's,
   not the protocol's, so the target is per note; at the usage assumptions of
   section 4.1 a year's retrieval is 30 MB (12 notes) to 913 MB (365 notes).
3. *Any scan:* at most **50 GB per year of history**, headers of that history
   included, even under a flood at the gas floor (about 3 hours a year of
   history at 50 Mbit/s). This part is set by how many leaves an attacker can
   add, so it falls in proportion if a consensus rule lowers the rate (a
   higher floor on the cost of a commit, or a cap on commits per block); that
   choice is for the founder and is not made here.
4. *Headers on a clean device:* no target. They come from genesis at 612 MB
   (746 MB with design C) per year of the chain's age, on top of targets 1 and
   2 (section 3.3). Any all-in target, such as "a typical restore under 2 GB",
   holds only while the chain is younger than about one year and cannot be
   promised without a shorter header proof (section 7).
5. *Never required:* a service, an indexer or a trusted snapshot.

This target is on bytes only. **It is not a target on the time to finish a
restore**, because checking the seals of the headers dominates that time and no
tree design changes it (section 3.3, section 7). Until that is solved, no
restore on a chain a year or more old is a matter of minutes on a phone.

What each design achieves against it, from section 4:

| Target | A | B | C with PIR | C with 16 decoys |
|---|---|---|---|---|
| 1. Scan, 1 year, busy: 1 GB | 4.97 GB, no | 3.0 GB, no | 412 MB, yes | 412 MB, yes |
| 2. Retrieval: 5 MB per note | 0, yes | 0, yes | 2.5 MB, yes (assumed PIR cost) | 19.8 MB, no |
| 3. Scan, 1 year of flood: 50 GB | 617 GB, no | 372 GB, no | 47.7 GB, yes (barely) | 47.7 GB, yes (barely) |
| 3. Scan, 10 years busy: 500 GB | 55.8 GB, yes | 36.1 GB, yes | 11.6 GB, yes | 11.6 GB, yes |
| 4. Headers, 10-year chain (no target) | 6.1 GB | 6.1 GB | 7.5 GB | 7.5 GB |
| All-in, 10-year chain, 1-year key, 52 notes (no target) | 11.1 GB | 9.1 GB | 8.0 GB | 8.9 GB |
| All-in, same, 365 notes (no target) | 11.1 GB | 9.1 GB | 8.8 GB | 15.1 GB |

Design C meets targets 1 to 3 only with PIR at about the assumed cost; if a
real PIR query for these records costs more than 5 MB, or until PIR is
deployed and decoys are used, it fails target 2 and a heavy user's retrieval
is larger than the scan. Target 3 under a flood is met with 2.3 GB to spare
per year, and the flood year's 52 notes by PIR (130 MB) fit in that margin;
365 notes with 16 decoys (7.2 GB) do not.

**Spec changes, in the order to do them.**

1. *Now, no format change (design B plus F):* restate spec 05, section 9 and
   question 4 with the receipt cost (about 285 bytes per leaf, about 544 with the
   bloom, plus 582 bytes per header), so the figure of 188 bytes stops being the
   quoted cost; let a wallet scan receipts only and take a page only for the
   witness below its scan start; show a date bucket beside the key (outside
   the digits). Together these cut the 1-week and 1-month rows by about 35
   percent and a young key's span by the key's age. They do not meet the
   target alone.
2. *Before the note layout and the header are frozen (design C):* in spec 01,
   section 9, make the nonce a 4-byte tag (at offsets 0 to 3) followed by 8
   random bytes, with the new derived key and the tag bound to the leaf; in spec 05, add `coinTagRoot` and `dataTagRoot` to the
   header (and, with the answer to spec 04 question 2, a root over each
   spent-marker set), with the third tree, its frontier, its golden vectors and
   its recovery test steps (RT-5 to RT-7). After the freeze this is a hard fork
   of the header and the note, which is why it is listed before it.
3. *Before the first public wallet (design H):* a PIR service interface for
   the hit fetch; a fixed set of decoy pages until then. This needs no
   consensus change.

**What the founder decides:** accept or change the target (section 6); accept
step 1 (no risk, no cost); and yes or no to step 2. If the answer to step 2 is
no, the honest statement to publish is that the scan of a one-year-old key
costs about 3.0 GB at the busy load and hundreds of GB under a flood, that a
clean device adds 612 MB of headers per year of the chain's age (9.1 GB in all
on a 10-year-old chain), and that a service is the practical way for a flooded
chain. If the answer is yes, the statement is the one of section 4.3: about
8 to 9 GB for a one-year-old key on a 10-year-old chain at the busy load, most
of it headers, and only with PIR.

## 7. Open items and limits

- **Header chain sync is the larger cost in time at every load, and on an old
  chain in bytes too** (section 3.3): 612 MB and, with the Rust port, 73 hours
  of seal checks per year of the chain's age on one core, 6.8 hours with the
  C++ JIT library, all from genesis on a clean device. A clean-device restore
  needs either an independently authenticated starting point later than
  genesis (for example a header hash the holder writes down with the key, or a
  succinct hash-based proof of the chain's work committed in the headers) or a
  fast native check. This is a header and consensus question (spec 06 and 08),
  not a tree one, and is noted here only because it sets the floor of every
  clean-device figure in section 4.
- **The PIR cost is an assumption.** The 2.5 MB per hit is a published figure
  for a different database and record size. If a real query for a receipt with
  its proof costs more than 5 MB, design C misses target 2 and its retrieval
  grows past its scan for a heavy user (section 4.1).
- **No phone and no network** were measured. Phone times are the Mac Studio
  times times 4; link times assume 5 MB/s. Real phones throttle on heat and
  battery, and real links vary by an order of magnitude. Scale the byte counts
  rather than the times.
- **The receipt layout is an assumption.** A tighter encoding than the one in
  section 3.2 (leaf data only, 204 bytes) would put B near 210 bytes per leaf.
  It cannot go below 204 without leaving data out of the receipt.
- **Load levels are assumptions.** The flood row depends on a commit costing
  24,200 gas. The real gas of a commit includes the tree update and will be
  higher, which lowers the flood rate.
- **Only the coin tree was measured**; the data tree has the same shape and
  the same note, so its cost per leaf is the same.
- **Privacy of tags and decoys** is argued here, not tested. A real design
  needs a review in the style of review 01 before it enters a specification.
- **Marker status** (spec 05, section 8) is solved by a header root only if
  spec 04 question 2 is answered that way.

## 8. Method and how to repeat it

The measurements were taken with two throwaway Rust programs outside this
repository (the repository gets no program code from this write-up), built as
a separate crate that depends on `client/` by path at the commit that the
parent of this change builds on.

1. *Trial decryption and page roots.* Generate 1,048,576 random 32-byte
   leaves and random 156-byte notes; call `ghost_client::restore_coins` on a
   freshly generated `PhantomKey` over the whole list, three times, timing each
   call; then the same list split over 2, 4, 8 and 16 scoped threads. For the
   page root, build 64 pages of 4,096 leaves bottom-up with
   `ghost_client::hash::k("ghost/coin-tree-node/v1", [level, left, right])`,
   three timed runs.
2. *Seal check.* `ghost_client::seal::SealKey::new` on a fixed key block, then
   200 calls of `SealKey::hash` on a 40-byte input, one thread; then 8 threads
   of 200 calls each on the shared cache.
3. *Receipts.* RLP-encode a receipt `[status, cumulativeGas, (bloom,)
   [[address, [topic], data]...]]` with the 20-byte address, one 32-byte topic,
   and the data of section 3.2, using the base client's rule for lengths
   (one byte below 56, otherwise a length-of-length prefix).
4. *Tables.* Bytes are the products in sections 3.2 and 3.3 with the leaf
   counts of section 3.4: for A, `leaves * (188 + 32/4096 + 285) + blocks *
   582`; for B, `leaves * (285 + 32/4096) + blocks * 582`; for C, `leaves *
   36 + blocks * (582 + 128) + blocks * 32` (C4 uses 4 in place of 36). In
   section 4.2 `blocks` is the span; in section 4.3 the header term uses the
   chain's age and the rest the span, and C adds `(notes + leaves / 2^32) *
   per_hit`, with `per_hit` 2.5 MB for PIR or `17 * 4096 * 285` bytes for 16
   decoys. Times are bytes over 5 MB/s.

Raw timings of the runs (this machine, 2026-10-20), as printed:

```text
restore_coins 1 thread: 279, 287, 282 ns per leaf
restore_coins 2 / 4 / 8 / 16 threads: 6.93 / 13.14 / 26.24 / 34.58 million leaves per second
page root: 0.70, 0.68, 0.70 ms per page of 4096 leaves
SealKey::new: 0.517 s
RandomX light hash, Rust port: 250.48 ms per hash (200 hashes, one thread)
RandomX light hash, Rust port, 8 threads: 32.00 ms per hash aggregate
```

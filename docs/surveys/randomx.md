# Survey: the RandomX mining integration

Status: research plus measurements, 2026-10-17. The only code written was a
throwaway timing program and a few throwaway checks; none of it is in this
repository. Every number below was measured on one machine (see "Machine and
method"), and every claim about other projects comes from reading their source
at the commit named below.

## What was read and run

| Item | Pin |
|---|---|
| RandomX reference (`tevador/RandomX`), `master` | commit `418f5497e60215fcd8a7cff2a16be835135833e5`, 2026-10-17. **All measurements use this commit.** |
| RandomX `v1.2.3` (latest v1 tag) | commit `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab`, 2026-07-17 |
| RandomX `v1.x` branch tip | commit `9b012ab6189e0d6f896986eec2e6ab907e6a340d`, 2026-10-16 (v1.2.3 plus three fixes, no tag yet) |
| RandomX `v2.0.1` (latest v2 tag) | commit `aaafe71322df6602c21a5c72937ac284724ae561`, 2026-05-10 |
| Monero (`monero-project/monero`), `master` | commit `f8aba51d2d50ebe7c96a0f4d1f2d6e88add61710`, 2026-10-17. Its `external/randomx` submodule points at `12f2c2ff...` (v1.2.3). |
| XMRig (`xmrig/xmrig`), `master` | commit `b2ca72480c58d197e18c885d9fc1a0c8d517e60a`, 2026-03-28 |
| Core-Geth (`etclabscore/core-geth`) | commit `7ee328ca2d6734ecbda9f0757d35eb6b710a14cd`, 2026-09-17, the pinned fork point in decision 0001 |
| Go bindings | `mining-pool/go-randomx` `862b6dcef73c704c9065a256c5c55fa68034a392`; `git.gammaspectra.live/P2Pool/go-randomx/v5` tag `v5.0.1` = `7c1e2106fc15f20de343fca03efd497d48d1f842`; `opd-ai/go-randomx` `f1bcbaa0288abd1f97af107f45c46acc5a88e811`; `gcarreno/go-randomx` `8891fc59ecffcc0080790d7401b7ae3023466780`; `ngchain/go-randomx` `3a956c2ac17d2e394c703f4f9094d8d5bc0bd1bb` |

Paths without a prefix are in the repository the sentence is about.

## Bottom line

- **No blocker.** RandomX can be verified in Go, in full, for every header, at a
  cost the project can bound. Nothing measured contradicts the base client decision.
- **Binding.** The best path is a thin cgo wrapper of our own around a pinned
  RandomX source tree with a one-line patch. The existing Go bindings are
  either stale, unaudited or built on prebuilt binaries. A pure-Go
  implementation exists, passes the reference vectors, and matched the C++
  library bit for bit in my checks. It is the right second implementation for
  the cross-checks, not the primary one: on this machine it was 13 times slower
  per header than the C++ library with its JIT.
- **Configuration.** A salt-only change is enough to make every Ghost hash
  differ from every Monero hash. It does not make Ghost's hardware profile
  differ from Monero's (section 2 explains the difference).
- **Key rule.** Use Monero's arithmetic unchanged and tune two constants. My
  recommendation is an epoch of 8192 blocks and a lag of 256 blocks (about 2.8
  days and 2.1 hours at 30-second blocks), not Monero's 2048 and 64. The key must be looked up by walking parent hashes on the branch of the
  header being verified, never by block number.
- **Cost.** Checking every seal in light mode costs about 23 ms per header on
  one core of this machine. One year of 30-second headers (1,051,200) is about
  6.8 hours on one core, or about 35 minutes on all 16 cores. This grows
  linearly with chain age. Fast mode (2.3 GiB) is about 7 to 10 times faster per
  hash but saves less than that in total, because the dataset is rebuilt at
  every key change.
- **Version.** The reference now has two algorithm versions behind one flag
  (v1 and v2). Monero still uses v1. Section 2 recommends deciding this before
  the specification is written.

## 1. The Go binding and what cgo does to builds

### What exists

| Binding | State | Verdict |
|---|---|---|
| `mining-pool/go-randomx` | cgo. BSD-3-Clause. Untouched from 2020-07 to 2026-08, then one revival commit that adds prebuilt static libraries (`lib/librandomx_<os>_<arch>.a`, committed as binaries) for linux amd64 and arm64 and darwin arm64. Wraps RandomX v1.2.1 only. No v2 flag, no way to apply a different salt (the salt is compiled into the library). Light-mode VMs and a batch `Search`. One tag. | Not usable as a dependency. Binary blobs in a source repository defeat reproducible builds, and it is behind the reference by two releases and several fixes. Useful only as an example of the cgo glue. |
| `git.gammaspectra.live/P2Pool/go-randomx/v5` | Pure Go, no cgo. BSD-3-Clause (descended from the DERO Foundation port). Tags `v5.0.0`, `v5.0.1` (2026-08-03). One main author (30 of 30 commits in the shallow history I read). Hosted on a self-hosted Git server, but resolvable through the Go module proxy (`proxy.golang.org` lists both tags). Supports light and fast mode, **v1 and v2**, a runtime-configurable `VMConfig` (the salt is a field), and ships configurations for RandomWOW and Arweave. JIT only on amd64; arm64 and the rest use an interpreter. | The best second implementation. See below. |
| `opd-ai/go-randomx` | Pure Go. Its own README says hash outputs "do not yet match the official RandomX reference implementation" and warns against use for blockchain validation. History is mostly automated bot commits. | Reject. |
| `gcarreno/go-randomx` | cgo wrapper, one tag (`v0.0.1`), last commit 2025-07. | Reject; nothing a thin wrapper of our own would not do better. |
| `ngchain/go-randomx` | cgo fork of the first binding, last commit 2020-11. | Reject; stale. |

I also looked for RandomX engines inside go-ethereum forks. I found a few
(for example `PeerCashChain/PeerCashChain`, created 2026-10-02, and
`AgentChain-dev/agentchain`), all weeks to months old with no stars and no
sign of a live network. One of them derives the key from the block number
alone (`epochLength = 2048`, a constant per epoch), which is the pattern
section 3 warns against. None is a precedent to lean on; decision 0001 already
says the combination has no production precedent.

### The pure-Go implementation, checked

- I ran its light-mode tests (v1, v2, RandomWOW, single) on this machine; they
  passed in 8 seconds. Those tests carry the reference vectors.
- I computed the same hash four ways, for the stock configuration and for a
  salt-only configuration, in v1 and v2, once with the C++ library and once
  with this Go code. All four pairs are identical (the table is in section 2).
- Speed on arm64, light mode, v1: 316 ms per hash (100 hashes), against about
  23 ms for the C++ library with its JIT and about 92 ms for the C++ library's
  interpreter. On amd64 it has a JIT, which I could not measure here.
- Risk: one maintainer, a non-GitHub host, and no external review that I could
  find. That is acceptable for a cross-check implementation and not for the
  only implementation.

### What cgo does to builds

Measured here (Go 1.26.6, gcc 13.3.0, linux/arm64):

1. **The static library itself is reproducible.** `librandomx.a` built three
   times from the same source in three different directories, one with
   `-ffile-prefix-map`, had the same SHA-256 each time
   (`e394f213c58b25a889ecddd7b82c0ee1b7d10b3835880a098f5dac909168f49c`). The
   release build defines `NDEBUG`, so no source paths are embedded.
2. **The Go binary is not reproducible by default.** Two copies of the same
   module in two directories, built with `-trimpath`, produced different
   binaries (the Go build ID differs, because cgo's `${SRCDIR}` in the linker
   flags is an absolute path and the build ID hashes the flags). Adding
   `-ldflags=-buildid=` made them byte-identical
   (`7a22310dbcee5a38ff4e22c17df7e6bf59d4b8c0d96369c52eccdc44dfe56584`).
   Reproducibility is therefore achievable, but only with these flags fixed in
   the build script and a fixed C++ toolchain.
3. **The binary was dynamically linked to the C++ runtime** (`libstdc++.so.6`,
   `libgcc_s.so.1`) even though the cgo flags asked for static linking. A
   release binary then depends on the host's runtime libraries. Fully static
   linking was not tested here; it belongs in the fork's build work.
4. **Cost per call is negligible.** An empty cgo call took 16 ns; one hash takes
   about 23 ms. cgo overhead does not matter for verification speed.

Not measured here, from reading the reference and Core-Geth:

- **A C++ toolchain per target.** Core-Geth's release workflow
  (`.github/workflows/release-packages.yml`) builds on native macOS, Ubuntu and
  Windows runners and uses apt cross compilers for ARM. Adding RandomX means a
  C++ compiler and standard library on each of those, pinned by version, because
  the compiler version changes the machine code of the library's interpreter
  and JIT stubs. Windows needs a MinGW-style compiler (Go's cgo does not use
  MSVC).
- **JIT on hardened systems.** The reference handles macOS arm64 with
  `MAP_JIT` and `pthread_jit_write_protect_np` (`src/virtual_memory.c`). A
  signed and notarised macOS binary will also need Apple's JIT entitlement;
  that is from Apple's documentation and was not tested. `RANDOMX_FLAG_SECURE`
  avoids simultaneous write and execute pages where the operating system
  enforces it.
- **A dual path already has a precedent in the fork point.** Core-Geth's
  `crypto/signature_cgo.go` (`//go:build ... cgo ...`) and
  `crypto/signature_nocgo.go` (`//go:build ... !cgo ...`) are the same pattern:
  a C implementation and a pure-Go fallback behind a build tag. For RandomX
  the fallback would be the pure-Go library, and the two paths would be
  cross-checked in the test suite.
- **Memory outside the Go heap.** The 256 MiB cache is allocated by the C
  library, so eviction must call the free function explicitly. The Go garbage
  collector will not do it.

### Recommendation for the binding

- Vendor the RandomX source at a pinned commit, with the salt patch as a
  separate, reviewed patch file. Build it from source in the release container.
- Write a thin cgo wrapper (cache init, VM create, hash, free), roughly the
  size of the one in `mining-pool/go-randomx` but without the blobs.
- Use the pure-Go library only as the second implementation in the
  cross-implementation hash checks and, if wanted, as a `!cgo` fallback.
- Apply the fixes below. The reference has unreleased fixes that matter here:
  - `c981f99` and `397fd7a` fix a use-after-free in `randomx_vm_set_cache`
    (the stale-cache check compared the key and memory address but not the
    cache object, so a freed cache re-allocated at the same address with the
    same key was treated as unchanged). A node that evicts and re-creates
    caches and reuses VMs hits exactly this pattern.
  - `c1811ac` and `9b012ab` fix JIT page-protection errors that were ignored.
  - `418f549` fixes signed-overflow undefined behaviour in the portable
    `smulh` used when the compiler has no 128-bit integers (not the case for
    64-bit gcc and clang builds).
  - The v1.x branch has the use-after-free and JIT fixes but not the `smulh`
    fix; `master` has all three. There is no tagged release with these fixes as of 2026-10-17, so
    "pinned, patched release" means pinning a commit after the last tag, or
    waiting for the next tag. Either way the pin goes in the specification.

## 2. Separating Ghost's work from Monero and other chains

### What the reference says

From `doc/configuration.md` at the pinned commit:

- "We recommend each project using RandomX to select a unique configuration to
  prevent network attacks from hashpower rental services."
- There are 45 customisable parameters, in `src/configuration.h`.
- For the salt: "Every implementation should choose a unique salt value." It
  must be at least 8 characters.
- A disclaimer: "The compile-time checks only prevent obviously broken
  configurations. Passing the checks does not imply that the configuration is
  safe." Each non-standard configuration "is thoroughly tested before being
  deployed".
- For the instruction frequencies: "Making changes to the default values is not
  recommended", with only three functionally equivalent pairs listed as safe.

The 45 parameters are the 16 below plus 29 instruction frequencies
(`RANDOMX_FREQ_*`).

### Every parameter, and what Ghost changes

Recommendation: change exactly one.

| Parameter | Reference value | Ghost | Reason |
|---|---|---|---|
| `RANDOMX_ARGON_SALT` | `"RandomX\x03"` | **changed** to a Ghost-specific string (this survey measured `"Ghost-RandomX\x01"`; the final string is a specification decision) | Changes the Argon2d cache for every key, hence the dataset and every hash. See below. |
| `RANDOMX_ARGON_MEMORY` | 262144 (256 MiB cache) | unchanged | Sets light-mode memory; changing it changes verification cost and the memory-time-tradeoff condition |
| `RANDOMX_ARGON_ITERATIONS` | 3 | unchanged | Scales cache init time (about 0.4 s here) |
| `RANDOMX_ARGON_LANES` | 1 | unchanged | Cache init is single-threaded in the reference at 1 lane; more lanes change the cache |
| `RANDOMX_CACHE_ACCESSES` | 8 | unchanged | Sets the fast/light speed ratio and a safety condition |
| `RANDOMX_SUPERSCALAR_LATENCY` | 170 | unchanged | Tuned against DRAM latency |
| `RANDOMX_DATASET_BASE_SIZE` | 2147483648 | unchanged | Sets fast-mode memory (2080 MiB) and a safety condition |
| `RANDOMX_DATASET_EXTRA_SIZE` | 33554368 | unchanged | Same |
| `RANDOMX_PROGRAM_SIZE` | 256 (v1), 384 (v2) | unchanged (follows the version chosen) | Compute/latency balance and safety conditions |
| `RANDOMX_PROGRAM_ITERATIONS` | 2048 | unchanged | Per-hash cost; safety conditions |
| `RANDOMX_PROGRAM_COUNT` | 8 | unchanged | Per-hash cost; must stay above 1 |
| `RANDOMX_JUMP_BITS` | 8 | unchanged | Branch probability |
| `RANDOMX_JUMP_OFFSET` | 8 | unchanged | Same |
| `RANDOMX_SCRATCHPAD_L3` | 2097152 | unchanged | Cache-per-core design point |
| `RANDOMX_SCRATCHPAD_L2` | 262144 | unchanged | Same |
| `RANDOMX_SCRATCHPAD_L1` | 16384 | unchanged | Same |
| `RANDOMX_FREQ_*` (29 values, total 256) | per `src/configuration.h` | unchanged | The reference advises against changes |

Two things sit outside the 45 and are also unchanged: the AES round keys used
to fill the scratchpad (XMRig's RandomWOW configuration replaces them; Ghost
does not need to) and the version flag below.

### Why a salt-only change is enough, and what it does not do

The salt is an input to Argon2d, which builds the cache from the key. A
different salt gives a different cache for the same key, so the dataset and
every hash differ. I measured this with the key `test key 000` and the input
`Ghost survey test input` (23 bytes), compiling the reference once as shipped
and once with the one-line salt change. All four modes of each build agreed
(v1 and v2, each in light and fast mode, JIT and interpreter), and the
pure-Go library, given the same salt at run time, produced the same values.

| Configuration | Hash (hex) |
|---|---|
| v1, stock salt | `6038f21009dd6fd7aeb2c6e50a2ea8e2a228b13ac4c921e4d508275078c6765e` |
| v1, Ghost salt | `253de6bf1004419ac11fdb08b5a8efd7fa0269d82ea8bb39db173ba43d6cf8ee` |
| v2, stock salt | `9530c26b97315db4bb784b6e75c358b64a401f9e0cee355ffb8dcbcbb9b64270` |
| v2, Ghost salt | `c1f767fcf35840c6407361976a31eba600f20823409342908513a2ca9719dada` |

What this buys: no hash, share or solution for another RandomX chain is valid
on Ghost or the reverse, and no dataset can be shared between chains even if a
key ever coincided. Salt-only configurations are normal in the wild: XMRig
carries one for Safex (`RandomSFX\x01`) with no other change.

What it does **not** buy: the compute profile is identical to the reference. A
miner or a hardware design that is efficient at Monero's RandomX is exactly as
efficient on Ghost, and existing miners need only a one-line configuration
change (XMRig already holds its variants as runtime configurations). So a
salt-only Ghost is separated from Monero's *work* but not from Monero's
*hashrate market*: a rental service or a Monero miner can redirect hashpower to
Ghost within minutes of a miner build supporting the salt. Only changes to the
unsafe-listed compute parameters would change that, at the cost of leaving
audited territory. That is a trade for the specification, with the default
being the outline's: salt only.

Practical consequences of choosing the salt:

- It is a compile-time macro in the reference, so Ghost needs its own build of
  the library (section 1). The reference's built-in tests hard-code hashes for
  the stock configuration, so run them on the stock build and give the Ghost
  build its own vectors produced independently by the C++ and the Go
  implementations (the four pairs above are a start).
- External miners need a miner build with the Ghost salt. Pool and miner
  software must be told; the getWork response carries the key (section 3).

### v1 or v2

`RANDOMX_FLAG_V2` is a run-time flag in the same library. Measured here, v2 is
not slower to verify (23 to 25 ms per light hash in both).

| | v1 | v2 |
|---|---|---|
| Latest tag | `v1.2.3` (2026-07-17) | `v2.0.1` (2026-05-10); released 2026-03-16 as `v2.0` |
| Changes (from `doc/design_v2.md`) | reference algorithm | rounding-mode change on average every 16th execution instead of every one, AES mixing of the floating-point registers, program size 256 to 384, prefetch two iterations ahead |
| Independent audits | four in 2019 (Trail of Bits, X41, Kudelski, Quarkslab), reports in `audits/` | none in the repository (the `audits/` directory was last touched in 2019) |
| In production | Monero `master` pins it (checked above) | XMRig has a "Monero v2" configuration, but Monero's own source does not use the flag, and I found no live chain on it |

The requirements point both ways: decision 0001 wants existing,
reviewed components (v1), and v2 is the reference's current direction aimed at
closing known weaknesses. This survey recommends v1, because it is the audited
and deployed algorithm, and flags the choice for the specification, since the
flag is one line and changing it later is a hard fork.

## 3. The key (seed) rule

### Monero's arithmetic (the model)

In `src/crypto/rx-slow-hash.c` at the pinned Monero commit:

```c
#define SEEDHASH_EPOCH_BLOCKS 2048
#define SEEDHASH_EPOCH_LAG    64

uint64_t rx_seedheight(const uint64_t height) {
  uint64_t s_height = (height <= EPOCH_BLOCKS + EPOCH_LAG) ? 0 :
                      (height - EPOCH_LAG - 1) & ~(EPOCH_BLOCKS - 1);
  return s_height;
}
```

(Names shortened; Monero reads the two constants through helper functions that
allow smaller test values.) The key is the hash of the block at that height.
Three details matter:

- **The mask needs a power of two.** `& ~(E-1)` only rounds down correctly when
  the epoch length E is a power of two.
- **The README wording is off by one against the code.** The reference README
  says to change the key "when `blockHeight % 2048 == 64`". The code changes
  it one block later: the first height that uses key block `kE` is `kE + L + 1`.
  Stated exactly, there are L blocks strictly between the key block and the
  first block that uses it.
- **The first epoch is longer.** Heights up to and including `E + L` all use
  height 0.

The comment on `SEEDHASH_EPOCH_BLOCKS` in Monero says it "Must be same as
BLOCKS_SYNCHRONIZING_MAX_COUNT", the maximum batch of blocks processed at once
during sync. The comment does not say why; the natural reason is that if the
epoch is at least the batch size, a batch contains at most one key change.

For alternative chains Monero walks the alternative branch to find the key
block (`src/cryptonote_core/blockchain.cpp`, around line 1985) and, while a
batch is being prepared, resolves heights from the not-yet-stored batch first
(`get_pending_block_id_by_height`). Ghost needs the same two behaviours.

### The rule for Ghost

Write `E` for the epoch length (a power of two) and `L` for the lag, both in
blocks. For a header at height `h` (all arithmetic in `uint64`):

1. `seedHeight(h) = 0` if `h <= E + L`, else `(h - L - 1) & ~(E - 1)`.
2. The key is the hash of the block at height `seedHeight(h)` **on the branch
   that header `h` extends**, that is, an ancestor of the header, found by
   walking parent hashes. The key block is always an ancestor and never the
   header itself, since `seedHeight(h) <= h - L - 1`.
3. At height 0 the key block is the genesis block, whose hash is a chain
   constant.

Where the key changes, for Monero's constants and for my recommendation:

| | E = 2048, L = 64 (Monero's values) | E = 8192, L = 256 (recommended) |
|---|---|---|
| Epoch length at 30 s | 17.1 hours | 2.84 days |
| Lag at 30 s | 32 minutes | 2.13 hours |
| Key blocks | 0, 2048, 4096, ... | 0, 8192, 16384, ... |
| Heights using the genesis key | 1 to 2112 | 1 to 8448 |
| First height of the next key | 2113, then 4161, 6209 | 8449, then 16641, 24833 |
| Last height of key block `kE` | `(k+1)E + L` | `(k+1)E + L` |
| Key changes per year of 30 s blocks | 513 | 128 |
| Same at 60 s blocks | 257 | 64 |

(Computed with a ten-line script implementing the formula above; I checked
that the first heights listed in the table are exactly where it switches.)

### Choosing E and L for 30-second blocks

- **L is an efficiency parameter, not a safety parameter.** Consensus
  correctness does not depend on it: the key is looked up per branch, so a
  reorg that replaces the key block just changes the key on the new branch. A
  short lag only means that a reorg deeper than L blocks forces a cache
  rebuild and makes miners' prepared datasets wrong for a while. Monero's 64
  blocks is about 2 hours at its block time. Keeping about 2 hours at 30
  seconds gives L = 256. Reorg depth in blocks at launch is unknown, so pick
  from orphan data on a private test network; 128 (about an hour) is a reasonable
  floor.
- **E trades rebuild cost against nothing that I could find.** Each key change
  costs a cache build (0.36 to 0.47 s here, single-threaded) and, for anyone
  using fast mode, a dataset build (3 to 4 s with 16 threads, 49 to 53 s with
  one). Over a year of history that is 513 rebuilds at E = 2048 and 128 at
  E = 8192 (section 4 shows what that does to a fast-mode sync). The reference
  README recommends a key change about every 2.8 days; E = 8192 at 30 seconds
  is 2.84 days. I found no written rationale for a shorter epoch in the
  reference documents, so I would keep the wall-clock cadence, not the block
  count.
- **E must be at least the largest batch the downloader verifies at once.**
  In Core-Geth, `maxHeadersProcess` is 2048 (`eth/downloader/downloader.go`).
  Both options satisfy this, so a verification batch spans at most two keys.

### Lookup during batch sync and reorgs

The `consensus.Engine` interface hands the engine a `ChainHeaderReader` with
`GetHeader(hash, number)`, `GetHeaderByNumber(number)` (canonical chain only),
`GetHeaderByHash` and no ancestor function (`consensus/consensus.go`). Core-Geth's
Ethash engine never needed the chain for the seal check because its cache key
is a pure function of the block number (`ethash.cache(number)`). RandomX needs
history, so:

1. **Never use `GetHeaderByNumber` for the key block.** It returns the canonical
   header, which is wrong for a side branch, wrong during a reorg, and absent
   for a batch whose headers have not been stored yet.
2. **Batch sync.** `VerifyHeaders` runs one worker per core on a contiguous
   slice of headers, then the headers are written (`core/headerchain.go`,
   `ValidateHeaderChain`; `consensus/ethash/consensus.go`, `VerifyHeaders`). The
   key block for a header is in the slice if `seedHeight >= headers[0].Number`
   and in the database otherwise. The simplest safe design is one sequential
   pass over the batch, before the workers start, that computes the key hash
   for every header (below) and hands it to the workers.
3. **Make it cheap.** Walking back `E + L` parents for every header would cost
   thousands of lookups each. Instead: `key(h) = key(parent)` except at the
   first height of a new key (`h = kE + L + 1`), where the new key is the
   hash of the ancestor `L + 1` blocks back, found by one walk of at most
   `L + 1` parents. Store the key hash alongside each header, like total
   difficulty, so that a lone header (a newly announced block) finds its
   parent's key in one read. A header whose parent has no stored key falls back
   to a bounded walk of at most `E + L` parents; the cap and the rate limit on
   such fallbacks belong in the invalid-header defence.
4. **Alternative branches.** The parent-hash walk finds the right key block on
   any branch. Reorg tests that cross several epochs, with competing key blocks, exercise
   precisely this.
5. **Caches are keyed by key hash, not by epoch number.** Two branches that
   disagree on the key block have different keys for the same epoch.
6. **Bounded resources.** One cache is 256 MiB. Keep a least-recently-used set
   of at most three (the current key, the next key built ahead during the lag,
   and one more for a reorg or a straddling batch): 768 MiB. Never evict a
   cache in use by a verification in flight; cap new cache builds per peer and
   per time window; share one cache among all workers (I ran 16 VMs on one
   cache) and give each worker its own VM, about 2 MiB each here.
7. **Pruned history.** If old headers are ever dropped, keep the canonical key
   hash for each epoch (a few hundred small records per year).

### At and near genesis

- Heights `1` to `E + L` use the genesis block's hash as the key. The genesis
  header is not sealed (it has no parent and carries no work), so it must be
  exempt from the seal check; its hash is a constant of the chain.
- The genesis hash is derivable in advance by anyone with the frozen launch
  rules, so the first epoch's key is public before launch. Knowing the key
  early lets someone build the dataset early, nothing more. Mining a private
  chain ahead of launch is the separate no-early-mining problem that the
  Bitcoin block hash in genesis addresses.
- A node starting from genesis never needs to look up a block for heights up to
  `E + L`: the key is the constant.

### What the key rule does and does not give

The key is derived from chain history, not chosen by miners. Miners can still
influence it: whoever finds block `kE` can withhold it, or choose between
several candidate blocks that are valid at that height, and so pick among a
small set of possible keys at the cost of the work they discard. The
specification should say this plainly, and say that the lag (the time between
the key block and its first use) is what limits how long anyone can prepare a
chosen key.

For external miners, `getWork` must return the key (the seed hash) with the
work package, as Ethash's does, so a miner can build the right dataset.

## 4. What verification costs

### Machine and method

| Item | Value |
|---|---|
| CPU | `lscpu`: Vendor ID `Apple`, Model name `-` (not reported), architecture `aarch64`, 16 CPUs, 1 thread per core. Virtual machine under Apple's Virtualization framework, Linux 6.8.0-147, Ubuntu 24.04.5 LTS, 48 GiB RAM |
| Instruction set features | includes `aes`, `pmull`, `sha1`, `sha2`, `sha3`, `sha512`, `asimd`, `atomics`, `fphp` |
| Toolchain | gcc 13.3.0, cmake 3.28.3, Go 1.26.6 |
| RandomX | `418f5497e60215fcd8a7cff2a16be835135833e5` (`master`), portable build (no `-march=native`) |
| Flags used | hardware AES and JIT (flag value `0x0a`, plus `0x80` for v2); large pages not used |

This is an **arm64 virtual machine on a shared host**, not the x86-64 minimum
node the project will define. Load average on the host was about 3 during the
runs; an earlier set of runs under heavier load measured 27 to 35 ms per
light hash, so treat the figures as a plausible range rather than a floor.
The reference README lists light-mode rates per thread of roughly 40 to 70
hashes per second on desktop x86 CPUs (for example 1,160 per second on 16
threads for an i9-9900K), which puts these figures in the same range, but the
minimum-node bound must be measured on the real target before the
mining-phase gate.

The timing program is a small C++ file that calls the public C API: allocate and
initialise the cache for a fixed key, create a VM per thread on one shared
cache, warm up with three hashes, then time `randomx_calculate_hash` over 76-byte
inputs that differ in a counter. For fast mode it first builds the dataset
with `randomx_init_dataset` split across threads. It is not part of this
repository.

### Results

Single thread, light mode, v1, JIT, five runs of 300 hashes each:

| Run | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| ms per hash | 23.46 | 23.91 | 22.84 | 23.42 | 22.95 |

The same for v2: 22.43, 24.55, 22.88, 24.60, 24.13 ms. Median 23.4 ms (v1)
and 24.1 ms (v2).

| Measurement | Result |
|---|---|
| Light mode, JIT, one thread | about 23 ms per hash (about 43 hashes per second); 27 to 35 ms under heavier load |
| Light mode, interpreter, one thread | 92 ms (v1), 95 ms (v2) |
| Light mode, pure-Go library, arm64 interpreter, one thread | 316 ms |
| Light mode, JIT, 2 / 4 / 8 / 16 threads, one shared cache | 89 / 179 / 338 / about 500 hashes per second (the 16-thread run was under load) |
| Light mode, interpreter, 16 threads | 135 hashes per second |
| Cache initialisation (one thread) | 0.36 to 0.47 s |
| Light mode memory | 259 to 261 MiB resident with one VM; 291 MiB with 16 VMs |
| Fast mode, JIT, one thread | 3.2 ms (v1) and 2.4 ms (v2) per hash; one noisy sample each |
| Fast mode, JIT, 16 threads | 4,393 hashes per second (v1), 5,029 (v2) |
| Dataset initialisation, 1 thread | 53.3 s (v1), 48.7 s (v2) |
| Dataset initialisation, 16 threads | 4.0 s (v1), 3.0 s (v2) |
| Fast mode memory | 2,338 to 2,341 MiB resident (the 2080 MiB dataset plus the 256 MiB cache, which is only needed to build the dataset) |

The reference documents fast mode as needing "2080 MiB of shared memory" and
light mode "256 MiB"; the measured resident sizes agree.

### What it implies for initial sync

One year at 30-second blocks is 31,536,000 / 30 = **1,051,200 headers**.
Every seal checked, light mode, C++ library with JIT:

| Cores verifying | Rate | Time for one year of headers |
|---|---|---|
| 1 | 43 per second (23.4 ms) | 6.8 hours (10.2 hours at the loaded-run 35 ms) |
| 2 | 89 per second | 3.3 hours |
| 4 | 179 per second | 98 minutes |
| 8 | 338 per second | 52 minutes |
| 16 | about 500 per second | about 35 minutes |
| 1, interpreter instead of JIT | 11 per second | 27 hours |
| 1, pure-Go library on arm64 | 3.2 per second | 92 hours |

At the 60-second fallback block time the headers per year halve, and so does
each row.

Consequences:

1. **Cost grows with the age of the chain.** After 5 years there are 5.3 million
   headers, so about 34 hours on one core or 8 hours on four. After 10 years,
   about 68 hours on one core or 16 hours on four. These figures are for header
   seals only, before block bodies and state. The gate in decision 0001 (header sync must
   not be too slow) needs the
   bound stated as hours per year of chain on a stated core count, and the
   operator-facing statement that sync time grows with chain age.
2. **Verification must be parallel and use the JIT.** The interpreter is about
   four times slower, which turns the 4-core case from 98 minutes into about 6.8 hours
   per year. A node whose JIT is unavailable (some hardened systems, some
   architectures) falls to that speed. The release must detect this and say so.
3. **Fast mode helps less than its per-hash speed suggests.** A fast-mode hash
   is about 7 to 10 times quicker, but every key change needs a dataset rebuild.
   With E = 2048 that is 513 rebuilds per year: about 26 to 34 minutes with 16
   threads, or about 7 hours with one thread, which cancels the saving on a
   small machine. With E = 8192 it is 128 rebuilds: about 6 to 9 minutes with
   16 threads, or about 1.7 to 1.9 hours with one. Fast-mode verification
   for a year of headers on 16 threads is then about 4 minutes of hashing
   (1,051,200 / 4,393) plus the rebuilds. It needs 2.3 GiB, so it can only be
   an optional mode for nodes with spare memory, and the longer epoch makes it
   worthwhile. Light mode with 256 MiB per cache remains the baseline.
4. **Steady state is trivial.** One header every 30 seconds at 23 ms of one
   core is under 0.1% of a core. The cost matters only for sync and for
   hostile input.
5. **Hostile input is the real load.** A peer can send well-formed headers with
   bad nonces; each costs a node about 23 ms of one core to reject. One core
   rejects about 43 per second; 16 cores about 500 per second. A peer on an
   ordinary connection can send headers much faster than that, so the cheap
   checks must run first (parent link, difficulty, timestamp, key availability),
   and seal checks need per-peer budgets and scoring. The
   numbers above are the budget to design against.
6. **Header download is not the limit.** Headers are a few hundred bytes each;
   at an estimated 0.5 to 0.6 GB per year, transfer time is small next to the
   verification time on a slow node. This size is an estimate and was not
   measured.
7. **Core-Geth's sampling is not used for Ghost.** Its downloader
   verifies about one seal in 100 for older headers
   (`fsHeaderCheckFrequency = 100`, `eth/downloader/downloader.go`, with the
   random choice in `core/headerchain.go`), forcing a check near the pivot
   (`fsHeaderForceVerify = 24`). With every seal checked there is no such
   shortcut, and the figures above are the full price.

## Risks and open items

1. **x86-64 numbers are missing.** Everything above is arm64. The minimum-node
   bound needs the same program run on the intended minimum x86-64 machine,
   with and without the JIT, before the mining-phase gate.
2. **v1 or v2 is undecided** and is a one-line, hard-fork-sized choice.
3. **No tagged release has the recent fixes.** Pin a commit and put it, with
   the patch, in the specification; revisit when the next tag appears.
4. **Static linking and reproducible builds are only partly shown.** The
   library is reproducible and the Go binary can be made so, but static C++
   runtime linking and the per-platform toolchains (Windows, macOS signing)
   were not tested.
5. **The second implementation has one maintainer.** It is a cross-check, not a
   dependency of consensus.
6. **Salt-only does not separate hardware markets** (section 2).
7. **Epoch and lag are recommendations, not measurements.** E = 8192 and
   L = 256 follow the reference's wall-clock cadence; the lag should be
   revisited against orphan data from the private test network.
8. **Light-mode memory is 768 MiB for three caches**, which counts against the
   minimum node's memory.
9. **Line references age.** Anything cited refers to the pins at the top.

## Method and limits

- Source read at the pinned commits. GitHub data (tags, commit dates,
  contributors) is from the public API on 2026-10-17.
- Measurements are from a single machine, described above, with other work
  running on it; ranges are given where the spread mattered. Hash rates are
  single-process wall-clock times of the public C API, not the reference's
  own `randomx-benchmark`.
- The reference's own test suite (`randomx-tests`) was run on the stock
  portable build and passed (4 tests skipped as incompatible with the build
  configuration).
- Nothing was tested on x86-64, on Windows, or on macOS.

## Commands

Reference build (portable; a `-DARCH=native` build was also compiled and took 27
to 28 ms per light hash under the heavier load):

```sh
git clone https://github.com/tevador/RandomX.git ref
cd ref && git checkout 418f5497e60215fcd8a7cff2a16be835135833e5 && cd ..
mkdir build-portable && cd build-portable
cmake ../ref && make -j16 && ./randomx-tests
```

Salt-only variant used for the hash table: copy `ref` without `.git`, change
the one line in `src/configuration.h` to
`#define RANDOMX_ARGON_SALT "Ghost-RandomX\x01"`, and build the same way.

Timing program (arguments: version, `jit` or `interp`, `light` or `fast`,
hashes per thread, threads), built against the static library:

```sh
g++ -O2 -std=c++11 -pthread -Iref/src bench.cpp build-portable/librandomx.a -o bench
./bench v1 jit light 300 1      # about 23 ms per hash
./bench v1 jit light 100 16     # parallel light mode
./bench v1 jit fast 2000 16     # dataset init and fast mode
./bench v1 interp light 200 1   # interpreter
```

cgo reproducibility check:

```sh
CGO_ENABLED=1 go build -trimpath -o rxbench .                        # differs by directory
CGO_ENABLED=1 go build -trimpath -ldflags='-buildid=' -o rxbench .   # identical
```

Pure-Go library check (a ten-line program that calls `NewCacheWithConfig`,
`NewVMWithConfig` and `CalculateHash`, with `ArgonSalt` set on a copy of
`VMConfigV1` or `VMConfigV2`) and its own tests:

```sh
go test -count=1 -run 'Test_RandomXLight$|Test_RandomXLight_V2|Test_RandomXWOWLight|Test_RandomXLight_Single' .
go test -run XXX -bench 'Benchmark_RandomXLight$' -benchtime 100x .
```

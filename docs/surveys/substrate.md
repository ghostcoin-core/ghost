# Survey: Polkadot SDK (Substrate) with Frontier as the base client

Status: research only. No code was written or run. Every claim below comes from
reading source, and where the evidence is thin the text says so. Written
2026-10-16.

This survey answers the same questions as the Reth survey
([reth.md](reth.md)) and the Ethereum Classic-family survey
([etc-family.md](etc-family.md)), so the three can be compared. It adds two
questions that only Substrate raises: checking a hash-based proof inside the
Wasm runtime, and adding GRANDPA finality later. Scope and choices come from
[docs/ghost-outline.md](../ghost-outline.md).

## What was read

| Item | Pin |
|---|---|
| Polkadot SDK (`paritytech/polkadot-sdk`), `master` | commit `2cd0e4fe5b5ef1355d89ffff40f69c2713f01b34`, 2026-10-15 |
| Latest stable release of the SDK | tag `polkadot-stable2609`, commit `7a8daa68e18718c18823c1109513fdc1c8aa71fe`, 2026-10-08. Not read directly; I did not diff the cited files against it |
| Frontier (`polkadot-evm/frontier`), `master` | commit `24fcbdb175d15c4727c9e139a5e84a71270afeba`, 2026-06-18. Depends on the SDK branch `stable2603` |
| `evm` (SputnikVM), Frontier's EVM engine | v0.43.4, git branch `v0.x` (`Cargo.toml:65` and `Cargo.lock:2927-2929` in Frontier), source read from `rust-ethereum/evm` at commit `a656db9` |
| Kulupu (`kulupu/kulupu`), `master` | commit `d9428305d1155514574df79a4692a48711c2bcb2`, 2022-09-30. Substrate dependency resolves to commit `4a9b8d1977ff5844ef07be76337de7034d1d50d3` (`Cargo.lock:1561`) |
| Plonky3 crates (`p3-*`) | 0.9.0-rc.2 from crates.io, published 2026-10-16 |
| Moonbeam, Astar | `Cargo.toml` of each `master` on 2026-10-16, to see how production chains consume the SDK and Frontier |

Paths without a prefix are in the SDK commit above. Paths prefixed `frontier:`
or `kulupu:` are in those repositories. Line numbers drift, so re-check them
against the pinned commits.

The SDK is a large tree: about 1.77 million lines of Rust under `substrate/`,
`polkadot/`, `cumulus/` and `bridges/`, of which the node-side `substrate/client`
is about 263,000. Ghost would use a small part of it.

An outside write-up that recommends this stack was read as input only. Its
claims were checked against code here, not relied on, and its proof-system
recommendation is out of scope because the outline requires hash-based proofs.

## Bottom line

- Substrate plus Frontier can carry Ghost. It supplies most of the pieces Reth
  lacks for proof of work: a seal-checking import path, fork choice by
  accumulated difficulty, and a mining worker. It also gives Ghost three things
  the other two bases do not: a runtime that every node re-executes (so the two
  tree roots in the header are checked for free), a built-in way to mark a
  transaction as having no sender, and a Wasm runtime that is a natural place
  for the commitment logic.
- But the proof-of-work engine is thin and unused. `sc_consensus_pow` is 965
  lines, has no tests, has had only follow-up edits for SDK-wide refactors since
  2024, and is used by no live chain I could verify. The one real user, Kulupu, copied the crate into
  its own tree in 2021, last released in October 2022, and is a volunteer side
  project. A pure proof-of-work chain on Substrate also never finalises a block.
  State pruning still works, but the storage layer quietly sets a reorg limit of
  4,096 blocks, and new nodes cannot fast-sync (question 1).
- Frontier is good enough for MetaMask-style use but is not Ethereum. It is
  built on a different EVM (SputnikVM, not revm), emulates Ethereum block
  headers instead of using them, uses its own base fee formula, returns zero for
  DIFFICULTY and PREVRANDAO, and lacks `eth_getProof` and the trace methods
  (question 6). It also lags the SDK: it is on `stable2603` while `stable2609`
  has shipped.
- Licence is the best of the three for a dual MIT and Apache project: runtime
  code (FRAME, primitives, most Frontier pallets) is Apache-2.0, and node code is
  GPL-3.0 with the Classpath exception, which permits linking with code under
  other licences. It needs a legal reading (question 8).
- Rough effort to the same private test network as the other two surveys: 28 to
  44 engineer-weeks including RandomX (about 6.5 to 10 months), against 32 to 49
  for Reth and 12 to 21 for the Ethereum Classic family on the same scope (see
  the normalised table). Substrate does not shrink the total much. It moves
  the risk from "no proof-of-work precedent in the code" to "a thin engine, a
  lagging EVM layer and a framework with a steep learning curve".
- Verdict: a credible second choice and a real alternative to Reth, not a clear
  winner. It is worth choosing only if the runtime model (pallets, digest-checked
  header fields, bare transactions) is valued more than a more faithful EVM.
  Questions 9 and 10 are separate from this verdict and are answered below.

## 1. Where consensus plugs in, and proof of work from block one

### The pieces

Substrate splits consensus into separate parts that the node assembles. For
proof of work (`substrate/client/consensus/pow/src/lib.rs`, 683 lines, plus
`worker.rs`, 282 lines):

- **`PowAlgorithm`** (lines 174-211). Ghost implements four methods:
  `difficulty(parent)` returns the difficulty the next block must meet (line
  182); `verify(...)` checks a seal against the header hash, the pre-runtime
  digest and the difficulty (line 203); `preliminary_verify` is an optional
  cheap check done before the parent is known (line 186); `break_tie` decides
  between equal-work blocks (line 199, default: first seen wins).
- **`PowBlockImport`** (lines 214-395). Wraps the normal block import. On every
  import it reads the parent's stored total difficulty, adds this block's
  difficulty, and stores the result (lines 331-332, 373-377). It then sets the
  fork choice: more total difficulty wins, and equal difficulty goes to
  `break_tie` (lines 378-391). This is the greatest-cumulative-work rule the
  outline asks for, already written.
- **`PowVerifier` and `import_queue`** (lines 398-477). The verifier removes the
  last digest item, which must be a seal with engine id `pow_`
  (`substrate/primitives/consensus/pow/src/lib.rs:30`), and hashes the rest as
  the "pre-hash" the miner worked on (lines 408-432).
- **`start_mining_worker`** (lines 488-650) and `MiningHandle`
  (`worker.rs:71-216`). It builds a block on the best chain, and hands out the
  pre-hash, difficulty and best hash. A miner thread finds a seal and calls
  `submit(seal)`, which verifies it again and imports the block
  (`worker.rs:141-215`). The crate states it does not do the search itself (lines
  479-481).

Proof of work from block one needs nothing special: the crate has no
transition logic. Total difficulty for an unknown parent reads as zero
(`PowAux::read`, lines 163-170), so genesis starts at zero and block 1 gets
whatever `difficulty(genesis)` returns.

The runtime does not need to know about consensus. It can learn the block's
author from the pre-runtime digest through the `FindAuthor` trait that
`pallet-authorship` uses (`substrate/frame/authorship/src/lib.rs`). The
digest is placed into the header before the block is built, so it is covered
by the proof of work.

### How complete, used and maintained is it

- **Maintenance.** `git log` for the crate shows 15 commits since January 2024.
  All are repository-wide refactors: dependency lifting, formatting, a
  `BlockImport` signature change (#5339), a block-import refactor (#4844) and
  proposer API follow-ups (#9947, 2025-11-30). The last touch was formatting
  (#10958, 2026-02-06). I found no feature or fix aimed at proof of work.
  GitHub search for the crate name returns six issues and pull requests across
  the whole history; the three open ones (#13423, #9247, #8446) are about block
  building, state sync and import checks, not about proof of work.
- **Tests.** None. The crate has no test functions and no tests directory.
- **Use.** On crates.io `sc-consensus-pow` has about 126,000 downloads against
  639,000 for `sp-consensus-pow`, and its only reverse dependency is the
  `polkadot-sdk` umbrella crate. The SDK's own node (`substrate/bin/node/cli`)
  lists it in `Cargo.toml:91` only as an umbrella feature. The only mention in
  the documentation is a link list (`docs/sdk/src/polkadot_sdk/substrate.rs:142`).
  The version in the source tree reads 0.33.0 and crates.io carries 0.60.0
  (published 2026-10-08); I did not investigate why they differ.
- **Production users.** Kulupu is the only chain I could verify (question 7). I
  searched for others and found none I could confirm. Absence of evidence, not
  proof of absence.

### What it lacks

1. **Difficulty adjustment.** None in the crate. Ghost writes it. The SDK offers
   a runtime API for this, `DifficultyApi` (`primitives/consensus/pow/src/lib.rs:61-67`),
   with a warning that putting the adjustment in the runtime is safe but
   putting the proof-of-work algorithm there is not.
2. **A timestamp rule.** `Error::TooFarInFuture` is declared (lines 82-83) and
   never returned. The only drift check is the timestamp pallet's, a hard-coded
   30 seconds (`substrate/frame/timestamp/src/lib.rs:305-306`) which equals
   Ghost's whole block time target. There is no median-time-past rule anywhere
   in the SDK that I found. Ghost must specify and write one, as the outline
   already says under "To specify". The inherent check also starts only at a
   configurable height (`check_inherents_after`, line 275).
3. **Mining RPC or Stratum.** None. Frontier's mining methods are stubs
   (`frontier: client/rpc/src/eth/mining.rs:32-50`: hashrate returns zero, work
   returns an empty value, `eth_submitWork` returns false). Ghost writes a
   work-request and submit interface, and a pool protocol is separate work.
4. **Sync by work.** The sync code ranks peers and schedules downloads by block
   number (for example `substrate/client/network/sync/src/strategy/chain_sync.rs:665`
   and `:2123`). The word "difficulty" does not appear anywhere in
   `substrate/client/network/sync/src`. A peer that announces a block it
   considers its best (`is_best`, lines 527-570) triggers an ancestor search if
   the parent is unknown, so forks are chased. But a node that is behind picks
   the highest peer, not the heaviest. Whether this can be abused depends on the
   difficulty rule and must be tested. I did not trace every sync path.
5. **Finality, and everything that hangs on it** (next section).

### Pure proof of work leaves genesis as the only finalised block

A pure proof-of-work chain never calls finalise, so the finalised block stays at
genesis. Substrate copes with that better than I first expected, but with a
hidden depth limit. What I verified:

- **State pruning works without finality, on a delay.** The database layer
  force-canonicalises state a fixed number of blocks behind the best block
  "regardless of finality" (`substrate/client/db/src/lib.rs:1580-1624` and the
  call at `:1840-1842`). The delay is a constant, 4,096 blocks
  (`substrate/client/service/src/builder.rs:389-397`), about 34 hours at 30-second
  blocks. State older than that is eligible for pruning under the normal
  pruning setting (`substrate/client/state-db/src/lib.rs:349-365`). Only archive
  mode (`state-db/src/lib.rs:328-346`) keeps everything. Younger state sits in an
  overlay (`state-db/src/noncanonical.rs:35-39`) that allows at most 32 sibling
  blocks per height (line 32), so it is bounded.
- **That delay is a hidden reorg limit.** Setting a head more than the delay
  below the current best block returns `SetHeadTooOld`
  (`db/src/lib.rs:1472-1475`, with a test at `:5454`), and a fork that branches
  from a block whose state has already been canonicalised and pruned cannot be
  executed. I did not test the fork-point case, but the effect is that a reorg
  deeper than about 4,096 blocks is not applied by nodes with default settings,
  which makes the storage layer, not the specification, the place where deep
  reorgs are refused. A node that has pruned older state and one that is an
  archive node would behave differently on such a fork, which is a split risk.
  Ghost should set this depth deliberately and write it into the specification.
- **Block history.** Pruning of block bodies is keyed to the finalised block
  number (`db/src/lib.rs:2104-2135`), so with finality stuck at genesis nothing
  is pruned. I did not check the default setting. Nodes that serve sync keep full
  history anyway.
- **Fast sync.** Warp sync exists only through GRANDPA proofs: the only real
  `WarpSyncProvider` is in `substrate/client/consensus/grandpa/src/warp_proof.rs:356`.
  A new node must therefore download and execute every block from genesis, at
  1,051,200 blocks a year at 30-second blocks. Every historical Reveal proof is
  verified again during that replay.
- **No explicit reorg rule.** Beyond the storage limit above, the proof-of-work
  import accepts any fork with more total difficulty. Kulupu added a "weak
  subjectivity" wrapper that refuses deep reorgs unless they carry far more work
  (`kulupu: pow/src/weak_sub.rs`, wired in at `src/service.rs:207-211` with
  parameters 30 and 1.1).
- **Fork-choice storage.** Total difficulty lives only in each node's own
  auxiliary storage (`POW_AUX_PREFIX`, lines 131-147), not in the header. A
  node that imports a block without its parent's entry restarts the count from
  zero, which is one more reason fast sync cannot be bolted on without work.

So pruning does not need a new finality rule. What Ghost needs is an explicit
reorg-depth rule that matches what the storage layer enforces, which could be
the 4,096-block default made official, a weak-subjectivity check like Kulupu's,
or a depth finaliser in the node, or later GRANDPA (question 10). Each turns a
depth into a consensus rule. The outline lists "behaviour when mining power
drops" and settlement as open, so this is a specification decision for Ghost
either way.

### Verdict for question 1

The engine is real but small. It saves the seal-checking import path, the
cumulative-work fork choice and the mining worker loop, which the Reth survey
puts at the larger share of its proof-of-work cost. It does not save the
difficulty rule, the timestamp rule, mining RPC, reorg-depth and pruning policy,
or sync by work. Estimate in the effort table below.

## 2. Adding a RandomX mining module

**Where it lives.** In the node, never in the runtime. The SDK's own comment is
explicit that the algorithm must stay out of the runtime
(`primitives/consensus/pow/src/lib.rs:61-63`). RandomX is C++, so the node links
it through a foreign-function wrapper. Kulupu did this with its own bindings to a
fork of the reference code (`kulupu: pow/randomx/sys`), and it is the only
example of RandomX inside Substrate I found.

**Building.** The mining worker already builds the full block through the
normal proposer, runs the runtime, and returns the metadata a miner needs. The
parts of the header that execute are fixed before sealing. The seal (nonce and
whatever else the algorithm wants) is a byte string appended afterwards as
the last digest item, so it does not change the state root or any value a
contract can read (`worker.rs:179-183`). This avoids the problem the Reth
survey describes with `mix_hash` and PREVRANDAO: here the nonce is never part of
the executed header.

**Sealing.** Ghost's seal could carry just the nonce. The miner address
(for the reward) goes in the pre-runtime digest, which is part of the pre-hash
and so cannot be changed after the work is done. `start_mining_worker` takes
this as its `pre_runtime` argument (line 496).

**Key rotation.** Ghost must define a key-block rule. Kulupu's is the model
and its flaw is a warning:

- Kulupu changes the key every 4,096 blocks with a lag of 128 blocks, and the key
  is the hash of the key block (`kulupu: pow/src/lib.rs:58-98`).
- It finds that block by walking parent headers one at a time on every
  verification, up to about 4,200 header reads (lines 80-95).
- A runtime can do this better: store the key-block hash in a storage item at
  each epoch boundary (the runtime sees its own parent hash) and expose it
  through a runtime API. Verification then costs one lookup. This is my design,
  not something I saw built.
- At 30-second blocks, Kulupu's 4,096 and 128 would need to be about 8,192 and
  256 to keep the same wall-clock times.

**Difficulty in the header.** Substrate's header has fixed fields (parent hash,
number, state root, extrinsics root, digest). Difficulty is not one of them;
Kulupu keeps it in runtime storage and reads it through a runtime API
(`kulupu: runtime/src/lib.rs`, `DifficultyApi`). To have it in the header, the
runtime deposits a digest item holding the block's difficulty and its
cumulative work in `on_initialize`. The digest is then part of the pre-hash and
every importing node checks it by re-executing (see question 4). This lets a
light verifier read work from headers alone.

**Difficulty algorithm.** A runtime pallet can implement any rule in integer
math. Kulupu's (`kulupu: frame/difficulty/src/lib.rs:80-144`) is a moving
average over 60 blocks with damping by 3 and a clamp of 2 (`primitives/src/lib.rs:36-56`).
The outline asks for a per-block "proven design"; this is a place to implement
that, not to copy Kulupu.

**Reward.** Kulupu's reward pallet pays the whole reward to the author named in
the digest in `on_finalize` (`kulupu: frame/rewards/src/lib.rs:175-189, 224-228`).
Ghost's schedule differs but the shape is the same.

**Signed mining (do not copy).** Kulupu's second algorithm version requires the
miner to sign each candidate with the coinbase private key
(`kulupu: pow/src/compute/v2.rs:25-30, 78-96`; its README says the key must sit
in the mining software, `README.md:72-75`). Anyone mining on behalf of others
would need that key, so this works against pool mining. That is my reading, not
a statement in the repository. The outline requires an operator-free pool, so
Ghost should not use it.

**Light and fast mode.** Kulupu mines in full mode and verifies with a light
cache, with a shared pool of two full and three light VMs
(`kulupu: pow/src/compute/mod.rs:40-45, 296-340`). The memory figures
(about 2 GiB for mining, about 256 MiB for light verification) are from general
knowledge of RandomX and are not checked here. The benchmark task should
measure verification cost, as for the other bases.

## 3. A native transaction type with no sender account

This is better supported here than on either other base.

**Extrinsic formats.** Substrate's transaction wrapper has three shapes
(`substrate/primitives/runtime/src/generic/unchecked_extrinsic.rs:88-103`):
signed (a signature and an address), bare (no signature, no extension), and
"general" (no signature, with a transaction extension that does the
authorisation). A bare extrinsic is validated by the runtime's
`ValidateUnsigned` trait (`primitives/runtime/src/traits/mod.rs:1917-1958`).
The source comment there says the bare format may in time shrink to inherents
only, with general transactions replacing unsigned ones.

**What validation can say.** `validate_unsigned` returns a `ValidTransaction`
with a priority, `requires` and `provides` tags, a longevity and a propagate
flag (`primitives/runtime/src/transaction_validity.rs:283-322`). Two
transactions with the same `provides` tag conflict and one is dropped
(lines 301-309). That is exactly a one-time marker: Ghost sets `provides` to the
marker, and the pool refuses a second pending Reveal for it with no extra code.
The runtime's `pre_dispatch` runs again at block-build time and during import
(`traits/mod.rs:1917-1930`), so a marker spent in the chain is also rejected
there.

**The proof is the authorisation.** The bare path has no signer, so there is no
sender account, no nonce and no fee payer. This removes the "pseudo-sender" the
Reth survey needs and the whole signature-recovery path. Anything that assumes
a signer, such as the standard fee extension, simply does not apply, so the
Reveal pallet takes the fixed fee from the commitment itself, burns the base
fee and pays the fixed tip to the block author. That is Ghost code, and it must
return a constant weight (question 9) so that every private transaction costs
the same and has the same shape.

**Beside Frontier's Ethereum transactions.** Frontier wraps the extrinsic type in
`fp_self_contained::UncheckedExtrinsic`. Its validation code routes three ways:
Ethereum transactions are "self-contained" (signed inside the call, recovered
by `pallet-ethereum`), and bare and general extrinsics are handed to the stock
path (`frontier: primitives/self-contained/src/checked_extrinsic.rs:76-114`
for validation, `:117-150` for execution, and
`unchecked_extrinsic.rs:93-140`). So one block can hold Ethereum transactions
(commits and public transfers) and bare Reveal transactions with no changes to
Frontier. I read this code; I did not run it.

**The Ethereum side does not see it.** Frontier builds its Ethereum-shaped
blocks only from Ethereum transactions. A Reveal is a Substrate extrinsic, so it
would not appear in `eth_getBlockByNumber` or as an Ethereum receipt. Wallets
and explorers that read the Ethereum view will not see Reveals unless Ghost
adds them (a custom RPC namespace or a fork of the Ethereum block builder).

**Denial of service.** Pool admission runs `validate_unsigned` on every node
for every submitted transaction, and again periodically as the pool
revalidates. For Ghost that call would verify a proof. A sender-less
transaction carries no fee until the proof checks, so an attacker pays nothing
for invalid ones. The mitigation is ordering the checks cheapest first (known
tree root, unspent marker, exact size and shape, then the proof) and limiting
the pool. This risk is the same on all three bases.

## 4. Coin tree and data tree state in every block header

**Where to put the fields.** The Substrate header has no custom fields, and
the standard way to commit extra data in it is a digest item. Precedents in the
SDK itself: the Merkle mountain range root, which is deposited as a header
digest by the BEEFY pallet (`substrate/frame/beefy-mmr/src/lib.rs:70-85`, using
`frame_system::Pallet::deposit_log`, `substrate/frame/system/src/lib.rs:2120`),
and Frontier's Ethereum block hash, carried as a digest under its own engine
id (`frontier: frame/ethereum/src/lib.rs:511-530`).

**How they get verified.** This is the strongest point of the Substrate design.
When a node imports a block it re-executes it in the runtime, and the final
step compares the header with what the runtime computed. That step requires
the same number of digest items, each item equal, and the same state root
(`substrate/frame/executive/src/lib.rs:919-945`). So if Ghost's pallet deposits
the two tree roots as digest items in its hooks, any block whose header carries
a different root is rejected by every full node, with no extra hook and no extra
code. The Reth survey needed a custom post-execution hook for this and could
not confirm it works.

**Light verification.** A verifier that holds only headers can read the roots
from the digest. It must also check the seal (RandomX in light mode) and the
chain of headers. I found no light client in the SDK that supports proof of
work: the SDK's light-client path is built around BABE, Aura and GRANDPA, and
I did not look at smoldot. Treat a proof-of-work header verifier as new work,
shared with the other two bases. As a fallback, a storage read proof against the
state root works in Substrate today (`state_getReadProof`), but it uses the
trie and its hash, not Ghost's proof-friendly hash, and is heavier.

**The trees themselves.** Two trees of depth 32 with a fixed hash are ordinary
storage in a Ghost pallet. The SDK's `pallet-merkle-mountain-range`
(`substrate/frame/merkle-mountain-range/src/lib.rs:240-265`) is a worked example
of an append-only accumulator that appends in `on_initialize`, stores a root
and exposes proofs through a runtime API. It uses its own hash and a
different tree shape, so it is a pattern to copy, not a part to reuse.
Keeping the leaves out of the state trie and only the frontier and root in
state is a design choice for the specification.

**What the EVM sees.** Frontier's Ethereum header is a copy built in
`on_finalize` (`frontier: frame/ethereum/src/lib.rs:464-534`) and has no spare
fields; Ghost's roots would not be in it unless the builder is patched. They
would live in the Substrate header digest, reachable through a Ghost RPC method
and a precompile, not through `eth_getBlockByNumber`.

## 5. Burn on commit and mint on reveal with no contract holding mint rights

**Mint on Reveal.** The Reveal pallet is runtime code that credits the
destination through the balances pallet's mint operation. Nothing is a
contract and no address holds the right; the code path exists only in the
Reveal call. Anyone auditing "no contract can mint" reads one pallet.

**Burn on Commit.** A Commit is an ordinary Ethereum transaction, so it runs in
the EVM. Frontier's precompiles are Rust code inside the runtime. They can read
and write any pallet's storage and call the balances pallet
(`frontier: frame/evm/src/runner/stack.rs:1394-1408` shows the runner doing
transfers the same way; `precompiles/src/substrate.rs:106` shows a precompile
dispatching a runtime call). So a precompile at a fixed address can verify the
commit statement, insert the commitment, and burn the value that came with the
call, with no contract, owner or upgrade path.

**Atomicity.** This was the open worry in the Reth survey and it is better
answered here. Every EVM call frame opens a storage transaction, and a revert
rolls it back: `sp_io::storage::start_transaction`, `commit_transaction` and
`rollback_transaction` at `frontier: frame/evm/src/runner/stack.rs:894-923`.
Pallet storage written by a precompile is inside that transaction, so a
reverted Commit undoes both the burn and the tree insert. I read the code and
did not test it; it still needs focused tests for static calls and out-of-gas
paths.

**The amount binding.** The outline's "amount bound at commit" rule fits: the
precompile reads the call value and the claimed amount in the same call.

**Base fee.** Frontier's adapter drops the base-fee portion of the payment
rather than crediting anyone, which is a burn, and pays the tip to the block
author (`frontier: frame/evm/src/lib.rs:1200-1260`; the burn is my inference
from the types and was not tested). The block author is whatever the runtime's
`FindAuthor` returns. If it returns nothing, tips go to the zero address, so a
proof-of-work `FindAuthor` that reads the miner address from the pre-runtime
digest is required.

## 6. Frontier's EVM fidelity against Ethereum's current stable feature set

The outline asks for "Ethereum's current stable feature set, minus the
proof-of-stake parts". Frontier gets the opcodes close and the surrounding
chain behaviour less close.

### Engine and feature coverage

Frontier runs the SputnikVM crate `evm` v0.43.4, configured for the Osaka fork
(`frontier: primitives/evm/src/lib.rs:43`, `Config::osaka()`). That engine
has flags for PUSH0, transient storage, MCOPY, the SELFDESTRUCT change (EIP-6780),
EIP-7702 account delegation, the EIP-7623 calldata floor, CLZ (EIP-7939) and a
raised initcode limit. Frontier also sets the per-transaction gas cap
(`primitives/evm/src/lib.rs:46`). SputnikVM is a different engine from revm,
the one Reth uses, with far fewer deployments outside Substrate chains.

| Feature | Frontier | Note |
|---|---|---|
| EIP-1559 transactions, EIP-2930, legacy, EIP-7702 | Present | `frontier: frame/ethereum/src/lib.rs:427-451` |
| Blob transactions (EIP-4844) and blob opcodes | Absent | No transaction type and no opcode found. Fine for Ghost, which drops blobs |
| Withdrawals, beacon roots, staking requests | Not applicable | There is no beacon chain in this stack, so nothing to remove |
| Precompiles 1-5 and 1024-1027 | Wired in the template | `frontier: template/runtime/src/precompiles.rs:21-31` |
| bn128, blake2, BLS12-381 | Crates exist, not wired by default | Ghost wires them |
| KZG point evaluation, P256 verify | Not found | Not needed unless Ghost wants them |
| Empty-account rules (EIP-161) | Differs | `exists()` is always true and `reset_balance` does nothing (`runner/stack.rs:1163`) |

### Divergences that matter

1. **DIFFICULTY and PREVRANDAO return zero.** The runner hard-codes
   `block_difficulty` to zero and gives no randomness value
   (`frontier: frame/evm/src/runner/stack.rs:1140-1144`), and the engine falls
   back from PREVRANDAO to difficulty, so both read 0. A proof-of-work chain that
   wants a real value for contracts must patch the runner. This avoids the
   Reth problem of the nonce leaking into execution, but it is a fork of
   Frontier's code. The block timestamp is divided from milliseconds to seconds
   (`stack.rs:1118-1155`).
2. **Emulated Ethereum blocks.** `pallet-ethereum` builds an Ethereum header at
   the end of each block (`frontier: frame/ethereum/src/lib.rs:464-534`). Its
   state root is the Substrate trie root at that moment, taken before the block
   is finished (`:1119-1125`), not an Ethereum state trie. Difficulty is 0, the
   mix hash and nonce are 0 and extra data is empty. Its hash is stored in
   pallet storage and in a digest item, not the Substrate block hash. An index
   (`frontier: client/mapping-sync` and `client/db`) maps the two so JSON-RPC
   lookups work.
3. **Base fee formula.** `pallet-base-fee` moves the fee by how full the
   block is in execution-time weight, linearly between a lower and upper
   threshold, with a default 12.5% elasticity and a floor
   (`frontier: frame/base-fee/src/lib.rs:130-200`). It is not the Ethereum
   formula based on gas used against a gas target. Wallets read the same
   field and work, but the fee dynamics differ, and the outline's "set by the
   chain's formula and burned, as on Ethereum" needs a runtime-level decision.
4. **Gas versus weight.** Gas is derived from Substrate weight
   (`frontier: frame/evm/src/lib.rs:912-956`), which is a measured execution
   time and proof size. The runner also meters storage growth and proof size,
   so a call can run out of gas before its nominal limit
   (`runner/stack.rs:1098`). The pallet's own documentation says gas is an
   approximation of weight, so Ethereum's gas costs are not reproduced exactly
   for state-heavy operations. The proof-size part is built for chains that
   share a relay chain: the runner imports a Cumulus crate
   (`runner/stack.rs:34`, `frame/evm/Cargo.toml:26`), which a solo proof-of-work
   chain would keep as a dependency and set to zero. I did not check what else
   needs it.
5. **Accounts.** Frontier supports 20-byte accounts end to end: an
   `AccountId20` type, Ethereum signatures and an identity address mapping (the
   template does this, `frontier: template/runtime/src/lib.rs:78-82, 372-377`).
   This keeps standard `0x` addresses, which the outline wants. The default
   hashed mapping for 32-byte accounts breaks that identity and should not be
   used. Decimals are not handled: the balance is read from the currency and
   converted one to one (`frame/evm/src/lib.rs:1051-1064`), so set the balances
   pallet to 18 decimals. The balance the EVM sees excludes the existential
   deposit, so Ghost sets that deposit to zero.

### JSON-RPC and tooling

- **Present** (`frontier: client/rpc-core/src`): the usual `eth_` read, call,
  estimate-gas, fee-history, logs, filters and `eth_subscribe` methods,
  `eth_getBlockReceipts`, `eth_sendRawTransaction`, `net_`, `web3_` and
  `txpool_`. The `eth_call` family supports state overrides
  (`client/rpc/src/eth/execute.rs:41`).
- **Missing:** `eth_getProof` and `eth_createAccessList` exist only as type
  definitions in a stub crate (`client/rpc-v2` is 19 lines of code), and I found
  no `debug_trace*` or `trace_*` method. `debug_` has only raw-block and
  raw-receipt methods. Tools that rely on proofs or traces will fail.
- **Mining methods:** stubs, as above.
- **Foundry, Hardhat, MetaMask:** the repository's test suite (`ts-tests`)
  covers fee history, filters, logs, subscriptions, transient storage,
  EIP-7702, state overrides and precompiles. I found no Foundry or Hardhat run
  in its CI and did not run either tool. Frontier's README says Ethereum apps
  run unmodified, and production chains rely on it, but I did not test
  compatibility, and that claim is the vendor's. This needs a hands-on check
  before any commitment.

### Fit for Ghost

The right summary is: Frontier is a faithful enough execution layer for
wallets and Solidity, a poor fit if anything must treat the Ethereum header as
the chain's truth, and a code base Ghost will patch in at least three places
(the EVM block context, the Ethereum header builder and the base fee). Those
patches are on top of an upstream that is already behind.

## 7. Custom chains already built this way, and Kulupu

### Frontier and the SDK in production

Moonbeam and Astar are real chains built on this stack (both are parachains,
so neither runs proof of work), and both show a pattern worth noting. Each depends on its own fork of Frontier, not the upstream
repository: Moonbeam on `moonbeam-foundation/frontier`, branch
`moonbeam-polkadot-stable2603`, and `moonbeam-foundation/polkadot-sdk`, branch
`moonbeam-polkadot-stable2603`; Astar on `AstarNetwork/frontier`, branch
`stable2512` (each repository's `Cargo.toml`, read 2026-10-16). Moonbeam's last commit
was 2026-10-14.

Proof of work with Frontier: I found no chain. Frontier's code and tests contain
no proof-of-work references beyond the stubbed mining RPCs, and its template
node uses Aura, GRANDPA and manual seal
(`frontier: template/node/Cargo.toml:31-34`). The engine does not depend on the
consensus type: it needs a `FindAuthor` and a timestamp. This is a design
inference from the code, not an observed build.

### Kulupu

Kulupu is a Substrate chain with RandomX proof of work, launched in 2019. What
the code at the pinned commit shows:

- **Size and age.** About 518 commits: 129 in 2019, 327 in 2020, 60 in 2021 and 2
  in 2022. One author made 489 of them; the next has 20. Last release v2.9.2
  (2022-10-02). The Substrate dependency is an untagged git reference resolved
  to a commit from October 2021 (`kulupu: Cargo.toml:21-52`, `Cargo.lock:1561`).
  It uses macros (`decl_module!`, `decl_storage!`) and a native executor that
  the SDK has since removed. Porting means rewriting the node glue, not
  bumping a version. The exact API differences were not verified.
- **What it built on `sc_consensus_pow`.** It did not use the crate as is. It
  copied it into the repository ("Vendor sc-consensus-pow", commit `bd27c2b`,
  2021-10-08) as `kulupu-pow-consensus`, with two changes: `verify` also
  receives the pre-runtime digest, and the mining worker can add a
  pre-runtime digest naming the author (`kulupu: pow/consensus/src/lib.rs:206-213, 547, 660-662`).
  Both are now in the upstream crate (`lib.rs:203-210, 488-496`), so the
  vendoring would probably not be needed today.
- **Algorithm.** `RandomXAlgorithm` (`kulupu: pow/src/lib.rs:132`) reads the
  difficulty through the runtime API, breaks ties by comparing hashes of the two
  seals (line 154), and verifies by re-running RandomX and checking that the
  hash times the difficulty does not overflow 256 bits (lines 51-56, 158-254).
  An on-chain algorithm identifier (`randomx1` or `randomx2`,
  `primitives/src/lib.rs:72-73`) chooses the version, so an upgrade can switch
  the rule at a runtime change.
- **Chain selection.** It uses `LongestChain` with no finality
  (`src/service.rs:195`). The SDK's `LongestChain` asks the database for the best
  block and then its longest descendant
  (`substrate/client/consensus/common/src/longest_chain.rs:51-58`), and the
  database's best block is set by the proof-of-work import's fork choice, so in
  practice it follows total difficulty. I did not test a case where the
  heaviest chain is shorter.
- **Difficulty rule.** A runtime pallet, run each block when the timestamp is
  set (`kulupu: frame/difficulty/src/lib.rs:80-144`): a 60-block window
  (one hour at 60 seconds), the sum of recent difficulties scaled by target time
  over damped actual time, dampening of 3, a clamp of 2, a minimum of 3. There is
  no median-time-past rule. Window and key period are set for 60-second blocks
  and would need redoing at 30.
- **Reward and genesis.** The whole block reward goes to the digest author. A
  flat 60 units per block, locked and released in steps by default, with
  governance-settable changes (`kulupu: frame/rewards/src/lib.rs:175-282`,
  `runtime/src/lib.rs:354-401`). The README claims no premine. The current
  mainnet genesis is built from a snapshot of the previous era's final balances
  (`src/eras.rs`, `res/eras/0/final.json`, `src/chain_spec.rs:147-165`).
- **Re-genesis.** The maintainer's 2020 review describes the move to a new
  genesis ("Re-Genesis") with a short downtime, around April and May 2020 (git
  history `1aa9c21` to `b81daf5`). I found no stated reason beyond that, so I do
  not know why it was needed.
- **Mining.** Threads in the node call `worker.metadata()`, search, then
  `submit` (`src/service.rs:354-396`). There is no Stratum and no mining RPC;
  `src/rpc.rs` serves only system, payment and contracts.
- **Other features.** No EVM. Governance, treasury, identity and contract pallets
  with 12 decimals.
- **Licence.** All Kulupu crates are GPL-3.0-or-later (RandomX fork:
  BSD-3-Clause). Copying code into Ghost would bring GPL terms with it, so treat
  it as a design reference only.

### Why activity dropped

I found no official explanation, so what follows separates the documented from
the inferred.

- **Documented** (the maintainer's 2020 year review, `github.com/kulupu/coordination`
  discussion 10): an August 2020 exchange listing was followed by a pump and
  dump; hashrate stayed small with a few dominant miners; the council had
  serious inactivity; and it is described as a side project of one person.
- **Observed from the repository:** feature work stops in October 2021, the last
  release is October 2022, and later activity is small (a bootnode in January
  2025 and a RandomX pin update in November 2025).
- **Inferred, not documented:** dependence on one maintainer and a small
  hashrate are the likely causes. Whether the chain is still producing blocks, and
  its hashrate, I did not verify.

What this is evidence of: Substrate plus RandomX proof of work launched and
ran, with the pieces named above. It is not evidence the combination attracts or
holds miners, and it shows the upstream engine was not trusted enough to use
as shipped.

## 8. Licence and tracking upstream

**Licence.** The SDK is split by role, in each crate's `Cargo.toml` and SPDX
headers (`substrate/LICENSE-APACHE2`, `substrate/LICENSE-GPL3`):

| Part | Licence |
|---|---|
| Runtime side: FRAME pallets and support, primitives (`frame/*`, `primitives/*`), e.g. `frame/system`, `frame/executive`, `frame/grandpa`, `primitives/runtime`, `primitives/consensus/pow` | Apache-2.0 |
| Node side: `client/*`, e.g. `client/service`, `client/network`, `client/consensus/pow`, `client/consensus/grandpa` | GPL-3.0-or-later with the Classpath exception |
| Frontier runtime side: `frame/*`, `primitives/*` | Apache-2.0 |
| Frontier node side: `client/*` (RPC, mapping, database) | GPL-3.0-or-later with the Classpath exception |
| Frontier `precompiles/` helper crate | No licence line in its `Cargo.toml`; file headers say Apache-2.0 with a Moonsong Labs copyright |
| The node template (`templates/solochain`) | Unlicense (public domain) |
| RandomX reference | BSD-3-Clause (Kulupu's fork per the GitHub API; the reference repository was not read) |

The Classpath exception (`substrate/LICENSE-GPL3` at the end) lets code that
links the library statically or dynamically keep its own licence. On that reading
Ghost's own node and runtime code can stay MIT and Apache while the SDK's node
crates stay GPL. That is a better outcome than the Ethereum Classic family
(GPL node, LGPL libraries) and is in line with Reth, but it depends on the
exception applying to a combined binary the way the text suggests. I am not a
lawyer, and the outline lists legal review as an open decision. If Ghost
copies Kulupu code, GPL-3.0 applies to it.

**Tracking upstream.**

- The SDK cuts a stable release every three months (`docs/RELEASE.md:124`;
  recent: stable2603, stable2606, stable2609) and supports each for one year
  with monthly patch releases (`docs/RELEASE.md:31-36`). Only the latest release
  gets binaries; older ones are published to crates.io. Trait and API changes
  land between stables, and the crates are versioned individually (the PoW crate
  went 0.33 to 0.60 on crates.io in one release). Upgrade work per stable is a
  compile-and-fix pass over the node and runtime.
- **Frontier is the constraint.** It tracks the SDK through a git branch per
  stable (`stable2407` through `stable2603`), and every dependency in its
  `Cargo.toml` points at the SDK branch `stable2603`. At the time of writing
  `stable2606` and `stable2609` exist and Frontier has no branch for either, and
  its last commit is 2026-06-18, four months old. It has 157 open issues and
  pull requests. Its `SECURITY.md` supports only the latest pinned master and says
  the release pipeline is not finished. Its crates are not on crates.io beyond
  versions from 2021, so it can only be used as a git dependency.
- **What production chains do.** Both Moonbeam and Astar run their own forks of
  Frontier, and Moonbeam also a fork of the SDK. A small team that depends on
  Frontier should expect to carry a fork too, which is true for Ghost anyway
  because of the patches in question 6.
- **Recommended model.** Pin one SDK stable and the matching Frontier branch in
  `Cargo.lock`, keep Ghost code in few crates (a runtime, a node, a handful of
  pallets), and upgrade on a schedule, not on release. Plan for stable2603's
  end of life at about March 2027 (one year from release), unless Ghost
  ports Frontier to a newer stable itself, which is a budget item below.
- **Runtime upgrade model.** Substrate normally upgrades a chain by putting new
  Wasm on chain through a privileged call. The outline says nobody has authority
  over the chain, and upgrades happen at a set height when miners run new
  software. So Ghost removes the privileged upgrade call and the runtime in
  state is fixed. The SDK has a mechanism that swaps the on-chain Wasm for a
  blob in the chain spec starting at a block number
  (`substrate/client/chain-spec/src/chain_spec.rs:310-316`;
  `client/service/src/builder.rs:251-261`), meant for emergency fixes. It could
  carry a scheduled hard fork, but that is a use it was not built for, and I
  did not test it.

## 9. Verifying a hash-based proof (Plonky3) inside the Wasm runtime

**Can it be done in Wasm.** Yes in principle. The Plonky3 crates I read at
0.9.0-rc.2 (`p3-uni-stark`, `p3-fri`, `p3-baby-bear`, `p3-keccak`,
`p3-poseidon2`, `p3-merkle-tree`, `p3-field`, `p3-challenger`, `p3-commit`) are
all `no_std` in their `lib.rs`. They are release candidates, published the day
of this survey, so the API will move. Their processor-specific speedups are gated
to x86 and ARM features, so a Wasm build uses the portable code.

**What the runtime provides.**

- Runtime code is compiled to Wasm and run by wasmtime (`substrate/client/executor/wasmtime/src/runtime.rs:269`,
  Cranelift). The default settings switch off the SIMD and bulk-memory
  features (`substrate/client/executor/src/wasm_runtime.rs:436-453`,
  `wasm_simd: false` at line 449). There are no threads, so Plonky3's parallel
  feature is unavailable. The default heap is 2,048 pages, 128 MiB
  (`client/executor/common/src/wasm_runtime.rs:32`). Neither limit looks like a
  problem for one verification, but I have not measured.
- The host exposes fast hash functions: Keccak-256, SHA-256 and Blake2 as host
  calls (`substrate/primitives/io/src/relay_chain.rs:1398-1440`, the `Hashing`
  trait). If Ghost's in-proof hash is Keccak-256 (candidate B in
  [the benchmark plan](../benchmarks/plan.md)), Merkle-path hashing could call
  the host function instead of running Keccak in Wasm. Poseidon2 has no host
  function.

**Expected cost.** I have no measurement and will not guess a number. What can be
said from the structure:

- Verification is dominated by hashing (Merkle paths and the transcript) and field
  arithmetic on the 31-bit BabyBear field, with a degree-5 extension for
  challenges. These are 32-bit and 64-bit integer operations that Wasm handles
  well. Typical native-to-Wasm slowdowns for integer code are a small multiple;
  without SIMD it is worse for hashing. That is general knowledge, not checked
  here.
- The verifier runs for each Reveal at pool admission on every node that
  receives it, again when a miner builds a block, and again at import on every
  node, and once more on every historical replay for a new node (question 1, no
  fast sync).
- The Reveal call has a fixed shape, so its weight can be one constant, set by
  the SDK's benchmarking tool on reference hardware. Weight is what limits how
  many Reveals fit in a block. This gives a clean rule: choose the weight from
  the measured Wasm time, and the block limit follows.

**Is a native host function needed.** Not for correctness; Wasm is enough to be
correct. It is a speed decision to make after the browser benchmark and a Wasm
build of the verifier give real numbers. If the verifier is slow, the options are:
a host function for the hash only (smallest, and exists for Keccak), a host
function for the whole verifier, or a lower number of Reveals per block. A
custom host function lives in the node, not the runtime, so it becomes consensus
code that every client release must reproduce exactly, and a fix needs a new
node release at a set height rather than a runtime upgrade. The outline already
treats a chain change as a coordinated release, so this is less of a break than
on a stock Substrate chain, but it widens what a second implementation must
copy. My recommendation is to start in Wasm and add a host function only if the
numbers force it.

**Effort.** 2 to 4 engineer-weeks to build the verifier into the runtime, measure
it and set the weight. This is not in the totals below because the other two
surveys exclude the proof system.

## 10. GRANDPA as a later, optional finality layer

**What it takes.**

- **Runtime.** `pallet-grandpa` (Apache-2.0) holds the voter set and exposes the
  runtime API. The set is changed by calling `schedule_change`
  (`substrate/frame/grandpa/src/lib.rs:518`) or through the session pallet.
- **Node.** `sc-consensus-grandpa` wraps the block import (`block_import`,
  `substrate/client/consensus/grandpa/src/lib.rs:515-535`), runs a voter task,
  adds its own network protocol, and handles justifications. Wrapping the
  proof-of-work import is the intended shape of a hybrid. The SDK ships no
  proof-of-work-plus-GRANDPA example that I found. The solochain template uses
  Aura plus GRANDPA (`templates/solochain/node/Cargo.toml`).
- **Voters.** This is the hard part and not a code problem. GRANDPA needs a
  known set of keys that vote. With pure proof of work there is none. The options
  are a fixed list (a privileged set, which contradicts the outline's
  principle), a set derived from recent miners (a new design with no precedent I
  found), or a staked set (the outline puts staking out of scope).

**What it would change.**

- It would add a second kind of authority. Finality would depend on two-thirds
  of the voters being honest and online, not only on work.
- Blocks it finalises can never be reorganised. Both the long-range-attack
  question and the "deep reorganisation" question go away for finalised blocks.
  They are replaced by a question of what happens if the voters stall or are
  captured: the chain keeps producing blocks, but finality stops.
- It would make warp sync possible (`warp_proof.rs:356`), and let nodes prune
  block history, which pure proof of work does not.
- The outline puts "Stake and finality layers" out of scope and calls settlement
  probabilistic, so this stays a later option.

**A lighter alternative.** A depth finaliser in the node (finalise the block N
behind the best, refuse deeper reorgs) gives an explicit reorg limit and block
history pruning without a voter set. It is
a consensus rule, so every miner and node must apply the same N. Kulupu used a
related idea, a weak-subjectivity check that refuses deep reorgs unless the new
chain has far more work.

**Effort.** Low confidence. A fixed voter set: 6 to 10 engineer-weeks including
tests. A miner-derived or other open set: 10 to 16 or more, mostly design and
adversarial testing. A depth finaliser: 1 to 2 weeks, already counted in the
sync row below because Ghost needs an explicit reorg-depth decision from day one.

## Effort estimate

Engineer-weeks, one strong Rust engineer, for the same private test network the
Reth survey estimates. It includes: proof of work from block one (seal,
difficulty, reward, fork choice, miner loop, sync and reorg policy), RandomX
binding with key rotation and light verification, the sender-less Reveal
transaction, two tree roots in every header with verification, burn and mint,
the EVM feature set, genesis, and a private test network with reorg and sync
tests. It excludes: the proof system and its verifier, the wallet and web app,
mining installers and pools, security review, and the standing cost of following
upstream. Ranges, not promises.

| Work | Weeks | Confidence |
|---|---|---|
| Ramp-up on Substrate and Frontier; node and runtime skeleton from the solochain template on one SDK stable and its Frontier branch; remove Aura and GRANDPA; CI | 3 to 4 | Medium |
| Proof-of-work core: `PowAlgorithm`, difficulty pallet and runtime API, difficulty and cumulative work in the digest, miner address in the pre-runtime digest, `FindAuthor`, timestamp rule, reward pallet, mining thread, work request and submit interface | 4 to 6 | Medium; Kulupu is a design reference only |
| RandomX: native binding and build, key-block rule held in runtime storage, caches, light verification | 3 to 5 | Medium; the Ethereum Classic survey budgets 4 to 6 for its equivalent |
| Sync and reorg policy: sync by work, explicit reorg-depth rule and pruning settings, tests of partitions and long forks | 4 to 7 | Low; nothing to copy and no tests upstream |
| Frontier on a proof-of-work chain: EVM block context (difficulty), Ethereum header builder, base fee, 18 decimals, precompile set, Cumulus coupling, EVM feature selection | 3 to 5 | Medium; patches an upstream that is behind |
| Tree pallets, root digests, header check, runtime API and RPC for header-only verification | 3 to 5 | Medium; the digest check is built in |
| Sender-less Reveal and Commit: bare extrinsic validation, marker tags, fixed-fee path, pool limits, burn and mint, Commit precompile, Ethereum-side visibility | 4 to 6 | Medium |
| Weights and benchmarks for custom calls, test networks, adversarial tests of seals, key boundaries, reorgs and timestamps | 4 to 6 | Medium |
| Total | 28 to 44 (about 6.5 to 10 months) | |

Without the RandomX row the total is 25 to 39, which is the figure comparable to
the Reth survey's own total (see the next section). The sync and reorg
row (Low) and the Frontier row hold the schedule risk. The Reth survey's 9 to 14
person-months applied about 40 percent slack on top of its weeks; the same slack
on this total gives roughly 9 to 14 person-months.

Separate, not in the total: verifier in the Wasm runtime, 2 to 4 weeks
(question 9); GRANDPA, 6 to 16 weeks depending on the voter set (question 10);
porting Frontier to a newer SDK stable than it tracks, unknown and best budgeted
at 2 to 4 weeks per stable.

## Comparison with the Reth and Ethereum Classic estimates

The three surveys did not define scope the same way. The Reth total excludes
RandomX; the Ethereum Classic total includes it, and also includes catching up on
security fixes since the upstream freeze. Normalised to the scope stated in the
effort section above (RandomX included, security catch-up and standing
maintenance excluded), the figures are:

| | Reth | Ethereum Classic family (Core-Geth) | Substrate with Frontier |
|---|---|---|---|
| Stated total in its own survey | 28 to 43 weeks | 15 to 23 weeks | 28 to 44 weeks |
| Adjustment | Add RandomX binding, key rule and light verification, 4 to 6 weeks (the Classic survey's own figure for it) | Remove the one-time security catch-up, 2 to 3 weeks; its rows add to 16 to 25 against the stated 15 to 23, and I used the stated total | None; RandomX is already a row |
| Normalised total | 32 to 49 weeks (about 7.5 to 11.5 months) | 12 to 21 weeks (about 3 to 5 months) | 28 to 44 weeks (about 6.5 to 10 months) |
| Proof-of-work precedent | None found on this base | Built in; clean seam | A thin engine; one past chain that copied it |
| Biggest risk | Proof-of-work fork choice and sync have no precedent | Frozen 2024 upstream, one maintainer, standing backport duty | Thin and untested engine, no finality, lagging Frontier |
| EVM | Current (revm), EVM version to Amsterdam | Go Ethereum 1.13.15, nothing after Cancun | Osaka flags on SputnikVM; emulated Ethereum header, own base fee, no `eth_getProof` or tracing |
| Header fields | Custom header type; verification hook unproven | Many mechanical file changes | Digest items, checked by every node on import |
| Sender-less transaction | Pseudo-sender workaround through the type system | New type through about 20 files | Bare extrinsic with the pool tag as the marker, beside Ethereum transactions |
| Burn on commit | Stateful precompile; atomicity to verify | Native state change | Precompile; atomicity from storage transactions, read not run |
| Node licence | MIT and Apache | GPL-3.0 node, LGPL-3.0 libraries | Apache-2.0 runtime; GPL-3.0 with Classpath exception for node crates |
| Upstream pace | A release every 2 to 4 weeks | One backport round every few months | Stable every 3 months, supported 1 year; Frontier one or two stables behind |
| Finality and reorg limit | Choice for Ghost; untested for long runs | Standard for proof of work | Choice for Ghost; no finality, and an implicit 4,096-block storage limit |

Reading it fairly: Core-Geth is cheapest to build and most expensive to keep
alive. Reth and Substrate cost about the same to build on the normalised scope,
and Substrate's range is a few weeks lower. Substrate is not much cheaper
than the "proof-of-work engine exists" premise suggests because the engine
covers only the import and fork-choice path, which is part of Reth's
proof-of-work rows, while Substrate adds a ramp-up, the reorg-depth and pruning
decision, and the Frontier patching. The choice should not rest on effort.

## Risks

1. **The proof-of-work engine is thin and has no tests.** 965 lines, no test
   functions, no functional change since 2024, and no live user I could verify.
   Ghost would become its real maintainer. Mitigation: build the sync, reorg and
   key-boundary tests first on a private test network, and plan to vendor the
   crate as Kulupu did.
2. **No finality, and a hidden reorg limit.** Genesis stays the only finalised
   block. New nodes cannot fast-sync. State pruning works, but the default
   4,096-block canonicalisation delay acts as a reorg limit that archive and
   pruned nodes may apply differently. A depth rule is a consensus rule that
   splits the network if a reorg beyond it is ever honest. Mitigation: decide it
   in the specification before writing the fork-choice code, as the Reth survey
   also says, and test a reorg at and beyond the limit.
3. **Sync ranks peers by height.** There is no accumulated work in the sync
   code. Possible abuse by a high chain with little work depends on the
   difficulty rule; untested. Mitigation: a seal-checking header phase and an
   adversarial test.
4. **Timestamp rule.** The only drift limit is 30 seconds, equal to the block
   time, and difficulty depends on timestamps the miner sets. Needs a written
   rule and simulation, as in the outline's "to specify" list.
5. **Frontier lags and is a fork-in-waiting.** It is on `stable2603`, last
   commit four months old, with no branch for the newer stables, and its
   production users carry their own forks. Ghost needs at least three patches
   (EVM block context, Ethereum header builder, base fee). Each upstream bump is
   a merge.
6. **EVM fidelity is lower than on Reth.** Different engine (SputnikVM), emulated
   Ethereum headers, an Ethereum "state root" that is not an Ethereum state root,
   zero DIFFICULTY and PREVRANDAO, a different base fee formula, no
   `eth_getProof` or trace methods, and gas that approximates weight. Whether
   Foundry and Hardhat work well was not tested. The outline commits to
   "standard EVM wallet interfaces", so a hands-on compatibility pass is needed
   before deciding.
7. **Reveals are invisible to the Ethereum view.** Explorers and wallets reading
   `eth_` methods will not see them unless Ghost adds that.
8. **Pool and block-build cost of proof verification.** Verification runs at
   admission, at block build and on every import, with no fee to deter invalid
   transactions. Cheapest-first checks and pool limits are required, as on the
   other bases.
9. **Wasm verifier speed is unmeasured.** The decision between pure Wasm and a
   host function waits for a benchmark. A host function turns part of the
   verifier into client code every release must match.
10. **Upgrade model.** Removing the privileged upgrade call fixes the runtime in
    state, and scheduled hard forks would rely on the chain-spec code substitute,
    which is meant for emergency fixes and was not tested for this.
11. **Dependency and learning load.** Several crate families on a quarterly
    cadence, macros, weights and benchmarking. Estimate includes ramp-up, but a
    single engineer carrying consensus, runtime and node is a bus-factor risk
    that the review approach in the outline (a different model checks the code)
    does not remove.
12. **RandomX integration.** Native build and cross-compilation collide with the
    signed, rebuildable release goal; light-verification cost during header sync
    is unmeasured; the memory figures here are from general knowledge. Kulupu's
    key-block walk is a performance trap to avoid.
13. **Licence reading.** The Classpath exception looks sufficient for a dual MIT
    and Apache project but needs legal confirmation, and anything copied from
    Kulupu is GPL-3.0.
14. **Thin evidence.** Items marked "I found no" or "not verified" are absence of
    evidence in the commits read. I built and ran nothing. The Kulupu chain's
    current liveness was not checked. The outside write-up's claims about this
    stack were not independently re-derived beyond what is cited here.

## Suggested next steps

1. Read the other two surveys and the normalised table above together before
   choosing. The three bases differ in where the risk sits: what has to be
   maintained (Core-Geth), proof of work with no precedent (Reth), and what has to
   be patched and decided about finality (Substrate).
2. If Substrate is chosen, make the first engineering task a minimal node: the
   solochain template with Aura and GRANDPA removed, `sc_consensus_pow` with a
   dummy hash, a difficulty pallet, an explicit reorg-depth rule, and a three-node test
   network that survives a deep reorg and a partition. That retires risks 1 to 4
   cheaply, before anything else depends on them.
3. In parallel, run a hands-on Frontier pass: deploy a contract with Foundry,
   connect MetaMask, and read `eth_feeHistory`, against a local node. That
   settles risk 6 in days.
4. Build the Plonky3 verifier as a `no_std` Wasm module once the browser benchmark
   fixes the hash and field, measure it under the runtime executor, and set the
   Reveal weight from the result (question 9).
5. Decide in the specification, before code: what depth counts as final, the
   timestamp rule, and behaviour when mining power drops.

## Method and limits

- Read at the pinned commits by searching for the seams named in the questions
  and reading the code around them. Nothing was built or run, and no test was
  executed. Claims about behaviour are from reading, not running.
- Frontier's EVM engine source was read from `rust-ethereum/evm` at the commit
  Frontier pins, because the dependency is not vendored in the clone.
- Plonky3 `no_std` status is from each crate's `lib.rs` in the published 0.9.0-rc.2
  packages. Their Wasm build was not tried.
- GitHub and crates.io data (commits, tags, issue counts, download counts,
  branches) is from the public APIs on 2026-10-16. Private advisories and alerts
  are not visible. Counts of open issues for Frontier combine issues and pull
  requests.
- Kulupu was read in full at its last commit. Its RandomX fork directory was
  empty in the clone, so changes in the fork were not read. Reasons for the
  drop in activity rest on one maintainer post and repository history.
- The Reth and Ethereum Classic figures in the comparison are taken from those
  two surveys without re-checking their code.
- Line references age. Anything cited refers to the pinned commits.

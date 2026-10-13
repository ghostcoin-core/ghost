# Survey: Reth as the base client

Status: research only. No code was written or run. Every claim below comes from
reading source, and where the evidence is thin the text says so.

## What was read

| Item | Pin |
|---|---|
| Reth (`paradigmxyz/reth`), `main` | commit `44958846936ed9ff4748ecfc1ac6d68af9e88af4`, 2026-10-13, workspace version 2.7.0 (`Cargo.toml:2`) |
| `reth-primitives-traits` | 0.8.2, from crates.io (the version `Cargo.lock` pins) |
| `alloy-evm` | 0.39.0, from crates.io |
| `revm-interpreter`, `revm-handler` | 43.0.2, from crates.io |
| Tempo (`tempoxyz/tempo`), as a real chain built on Reth | commit `b4a4b295137cbf21144c7ac74c551fda0c3b3a3d` |

Paths without a prefix are in the Reth commit above. Paths marked with a crate
name and version are in that published crate, because Reth has moved the
transaction, header and EVM-execution building blocks out of its own tree into
separate crates. That matters for upstream tracking (question 8).

Reth is about 458,000 lines of Rust under `crates/` at this commit.

## Bottom line

- Reth can carry Ghost as a library: a custom node built from Reth's crates,
  not the stock binary. Everything except proof of work has a working precedent.
- Proof of work is the hard part and is the main risk. Reth at this commit is
  built around being driven by a proof-of-stake consensus client. It has no
  proof-of-work validation, no heaviest-chain rule and no proof-of-work sync
  path, and I found no chain that has added one.
- Rough effort to a working private test network with the full first milestone
  path: 9 to 14 person-months for one strong Rust engineer, with the proof-of-work
  fork choice and sync accounting for about a third of it.

## 1. Where consensus plugs in, and proof of work from block one

### The hooks

Block validation is three traits in `crates/consensus/consensus/src/lib.rs`:

- `HeaderValidator` (line 146): `validate_header` (line 150) and
  `validate_header_against_parent` (line 162).
- `Consensus` (line 95): `validate_body_against_header` (line 97) and
  `validate_block_pre_execution` (line 113).
- `FullConsensus` (line 74): `validate_block_post_execution` (line 84), which sees
  the executed receipts, gas used and requests.

The node takes any implementation through `ConsensusBuilder`
(`crates/node/builder/src/components/consensus.rs:9`), so replacing consensus is
a supported swap, not a patch.

Ethereum's implementation is `EthBeaconConsensus`
(`crates/ethereum/consensus/src/lib.rs`). Its `validate_header` (line 175) after
the merge requires difficulty zero, nonce zero and an empty ommers hash
(lines 177-190). Before the merge it checks only that the timestamp is not in the
future (lines 191-206). **There is no proof-of-work check anywhere**: a search of
the tree for ethash, proof of work and total difficulty finds only network
messages, era-file readers and chain-spec fields, not a verifier.

### What is not supported out of the box

1. **The engine only takes input in engine-API shape.** The launcher is
   `EngineNodeLauncher` (`crates/node/builder/src/launch/engine.rs:49`). It builds
   an in-process channel (line 164) and a `ConsensusEngineHandle` (line 211) that
   carries `newPayload` and `forkchoiceUpdated` messages. That channel is
   in-process, so "no beacon chain and no engine API dependency" is achievable:
   no JSON-RPC server, no JWT secret, no consensus client. But Ghost's own code
   must still turn every mined or received block into those two messages. I found
   no launcher that bypasses the engine.
2. **Reth has a ready-made in-process driver to copy.** `LocalMiner`
   (`crates/engine/local/src/miner.rs:200` `run`, line 247 `advance`) calls
   `fork_choice_updated`, resolves the built payload, then calls `new_payload`,
   all in process, with no network or RPC. It is a development tool that mines on
   an interval or per transaction (`MiningMode`, line 30). It is the closest
   existing shape to a proof-of-work miner loop.
3. **No heaviest-chain rule.** The engine follows whatever head the forkchoice
   message names. The node's own head record sets `total_difficulty: U256::ZERO`
   (`crates/node/core/src/node_config.rs:446`). A table for total difficulty
   exists (`crates/storage/db-api/src/tables/mod.rs:318`) but I found no code in
   this commit that writes it per block. Ghost would add cumulative-difficulty
   tracking and a fork-choice component that decides the head and sends it.
4. **Finality is a design choice for Ghost.** The engine rejects a forkchoice
   head below an established finalized block as a too-deep reorg
   (`crates/engine/tree/src/tree/mod.rs:1308-1322`). A zero finalized hash is
   tolerated: the backfill-distance check is skipped (line 1935) and the engine
   supports optimistic sync with an unset finalized hash, falling back to the
   head (around lines 2805-2856). So a proof-of-work driver may leave finality
   unset. `LocalMiner` instead passes a hash at a fixed depth (`miner.rs:221-231`).
   Passing a fixed depth turns a deep reorg into a hard rejection, which is a
   consensus rule; leaving it unset keeps pure heaviest-chain behaviour but I did
   not verify memory and retention behaviour over very long unfinalized runs
   (`mod.rs:1560-1573` falls back to a retention threshold when finality is unset).
5. **Reorgs on disk are supported.** The tree handles a reorg past persisted
   blocks (`mod.rs:1446-1451`, `remove_blocks_above` at line 1427). Persistence
   defaults are in `crates/engine/primitives/src/config.rs:7` (threshold 50) and
   line 17 (5 blocks kept in memory). At 30-second blocks, a threshold of 50 is
   about 25 minutes of reorg room in memory.
6. **Network block announcements are wired off.** `BlockImport`
   (`crates/net/network/src/import.rs:13`) is the hook for validating a
   proof-of-work block announcement, and its documentation still describes
   checking the proof-of-work value. The default,
   `ProofOfStakeBlockImport` (`import.rs:89-97`), ignores everything, and
   `config.rs:743` installs it unless replaced. A Ghost implementation must
   verify the seal, then hand the block to the engine.
7. **Initial sync needs a tip to chase.** The headers stage syncs toward a tip
   hash given by a watch channel (`crates/stages/stages/src/stages/headers.rs:50`
   and line 213), normally supplied by a consensus client. Reth's debug client
   (`crates/consensus/debug-client/src/client.rs:57`) fetches blocks from an RPC
   or Etherscan and feeds them to the engine; it is a testing aid, not a model
   for a peer-to-peer proof-of-work node. Ghost has to derive the tip from peers
   (best total difficulty), validate seals while downloading headers, and send the
   result to the engine.
8. **The wire protocol still carries difficulty.** `eth/68` status messages keep
   `total_difficulty` (`crates/net/eth-wire-types/src/status.rs:27`, `:108`).
   `eth/69` and later drop it (`status.rs:113-153`). A proof-of-work chain should
   advertise `eth/68` only, or define its own status. The handshake caps total
   difficulty at 160 bits (`crates/net/eth-wire/src/handshake.rs:177`), which is
   ample.

### Making the EVM work without a merge

The EVM version is chosen by a fixed ladder in `alloy-evm`
(`eth/spec_id.rs:16-47` in 0.39.0): Shanghai and later are tested by timestamp
first, then "merge" by block. In `revm-interpreter` 43.0.2
(`src/instructions/block_info.rs:46-57`), once the version is the merge or later,
the DIFFICULTY opcode reads `prevrandao` and unwraps it. The block environment
sets `prevrandao` only when the chain spec says the merge is active at that block
(`alloy-evm` `eth/env.rs:86-91`).

So a chain that wants Shanghai-era or later opcodes must mark the merge
fork active from block zero, so that `prevrandao` is filled from the header's
`mix_hash`, and then replace Ethereum's consensus rules so the "difficulty must
be zero" check is not applied. That is a design choice for Ghost to make
(difficulty lives in the header and the opcode returns the header's mix value, fixed before execution), and it is a
reason to treat the chain-spec and EVM-environment code as forked, not
configured. The in-tree example `examples/custom-hardforks` shows chain-spec
customisation but does not exercise this combination. This part is my reading
of the code, not something I saw run.

### Verdict for question 1

Pluggable at the trait level, but proof of work from block one means writing
four things Reth does not have: seal verification, cumulative-difficulty
fork choice, a peer-driven sync tip, and a block-import path to the engine.
Estimate in the effort table below.

## 2. Adding a mining module: block building, sealing, difficulty

**Building.** `ConfigureEvm` (`crates/evm/evm/src/lib.rs:183`) owns the block
assembler (`BlockAssembler`, `crates/evm/evm/src/execute.rs:295`). Ethereum's
assembler builds the header at `crates/ethereum/evm/src/build.rs:114-142`. Three
header lines are the proof-of-work surface: `mix_hash` (line 124), `nonce` set to
a fixed `BEACON_NONCE` (line 125) and `difficulty` copied from the block
environment (line 129). The payload builder
(`crates/ethereum/payload/src/lib.rs:147`, `default_ethereum_payload`) drives
the assembler through `BlockBuilder::finish` (lines 457-490).

**Sealing.** The state root, receipts root and transactions root do not depend on
the nonce. So the loop is: build the block with a placeholder nonce, hand the
header (without nonce) to the mining search, then write the found nonce into the
header and recompute the block hash. Only the nonce (and any extra seal field
that no contract can read) may change after execution. `mix_hash` must not: with
the merge mapping described in question 1 it becomes PREVRANDAO, which contracts
can read, so changing it would change execution results and invalidate the
state root. The mining search must therefore leave `mix_hash` fixed before
execution; the proof-of-work output is recomputed by verifiers from the header and
need not be stored in it. The sealed block is submitted with
`newPayload` and then a forkchoice update, as `LocalMiner::advance` does
(`miner.rs:247-290`).

**A catch on payload format.** The engine's `ExecutionPayload` JSON structure used
by `newPayload` has no difficulty, nonce or ommers fields. Ghost therefore needs
its own `PayloadTypes::ExecutionData` (`crates/payload/primitives/src/lib.rs:41`)
and `PayloadValidator::convert_payload_to_block`
(`crates/engine/primitives/src/lib.rs:180-190`) that carries the full header.
`examples/custom-engine-types` shows how to define custom engine types; I did not
find an example carrying a custom header.

**Difficulty.** Reth validates nothing here. Ghost writes the difficulty
adjustment as a pure function of the parent header and timestamp, called from
`validate_header_against_parent` (`consensus/src/lib.rs:162`), and calls it again
when assembling the next block. The Ethereum timestamp rule in
`validate_against_parent_timestamp` is strictly increasing seconds; Ghost's 30
second target is compatible with it but its timestamp-drift rules must be
specified (the outline already lists this under "to specify").

**RandomX.** Nothing in Reth helps. The RandomX reference code is C++; it would
be linked as a foreign library for both verification (light-mode, roughly 256 MB
cache per verifier) and mining. This survey did not read RandomX itself; the
memory figure is from general knowledge and should be checked in the benchmark
task.

**Block reward.** Ethereum's pre-merge block reward is already a code path:
`post_block_balance_increments` (`alloy-evm` `block/state_changes.rs:15-45`)
adds the reward to the beneficiary, with the schedule in `block/calc.rs:26-48`
(fixed 5, 3 or 2 ETH). Ghost's schedule differs, so it replaces this in a custom
block executor's `finish` (the Ethereum one is `eth/block.rs:283-355`).

## 3. A native transaction type with no sender account

What Reth requires of a transaction type (`reth-primitives-traits` 0.8.2):

- `NodePrimitives` (`src/node.rs:9-25`) names the block, header, body, signed
  transaction and receipt types. All five can be replaced.
- `SignedTransaction` (`src/transaction/signed.rs:27-47`) requires, among other
  things, `SignerRecoverable` (a function from transaction to sender address),
  EIP-2718 encoding, and `alloy_consensus::Transaction` (nonce, gas, fees and
  so on).

So the type system has no notion of a transaction without a sender. The
practical mapping is to give a Reveal transaction a **derived pseudo-sender**
(for example an address computed from the one-time marker), with nonce zero and
no balance, and to make every place that uses the sender skip it. Places found:

1. **Sender recovery** during sync: the stage's `recover_sender`
   (`crates/stages/stages/src/stages/sender_recovery.rs:398`) calls the
   transaction's recovery function and fails the stage if it errors, so the
   pseudo-sender must be recoverable from the transaction alone.
2. **Pool.** `PoolTransaction::sender` (`crates/transaction-pool/src/traits.rs:1488`)
   and two opt-outs: `requires_nonce_bound_check` (line 1541) and
   `requires_nonce_check` (line 1546). The default validator checks sender
   nonce and balance (`validate/eth.rs:690`, `:798`); a custom
   `TransactionValidator` (`validate/mod.rs:171`) would verify the proof instead.
   Because each Reveal would have its own derived sender, no two Reveals queue
   behind each other. The pool's replacement rules for equal sender and nonce
   would then also give one-pending-per-marker for free; I did not verify the
   replacement-bump behaviour.
3. **Execution.** The generic executor trait lets a custom executor intercept a
   transaction type before it reaches the EVM. `BlockExecutor` is
   `alloy-evm` `block/mod.rs:199`, with `execute_transaction_without_commit`
   (line 386), `commit_transaction` (line 401) and `finish` (line 405). The
   Ethereum version passes every transaction to `self.evm.transact`
   (`eth/block.rs:190-248`). Ghost's executor would branch on type: for a Reveal,
   verify the proof natively, check the marker is unused, then write the state
   changes directly and return a result of its own (`BlockExecutor::Result` is an
   associated type, so the result can be custom).
4. **Block gas accounting and receipts.** Fees on private transactions are fixed
   by formula in the outline. Gas accounting in `eth/block.rs:195-248` is by gas
   limit and gas used; a fixed-fee transaction would report a fixed gas figure.

**Precedent.** Tempo defines its own transaction envelope with a new type byte
(`crates/primitives/src/transaction/envelope.rs` at the pinned commit) and a
custom block executor (`crates/evm/src/block.rs`; `impl BlockExecutor` at line
492, `execute_transaction_without_commit` at line 564, `finish` at line 645). So
a new type with custom execution on a current Reth is demonstrated in
production. Tempo's transactions still have a signer; no sender-less
transaction was found in Reth or Tempo, so the pseudo-sender mapping above is
my design, not a copied one.

**Wire and RPC.** Transactions travel over the peer-to-peer network as EIP-2718
envelopes, so a new type needs its encoding registered in the custom envelope.
The RPC layer (`eth_getTransactionByHash` and similar) uses RPC conversion
traits for custom primitives; I did not read them in depth, and wallet-facing
output for a sender-less transaction needs its own decisions.

## 4. New header fields (coin tree state, data tree state) and their verification

The header is a type parameter: `NodePrimitives::BlockHeader`
(`reth-primitives-traits` `src/node.rs:15`) must implement `BlockHeader`
(`src/block/header.rs:17-37`: RLP encode and decode, hashing, serde, in-memory
size) plus a database codec (`MaybeCompact`). Header RLP also goes over the
`eth` wire (`BlockHeaders` messages), so peers see the extra fields.

**Precedent.** Tempo's header (`crates/primitives/src/header.rs:33`) wraps the
standard header and adds gas-limit, sub-second timestamp and consensus-metadata
fields, with RLP and database codec implementations
(`crates/primitives/src/reth_compat/header.rs:10-141`). That is the pattern
Ghost would copy.

**Producing the fields.** The assembler receives the post-execution state root
and the execution result (`BlockAssemblerInput`, `execute.rs:295` onward) and
builds the header, so computing two extra roots at that point is natural:
read the two tree roots from state after execution.

**Verifying them.** The straightforward design is to keep the two trees' state
(frontier, root, counters) in the chain's own state, for example storage of a
fixed system account. Then the existing state-root check covers it:
`payload_validator.rs:877-897` compares the computed state root to the header and
rejects a difference. The extra header fields are then a duplicate commitment that
light verifiers can read without state. They must still be checked equal to what
state says. Two places can do that:

- `FullConsensus::validate_block_post_execution` (`consensus/src/lib.rs:84`,
  called from `payload_validator.rs:1361`). It receives the block and the
  execution result, not the state, so it can only compare against something the
  executor put into the result. `BlockExecutionResult` has fixed fields
  (receipts, requests, gas used, blob gas); I found no spare slot. One
  workaround is to carry the roots in the `requests` list, which the header
  already commits to through `requests_hash`; that is a hack and not verified by
  me.
- `PayloadValidator::validate_block_post_execution_with_hashed_state`
  (`crates/engine/primitives/src/lib.rs:226`), called at
  `payload_validator.rs:811` and `:851`. It receives the hashed post-state
  and a provider for the parent state. The default does nothing and the
  comment says Ethereum does not use it. This looks like the intended hook
  for chain-specific state checks and is where I would put the tree-root check.
  Its documentation (`crates/engine/primitives/src/lib.rs:169-171`) says it is a
  no-op on Ethereum and is used by the Optimism stack for extra post-execution
  checks. The Optimism implementation is outside this checkout, so I did not read
  it.

A pure state-root approach (no extra header fields) would work with no
framework changes, but then "verify a proof from headers alone" (outline,
core protocol item 6) would need Merkle proofs of the system account's storage
against the standard state root. The extra header fields are worth their cost
only if that is judged too heavy for light verifiers.

## 5. Burn on commit and mint on reveal with no contract holding mint rights

Two routes, both found in the code:

**A. Native transaction.** A custom executor (question 3) can write balance
changes directly. The Reveal path mints by crediting the recipient; nothing else
can reach that code path because only the chain's own rule runs it. No contract
address is involved.

**B. Stateful precompile for Commit.** A Commit is an ordinary transaction from a
public account, so it must be handled inside the EVM. The EVM's precompile
interface gives full access to journaled state:

- `PrecompileProvider::run` takes the whole execution context mutably
  (`revm-handler` 43.0.2 `src/precompile_provider.rs:30-34`).
- `alloy-evm` wraps this as `PrecompileInput` with `internals_mut()`
  (`src/precompiles.rs:681-752`), exposing `set_balance`
  (`src/traits.rs:606`), `transfer` (line 617) and `sstore` (line 673).

So a precompile at a fixed address can verify the commit statement, record the
commitment, and burn by zeroing the value it was sent. It is not a contract: it
has no code, no owner and no upgrade path, and it is replaced only by a new
release at a fork height. Reth's own example (`examples/custom-evm/src/main.rs:105-117`)
only adds a stateless precompile, so the stateful use is documented by the
library source and not by an in-tree example.

The outline's "amount bound at commit" rule (the chain ties the amount burned to
the amount inside the commitment) fits route B: the precompile reads the
transaction value and the claimed amount in the same call.

Total-supply accounting also needs the base-fee burn: Ethereum's execution
already does not credit the base fee to anyone, so that part is unchanged.

## 6. EVM features to keep

The EVM version ladder at this commit runs to Amsterdam (`alloy-evm`
`eth/spec_id.rs:21-22`; Reth's consensus code checks Amsterdam headers at
`crates/ethereum/consensus/src/lib.rs:250-259`). What to keep or drop, from the
code read:

| Feature | Keep? | Why |
|---|---|---|
| London (EIP-1559 base fee and burn) | Keep | Required by the outline. Header check: `validate_header_base_fee`, `crates/ethereum/consensus/src/lib.rs:211` |
| Shanghai opcodes (PUSH0, warm coinbase) | Keep | Opcode-level, no staking dependency |
| Withdrawals (EIP-4895) | Drop | Exists only to move beacon-chain balances. Headers must have a withdrawals root once Shanghai is active (`crates/ethereum/consensus/src/lib.rs:215-224`), so the Ghost header type should remove the field |
| Cancun: transient storage, MCOPY, SELFDESTRUCT change | Keep | Opcode-level |
| Cancun: `parent_beacon_block_root` (EIP-4788) | Drop | A beacon-chain root; requires a system-call contract. Header check at `crates/ethereum/consensus/src/lib.rs:225-240` |
| Cancun/Prague: blobs (EIP-4844, 7691) | Drop for launch | No data-availability layer for rollups is in scope. Blob fields are validated in the header (`crates/ethereum/consensus/src/lib.rs:225-232`) and need the blob store |
| Prague: BLS12-381 precompiles, EIP-7702 | Keep, decide separately | Useful; not tied to staking. 7702 changes the account model, which interacts with the "ordinary accounts can never reveal" boundary and needs review |
| Prague: deposit/withdrawal/consolidation requests (EIP-6110, 7002, 7251, 7685) | Drop | Staking mechanics. `finish` collects them (`alloy-evm` `eth/block.rs:283-306`) |
| Osaka/Amsterdam | Defer | Newer, less deployed. Amsterdam adds block access lists and a slot number (`crates/ethereum/consensus/src/lib.rs:250-259`), which exist for the beacon-chain slot model |

Dropping features means a custom `ConfigureEvm`, executor and header type, not a
flag. The pieces to remove are scattered across the header validator, the
assembler (`crates/ethereum/evm/src/build.rs:57-100`) and the executor `finish`. This is the same
forking cost as the proof-of-work work and is best done once, in the
custom-primitives step.

## 7. Custom chains already built on Reth

Checked from public repositories (state as of 2026-10-13):

| Chain | What it shows | Evidence |
|---|---|---|
| Tempo (`tempoxyz/tempo`, Apache-2.0) | Custom transaction type, custom header with extra fields and database codec, custom block executor and assembler, custom precompiles, custom payload builder, a non-standard consensus layer; consumes Reth by git revision | `Cargo.toml:175-177` pins `rev = "1a4dbbe"`; `crates/primitives/src/header.rs`, `crates/primitives/src/transaction/envelope.rs`, `crates/evm/src/block.rs`, `crates/evm/src/assemble.rs`, `crates/precompiles/src/lib.rs` at commit `b4a4b29` |
| Berachain (`berachain/bera-reth`, Apache-2.0) | Custom chain on the Ethereum stack with changed rules; consumes Reth by git tag | `Cargo.toml:35` pins tag `v1.11.4`, while Reth is at 2.7.0, so it was behind by a major version on 2026-09-29 |
| Scroll (`scroll-tech/reth`, Apache-2.0) | A maintained fork of the whole repository | `Cargo.toml:7` and workspace paths at line 303 and after |
| Optimism | The largest user. Reth's README (line 25) says its Optimism node moved into the Optimism repository | `README.md:25` |
| Gnosis (`gnosischain/reth_gnosis`) | Not read in detail beyond its existence | Repository listing only |

Proof of work specifically: **I found no chain built on Reth that uses proof of
work.** Two web searches and a search of this tree found none. Reth's in-tree
examples cover custom EVM, custom payload builder, custom engine types and
custom hardforks (`examples/README.md`), and none involves mining. Everything
this survey says about the mining module is therefore designed from the code, not
copied from an existing build. That is the single most important caveat.

## 8. Licence and tracking upstream

**Licence.** Reth's workspace is `MIT OR Apache-2.0` (`Cargo.toml:5`), with
`LICENSE-MIT` and `LICENSE-APACHE` at the root. That matches Ghost's own
dual licence. Things to watch:

- The tree ships LGPL and GPL texts under `LICENSES/` because of the optional
  GMP dependency (`README.md:140`; `deny.toml:70` allows `gmp-mpfr-sys` under
  LGPL-3.0-or-later). It is behind a build feature, so a build without it is
  unaffected. Ghost should not enable it, or should record the consequence.
- The bundled `libmdbx-rs` is a fork of an earlier Apache-licensed version
  (`crates/storage/libmdbx-rs/README.md:6`). Its upstream later moved to a
  different licence; this fork is not affected, but it is a dependency that cannot
  simply be updated.
- Reth's `deny.toml` is the licence allow-list. Ghost should run an equivalent
  check on its pinned dependency tree; this survey did not run one.

**Tracking upstream.** Reth releases without a fixed cadence
(`docs/release.md`: "does not currently have a regular release cadence"). Recent
tags: 2.3.0 (2026-06-10), 2.4.0 (07-14), 2.4.1 (07-17), 2.5.0 (08-12), 2.5.1
(08-20), 2.5.2 (09-02), 2.6.0 (09-17), 2.7.0 (09-28). That is about one release
every two to four weeks. It is a 2.x line that changes internal traits between
minors; the checkout itself shows trait churn (for example the new
`validate_block_pre_execution_with_tx_root`, `consensus/src/lib.rs:134`). Reth's
hardfork checklist (`HARDFORK-CHECKLIST.md`) says new transaction types and
header fields land in `alloy-consensus` first, so a custom header must follow the
alloy crates as well.

Two models in use by real chains:

1. **Library dependency pinned to a revision or tag** (Tempo, Bera). Ghost code
   lives in its own crates and Reth is a pinned git dependency. Upgrades are a
   deliberate bump with a compile-and-fix pass. Cheapest to maintain.
2. **Full fork** (Scroll). Merges upstream by hand. More control, much more work.

Recommendation: model 1, with the version pinned in `Cargo.lock`, dependency
upgrades reviewed on a schedule (not tracking `main`), and an upgrade budget
per Reth minor release. Bera pinning a v1.11 tag against a 2.7.0 head is a
caution about how far behind a small team can fall.

## Effort estimate

One strong Rust engineer, with the custom parts reviewed by a second model as the
outline requires. Ranges, not promises. Excludes the proof system, RandomX
integration, wallet and web app, which are separate tasks.

| Work | Estimate | Confidence |
|---|---|---|
| Custom primitives crate: header, block, envelope, receipt, database codecs, chain spec | 3 to 5 weeks | Medium; Tempo is a template |
| Custom EVM configuration, assembler, executor with native Reveal and block reward | 4 to 6 weeks | Medium |
| Stateful precompile for Commit; tree state in system storage; header root check | 3 to 5 weeks | Medium; hooks exist, no end-to-end example |
| Sender-less transaction: pool validator, sender recovery, RPC output, wire encoding | 3 to 4 weeks | Low to medium |
| Proof of work: seal verification, difficulty function, fork choice by cumulative difficulty, miner loop, finality choice | 6 to 9 weeks | Low; no precedent found |
| Proof-of-work network: block import, sync tip from peers, eth/68 status, header download validation | 5 to 8 weeks | Low |
| Remove or disable staking-era features; test network; adversarial tests of reorgs | 4 to 6 weeks | Medium |
| Total | about 28 to 43 weeks (roughly 7 to 10 months), call it 9 to 14 person-months with slack | |

The two "Low" rows hold the schedule risk.

## Risks

1. **Proof of work has no precedent on this client.** Nothing in the tree
   validates proof of work, tracks cumulative difficulty or syncs by it, and no
   chain was found that added them. Mitigation: build the fork-choice and sync
   pieces first, against a private test network, before anything else depends on
   them. The sibling survey of the Ethereum Classic family exists to compare.
2. **Reorg model mismatch.** The engine is built around a consensus client that
   supplies finality; Ghost has probabilistic settlement. Either a hard
   finalized depth (a new consensus rule; a deep reorg past it splits the
   network) or an unset finalized hash (untested here for long runs) must be
   chosen. The behaviour when mining power collapses must be specified (the
   outline lists this as open).
3. **EVM version and `prevrandao`.** A chain that uses modern opcodes without a
   merge hits the revm requirement described in question 1. The workaround is a
   design choice that affects what the DIFFICULTY opcode returns for contracts.
4. **Trait churn.** The building blocks sit in four separately versioned crate
   families (Reth, `reth-primitives-traits`, alloy, revm), and Reth ships 2.x
   releases every two to four weeks. Each bump can break a custom primitives
   crate. Mitigation: pin, upgrade on a schedule, keep Ghost code in few crates.
5. **Sender-less transactions fight the type system.** Every generic component
   assumes a signer. The pseudo-sender mapping needs care in the pool, sync, RPC
   and indexing, and each of those is a place for a denial-of-service or a
   privacy leak (for example, a derived sender that is linkable to the
   commitment). Needs an adversarial test list written with the specification.
6. **Header verification hook is unproven for Ghost.** The state-checking hook for
   the two tree roots exists (`validate_block_post_execution_with_hashed_state`)
   and the Optimism stack uses it, but nothing in this checkout does. Fallback: derive the roots only from state
   and skip extra header fields.
7. **Stateful precompile semantics.** Reverts, static calls, gas metering and
   journaling around a state-changing precompile are subtle. The burn must be
   atomic with the commitment insert on every path including reverts. Needs
   focused tests.
8. **Native verification cost on every node.** Reth executes with a parallel
   state-root pipeline tuned for Ethereum workloads (`payload_validator.rs` header
   comment, line 84 onward). A hash-based proof verifier running inside block
   validation adds time per block that Reth's existing caches do not account
   for. This survey did not measure it; it is for the benchmark task.
9. **Upstream drift and dependence.** Reth is run by one organisation. Ghost
   depends on timely upstream fixes for the networking and database code it
   does not own, and Ghost's own fixes cannot go through Reth's disclosure
   channel.
10. **Experimental status.** Reth's release document calls it "still
    experimental software". Combined with a public chain launched without a
    test-network period (outline), this raises the stakes on the review of every
    custom change.
11. **Thin evidence.** Items marked "I found no" in this document are absence of
    evidence in the commit read, not proof of absence. I did not build or run
    anything. The RandomX figure is from general knowledge. The Gnosis row is
    an existence check only.

## Suggested next steps

1. Read the Ethereum Classic family survey and compare the proof-of-work
   rows (questions 1, 2 and 7 here) before choosing.
2. If Reth is chosen, make the first engineering task a minimal custom node
   that mines blocks with a dummy seal and survives a three-block reorg on a
   private test network. That retires risks 1 and 2 cheaply.
3. Decide whether any depth counts as final, and the behaviour when mining
   power drops, in the specification before writing the fork-choice code.

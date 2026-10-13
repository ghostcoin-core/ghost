# Survey: an Ethereum Classic-family client as the base

Status: research only, no code. Written 2026-10-13.

This survey reads the leading Ethereum Classic-family client and answers the
questions the outline sets for choosing a base client (see
[docs/ghost-outline.md](../ghost-outline.md), "Foundation" and "Technical
starting picks"). The competing candidate, Reth, is surveyed separately.

## Bottom line

- Core-Geth already does the one hard thing Ghost needs from a base, proof of
  work with a clean engine seam, so a RandomX engine is a bounded job. Everything
  else Ghost needs (a no-sender transaction, new header fields, burn and mint)
  is custom work in either base, and here it lands in a frozen 2023 fork of Go
  Ethereum.
- The cost is carried by maintenance and licence, not by features. The code
  tracks upstream Go Ethereum 1.13.15 (merged 2024-06-07), had no release for
  21 months, and in March 2026 needed an emergency patch during a live attack on
  Classic bootnodes. One person made nearly all recent merges. The node binary
  is GPL-3.0 and the libraries are LGPL-3.0.
- Verdict: a credible fallback, not the better foundation. Choose it over Reth
  only if the Reth survey shows that adding proof of work there costs more than
  the whole estimate in this document (about 15 to 23 engineer-weeks, plus a
  standing security-backport duty).

## What was read

| Item | Value |
|---|---|
| Client | Core-Geth, `github.com/etclabscore/core-geth` |
| Commit read | `7ee328ca2d6734ecbda9f0757d35eb6b710a14cd` on `master`, committed 2026-09-17 |
| Latest release at that commit | `v1.12.23`, published 2026-08-14 (the tree reports itself as `v1.12.24-unstable`, `params/version.go:24-28`) |
| Language and toolchain | Go, `go 1.21` (`go.mod:3`) |
| Upstream base | Go Ethereum 1.13.15 (upstream tag dated 2024-04-17, an ancestor of the pinned commit). The last upstream merge is "Merge/foundation release/1.13.14+15", 2024-06-07. Later changes are individual backports. Current upstream release is v1.17.8 (2026-10-08). |

All file references below are `path:line` at that commit. Line numbers drift
with every upstream backport, so re-check them against the pinned commit rather
than against `master`.

### Maintained alternatives

- **Besu** (`besu-eth/besu`, Java, Apache-2.0, very active). It no longer
  carries Classic or proof-of-work code: a full listing of its `main` tree on
  2026-10-13 (not truncated) has no path containing `classic`, `ethash`,
  `etchash` or `mordor`. Not a candidate.
- **Fukuii** (`chippr-robotics/fukuii`, Scala 3 on JDK 25, Apache-2.0). Its
  README calls it a continuation of the older IOHK Mantis client and says it
  runs Classic mainnet with proof of work. Created 2025-10-24, 2 stars, and
  four releases (v0.9.75 to v0.9.78) all published on 2026-10-13. The largest
  share of commits comes from automated accounts, followed by a handful of
  human contributors. I did not read its code. What I can say from
  metadata alone: its licence is permissive, which would remove the LGPL/GPL
  problem in question 7, but it is a JVM codebase with a short public track
  record, no outside review that I could find, and a development pace I cannot
  characterise. It is not a safe base for a chain whose launch needs frozen,
  reviewed software. Evidence is thin; treat it as an unread option.
- Older Classic clients (Multi-Geth, from which Core-Geth grew) are superseded
  by Core-Geth.

## 1. Proof of work as it stands

Core-Geth keeps the pre-merge proof-of-work path alive, which current upstream
Go Ethereum has deleted. That is its main value to Ghost.

**Engine seam.** All consensus rules sit behind one interface,
`consensus.Engine` (`consensus/consensus.go:62`). The methods that matter for a
new algorithm: `VerifyHeader` and `VerifyHeaders` (`:71`, `:77`), `Prepare`
(`:85`), `Finalize` and `FinalizeAndAssemble` (`:92`, `:100`), `Seal` (`:108`),
`SealHash` (`:111`), `CalcDifficulty` (`:115`), `APIs` (`:118`), `Hashrate`
(`:129`). Engines available: ethash (`consensus/ethash`), clique
(`consensus/clique`), lyra2 (`consensus/lyra2`, used by MintMe), and a
`beacon` wrapper (`consensus/beacon`).

**Engine selection.** `CreateConsensusEngine` (`eth/ethconfig/config.go:238`)
picks the engine from the chain config and always wraps it in the proof-of-stake
`beacon.New(engine)` (`:277`). It is called from `eth/backend.go:171`. A RandomX
engine is a new branch in this function; the beacon wrapper should be removed
or confirmed inert, since Ghost has no proof-of-stake transition.

**Sealing and mining.**

- The miner loop hands a block to the engine: `taskLoop`
  (`miner/worker.go:701`) calls `w.engine.Seal` (`:737`), and `resultLoop`
  (`:752`) takes the sealed block. Work is built in `prepareWork` (`:1080`,
  which calls `engine.Prepare` at `:1143`), filled by `fillTransactions`
  (`:1205`) and assembled in `commit` (`:1365`, `FinalizeAndAssemble` at
  `:1374`).
- Ethash sealing is `Ethash.Seal` (`consensus/ethash/sealer.go:68`), which
  spawns CPU search threads (`mine`, `sealer.go:178`) and a remote-miner server
  (`startRemoteSealer`, `sealer.go:291`).
- External miners use the Ethereum getWork protocol:
  `GetWork` (`consensus/ethash/api.go:42`) returns four strings
  (hash, seed, target, number), `SubmitWork` (`:67`) takes nonce, hash and mix
  digest, `SubmitHashrate` (`:93`). This is the natural interface for a
  RandomX miner or an operator-free pool.
- `StartMining` is `eth/backend.go:470`.

**Verification.** `verifySeal` (`consensus/ethash/consensus.go:544`) recomputes
the digest and result from `SealHash` and the nonce, compares the digest with
`header.MixDigest` (`:598`) and checks the result against
`2^256 / difficulty`. The seal hash itself is a hand-written list of header
fields (`SealHash`, `:642-678`). Header verification runs in parallel workers
(`VerifyHeaders` `:95`, `verifyHeaderWorker` `:158`, `verifyHeader` `:237`).

**Difficulty.** `CalcDifficulty` (`consensus/ethash/consensus.go:347` and the
package function below it) is a stack of historical rules selected by chain
config. The one Ghost wants is the Byzantium-style per-block rule, EIP-100
(`:380`): a step of `parent_diff / 2048` scaled by the block-time bucket, with
`EIP100FDifficultyIncrementDivisor = 9` and `DurationLimit = 13`
(`params/vars/protocol_params.go:218-220`), a floor of 131072
(`MinimumDifficulty`, `:217`, applied at `consensus/ethash/consensus.go:418`) and
an optional difficulty bomb (`:420-470`, disabled on Classic by `DisposalBlock`
in `params/config_classic.go`). Those constants are tuned for 13-second blocks.

**Classic-specific rules to leave switched off.** Classic adds an
"artificial finality" reorg guard (ECBP-1100, `core/blockchain.go:1576`,
configured in `params/config_classic.go`), uncle rewards, and a stepped reward
schedule (ECIP-1017, `params/mutations/rewards_classic.go:27`). Ghost wants
plain proof of work from block one, so the first is left unset (the MintMe
config in `params/config_mintme.go` shows an engine with all of them unset).

**Swapping the hash for RandomX.** Everything algorithm-specific is in
`consensus/ethash`. The work is:

1. A new `consensus/randomx` package implementing the interface above, copied
   from the ethash engine and stripped of the DAG, cache and epoch code
   (`consensus/ethash/algorithm.go`, `ethash.go`).
2. `verifySeal` becomes: build the RandomX input from `SealHash` and the nonce,
   hash it, compare with the target. The header already has the slots:
   `Nonce` (8 bytes, `core/types/block.go:80`) for the nonce and `MixDigest`
   (32 bytes, `:79`), which RandomX does not need and can be fixed at zero or
   used to commit the seed block hash.
3. A RandomX key block rule (the seed changes every fixed number of blocks)
   and a cache keyed by it. The `GetWork` reply already has a seed field.
4. Binding to RandomX. The reference implementation is `tevador/RandomX`
   (BSD-3-Clause, release 1.2.3 on 2026-07-17, active). There are Go bindings
   and a pure-Go port, but they are small projects (a 23-star cgo binding last
   pushed 2026-08-14 and a 3-star pure-Go port); I did not review them. The
   safer plan is a thin cgo wrapper of our own around the reference library
   with Ghost's own configuration and salt compiled in. Cgo breaks Go's easy
   cross-compilation and static builds, which touches the one-command miner
   installer and the "verifiable build" goal.
5. Verification cost. RandomX light verification needs a 256 MiB cache and
   runs in milliseconds per header, which is slower than ethash light
   verification and affects header sync speed. The ethash code already
   parallelises it, so the structure is right. Measure before launch.
6. Replace `CalcDifficulty` with a per-block rule retuned for a 30-second
   target (the divisor and bucket width above). A 60-second fallback is a
   parameter change.

Not found: any hook for CPU/GPU mining of a non-ethash algorithm, so Ghost's
miner would be an external program speaking `getWork`.

## 2. A new native transaction type with no sender

Transaction types are a closed set in the code: legacy, access-list (0x01),
dynamic-fee (0x02) and blob (0x03) (`core/types/transaction.go:48-51`). The
envelope interface is `TxData` (`:75`); typed encoding/decoding is
`encodeTyped` (`:121`), `UnmarshalBinary` (`:176`) and `decodeTyped` (`:197`,
returns `ErrTxTypeNotSupported` for anything else). There is no 0x04
(set-code) type, so Ghost's type does not collide with anything already
here, but a future upstream type might.

What a type with no sender touches. Every path assumes a sender exists, so
the type has to be handled in each:

| Place | What it does today | Needed change |
|---|---|---|
| `core/types/tx_*.go`, `transaction.go:75` | each type implements `TxData` | new `tx_reveal.go`; the interface demands gas price, nonce and signature accessors, so a no-account type returns fixed or zero values |
| `core/types/transaction_signing.go:40`, `:59`, `:137` | `MakeSigner` and `Sender` recover the sender from the signature | return a defined "no sender" result for the new type instead of an error |
| `core/state_transition.go:151` | `TransactionToMessage` resolves `msg.From` with `types.Sender` | skip sender resolution; `Message.SkipAccountChecks` (`:147`) already exists as a switch for "no nonce check" |
| `core/state_transition.go:235`, `:274`, `:367` | `buyGas`, `preCheck`, `TransitionDb` debit and check the sender's balance and nonce | a separate execution branch: no gas purchase from an account, fee taken from the commitment amount |
| `core/state_processor.go:60-110` | block processing loop | route the type to its own handler |
| `core/txpool/validation.go:103`, `:206`; `legacypool.go:689` and many more | pool validates, orders and replaces by sender and nonce | the type cannot live in the existing pool; a small separate pool (as blob transactions have, `core/txpool/blobpool`) keyed by marker, with spam limits |
| `miner/worker.go:894`, `:945` | picks and commits transactions | a commit path for the type |
| `eth/protocols/eth`, `eth/handler*.go` | gossip and announcements | accept the type |
| `core/types/receipt.go` | receipts carry a tx type | add the type, decide on logs |
| `internal/ethapi`, `graphql` | JSON-RPC and GraphQL marshalling | marshal the type |

The type-specific references to `BlobTxType`/`DynamicFeeTxType` outside
`core/types` are in about 20 files (graphql, ethapi, txpool, blobpool,
`eth/handler*.go`, worker, `cmd/evm`); that is a good proxy for the touch
count. Ordinary EVM wallets never create the type, which matches the outline
(a wallet signs the commit; the reveal is proven, not signed).

A useful precedent: the chain already has a pre-transaction system action
driven by a header field, `ProcessBeaconBlockRoot` (`core/state_processor.go:184`,
called at `:83`). A Ghost system action can follow the same shape.

## 3. Adding header fields (coin tree state, data tree state)

The header struct is `core/types/block.go:65`. Fields added after Ethereum's
original set are `rlp:"optional"` and strictly ordered: `BaseFee`,
`WithdrawalsHash`, `BlobGasUsed`, `ExcessBlobGas`, `ParentBeaconRoot`
(`:82-95`). Ghost's two roots are two more optional fields appended in the
same style. The change is mechanical but wide:

- `core/types/block.go:65-96` (struct), `:276` (`CopyHeader`), and the two
  generated files `gen_header_rlp.go` and `gen_header_json.go`, regenerated
  with the `go:generate` lines at `block.go:61-62`. The generated RLP code
  nests the "is anything later set" checks (`gen_header_rlp.go`), so the new
  fields must be appended last.
- `consensus/ethash/consensus.go:237` onward: the existing checks reject
  fields that are not valid before their fork (the baseFee, withdrawals,
  blob and beacon-root checks in `verifyHeader`). Ghost's fields need the
  inverse check, required from block one.
- `SealHash` (`consensus/ethash/consensus.go:642`) lists header fields by
  hand and panics on a few unsupported ones. A new field not added there is
  not covered by the proof of work, so a relay could alter it without
  redoing the work. The same applies to the clique engine if kept.
- The files that mention a recent optional field (`ExcessBlobGas`), as a
  checklist: `core/blockchain.go`, `core/chain_makers.go`, `core/evm.go`,
  `core/genesis.go`, `core/rawdb/accessors_chain.go`, `miner/worker.go`,
  `internal/ethapi/api.go` (`:1237` shows the withdrawals root being
  marshalled for RPC), `graphql/graphql.go` and `schema.go`,
  `params/types/genesisT/genesis.go` and its generated `gen_genesis.go`,
  `eth/catalyst/api.go`, `beacon/engine/types.go`, `cmd/evm/internal/t8ntool`,
  `tests/gen_*.go`. About 30 files, most of them one or two lines.
- Validation of the roots against execution goes with the other root checks in
  `core/block_validator.go:125-143` (`ValidateState`, which already compares
  the receipt root and state root).

Where the trees live is a bigger decision than where the field goes:

- If each tree is kept as storage of a reserved system account inside the
  normal state trie, the header field is just a copy of a storage-derived
  value, and snap sync, pruning, reorg handling and state proofs all work with
  no new code. The cost is that the tree hash is not the main trie's keccak
  hash, so the in-proof hash tree would sit in storage slots and the header
  field would be the root of that structure, computed by Ghost code.
- If the trees are kept outside the state trie, the snap-sync protocol
  (`eth/protocols/snap`) and database layer must carry them, and reorgs must
  roll them back (`core/blockchain.go:2150`, `reorg`). That is a much larger
  change. The first option is the recommended one for either base.

## 4. Chain-level burn on commit and mint on reveal

- **Mint** has a direct precedent: block rewards are credited with
  `state.AddBalance(header.Coinbase, ...)` (`params/mutations/rewards.go:66-72`,
  called from `Finalize` at `consensus/ethash/consensus.go:622`). A reveal that
  credits a public address is the same call, executed by the new transaction
  type's handler (question 2).
- **Burn** has a precedent too. Under EIP-1559 the base fee is deducted when
  gas is bought (`core/state_transition.go:235-270`) and only the tip is
  credited to the miner (`:478-491`), so the base fee is already destroyed.
  A commit's burn is a debit with no matching credit.
- **Where the logic goes.** Precompiles are not enough: the interface is
  stateless, `Run(input []byte) ([]byte, error)`
  (`core/vm/contracts.go:41-44`), with no access to balances. The commit needs
  one of: a special-cased destination address handled in the EVM call path
  (`core/vm/evm.go:225`, `:325`, `:370` is where precompiles are dispatched),
  or the transaction processor (`core/state_transition.go:367`). Either way
  the debit, the check that the burned amount equals the amount inside the
  commitment, and the tree append must happen in one consensus function, not
  in contract code, because the outline forbids any contract from minting.
- **Accounting.** No total-supply counter exists. The "public accounting of
  value entering and leaving the hidden set" must be added, again as a
  reserved system account's storage so that it is covered by the state root.
- **Rewards.** The outline's reward (smooth decline, halving every two years,
  all to the block's miner) replaces `GetRewards` (`params/mutations/rewards.go:37`),
  which today dispatches to the stepped Classic schedule or to the Ethereum
  schedule, both with uncle rewards. Uncles must also be forbidden
  (`VerifyUncles`, `consensus/ethash/consensus.go:173`).

## 5. EVM feature set against Ethereum's current stable set

Features are individually switchable per EIP in the chain config
(`params/types/ctypes/configurator_iface.go`, one `GetEIPnnnnTransition`
getter per EIP, for example `:141`, `:173`, `:262`), and opcode sets are
built from those flags in `core/vm/jump_table.go` (Shanghai opcodes at
`:205-211`, Cancun at `:213-241`). The EIP implementations are in
`core/vm/eips.go`.

| Feature | In code | Enabled on Classic mainnet |
|---|---|---|
| Up to Berlin (access lists, typed transactions) | yes | yes (`params/config_classic.go`, Berlin-equivalent block 13,189,133) |
| London: EIP-1559 fee market, BASEFEE | yes (`consensus/misc/eip1559`) | no; only EIP-3529 and EIP-3541 are set |
| Shanghai: PUSH0 (3855), warm coinbase (3651), initcode limits (3860) | yes | yes (block 19,250,000, `config_classic.go:101-105`) |
| Shanghai withdrawals (4895) | yes | not applicable, no staking |
| Cancun: transient storage (1153), MCOPY (5656), SELFDESTRUCT limit (6780), blob transactions and BLOBHASH (4844), BLOBBASEFEE (7516), beacon-root contract (4788) | yes (`jump_table.go:213-241`, `core/vm/contracts.go:106`, `core/state_processor.go:184`) | no; none is set in the Classic or Mordor configs |
| BLS12-381 precompiles (2537) | yes (`core/vm/contracts.go:53`) | not set |
| Prague and later (set-code transactions 7702, history storage 2935, request contracts, etc.) | no: no 0x04 type, no matches in the tree | no |

Reading: the execution-only parts of Cancun (transient storage, MCOPY,
restricted SELFDESTRUCT) can be switched on from genesis with a config edit,
as MintMe did for part of it (`params/config_mintme.go`). The blob,
BLOBBASEFEE and beacon-root parts cannot be enabled
by config alone on the proof-of-work path: with EIP-4844 on, the miner fills
the blob header fields (`miner/worker.go:1126-1136`) and `SealHash` then panics
on them (`consensus/ethash/consensus.go:666-670`), and EIP-4788 expects a
beacon root that PoW block production never supplies (`:317-326`,
`miner/worker.go:1309-1312`), and BLOBBASEFEE would read a blob fee that is
never set when blobs are off (`core/evm.go:45`, `:58-59`; handler at
`core/vm/eips.go:290-292`), which is a crash risk in the EVM. Ghost has no use for either (they exist for the
proof-of-stake and rollup design), so the plan is to leave them off, and the
estimate assumes so. Anything after Cancun, which is part of "Ethereum's
current stable set" in 2026, would have to be backported by hand into a code
base whose upstream is about two and a half years ahead. That gap is the
cost. The proof-of-stake parts can be left off, which matches the outline
("minus the proof-of-stake parts").

The Classic-specific forks are named in the config comments (Magneto,
Mystique, Spiral); Ghost has no use for them beyond the EIP flags.

## 6. Maintenance health

All figures from GitHub on 2026-10-13 unless stated.

**Release cadence.**

| Release | Published |
|---|---|
| v1.12.12 | 2023-05-29 |
| v1.12.13 to v1.12.19 | 2023-07-07 to 2024-02-05 (seven releases) |
| v1.12.20 | 2024-06-10 |
| v1.12.21 | 2026-03-18 (21-month gap) |
| v1.12.22 | 2026-03-28 |
| v1.12.23 | 2026-08-14 |

The gap shows in the commit log: only 6 commits landed on `master` between
v1.12.20 (2024-06-10) and 2026-03-01 (the last of them 2025-01-23), against a
Go Ethereum that shipped a long series of security fixes in that time.

**Security handling.** Release notes for v1.12.21 (2026-03-18) call it an
"emergency patch addressing an active attack against Ethereum Classic
bootnodes", with three cherry-picked upstream fixes in the RLPx handshake and
ECIES paths. v1.12.22 backports further upstream cryptographic fixes, naming
CVE-2025-24883 and CVE-2026-26315, and adds hardening for CVE-2026-26313.
CVE-2025-24883 carries a 2025 number, so that fix appears to have shipped about
a year after disclosure (inference from the CVE year; I did not look up the
disclosure date). v1.12.23 backports upstream's delayed p2p message decoding
(an upstream change of 15 pull requests). So fixes do arrive, but by manual
backport and after the fact, and the first sign of the March 2026 problem was
an attack in the wild.

**Published advisories.** The repository's security-advisory listing is empty
(0 entries, `GET /repos/etclabscore/core-geth/security-advisories`), and
`SECURITY.md` is an unchanged copy of upstream's, pointing to upstream's
disclosure address and bounty page (`SECURITY.md:18-22`). Core-Geth has no
disclosure channel of its own and no published advisory history. The
`docs/audits` folder holds four old audits of upstream components from
2017 to 2020 (`docs/audits`); none audits Core-Geth's own code. Open issues:
32, none labelled security; the newest is #697 (2026-04-03, a wrong
`eth_syncing` response in v1.12.22). I could not see private advisories or
dependency alerts, which need repository access.

**Maintainers.** Of the 40 commits since 2025-10-13, 28 are by one person
(Diego López León), who also made all 6 merge commits in that period; the
rest are upstream authors' cherry-picked commits and a few outside
contributors. All-time top contributors by commits are upstream Go Ethereum
authors and one prolific early Core-Geth author (3,325 commits), who does not
appear in recent history. Repository: 305 stars, 188 forks, 40 commits in the
last 26 weeks, not archived, last push 2026-10-06. Bus factor: effectively
one.

**Fit.** A Ghost node would depend on that one maintainer's willingness to
keep backporting upstream fixes, or Ghost would have to take that job on.
The outline already says nobody is paid to build or review, which makes a
standing backport duty the biggest hidden cost of this base.

## 7. Licence

Core-Geth's README (`README.md:83-91`) states the split, and the files
match it (`COPYING` is GPL-3.0, `COPYING.LESSER` is LGPL-3.0):

- all code outside `cmd/`, which is the consensus engine, the EVM, types,
  networking and database (about 99 percent of what Ghost would modify), is
  LGPL-3.0;
- everything under `cmd/` (the `geth` command and the other binaries) is
  GPL-3.0.

What that means for Ghost (not legal advice; the outline leaves legal review
as an open decision):

- The node Ghost ships is `geth`-derived, so the distributed node binary is
  GPL-3.0 as a whole. Anyone who receives it, including miners who run it,
  must be given the full source under the same terms. For an open project
  this is not a blocker, and the outline already expects it ("LGPL and GPL if
  an Ethereum Classic-family client").
- Changes to LGPL files (the consensus and state changes in questions 1 to 4)
  must be released under LGPL-3.0 when distributed. New files that are only
  part of the node binary are most simply licensed GPL-3.0/LGPL-3.0 as well.
- The dual MIT/Apache-2.0 promise for Ghost's own code holds for code that
  does not link into the node: the proof statements, the web app, the SDK and
  the mining tools, as long as they talk to the node over JSON-RPC or
  `getWork` and do not import its Go packages. Apache-2.0 is compatible with
  GPL-3.0, so MIT/Apache code can also be included in the node, but the
  combined binary is then GPL-3.0.
- RandomX is BSD-3-Clause and fits under both. The cgo wrapper is part of the
  node and so is GPL/LGPL.
- Practical effect: two licence regimes in one repository or two repositories,
  with a rule for where each kind of code goes, and a GPL-3.0 burden on anyone
  who wants to build a closed product on the node. Reth's MIT/Apache licence
  has none of this.

## Effort estimate

Engineer-weeks, one engineer who knows Go and Ethereum internals, excluding
review, the proof system and the web app. Ranges reflect unknowns noted.

| Work | Weeks |
|---|---|
| RandomX engine: new package, cgo wrapper, key block rule, work protocol, light verification, tests | 4 to 6 |
| Difficulty and reward rules (30-second target, smooth emission, no uncles, simulation) | 2 to 3 |
| New no-sender transaction type through types, processor, pool, miner, networking, RPC, receipts | 3 to 4 |
| Two header fields end to end, plus the two trees as reserved-account storage and root validation | 2 to 3 |
| Burn, mint, supply accounting, and tests of the value rules | 1 to 2 |
| Chain config, genesis, EVM feature set to Cancun, removal of Classic-only rules, test networks | 1 to 2 |
| Backport of anything after Cancun that Ghost wants, if any | 1 to 2 per feature set, unknown |
| Catch-up of security fixes between upstream 1.13.15 and now (a one-time audit of the Go Ethereum advisories since 2024-04) | 2 to 3 |
| Total | about 15 to 23 |

Then a standing cost: following upstream security fixes, which today means
one backport round every few months.

## Risks

1. **Frozen upstream.** The base is Go Ethereum 1.13.15 from spring 2024. Fixes
   are hand-carried. A fix missed by the one backporting maintainer is a
   Ghost vulnerability, found at the earliest by an attacker (as in March
   2026).
2. **Bus factor of one.** If the current maintainer stops, the base is
   unmaintained. A fork would be needed within weeks.
3. **Security work falls on Ghost.** With nobody paid and no outside audit,
   the standing backport duty and the one-time 2024-onward catch-up land on the
   same small team that must also review the custom consensus code.
4. **No disclosure channel or advisory history** upstream of Ghost: Ghost's
   own security policy must be written from nothing.
5. **EVM drift.** Nothing after Cancun is present. The longer Ghost runs, the
   wider the gap to contract tooling that assumes current Ethereum.
6. **Wide, mechanical change surface** for the transaction type and header
   fields (about 20 and 30 files). Each file is simple but a missed spot
   (seal hash, gossip, RPC marshalling, pool) is a consensus or denial-of-service
   bug.
7. **Seal hash coverage.** A header field omitted from `SealHash` is not
   protected by the proof of work. This needs a test that every header field
   is sealed.
8. **Cgo and RandomX.** Static builds, cross-compilation and reproducible
   builds are harder with cgo, which collides with the signed, rebuildable
   release goal. Pure-Go RandomX ports exist but are small and unreviewed.
9. **Light-verification cost** of RandomX during header sync is unmeasured.
10. **Licence friction.** GPL-3.0 node and LGPL-3.0 libraries, against a
    dual MIT/Apache project. Manageable, but it constrains who can build on
    the node, and legal review is still open.
11. **Pool and gossip design for the sender-less type** has no upstream
    precedent in the code (it is closer to an unsigned system transaction than
    anything here), and sender-less transactions are an obvious spam surface
    until the pool rules are right.
12. **Thin evidence on the alternative.** Fukuii was assessed from public
    metadata only; if it matured it could change the licence and maintenance
    picture, but it would be a Scala/JVM base and a rewrite of every change
    described here.
13. **Line references age.** Anything cited above refers to the pinned commit.

## Method and limits

- Read at the pinned commit by searching for the seams named in the
  questions and reading the code around them. Nothing was built or run, and
  no test was executed, so claims about behaviour are from reading, not from
  running.
- GitHub data (releases, commits, issues, contributors, advisories) is from
  the public API on 2026-10-13. Private advisories and alerts are not visible.
- The Reth side of the comparison is not examined here.

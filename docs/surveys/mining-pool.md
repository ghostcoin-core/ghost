# Survey: an operator-free mining pool

Status: research only, no code. Written 2026-10-17.

The outline requires that solo mining and an operator-free pool both work before
launch day, that one copy-and-paste command gets a basic computer mining in
about a minute, and that the whole block reward goes to the miner who finds the
block (see [docs/ghost-outline.md](../ghost-outline.md), "Consensus and mining"
and "Launch"). The base client plan lists the pool as a separate deliverable
whose protocol is not yet chosen. This survey chooses one, estimates it, and
sets its launch gate.

## What was read

| Item | Pin |
|---|---|
| Monero P2Pool (`SChernykh/p2pool`), `master` | commit `522a55a18127f66be8cdc5eb35a113f3391476c4`, 2026-10-08. GPL-3.0. C++. |
| Go reimplementation of P2Pool consensus (`git.gammaspectra.live/P2Pool/consensus`) | commit `9b25882f908d38b392d3aa55b9c50d6c0f784680`, 2026-08-04. MIT. Read as a shallow clone, so its history is not known. |
| Original P2Pool (`forrestv/p2pool`) and its wiki page at `en.bitcoin.it/wiki/P2Pool` | README and wiki text as served on 2026-10-17. Python 2. |
| Braidpool (`braidpool/braidpool`) | commit `8d3c5198593d691f50ae5238cdaee215f4213cda` (shallow clone; the date shown by git was 2025-06-02). AGPL-3.0. Rust. Its `docs/overview.md`, `docs/general_considerations.md` and `docs/braidpool_spec.md` were read. |
| SmartPool: Luu, Velner, Teutsch, Saxena, "SmartPool: Practical Decentralized Pooled Mining", USENIX Security 2017 (`eprint.iacr.org/2017/019`) | Paper abstract and summaries only. I did not read the full paper or find its code. |
| This repository's [RandomX survey](randomx.md) and the base client plan | Source of every RandomX timing and memory figure below. Those were measured on one arm64 virtual machine, not on the project's minimum machine. |

Statements about P2Pool's constants come from reading its source at the commit
above. Everything labelled "estimate" or "analysis" is my judgement, not a
measurement and not a claim about another project.

## Bottom line

- **Recommended: a Ghost sharechain in the P2Pool design, with payouts through a
  per-block payout vault contract.** The design is Monero P2Pool's (a small side
  chain of "shares", a payout window, uncles, nodes that need no operator). The
  code is new, written in Go, and the payout is an ordinary contract, because an
  account-based chain pays the whole block reward to one address.
- **No consensus change is needed, and nothing conflicts with the outline.** The
  chain still credits the entire reward to the block's coinbase address. A pool
  block simply names a vault contract as that address, as SmartPool did on
  Ethereum in 2017. A miner who mines solo still gets the whole reward. A
  multi-output reward rule in consensus would conflict with the outline's
  sentence and is rejected (section 4).
- **Two small dependencies on the chain specification, neither a rule change:** the
  header `extra` field must stay free for a 32-byte pool commitment (geth allows at
  most 32 bytes), and a code-only factory contract with zero balance must be
  allowed at a fixed address in the genesis state (or deployed in the first
  blocks). The founder should confirm both; the second touches the "zero genesis
  balances" launch check only in the sense that it adds code, not balance.
- **Effort: about 25 engineer-weeks, range 20 to 32,** for one team that already
  knows the geth fork, excluding the external review of the vault and the sharechain.
- **The "about a minute" goal is reachable for the miner machine** (dataset
  initialisation is seconds, section 6) **but not if it also means syncing a full
  node.** A pool node needs a synced Ghost node. The one-command path therefore
  connects to a volunteer pool node and verifies that node's work itself with a
  thin sharechain checker. That checker is part of the estimate, and it is the
  riskiest piece of the miner experience.
- **Biggest unknowns:** the share rate and window that give small machines a real
  chance of appearing in a payout (needs the simulator in the launch gate), and
  the stale-share rate of a volunteer network at 30-second blocks.

## 1. Existing protocols and how they fit

| Candidate | What it is | Fit for a geth-based RandomX chain with 30-second blocks |
|---|---|---|
| Monero P2Pool | A side chain of shares ("pool blocks") at a lower difficulty. Defaults in `src/side_chain.cpp`: 10-second target, 2160-share window, minimum difficulty 100000, uncle depth 3, uncle penalty 20%, up to 5 uncles per block (`MAX_UNCLES_PER_BLOCK`). A "nano" variant uses 30 seconds. When a share also meets the network target it is a Monero block, whose miner transaction pays every window member directly. | The **design** fits. The **code** does not (below). |
| Go reimplementation of P2Pool consensus | A second, consensus-compatible implementation of the same protocol, in Go. | Shows the protocol can be specified and reimplemented independently, and has a reusable layout. Its code is Monero-specific (address, transaction and block types). |
| Original P2Pool (Bitcoin) | Share chain of Bitcoin-format share headers, one share every 30 seconds, payouts in the generation transaction over the last shares (up to 8640, about 72 hours) with 0.5% to the block finder, per the wiki. | A design reference only: Python 2, Bitcoin-format, a finder bonus the outline does not allow, and a limit on how many payees fit in a coinbase. |
| Braidpool | A DAG of "beads" (shares) with settlement paid out over a 2016-block window, using Bitcoin Core and threshold signing. The README's own progress list still shows P2P gossip, block validation, and threshold signatures unchecked. | Not usable. Bitcoin-only, a prototype, payouts on a two-week cycle. Its `general_considerations.md` is a good survey of the problem, including the difficulty of signing payouts without an operator, which the vault design avoids. |
| SmartPool | A pool whose operator is an Ethereum contract. The contract is the coinbase address and verifies sampled share proofs on chain. The authors report running it on Ethereum and Ethereum Classic. | The **payout idea** carries over. The **on-chain share verification does not**: verifying a RandomX hash needs the 256 MiB cache, which no contract can hold, and the base plan has no RandomX precompile. |
| Operator-run stratum pool | Ordinary pool software with one server and one wallet. | Does not meet "operator-free". Volunteers may still run these; they are not the deliverable. |
| Consensus multi-output reward | A chain rule that pays a header-committed list of addresses. | Works technically but is a consensus change that conflicts with the outline (section 4). |

### Why Monero P2Pool does not work with geth blocks as-is

Reading the source shows the dependency is deep, not cosmetic:

- **Block format.** It builds and parses Monero blocks and the Monero miner
  transaction, including a 128-byte `tx_extra` area that carries the sidechain
  hash and the merge-mining tag (`src/pool_block.cpp`,
  `MAX_BLOCK_SIZE = 128 * 1024 - 5` in `src/pool_block.h`).
- **Payout model.** Every window member gets its own output in the Monero miner
  transaction, with one-time keys derived from a shared secret. Geth has no
  such transaction. A block has one header `coinbase` field and the state
  transition credits it once.
- **Chain interface.** It needs `monerod` with a ZMQ feed (`--zmq-pub`, README)
  and Monero's block template RPC. Geth's getWork returns a header hash, a seed
  hash and a target and offers no custom coinbase per request.
- **Licence.** P2Pool is GPL-3.0. Ghost's own tools are MIT and Apache 2.0
  (outline, "Licensing"). Copying its code into the pool would pull the pool under
  GPL. Reading it for the design is fine; the Go reimplementation is MIT but its
  Monero types are not useful here.
- **No merge mining.** Monero's P2Pool can merge-mine other chains through a
  `tx_extra` tag (`docs/MERGE_MINING.MD`), but that works only for Monero's own
  RandomX. Ghost's salt gives it different hashes (RandomX survey), so Ghost is
  not merge-mined under Monero.

A search of the P2Pool repository for audit reports finds none, only CI and
static-analysis badges and reproducible builds. "Reviewed" here therefore means
years of production use and public source, not an independent audit.

## 2. Recommended design

### Shares

A share is a complete Ghost block header (so a share that meets the network
target is a valid block) plus a short sidecar, sealed with RandomX against a much
lower share target. The sidecar carries the share's parent share, up to a few
uncle shares, the payout address, and the hashes of the transactions in the
template. The header's `extra` field holds a 32-byte hash of the sidecar, so the
RandomX work covers the sidecar and cannot be reused under another one.
Verifiers fetch transaction bodies from their own pool or peers, as P2Pool does.

### Fork choice, difficulty, uncles

Copy P2Pool's structure: heaviest cumulative share difficulty, uncles within a
small depth counting at a reduced weight (P2Pool: depth 3, 20% penalty), and a
share-difficulty rule that targets a fixed share interval. Every value is a
parameter to be set by the simulator in the launch gate, not by this survey. A
consensus ID mixed into the sidecar hash separates Ghost's pool from any other.

### The payout window and the table

The payout table is a deterministic function of the sharechain up to the share's
parent: each distinct payout address in the window, weighted by the work of its
shares (and uncles after the penalty). Every verifier recomputes it. The share is
valid only if its header's `coinbase` equals the vault address derived from that
table (next section).

### Payout vault

- **One vault per template.** The `coinbase` is the address of a vault contract
  created by the factory with the CREATE2 opcode. Its salt is a hash of the
  Merkle root of the payout table, the hash of the share's Ghost parent block and
  the sharechain parent. Two sibling shares with the same sharechain parent and
  the same Ghost parent therefore share an address, and two blocks on different
  Ghost parents never do. Two canonical blocks cannot share a Ghost parent, but
  the vault does not rely on that: it accounts cumulatively, so it stays correct
  if it is funded more than once, before or after deployment, between claims, or
  after every payee has claimed (see Claims).
- **The vault can be deployed after the block is found.** An address with no code
  can receive the coinbase credit. Anyone may deploy it later.
- **Claims.** `claim(index, payee, weight, proof)` checks the proof against the
  root. The vault tracks `total_received` (its balance plus everything it has
  paid out) and `paid[payee]`, and pays
  `total_received * weight / total_weight - paid[payee]`, then raises
  `paid[payee]`. Payments are rounded down, so the rounding remainder stays in the
  vault as dust, and later funding is shared in the same proportions. No claim can
  pay a payee more than its weight's share of everything the vault ever received.
  Claims are pull-style because a window of a few thousand payees cannot
  be paid in one transaction under any realistic block gas limit. A `claimMany`
  helper batches claims across vaults, so a small miner can let dust accumulate
  and claim once, with no expiry. This is the answer to the original P2Pool's
  dust problem (the wiki lists it as a known weakness): nothing is lost to dust,
  it is only worth claiming later.
- **First claim with no gas.** A new miner holds no GHOST for gas. Anyone may
  claim for a payee with no reimbursement at all, which is always safe because
  the money goes to the payee. For a payee with no balance, the vault also
  accepts a reimbursed claim only with the payee's own signed authorisation (a
  typed-data signature binding the payee, the maximum reimbursement, a nonce and
  a deadline). A permissionless "caller takes back its gas cost" rule is rejected:
  the caller picks the gas price, and a block producer receives priority fees as
  coinbase income, so it could claim for others at an inflated price and be
  repaid from their rewards. The signed form removes that, and a payee who
  cannot pay for any transaction can still have a relayer submit it. The
  reimbursement is the only place value moves other than to the payee, so it is
  a rule to review.
- **Safety properties to prove by test and review:** the sum paid never exceeds
  what the vault has received; no payee is paid more than its share of that; no
  claim or signed authorisation can be replayed; funding before deployment,
  between claims and after all claims leaves the totals correct; a reverting recipient contract cannot block others; reentrancy is
  impossible by construction.

### Why this satisfies "no operator"

No party holds the funds. The reward lands at an address that only the table
fixed by the sharechain can spend. A pool node can do two things only: refuse to
relay work, and, if a miner trusts it blindly, hand that miner work paying the
node itself (section 6 explains how the miner software closes that gap).

## 3. What porting or building each option takes

Engineer-weeks are my estimates for experienced Go and Solidity engineers who
already know the geth fork. They assume no schedule pressure and no external
review time.

| Piece | Weeks |
|---|---|
| Specification: share format, sidecar, fork choice, difficulty, window, uncles, vault, test vectors | 3 |
| Geth side: a template RPC that takes a coinbase and extra, a share-aware seal hash, submit path for blocks found by shares | 2 |
| Sharechain daemon in Go: storage, verification (RandomX light, about 23 ms a share in the RandomX survey), fork choice, uncles, difficulty, window, peer-to-peer gossip and sync, DoS limits | 8 |
| Vault and factory contracts, deployment, gas analysis, property tests | 2 |
| Stratum server, miner integration, thin sharechain checker for miners | 4 |
| Simulator and a multi-node private test network | 3 |
| Fuzzing, adversarial tests, hardening | 3 |
| **Total** | **25 (range 20 to 32)** |

Alternatives, same unit:

- **Literal port of P2Pool's C++:** 24 to 34, no savings. Only its side-chain logic is
  portable, the block, transaction and payout code is replaced, and the licence is
  GPL.
- **Original P2Pool design:** about the same as the recommended design but
  with a worse starting point (Python 2) and a payout limit that the vault removes.
- **Consensus multi-output reward:** 20 to 26 for the sharechain plus 3 to 4 for the
  consensus rule, and it needs the founder decision in section 4.
- **SmartPool-style on-chain share checks:** not feasible for RandomX.
- **Braidpool:** not an option.

Main risks of the recommended design:

1. **The vault is real money code.** It needs an independent review before launch.
2. **Share-flood load.** Each submitted share costs a light-mode hash to check.
   Cheap checks go first and peers are scored, as the base plan requires for
   headers.
3. **Small-miner experience** depends on parameters that cannot be chosen until
   simulated (section 5).
4. **The thin miner checker** is new, security-relevant client code.
5. **Header `extra` and genesis dependencies** (bottom line) must be settled in the
   specification early, because changing them later is a hard fork.

## 4. Payouts: does this conflict with the outline?

Account-based chains credit the block reward to the header's `coinbase` address
in the state transition. There are three ways to share it.

| Approach | Consensus change | Conflict with "whole reward to the finder" |
|---|---|---|
| **Vault contract as coinbase (recommended)** | None. The reward is still credited whole to the address in the header. | None. The finder chooses the vault, as a solo miner chooses a wallet. Nothing is diverted by the protocol. |
| Multi-output reward rule (a list of payees committed in the header, paid in the state transition) | Yes, a new rule in every client from block one | Yes, in the literal text: the consensus rules would pay people other than the miner whose header it is. It could be defended as the finder's own choice of payees, but it is a rule change the founder would have to make, plus a payee-count limit |
| An operator pays out by transactions | None | None, but it is not operator-free |

**Founder decision, only if the vault design is not accepted:** any multi-output
rule changes the outline's consensus text. With the vault, the only items to
confirm are the two specification dependencies in the bottom line and the
signed-reimbursement rule in section 2.

One further point to state plainly: pooled mining shares the reward by
agreement, so a finder in a pool does not keep the whole reward. The outline's
sentence describes what consensus pays, and the vault design keeps it true.

## 5. Reorgs and stale shares at 30-second blocks

Two chains reorganise independently: the Ghost chain and the sharechain.

- **Sharechain validity does not depend on a node's view of the Ghost tip.**
  Nodes disagree about the tip, so a rule that rejects shares for building on a
  stale Ghost parent would split the sharechain. A share is valid if its header
  is valid in isolation (its parent header is known and checks out, RandomX
  work meets the share target, coinbase equals the vault of its table). A share
  on an orphaned Ghost branch is still a valid, paid share. It simply cannot
  become a block. Three limits keep this from being exploited:
  - **Executable templates.** A pool node is a full node. It executes the share's
    block (state root, receipts) when it has the parent state and refuses a share
    whose block would fail, so work cannot be paid for a template that could
    never become a block. A node without the parent state holds the share
    unaccepted until it has it.
  - **Deterministic freshness.** A share's Ghost parent timestamp must be within a
    fixed limit of the share's own timestamp (a few blocks, set by the simulator),
    and share timestamps must not run backwards along the sharechain.
  - **First-seen staleness.** A node does not adopt as its sharechain tip a
    share whose timestamp is further behind its own clock than a fixed limit when
    first seen (not applied while syncing history). An attacker who mines against
    an obsolete Ghost parent for longer than the limit has to hold back or
    backdate shares and cannot extend the tip honest nodes follow. This is a
    local rule, not a consensus rule, and needs its own tests (launch gate).
- **A Ghost reorg of a pool block** removes the block, its vault credit and any
  claims made against that vault in the same reorged blocks, together. The state
  stays consistent. Wallets and the miner software should show a claim as final
  only after the chain's own confirmation depth, which is a display rule.
- **Sharechain reorgs** are resolved by heaviest chain. A block found on a share
  that later loses still pays its own table, which was computed from its own
  ancestry. This can briefly leave a valid block paying a slightly different
  table from the winning sharechain. P2Pool has the same property.
- **Stale and wasted work at 30 seconds.** If shares come every 10 seconds, three
  land per block. A share whose Ghost parent is replaced mid-interval cannot
  become a block, but still earns credit. Uncles recover shares found at nearly
  the same time. The share interval trades variance against stale rate: shorter
  intervals mean more shares and less variance per miner, and more stale shares
  when gossip is slow. A volunteer network with gossip delays of a second or so
  is a small fraction of a 10-second interval; a 2-second interval would not be.
  I recommend starting the simulator at 10 seconds and moving only if it shows
  a clear gain.
- **Who appears in the window.** Analysis: with a pool hashrate H and a share
  interval T, the share difficulty is about H times T, and a miner with hashrate
  h finds one share every (H / h) times T on average. A miner is likely to appear
  in a window of W shares only if h is above about H / W. For example, with
  W = 2160 and H = 1 MH/s, miners below about 460 H/s often miss the window.
  The window length W (and hence how far back payments reach) is therefore a
  launch parameter, chosen by simulation. A longer window helps small machines but
  grows the table and delays payment of changes in the pool's makeup.
- **Attacks the simulator and review must cover:** withholding a block-finding
  share (a withholder loses its own payout, so this is a griefing attack, not a
  profit one; confirm by simulation), selfish sharechain mining, pool hopping
  against the window, and share-chain eclipse of a thin miner client.

## 6. The one-command, minute-to-mining goal

Figures from the RandomX survey (arm64 virtual machine; the project's minimum x86
machine has not been measured):

| Item | Value |
|---|---|
| Light mode memory | about 260 MiB |
| Light mode speed | about 23 ms per hash, about 43 H/s per thread |
| Cache initialisation | 0.36 to 0.47 s on one thread |
| Fast mode memory | about 2.3 GiB resident (dataset 2080 MiB plus the cache) |
| Fast mode speed | 3.2 ms per hash on one thread, about 4400 H/s on 16 threads |
| Dataset initialisation | about 53 s on one thread, about 4 s on 16 |

What the goal needs:

1. **Time.** Cache build under half a second and a dataset build of 4 s (16
   threads) to about a minute (one thread) fit the budget. The miner starts in
   light mode, builds the dataset in the background and switches when it is ready
   (design requirement; I did not check that the existing miner software does
   this). Machines with under about 3 GiB free stay in light mode, which is much
   slower per thread but works.
2. **A miner build with Ghost's salt.** The compiled salt differs from Monero's,
   so stock miners cannot mine Ghost (RandomX survey). Shipping a patched miner
   is part of the installer deliverable, not the pool.
3. **A node to talk to.** A pool node needs a synced Ghost node (state for
   templates) plus the sharechain daemon. That cannot happen in a minute from
   scratch. The default command therefore points the miner at a volunteer pool
   node, with the endpoint list shipped in the signed bundle and replaceable.
4. **Verification so a node cannot steal hashrate.** An untrusted pool node could
   hand out work whose coinbase pays the node. The miner bundle includes a thin
   checker that syncs only the sharechain window and the Ghost headers it refers
   to (a few hundred headers at 30-second blocks, so tens of seconds of
   light-mode checking, analysis), then confirms for each job that the coinbase is
   the vault of the table and that the share's `extra` commits to the miner's own
   payout address. The miner does not hash remote work until these checks pass,
   because a block found in the meantime would pay a lying node irrecoverably.
   Once they pass, a node that lies can only waste the miner's work, not redirect
   it. Whether this fits in the minute depends on measurement. If it does not, the
   goal is relaxed or the checker starts from a bundled recent state (see the
   last open question); there is no unverified-mining fallback.
5. **The signed installer.** The outline already requires that the one-command
   installer verify a signature on what it downloads, and an app alternative. The
   pool adds only its endpoint list and the miner build to the signed bundle.
6. **Solo mining stays first-class.** The same command can mine solo through
   getWork against a local node, with the whole reward to the miner's address and
   no sharechain.

## 7. Launch gate for the pool

All of the following must be shown, in the open, before the launch date is
announced:

1. A written specification with test vectors, and a second implementation of the
   share validation that agrees on all vectors.
2. A simulator run showing, for 30-second blocks, stale and uncle rates, the
   smallest hashrate that appears in a window at the planned pool size, and the
   chosen interval, window and uncle parameters with the reasons.
3. Tests for invalid templates, indefinitely stale Ghost parents, and the
   first-seen staleness limit, alongside ordinary propagation races.
4. A private multi-node network with at least ten independent pool nodes,
   volunteers included, with pool blocks found, claimed and reorganised, and with
   a fresh node syncing the sharechain from peers.
5. Vault tests: property tests and fuzzing of the safety properties in section 2,
   a test for every reorg case in section 5, and a written independent review of
   the vault and factory with every Critical or High finding fixed.
6. Adversarial tests: forged coinbase, table mismatch, wrong consensus ID,
   share floods (bounded load), malformed sidecars, a lying pool node against the
   thin checker.
7. Measured "minute to mining": wall-clock from running the one command to the
   first accepted share, on the project's defined minimum machine, in light mode
   and with the switch to fast mode, over a clean network.
8. Hardware and architecture coverage matching the base plan's RandomX
   cross-checks, applied to the pool's miner build.
9. The two specification dependencies (header `extra`, factory at genesis or in
   the first blocks) recorded in the chain specification, and the review of the
   signed-reimbursement rule.
10. Solo mining and pool mining both working in the frozen release candidate.

If any item fails, the launch date moves, because the outline makes the pool a
launch requirement, unless the founder changes that requirement in writing.

## Open questions for the specification

- The share interval, window length, uncle depth and penalty, and minimum share
  difficulty: set by the simulator.
- Whether a finder bonus (the original P2Pool paid 0.5%) is wanted. The outline
  suggests not.
- Whether the vault should pay out through a single `claim` only or also support a
  time-limited push for small tables.
- Whether the thin miner checker may start from a bundled recent header, as a
  client convenience, without becoming a consensus checkpoint (the base plan
  forbids checkpoint overrides in release builds, so this needs an explicit
  carve-out for a client that only mines).

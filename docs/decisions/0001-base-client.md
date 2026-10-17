# Decision 0001: the base client

Status: settled by the founder, 2026-10-17.

## Decision

Ghost's node will be our own maintained fork of Go Ethereum's
proof-of-work code, taken from Core-Geth at a pinned commit. RandomX replaces
Etchash as the mining algorithm. Ghost's own consensus parts (the two tree
roots in the header, the Commit and Reveal handling, burn and mint) are added
on top.

This replaces the outline's earlier starting pick of Reth with a mining module.

## What is proven and what is not

The base is proven. Ethereum's proof-of-work block import, fork choice, sync,
EVM and external-miner interface ran Ethereum mainnet from 2015 to 2022 and
still run Ethereum Classic. RandomX and the difficulty rule Ghost will use are
each proven in other chains.

Their combination is not proven. A RandomX engine inside this client has no
production precedent. It is one new, contained piece of integration work, and
it has to earn trust through a written specification, tests and review before
launch. The founder accepted this trade knowingly, over the alternatives below.

## Alternatives and why they were not chosen

| Alternative | Why not |
|---|---|
| Etchash unchanged | Fully proven, but Ghost would share Ethereum Classic's GPU hashrate and would not be CPU-friendly. Rejected for the exposure to that hashrate. |
| Cosmos SDK (proof of stake or authority) | Proven, but it has no mining and no fair launch. It would be a different product, not a fallback. |
| Reth with a mining module | Reth is built around a proof-of-stake consensus client. The survey found no proof-of-work chain on it, so fork choice and sync would be built from scratch. The weakest fit for a proven base. |
| Polkadot SDK (Substrate) with Frontier | Rejected by the founder from direct experience with it. The survey also found a thin, untested proof-of-work engine with no verified live user, no finality, and an EVM layer that is not Ethereum's and lags the SDK. |
| Core-Geth as a live upstream dependency | Deprecated in practice, with effectively one maintainer. Ghost takes a pinned copy and owns it instead. |
| Fukuii | Marked alpha and "do not use in production". |
| Zcash (Zebra) or Monero forks | Proven and fair, but no EVM. |

Owning a pinned fork gives control over releases. It does not remove Ghost's
dependence on knowledge of, and fixes from, upstream Go Ethereum (see
"Taking upstream updates").

## Side-by-side comparison

From the three surveys, put on one scope: RandomX included; the proof system,
wallet and web app, security review and standing maintenance excluded. The
Core-Geth range is the survey's own figure, which includes a two to three week
one-time security catch-up that the plan counts separately.

| | Core-Geth fork (chosen) | Reth | Substrate with Frontier |
|---|---|---|---|
| Effort to a private test network with RandomX | 15 to 23 weeks as stated (its rows add to 16 to 25) | 32 to 49 weeks | 30 to 48 weeks, including 2 to 4 for a Wasm proof verifier |
| Proof-of-work precedent | Built in, with a clean engine seam | None found | A thin engine, one past chain that copied it |
| New private transaction type (no sender) | New type through about 20 files | Pseudo-sender workaround through the type system | Bare extrinsic beside Ethereum transactions, a better fit |
| Header changes (two tree roots) | Many mechanical file changes | Custom header type, verification hook unproven | Digest items checked by every node on import |
| Chain-level burn and mint | Native state change | Stateful precompile, atomicity to verify | Precompile, atomicity read but not run |
| EVM | Go Ethereum 1.13.15, nothing after Cancun | Current (revm) | Different engine, emulated headers, own base fee, no `eth_getProof` or tracing |
| Maintenance health | Frozen 2024 upstream, one active maintainer, fixes hand-carried | A release every 2 to 4 weeks, internal traits change between minors | Stable every 3 months, but Frontier lags one or two stables |
| Finality and reorg limit | Standard proof of work | A choice for Ghost, untested | None, and an implicit 4,096-block limit |
| Node licence | GPL-3.0 node, LGPL-3.0 libraries | MIT and Apache | Apache runtime, GPL-3.0 with Classpath exception for the node |

Reading it: the Core-Geth fork is cheapest to build and the most expensive to
keep alive. Ghost chose it because its proof-of-work base is proven, and
accepted the standing maintenance work in return. The surveys are:

- [Ethereum Classic family (Core-Geth)](../surveys/etc-family.md)
- [Reth](../surveys/reth.md)
- [Polkadot SDK (Substrate) with Frontier](../surveys/substrate.md)

## EVM feature set Ghost keeps

Enabled from genesis:

- Frontier through Shanghai, excluding staking withdrawals (EIP-4895).
- London's EIP-1559 base fee, burned.
- Cancun's execution parts: transient storage (EIP-1153), memory copy
  (EIP-5656) and the restricted self-destruct (EIP-6780).

Defined behaviour: `DIFFICULTY` (also read as `PREVRANDAO`) returns the
block's difficulty, as before the Merge, and `BLOCKHASH` is specified
explicitly.

Switched off or removed:

- Blob transactions (EIP-4844), the blob base fee opcode, and the beacon-root
  contract (EIP-4788).
- The proof-of-stake wrapper and Engine API.
- Uncles and uncle rewards, the difficulty bomb, Ethereum Classic's reward
  schedule and its artificial finality rule, and other networks' configurations.

Gap from the outline: this is narrower than "Ethereum's current stable feature
set". Execution features after Cancun (for example EIP-7702) are absent until
deliberately backported, and each is a tracked item. Before launch Ghost
publishes a table of supported EIPs and JSON-RPC methods, with the Solidity
`evmVersion` to use (`cancun`), and proves it with Ethereum's execution test
fixtures, representative contracts, and MetaMask, Foundry, Hardhat and a block
explorer.

## Licence

The node follows its base. Core-Geth is LGPL-3.0 for its libraries (consensus,
EVM, networking, storage, about 99 percent of what Ghost changes) and GPL-3.0
for its commands. The node Ghost ships is therefore GPL-3.0 as a whole, with
Ghost's changes to library files released under LGPL-3.0.

To keep the project's own licence clean:

- The node lives in a separate repository, `ghost-node`, with the inherited
  GPL and LGPL terms and the full upstream git history.
- This repository stays MIT and Apache 2.0: the proof statements, web app, SDK
  and mining tools.
- Ghost's own tools talk to the node only over JSON-RPC and the external-miner
  interface. They never import the node's code.
- RandomX is BSD-3-Clause and fits under both. Its Go binding is part of the
  node and so is GPL and LGPL.

This is a reading of the licences, not legal advice. The founder knowingly
skipped legal review.

## Fork point

The candidate is the Core-Geth `master` commit
`7ee328ca2d6734ecbda9f0757d35eb6b710a14cd` (2026-09-17, after release
v1.12.23), which is based on Go Ethereum 1.13.15 plus individual backports.

Before choosing it, the first piece of work must compare it with the disputed
v1.13.0 release line of Core-Geth, at exact commits. That release is disputed,
but it claims security fixes missing from the v1.12 line. Each patch is judged
on its own provenance and tests, not on which group published it.

## Taking upstream updates

A missed upstream fix would be a Ghost vulnerability, so this is standing work.

- **Before any public node:** an inventory of every Go Ethereum release,
  advisory and security-relevant commit since 1.13.15, plus Core-Geth's fixes,
  Go dependency advisories and the Go toolchain version. Each item is recorded
  as applied, not applicable (with a reason), or open in a public
  `SECURITY-BACKPORTS.md`. No node is exposed publicly until every item is
  resolved.
- **Watch:** Go Ethereum releases and advisories, Ethereum Classic client
  advisories, RandomX releases, Go security releases and Go module advisories.
- **Triage within 7 days** of each upstream release, logged in
  `SECURITY-BACKPORTS.md`. Critical network-level fixes ship fast.
- **People:** a named primary maintainer and a named backup, a written
  emergency-release procedure, and a private disclosure address in the node's
  own security policy.
- **Review:** backports are prepared, reviewed by a different AI model, tested
  and signed by a maintainer. Release signing is not chain authority:
  maintainers can publish software but have no power over the chain.

Disable before deleting: unwanted features are switched off by configuration
first, and code is removed only where that clearly reduces attack surface, so
upstream fixes stay easy to carry over.

## What would reverse this decision

Work proceeds in gated phases, and a failed gate stops work and returns the
choice to the founder. The alternatives are product changes, not automatic
fallbacks. The gates that bear on this decision:

- The fork does not build reproducibly on a supported Go version, or the kept
  upstream tests do not pass.
- The security catch-up inventory cannot be fully resolved before any public
  node.
- The RandomX engine fails its cross-implementation hash checks, survives
  neither a deep reorganisation nor a network split, misses the bound set for
  recovery after miners leave, or is too slow to verify during header sync.
- The EVM execution fixtures or the wallet and tooling checks fail.
- The first-milestone lifecycle tests fail, or the worst-case invalid-proof
  benchmark exceeds its limits.
- A release build still contains a fake-seal mode, a verifier swap, a
  checkpoint override or any mint path other than the block reward and Reveal.
- Maintenance proves unsustainable: no named maintainer and backup, or upstream
  fixes cannot be triaged within the 7 days above.

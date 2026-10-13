# Ghost: locked outline

Locked 2026-10-13. Details for each section are worked out separately and do not change this outline unless noted.

## Context
This is a rebuild of a system that previously ran on a public testnet under the name Specter. The old code is used as reference only (see "Reference: old Specter code"). Its audits were all done by AI, not an outside firm, and nothing here relies on them.

## Goal
A public, open-source **commit and reveal system for data** with no privileged protocol administrator. Any kind of information can be committed privately and later revealed under rules the chain enforces. GHOST is the coin that runs the chain, and it is one type of data the system handles.

## Positioning
- General data architecture, payments-first validation.
- Launched by open proof of work with no allocation to anyone.
- Designed for post-quantum security within a defined threat model.
- Built for an era of AI agents: the chain is the root of trust, and agents verify proofs between themselves at machine speed.

## Design principles
- **Rigid money, flexible data.** The coin rules stay small and heavily reviewed, and everything else is built to be extended.
- **Build from existing, reviewed components.** Nothing is written from scratch where a proven implementation exists. No new cryptography is invented.

## Foundation
- **Base:** an Ethereum-compatible client with proof-of-work mining. The current lean is the modern Rust client (Reth) with a mining module added, over an Ethereum Classic-family client. It is confirmed by reading both codebases as the first task.
- **Taken off the shelf:**
  - the EVM, networking and storage from the base;
  - the RandomX reference implementation;
  - an existing open-source hash-based prover and verifier;
  - standard hashes and standard encryption;
  - standard EVM wallet interfaces.
- **Necessarily custom, and where review effort goes:**
  - the commit and reveal statements;
  - the coin accounting and origin rule;
  - the native private transaction and its fee formula;
  - how Phantom Key digits derive everything else;
  - the RandomX mining integration.
- **Dependencies** are pinned to specific versions, licence-checked and updated deliberately.

## Names
- **Chain and coin:** Ghost and GHOST, with ghostcoin.com as the single home.
- **Protocol actions:** Commit and Reveal.
- **App labels:** "Vanish" and "Summon," for the coin only.

## Core protocol
1. **Data first.** The generic data commitment is the base, and the coin is a special case with extra rules.
2. **In the chain from block one:** the coin tree, the data tree, one-time reveal and proof of holding.
3. **One commitment format with a type tag.** It contains a secret, a separate reveal secret, random blinding, a version and type, a content fingerprint, and an optional rule. Coin commitments add the amount.
4. **Commit:** record a commitment in a tree on the chain.
5. **Reveal:** there are two kinds.
   - **One-time reveal:** prove you hold the key and use the commitment. The chain publishes a one-time marker and rejects any repeat on the canonical chain.
   - **Proof of holding:** show you hold a commitment without using it up, repeatably, on or off the chain.
6. **Tree states in every block header,** so a proof can be verified from headers alone without running a full node.
7. **Showing contents** happens off the chain, in a way that never gives the other party the ability to reveal.
8. **Two trees,** one for coins and one for data, each with room for about four billion commitments and a defined rollover.
9. **Historical tree states** on the canonical chain stay valid for showing membership. A one-time reveal also checks that the commitment is unused, its rule allows it, and the fee is current.
10. **Proofs are bound to their purpose,** so a captured proof cannot be replayed. A proof of holding is bound to the verifier, the chain and a challenge the verifier chooses.
    - **Tagged hashing.** Every use of a hash (commitment, marker, tree node, note key) carries its own explicit tag, so a value from one use can never be passed off as another.
    - **Shared tree state.** A wallet proves against a recent, widely shared tree state, never the one its own commit created, because that value would appear in both transactions and link them.
11. **Encrypted note.** A small note stored with the commitment lets the key recover its own details. It is encrypted with a key derived from the digits.
12. **Later layers.** Custom contract rules on data, granting access, delegation and revocation.

## Phantom Keys
- **What it is:** the digits returned on commit. They control that commitment and its continuing remainder.
- **Bearer object:** whoever holds the digits controls it fully, and the first to reveal wins. There is no recovery and no admin override.
- **Format:** twelve groups of four digits, the last a checksum, about 146 bits of secret. An optional 24-group version is available.
- **Generation:** always by the app from a secure random source.
- **The digits are all you need.** Everything else is derived from them.
- **Delivery:** a key reaches another person outside the chain.
- **No master number and no receiving address** in version one.

## Coin rules
- **Origin.** Coin commitments arise only from authorized issuance, conversion of public balances, or value-conserving reveal of existing coin commitments. A data commitment can never create money.
- **Burn and mint.** Public GHOST is burned on commit and minted on reveal. No custodian holds a reserve.
- **Amount bound at commit.** The chain itself ties the amount burned to the amount inside the commitment. A user can never commit a hash claiming more than was burned.
- **No mint authority for contracts.** Only the chain's own reveal rule mints. No contract address is ever authorized to mint.
- **Partial reveals.** Any amount up to the balance after fees can be revealed, any number of times. Each reveal creates a fresh commitment for the remainder.
- **Remainder key.** The same Phantom Key controls the remainder by default, with a new key as an option.
- **Conservation is proven on every reveal.**
- **Public accounting** tracks value entering and leaving the hidden set. It is a backstop, not a detector of counterfeits inside the set.
- **Rules on GHOST.** There are none in the first milestone. Afterwards a short fixed list is added (time lock, expiry, restricted destination), with defined carry-over into remainders and claims.

## Transactions and fees
- **Public transfers:** ordinary EVM transfers.
- **Commit:** a normal transaction from a public account, visible.
- **Reveal:** a native private transaction with no account. The proof is the authorization.
- **One private shape:** one commitment in, an optional public amount out, and one remainder commitment.
- **Base fee:** set by the chain's formula and burned, as on Ethereum.
- **Tips:** public transactions keep Ethereum's optional tip to the miner. Private transactions carry a fixed tip set by formula, identical for every private transaction at that moment.
- **Fee privacy:** the base fee and tip are taken from the commitment inside the proof, never chosen by the user, and every private transaction has an identical size and shape.
- **Privacy claim.** The chain does not expose links between a commitment and its reveal. Destinations, amounts, timing and network data can still correlate.

## Data storage
- The chain holds commitments plus the small encrypted note.
- The data itself lives wherever the user chooses. The chain does not guarantee the file stays available.

## Cryptography
- **Proofs:** hash-based zero-knowledge proofs with no trusted setup, from an existing library.
- **Hash inside proofs:** the most-studied one that meets the speed target, chosen from prototype measurements. The tree uses the same hash, native to the proof system; the two are one decision.
- **Never wrapped.** The hash-based proof is verified natively by the chain. It is never wrapped inside an elliptic-curve proof to shrink it, which would bring the quantum weakness back.
- **Privacy mode on.** The proof library's zero-knowledge mode is confirmed enabled in the shipped configuration.
- **No proving-key download.** Hash-based proofs need none. The old app made users download a 370 MB key.
- **Speed requirement:** 10 seconds or less in a browser on named reference hardware. The proof system is revisited if this is not met.
- **Boundary:** ordinary accounts can never authorize the reveal of a commitment.
- **Ordinary accounts:** these start as safe as Ethereum's, with a post-quantum migration planned.

## Extension points
1. Version tags on every commitment, proof and transaction.
2. Application-defined commitment types.
3. A general proof checker for developer-written statements, which can never stand in for the coin's checks.
4. Cryptographic schemes identified by ID, with safe migration.
5. The EVM for general public logic.

## Agent readiness
- **Off-chain proof of holding** is the agent-speed feature: agents verify each other's proofs in milliseconds against block headers, with no transaction.
- **Commitments as capabilities:** keys, permissions, budgets and credentials. A one-time reveal is a single-use ticket.
- **Programmatic keys and an SDK** are provided alongside the human formats.
- **Delegated, scoped authority** is to be demonstrated through the general proof checker.

## Consensus and mining
- **Consensus:** plain proof of work from block one.
- **Algorithm:** RandomX with a unique configuration and salt.
- **Block time:** a target of 30 seconds, with 60 seconds as the fallback if testing shows too many wasted blocks.
- **Block reward:** the whole reward goes to the miner who finds the block. Nothing is diverted.
- **To specify:** difficulty adjustment, starting difficulty, timestamp rules, and behaviour when mining power drops.
- **Settlement:** probabilistic.

## Supply and emission
- **Starting supply:** zero.
- **Main emission:** 21 million GHOST on a smooth per-block decline, halving every two years. It is never described as a cap.
- **Starting reward:** about 6.92 GHOST per block at 30-second blocks.
- **Pace:** 29% in year one and 75% by year four.
- **Tail:** 0.2 GHOST per block forever, which is 1% of the main emission per year. It begins after about eight years.
- **If the block time changes,** per-block figures scale so yearly amounts stay the same.

## First product
A web application where a user connects a supported EVM wallet and uses GHOST privately.

- **Vanish:** a commit. It returns a Phantom Key.
- **Summon:** a reveal of any available amount to any address.
- **Claim:** a reveal that moves the remaining value, minus the fee, to a new key. A received key shows as unclaimed until this settles.
- **Paying with a key:** showing someone the digits.
- **No key storage.** The app creates and displays a key, and the user copies it, writes it down or downloads it as an image. To use a key, the user enters the digits.
- **Proofs** are made in the browser, in a background worker.
- **Save check:** before a commit is sent, the user re-types a few groups of the key to show it was recorded.
- **Distribution:** the app is also available as a verifiable build people can run themselves, with a choice of network endpoint.

## First milestone
One complete lifecycle with plain GHOST, tested adversarially:

1. Commit and receive a Phantom Key.
2. Partially reveal it, several times.
3. Claim the remainder to a new key.
4. Restore the current remainder from the digits alone on a clean device, without leaking a value that ties the sequence together.
5. Reject a second reveal.
6. Recover after a chain reorganisation.
7. Pass the linkage test: pull the raw commit and reveal transactions and assert no value appears in both, apart from a whitelisted shared tree state. Run it across three hops (commit, partial reveal, reveal of the remainder), and show the test fails against a deliberately linked design.
8. Handle the boundary cases:
   - a full reveal;
   - a zero-amount claim;
   - a fee that uses the whole balance;
   - two competing reveals.

## Later
- Built-in rules on GHOST.
- Sending hidden GHOST to someone not present.
- Combining keys.
- Data applications.
- Swaps with Bitcoin.

## Launch
- Code, mining software and launch date are published in advance, with a sensible starting difficulty.
- **No public test network period.** The main network is where the public finds bugs, and it is labelled experimental at launch. Internal test networks are used during development only.
- **Mining software for non-technical people:** one copy-and-paste command gets a basic computer mining in about a minute.
- **Solo mining and an operator-free pool** both work before launch day.
- There is no premine, no treasury and no founder allocation.
- The founder mines alongside everyone else, with real miners lined up before launch day.
- **Proof of no early mining:** the first block embeds the hash of a recent Bitcoin block.
- **Notice:** the launch date is announced at least 30 days ahead, and the final software is frozen and published at least two weeks ahead.
- **Miner safety:** the one-command installer verifies a signature on what it downloads, and a normal downloadable app exists as an alternative.

## Maintenance
- The founder is the first maintainer. The repository sits under a neutral project name, and maintainers are added as contributors earn it.
- Maintainers can publish software. They have no power over the chain.
- Every release is signed and rebuildable, and the code is mirrored in more than one place.

## Upgrades and incidents
- Anyone can propose a change publicly. It takes effect at a set block height only if miners and node operators run the new software.
- Vulnerabilities are reported privately to the maintainers, fixed, released, and disclosed once most of the network has upgraded.
- Existing commitments have a defined path to survive or migrate.

## Community and funding
- There are no bug rewards at the start. A voluntary miner-funded treasury may form later.
- There is no budget for paid work. Nobody is paid to build or review.

## Review approach
- All review is done with AI, with no paid audit.
- Reviews use a different AI model from the one that wrote the code, so the two do not share blind spots.
- The custom parts get adversarial tests and written properties that must always hold (for example, value in equals value out).
- The code is public from the first commit, with an open invitation for anyone to review it.
- The main network is labelled experimental at launch.

## Technical starting picks
These are starting points. Each is confirmed or changed by the work named beside it.

| Detail | Starting pick | Settled by |
|---|---|---|
| Base client | Reth with a mining module | Reading both candidate codebases |
| Proof library | Plonky3 | Browser benchmark against the 10-second target |
| Hash inside proofs | A fast proof-friendly hash | The same benchmark |
| Private transaction | A new transaction type alongside Ethereum's existing ones | The specification |
| Key derivation | Every secret derived from the digits with standard hashing | The specification |
| Difficulty adjustment | Per-block adjustment using a proven design | Simulation on a private test network |
| EVM features | Ethereum's current stable feature set, minus the proof-of-stake parts | The base client survey |
| Decimals and addresses | 18 decimals, standard `0x` addresses | No work needed |

## Starting point
- The old Specter code is not recovered and is not used. Everything is built fresh.
- The code lives in a new GitHub organization named for Ghost, set up by the founder.

## Reference: old Specter code
The old Specter code is not part of this repository. File paths below are relative to the root of the old code.

**Why it is reference only:** each old reveal publicly named the commitment it spent, so commit and reveal were linked on the chain. The proof statements must be redesigned, not ported.

**Worth reading when writing the specification:**
- `circuits/circom/lib/nullifier.circom`, `lib/commitment.circom`: marker construction, and reusing the same secrets with fresh blinding for the remainder.
- `circuits/circom/redemption.circom` lines 125-166: conservation arithmetic and the full-reveal case.
- `contracts/src/core/CommitRevealVault.sol` lines 482-599: the order of checks on a reveal.
- `docs/security-audit-2026-06-09.md` lines 470-488: the list of binding mistakes to avoid.
- `docs/plans/route1-postquantum-unlinkable.md`: the earlier plan for hash-based proofs, with its feasibility test and traps.
- `contracts/test/Audit*.t.sol`: test ideas.
- `webapp/src/components/vanish/VanishPreview.jsx`, `components/summon/SummonChangePreview.jsx`, `BlurredSecret.jsx`, `SummonInput.jsx`: the save-before-send flow and key entry screens.

**Do not carry over:**
- The amount, tree position or any extra secret inside the key. The old key was about 34 groups of digits.
- The same remainder blinding derived on every partial reveal.
- A guessed tree position for the remainder.
- Fetching every commitment one call at a time to rebuild the tree in the browser.
- A public sender paying the fee on reveal.
- Any service that receives a user's secrets, or any operator who posts tree states.
- Owner-swappable verifiers, pausable contracts, and mint rights granted to a contract address.
- Passphrase-protected key variants, which allowed offline guessing.

**Old proving speed:** no measurements exist. The app's own text said "10 to 30 seconds," and the August plan recorded about 28 seconds.

## Open decisions for the founder
- **Public identity:** real name or pseudonym. This is irreversible and must be decided before the first public post.
- **Legal review:** paid, free consultation, or knowingly skipped.

## Scope of work order
1. Base client survey and choice.
2. Proof benchmark in a browser against the 10-second target.
3. The lifecycle specification.
4. The first milestone: one full commit, reveal and claim cycle, tested adversarially.

## Licence
- **Our own code** (proof statements, web app, SDK, mining tools): dual MIT and Apache 2.0.
- **Node:** follows the chosen base. That is MIT and Apache if Reth, or LGPL and GPL if an Ethereum Classic-family client.

## Before any launch date
1. The lifecycle specification and first milestone.
2. A threat model.
3. Measurements of proving time, verification cost, chain growth and mining behaviour.
4. An AI review of the custom parts by a model other than the one that wrote them.
5. A legal review (open: see the question on whether this is paid for or skipped).

## Out of scope
- Phantom Swarm.
- Stake and finality layers.
- Sub-second settlement.

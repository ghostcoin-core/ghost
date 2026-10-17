# Decision 0002: the core value proposition

Status: settled by the founder, 2026-10-17.

## Decision

**Quantum-safe bearer commit and reveal for any data, with no administrator.**

Commit anything and get digits that are the only authority over it. Reveal it, spend it or prove you hold it, under rules the chain enforces. Crypto is the first type of data and the first demo. Data commitments are part of the core from block one.

The fixed requirements, the claims we make and the claims we never make are in the "Core value proposition" section of the [outline](../ghost-outline.md).

## What makes it distinct

Checked against the closest existing systems on 2026-10-17:

- **Firo (formerly Zcoin), Lelantus and Spark:** burn-and-redeem with partial redemption since 2021. Coins go to locked outputs that stay in the coin set and still count in total supply (`gettotalsupply` counts only block rewards minus fees). Hidden coins belong to wallet keys, and the proofs use elliptic-curve cryptography.
- **Zcash, Monero, PIVX:** private coins whose value stays in the chain's books. Not bearer, not quantum-safe.
- **Tornado Cash notes:** bearer secrets, but fixed denominations, no partial spends, elliptic-curve proofs.
- **Cashu and Fedimint:** bearer ecash run by a custodian.
- **Aleo/Zexe records, Anoma:** private records for arbitrary data, owned by account keys, not quantum-safe.

None of these combines: coins removed from supply and replaced by a bearer authorization to mint them again; bearer digits for coins and any other data; unlinkable partial reveals; no custodian or administrator; quantum-safe hash-based proofs; and an EVM alongside.

## Directions examined and set aside

| Direction | Why it was set aside |
|---|---|
| Delegation trees (offline, narrowing sub-keys sharing one budget) as the core | A feature, not a core. Recursive anonymous delegation already exists (ePrint 2026/1855). |
| Unforkable agents (an agent's state as one singular commitment) | Single-use seals (2016) already give the mechanism; freshness faster than a block is unsolved. |
| Digital originals (one live original for any data) | The same content can be committed twice under different secrets, a copy plus headers cannot prove currency, and Zexe, Enigio and OpenETR already cover the rest. |
| Self-acting data (data that enforces its own rules with nobody present) | A copied program cannot tell the real chain from a valid private fork, so on proof of work it can only ever be protected by cost. Research only, with no launch dependency. |
| One-way bridges from other chains, with staking incentives | Burned coins can never return, so demand is weak (Counterparty's 2014 burn drew about 2,125 BTC once). Incentives would need a premine or diverted block rewards, which break the fair launch. |
| Sealed audit reports for AI labs | A plain hash commitment in any public log does the same job. |
| Agentic AI pain points (22 surveyed) | No pain point where bearer data keys clearly beat existing tools. The best fits (prepaid, revocable access keys; agent budgets) carry value, so they come after the coin. |

## Consequences

- The outline gains a second milestone: the full lifecycle with a data commitment.
- Data stays off the chain, encrypted under a key derived from the digits. Nothing that unlocks data is ever written to the chain; Specter's on-chain key part could be read from transaction history after "deletion".
- Public wording follows the outline's list of claims, so the core claim survives critics.

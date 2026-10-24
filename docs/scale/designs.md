# Rules and design requirements for the scale work

This page holds the rules every part of the scale work follows and the requirements four designs must meet before any of them is chosen: the private bundle, public transactions, wallet restore at scale, and markers and state. It is part of the first stage (feasibility and security) of that work. No design is chosen here; each section lists what a design must satisfy, in terms a later piece can check.

The workload, ceilings and budgets these requirements refer to are in workload.md, and the arithmetic in benchmarks/scale/budget.py. Every figure on this page carries one of the labels measured, modeled or not yet established, as on that page. The approach is recursive proof bundling with no elliptic-curve wrap anywhere. Keccak-256 is the provisional hash baseline, not locked, and there is no automatic Poseidon2 fallback. <!-- no-figure -->

## Rules every part of the work must follow

1. Authorization, not just verification. Two valid reveals, or two valid bundles, can carry the same marker. Nodes keep the sequential marker check against executed state (spec 05 section 6). A bundle binds the approved Ghost statement and verifier, the exact ordered transaction contents, the count, the chain and the versions. Recursion aggregates proof verification only; nodes still execute every state-dependent check.
2. Spent status follows the canonical chain exactly. Pruning, synchronisation and restore preserve spent status on the selected canonical chain. Reorganisations produce exactly the state obtained by replaying the replacement canonical chain, including undoing spends present only on disconnected blocks (spec 05 section 7). Any compact replacement for the marker set keeps authenticated spent-status checks. Age-based deletion of markers is not allowed. Tests: a spend kept on the replacement chain stays spent; a spend only on disconnected blocks becomes spendable again when its commitment and other validity conditions still hold.
3. Evidence matches the exact primitive. For every hash candidate state field, width, rounds, capacity, encoding and role. The CICO and zero-test records are Poseidon1 over KoalaBear t=16, not Poseidon2 over BabyBear width 24. Ghost uses Keccak-f\[1600\] in a padding-free sponge (proofs/src/stark.rs), not NIST SHA3-256. Industry adoption and unrelated reduced-round results do not decide the security comparison. <!-- no-figure -->
4. Finite resources. 3,499 merges at 0.3 s is 1,049.7 machine-seconds; 40 machines need at least 26.2 s for a batch that arrives at once. A 30 s block time is an average, not a proving window. Measure sustained throughput and transaction-to-inclusion delay separately, with bursts, failures and backlog. (Labels: the merge count, machine-seconds and wall time are modeled; the 0.3 s merge time is not yet established for Ghost proofs.)
5. Denial of service is bounded, not assumed away. A correctly sized transaction with a plausible marker and fee can still fail only at verification. Bound total verification work, memory, queue growth and honest-user delay under sustained adversarial traffic from many identities, including malformed recursive proofs and late failures.
6. Independent operation. "Anyone may bundle" must be shown, not stated: private transactions keep being included when the largest aggregator disappears or censors.

Facts about the tooling these rules apply to (no figure is claimed for Ghost from either): Plonky3-recursion is Poseidon-only, unaudited and "not recommended for production", and its compatibility check is shape-only and binds no child proving keys, statements or public claims. The leanMultisig merge time (0.303 s) is leanVM verifying its own proofs over a 192-bit binary field with Keccak as a placeholder, not Plonky3 proofs; for Ghost that merge time is not yet established.

## Private bundle

A private bundle carries many private reveals into one block under one recursive proof. A design meets every requirement below.

1. Under rule 1, the bundle proof binds the approved Ghost statement and its verifier, the exact ordered list of every included reveal's contents, the count, the chain identifier and the protocol and statement versions; changing, reordering, adding or dropping any one of them makes the bundle fail. A test shows each of these failures.
2. Nodes still run every state-dependent check on every reveal in the bundle, in order, against executed state: the sequential marker check (spec 05, section 6), the root being a canonical earlier root, and the fee in force. The recursive proof replaces proof verification only.
3. Two bundles, or a bundle and a single reveal, that carry the same marker: the first executed spends, every later one is refused by the marker check, and the block that includes both is invalid or excludes the later one by a stated rule. A test covers both orders.
4. The non-proof part of every reveal (347 bytes today, modeled from spec 07, section 3) is published in the block, so any node can execute and any wallet can restore without the original proofs. The design states its encoding and the bytes per block at 3,500 reveals (1,214,500 today, modeled).
5. The design states the gas and state cost of a bundle as a formula of its count, and shows that 3,500 reveals per block fit the block gas limit and the 3,000 ms verification budget (modeled from spec 07, section 4); today's rule would charge 73,816,302,000 gas, 2,460.5434 times the limit (modeled).
6. The design states who pays the aggregator and from which field; today no aggregator payment field exists and the fixed tip goes to the block finder (spec 07, section 4; no figure).
7. The design states how a bundle behaves across fee windows (spec 07, section 5): a reveal priced for one window either stays valid in the bundle's block or is dropped by a stated rule, never charged a different fee silently.
8. The design states what happens to a bundle across a reorganisation: its reveals are re-executed on the replacement chain by rule 2, and a reveal whose root or marker is invalid there is refused.
9. Tree rollover: a block that fills a tree may not also start the next tree of that type (spec 05, section 3), so a large prebuilt bundle can become unincludable when a tree fills. The design states how a bundle near a tree's last leaves is split, rebuilt or deferred, and a test fills a tree with a bundle in flight.
10. Under rule 5, the design bounds the verification work, memory and queue growth a node spends on bundles that fail late (a malformed recursive proof, a reveal that fails its marker check after the proof passes), with the bound stated per peer and in total.
11. Under rule 6, any party can build a bundle from public data and the reveals it receives, without a key or permission from another aggregator, and a single reveal can still be included when no aggregator takes it. The design states how, and a later piece shows inclusion continues when the largest aggregator disappears or censors.
12. Under rule 4, the design states the machine time and the transaction-to-inclusion delay to fold 3,500 reveals; at the not yet established 0.3 s per merge that is 1,049.7 machine-seconds and at least 26.2425 s on 40 machines (modeled).
13. The design uses no elliptic-curve wrap anywhere and names the exact hash construction of every proof layer by rule 3. <!-- no-figure -->

## Public transactions

A design for public transactions meets every requirement below at 3,500 public transactions per block beside 3,500 private reveals (modeled from the target).

1. Every message that carries a block or its transactions (a new block, a block bodies response, a pooled transactions message) fits under the base client's 10 MiB message cap, 10,485,760 bytes (modeled, spec 09, section 8.4), with headers and RLP framing counted. Today's encoding needs 14,283,500 bytes per block for the ML-DSA-44 scheme, key and signature plus the private non-proof parts, 3,797,740 over the cap (modeled).
2. If signatures leave the chain and a verification proof stands in for them, that proof binds each account, its signing key and the exact transaction it signs, so a valid proof for one transaction cannot authorize another, and a key change on an account is honoured from the block it takes effect.
3. Nodes still run every state-dependent check of a public transaction (nonce, balance, code, gas) by rule 1; only signature verification may be aggregated.
4. The design states the bytes per block of each kind in the public mix of workload.md (plain transfers, commits, contract calls) and its propagation path, and shows the largest block at the largest allowed gas limit still fits the cap.
5. The design keeps the admission bounds of spec 09, section 8.3 or states stronger ones: invalid signatures or invalid verification proofs cannot exhaust a node, with per-peer and total budgets (rule 5).
6. The design states who may build a signature proof and shows public transactions keep being included when that builder disappears (rule 6).
7. The design names the exact signature schemes and the exact hash construction of any proof it adds (rule 3), and uses no elliptic-curve wrap. <!-- no-figure -->

## Wallet restore at scale

A design for wallet restore meets every requirement below against a mature chain at the target (10,000,000 new leaves a day, modeled from the target).

1. "The digits are all you need" stays true: a wallet restores from its secret alone on the reference phone of workload.md, within its restore download, time and storage ceilings (not yet established), against a chain of at least one year at the target.
2. Today's method (download every leaf and note from the start, 188 bytes each, and trial-decrypt) needs 1,880,000,000 bytes a day and 686,200,000,000 bytes a year before receipts, markers and public commits (modeled); the design states its own bytes per day and per year of chain, and the phone's download for a full restore.
3. No endpoint learns which commitment is the wallet's: the wallet fetches data in bulk or under a scheme whose privacy the design states, never one commitment at a time (spec 05, section 8). A test shows two wallets with different coins make indistinguishable requests.
4. Every downloaded item is checked against canonical headers before use, as spec 05, section 8 does for pages, and a missing or wrong item is rejected, never guessed.
5. The wallet learns the spent status of its coins on the canonical chain by rule 2, without revealing which marker it asks about.
6. The design states what a full node or indexer must keep and serve for restore to work, and restore works from any honest full node (rule 6).

## Markers and state

A design for markers and state meets every requirement below at 10,000,000 spends a day (modeled from the target).

1. Spent status follows the canonical chain exactly (rule 2): after pruning, synchronisation or restore, a node answers every spent-status query as a node that replayed the canonical chain from genesis would.
2. A reorganisation produces exactly the state of replaying the replacement chain: a spend kept on the replacement chain stays spent, and a spend only on disconnected blocks becomes spendable again when its commitment and other validity conditions still hold. Both are tests.
3. Any compact replacement for the marker set keeps authenticated spent-status checks: a node or wallet can check a spent or unspent answer against a canonical header.
4. No marker is deleted for its age.
5. The design states its storage growth per year at the target and compares it with today's rule of keeping every marker and every commitment forever (spec 05, "Who keeps what"): 116,800,000,000 bytes of markers a year (modeled, 32 bytes each).
6. Historical roots stay valid forever, as today, or the design states which roots expire, how a wallet holding an old root still spends, and that no coin becomes unspendable.
7. A tree holds 2^32 leaves and fills in about 429.5 days at the target (modeled); the design states how state, roots and markers carry across tree rollover (spec 05, section 3).
8. The design states the fresh-node sync time at a year of chain on the ordinary full node of workload.md (not yet established until measured).

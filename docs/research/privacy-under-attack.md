# Privacy under a hostile, low-volume network

Status: research write-up, 2026-10-20. No code. It extends the threat model ([threat-model.md](../threat-model.md): T1, T2, T5, T11, A10; claims C3, C17, C31; section 6 items 4 and 12) and the shared tree state rule of [specification 02](../spec/02-proof-statements.md), section 8.

**Short version.** The linkage test shows that a commit, a partial reveal and a final reveal share no value. It does not show that an observer cannot pair them by amount, by timing, by who sent them over the network, or by counting how few other people were around. On an early network those statistical links are the main risk, and they are larger than the cryptographic one. The wallet's rule of "reveal 2 blocks after anyone else commits" gives **settlement depth**, not **privacy cover**. They are different things and the app and the docs must never present one as the other.

## 1. What is fixed by the design (numbers used below)

| Fact | Value | Source |
|---|---|---|
| Block time | 30 s target (60 s fallback), so 2,880 blocks a day | spec 06 |
| Settled root | newest root at least 2 blocks below the tip, about 1 minute | spec 02, section 8 |
| Private reveal gas | `G_PRIV` = 21,090,372, so at most **one private reveal per block** at the default 30,000,000 gas limit | spec 07, section 5 |
| Most private reveals per day | 2,880 (one per block, if every block carries one) | derived |
| Commit | an ordinary public transaction: sender and exact amount burned are visible | spec 03 |
| Reveal | visible: recipient, public amount out, fee (a known formula), the remainder is a new hidden commitment | spec 03, 07 |
| Minimum commit | 1 wei, no cooldown, no per-sender limit | spec 03 (Proposed) |
| Tree | one coin tree, 2^32 leaves; every commit and every reveal's remainder adds a leaf | spec 05 |

Because the fee is a known formula and `v = out + v' + fee`, a **full reveal pays out exactly `commit amount - fee`**. An observer can subtract the fee from a reveal and look for a commit of exactly that amount.

## 2. Settlement depth is not privacy cover

Two separate questions:

- **Will this reveal stay in the chain?** Answered by blocks on top of it. It is probabilistic (threat model A4). A secret-chain attacker with share `q` of the mining power eventually overtakes a reveal that has `z` blocks on top with probability about:

| Attacker mining share | z = 1 | z = 2 | z = 6 |
|---|---|---|---|
| 5% | 10% | 1.3% | about 0 |
| 10% | 20% | 5% | 0.02% |
| 25% | 52% | 32% | 5% |
| 30% | 63% | 45% | 13% |
| 40% | 83% | 74% | 50% |

(Nakamoto's catch-up calculation, which counts a block as on top of the transaction's own block; it ignores the attacker's cost and the stale-block rate of spec 06.) On a young chain with little hashpower a single party can reach these shares cheaply. "Revealed a couple of blocks later" is therefore neither final nor safe against a deliberate reorganisation. The 2-block root depth only keeps the proof's root on the canonical chain through ordinary short forks. A recipient who needs the payment to stay must wait for more blocks, by their own choice and risk.
- **How many other people could this reveal have come from?** Answered by the *anonymity set*: the commitments an observer cannot rule out. Blocks do not measure it. Two blocks after a commit and two blocks after a reveal can be the same number with very different cover.

The coin count the app shows ("the tree holds N coins") is the **upper bound** on the set, not the set. The tree counts leaves, not people (section 4), counts leaves of every amount (section 3), and counts leaves that are already spent or are remainders (section 6).

## 3. Amount matching on public entry and exit

The commit shows the amount burned. A reveal shows the amount out. An observer does not need the cryptography to be weak to use this.

- **Full reveal.** Look for a commit of exactly `out + fee` made before the reveal and not yet explained. The candidate set is every earlier commit of that amount that could still be unrevealed.
- **Partial reveal.** The reveal could come from any commit of at least `out + fee`. That is a wider set, but the remainder then carries a *known* value for each guess (`commit - out - fee`), and the next reveal from the remainder must fit inside it. Each later reveal rules out candidates, so the set shrinks as a coin is used again (the three-hop case).
- **Round amounts help the observer less and the holder less.** Many people commit round amounts, so a round amount has many look-alikes, but the *remainder* after a round commit is usually an odd number, which then stands out when it is later revealed in full.

**Estimate.** Expected number of *other* commits of the same amount class an observer must rule out, for a reveal made `t` after the commit. Assumptions (stated, not measured): commits per day of 50 (quiet), 500 (modest) or 5,000 (busy); a round amount is shared by 20% of commits, a common one by 2%, an unusual one by 0.1%; commits arrive evenly through the day; the observer knows the commit time within the window; the reveal is from a coin committed inside the window. The anonymity set is these plus the real one.

| Commits per day | Amount type | Reveal after 1 min | after 1 hour | after 1 day |
|---|---|---|---|---|
| 50 (quiet) | round (20%) | 0.01 | 0.4 | 10 |
| 50 | common (2%) | 0.001 | 0.04 | 1 |
| 50 | unusual (0.1%) | about 0 | 0.002 | 0.05 |
| 500 (modest) | round | 0.07 | 4 | 100 |
| 500 | common | 0.007 | 0.4 | 10 |
| 500 | unusual | about 0 | 0.02 | 0.5 |
| 5,000 (busy) | round | 0.7 | 42 | 1,000 |
| 5,000 | common | 0.07 | 4 | 100 |
| 5,000 | unusual | 0.003 | 0.2 | 5 |

Read the cells below 1 as "most of the time nobody else fits": the observer links the reveal to its commit with high confidence. On a quiet or modest network, a reveal within the hour with an unusual or common amount is **identifiable**, even though the three-hop test passes. The number only becomes comfortable (tens of look-alikes) for round amounts on a modest or busy network after hours, or for any amount on a busy network after a day. Older unrevealed coins of the same amount add to these figures; early on there are few.

Plain guidance for holders: choose an amount many others use, do not choose an amount that is unique to you (a price, a balance, a date), keep a full reveal away from a commit amount minus the known fee, and expect that a partial reveal with a distinctive remainder stands out the next time you use it.

## 4. An attacker who made most of the cover

Tree size counts commitments, not people. One party can add leaves at the price of ordinary commit transactions (1 wei minimum, no cooldown, no sender limit), so:

- **The number the wallet shows can be inflated.** A million dust commits turn "among 1,000,000 coins" into a figure that says nothing about people.
- **The honest crowd is smaller than the count.** The attacker knows which leaves are theirs, so they rule them out. The honest anonymity set is the honest leaves of the right amount class and age, not the leaf count. If the attacker created a share `f` of the plausible look-alikes, the honest set shrinks by about `1 - f`: at 90% attacker cover, a set of 10 becomes 1.
- **Cover can be the attacker's tracing tool.** An attacker who commits many coins of the common round amounts, each at a time they note, can pair their own commits with the reveals that appear just after, and discover what *they* look like to the network. More usefully, they can fill the look-alike pool with leaves they will later reveal themselves, so the honest user's reveal is the only one left to trace.
- **Early on this is cheap.** Real usage is near 50 to 500 commits a day, so an attacker adding 1,000 well-chosen commits a day can dominate the plausible set. Cost is the commit transaction's gas plus the amount, which comes back when the attacker reveals their own coins at the private fee of about 21 million gas each (spec 07), at most one per block.

What can be done without new features (all are wallet and wording, not protocol): show the count as "leaves in the tree", not "coins you hide among"; weigh by amount class, not by tree size; and say that a count is not a count of people. A protocol-level answer (minimum amount, commit fee, cooldown) is a founder decision (spec 03, question 3) and not proposed here.

## 5. Timing of the reveal after the commit

The founder's decision is that the wallet never forces a wait. The window is the holder's, so privacy comes from the holder's choice.

- **Two blocks (about a minute).** The only cover is commits made in the last minute, plus older unrevealed coins that fit the amount. On a quiet network that is usually the holder alone. If nobody else committed, the wallet already refuses and waits (spec 02, section 8), so a reveal against the holder's own root never happens by default.
- **Because a block holds one private reveal at most,** reveals are strictly ordered. An observer who sees one reveal after one commit with nothing between them has a single candidate. On a quiet chain the longest gaps are many minutes, so the pairing is easy.
- **Order tells too.** If commits and reveals arrive in the same order, the first-in first-out match is better than random. Waiting a random time, not a round one, breaks that.
- **Time of day.** A reveal at 03:00 local time of the sender's region, a regular interval after funding, or a reveal exactly at some earlier deadline is a signal. The wallet should not choose a timer for the holder.

Plain guidance: wait until the shown cover has several look-alikes of the same amount, not several blocks; if you need the money at once, accept that the link is weak. A longer wait helps more on a busy chain than a quiet one.

## 6. A quick in-and-out makes you easier to find, and history stays

- **In-and-out.** Committing an amount and revealing a similar amount soon after is the pattern the matcher looks for, and your two public amounts match more closely than random pairs. It is easier to identify than a long-held coin that is revealed in a different shape.
- **A reveal is a leaf too.** The remainder added by a reveal is a new commitment, so reveals do not shrink the tree, and a spent commitment is never marked on its leaf. The observer cannot see which leaves are spent, but each pairing they make removes a leaf from later guesses, so the first people to use the network make the later ones easier to trace if the first are linked.
- **History is permanent.** Every commit, reveal, amount, time and fee stays on the chain forever, as threat model T1 says. Anything learned later (a leaked exchange record, a better matcher, a deanonymised address, a reorganisation analysis) can be applied to old data. A pairing that is only 30% likely today can become certain with outside information. The system should be described as "hides the link now, with limits", never "untraceable".
- **A break in the proof, hash or note encryption** (A1 to A3) would expose all history at once; that is separate from this write-up.

## 7. A hostile endpoint

The webapp talks to a node endpoint the user picks (webapp/README).

- **What it sees.** The sender's IP address and time of every request; the reveal transaction before the network does; the fetches that rebuild the tree; the moment a user checks that a commit is still in the chain.
- **The pairing is not needed from the chain.** If a commit and a reveal are sent from the same address, or through the same endpoint seconds apart, the endpoint pairs them without any amount matching. Using a different endpoint for each step helps only if the endpoint operators do not talk, and a hostile endpoint can be several.
- **Fetching is the sharp edge.** Asking for one commitment's witness tells the endpoint which leaf is yours (threat model section 6, item 8). Bulk history fetch, not per-leaf, is the only form that keeps this private.
- **A stale or lying endpoint** can show the wallet a short or fork tree, which makes cover look larger or smaller than it is. Confirmation of a transaction also trusts the endpoint's block seals (webapp doc), so "Done" is the endpoint's word.
- **Guidance:** run your own node, or use endpoints you choose at random; do not commit and reveal through the same one; treat the shown cover as the endpoint's claim.

## 8. A network-level observer

An observer who sees traffic at several points (an internet provider, a hosting provider, many hostile peers) first-sees a transaction near where it entered the network.

- **Entry point.** A transaction that reaches a hostile node first, from one IP, is tied to that IP. The reveal's own proof is the same size and shape for everyone (fee privacy, spec 07), so the proof does not distinguish senders, but the arrival does.
- **Commit versus reveal addresses.** The commit comes from a funded account with an identifiable history (an exchange withdrawal, say). If the reveal is sent from the same IP address or the same device fingerprint, the link is given away. The wallet would need to send the two through different routes.
- **Pool timing.** A reveal sits in the public pool before it is mined. Anyone running many nodes sees it with a timestamp and can race it for miners; a hostile miner also sees the pool and can delay a reveal to narrow the window (T3). Neither reveals the commit, but a delay changes timing evidence.
- **Low volume makes it easy.** With few senders, a handful of watching nodes see most traffic; the network adds no cover of its own.
- **Guidance:** assume network privacy is outside the chain. Use a private route (Tor or a VPN) for the reveal that differs from the commit's route; do not rely on the chain for it. A built-in routing layer is a new feature, not part of the core scope.

## 9. Wording that must change

No document should say or imply that a block count is anonymity, that "a couple of blocks" gives both finality and privacy, or that the chain makes users untraceable. These are the smallest fixes, all wording; no behaviour changes:

- Outline, "Fixed requirements" 3: "No link between commit and reveal, shown by the linkage test" now says no *cryptographic* link, and that the test checks shared values, not matching by amount, timing or network.
- Outline, "First product": "uses GHOST privately" now says what is hidden and what is not, and that a block holding a transaction is neither settlement nor privacy.
- Specification 02, section 8: "that leaf count is the anonymity set of the reveal" now says it is an upper bound on it, a count of commitments and not of people, and that the 2-block depth is about the root, not settlement or privacy.
- Web app README: "using GHOST privately" now says what it hides and what it does not.
- Threat model: a link to this document, and section 6 item 4 now points here for the measurement it asks for.
- Web app (`webapp/src/app.mjs`), cover line: it used to say a reveal or claim now hid the coin among the N coins in the tree. It now says the tree holds N coins as of a block, that this is a count of commitments, not of people, and not a promise of anonymity, and keeps the choice to reveal now or wait.
- Web app, the "sent" lines of Vanish, Summon (reveal) and Claim: they used to say the step was done once one block held it, which read as final. They now say the app marks it Done when a block holds it, that one block is not final, that each block after it makes it harder to undo, and that blocks add no privacy. When the app marks a step Done is unchanged: still at the first block that holds it (`docs/webapp.md`, "Summon and Claim", item 8). That is first inclusion, not settlement.

`docs/webapp.md` still opens with "uses GHOST privately"; it is outside this change and should get the same wording as the outline when that document is next edited.

## 10. What to measure next

1. Run the amount and timing matcher of sections 3 and 5 against a simulated chain at the three volumes above, with real-style amount choices, and publish the share of reveals it pairs correctly. This is the measurement threat model section 6 item 4 asks for.
2. Run it again with an attacker who adds 10x the honest commits (section 4).
3. Test the wallet's cover figure against a dust-filled tree and show an amount-class figure beside it.
4. Test a route-separation check: commit and reveal from one IP versus two.

## 11. Plain guidance for holders (for the app and the docs)

- "Done" in the app means a block holds the transaction. One block is not final; each block after it makes it harder to undo. If you are receiving a payment that must stay, wait for more blocks.
- A few blocks give you a better chance the payment stays; they do not give you privacy.
- Privacy comes from how many others of your amount were around and from how long you wait. The app will show a figure and let you choose; it never makes you wait.
- Pick a common amount, not a unique one. Do not commit and reveal a similar amount back to back.
- Send the reveal over a different route from the commit.
- Everything stays on the chain for good. Assume anything weak today may be read later.

# Review 01: adversarial review of the lifecycle specification

Status: final for this review, 2026-10-17. This records the first adversarial review of the
whole lifecycle specification, its findings and how each was resolved.

## 1. How the review was done

The outline requires that review uses a different AI model from the one that
wrote the work, so the two do not share blind spots. The specification was
written with one AI model; this review was done with a different AI model, from
a different developer. No outside firm and no human cryptographer has reviewed
it; this is not an audit (threat model, "How to read this document").

- **Scope.** All seven chapters together:
  [01](01-commitments-and-keys.md), [02](02-proof-statements.md),
  [03](03-coin-rules.md), [04](04-data-commitments.md),
  [05](05-trees-and-headers.md), [06](06-consensus-and-emission.md) and
  [07](07-private-transaction.md), read against the
  [threat model](../threat-model.md) (T1 to T13, A1 to A11, C1 to C48), the
  [outline](../ghost-outline.md) and the list of binding mistakes in the old
  Specter design's last audit (security-critical values passed as free
  arguments instead of being bound inside the proof and checked by the node).
- **Hunt list.** H1, a value that appears in both a commit and its reveal (or
  a proof of holding); H2, any way a data commitment could create money or a
  coin's value could be inflated; H3, any proof that could be replayed or
  redirected; H4, any place a contract, an account, a miner or anyone but the
  holder could authorise a reveal or a mint; H5, any remainder that reuses
  blinding; H6, each binding mistake of the old audit; H7, the threat model
  claim by claim. X marks a contradiction between chapters that could split
  consensus.
- **Severity.** BREAKS-PROPERTY: a property the documents write down is broken
  as specified. GAP: the specification is silent or ambiguous where it must be
  exact, and a reasonable implementation would break a property. MINOR:
  wording only.
- **Read-only.** The reviewing model read the repository and ran the checking
  scripts of `scripts/`, and changed nothing; the working tree was compared
  before and after each pass and was identical.
- **Passes.** Pass 1 reviewed the specification as merged. Its findings were
  fixed in the chapters named below. Pass 2 reviewed those fixes and this
  record, did not accept three of them and found five new problems (section
  4). Those were fixed in turn, and pass 3 reviewed the second round of fixes
  (section 5).

## 2. Result

Pass 1 found **9 findings**: 2 that break a written property and 7 gaps. It
found no way to create money, no unauthorised mint or reveal path, no
replayable or redirectable reveal, and no binding mistake of the old design.

| Finding | Class | Severity | Resolution |
|---|---|---|---|
| F1 | H1 | BREAKS-PROPERTY | Fixed for quiet epochs; for leaves of a full tree the claim's wording is corrected in the threat model (section 6, item 12) |
| F2 | H5 | BREAKS-PROPERTY | Fixed in round 2 by numbering remainders by hop (with N3) |
| F3 | H7 | GAP | Fixed |
| F4 | H7 | GAP | Fixed |
| F5 | H6 | GAP | Round 1 fix withdrawn (N1); resolved by stating what the proof of holding shows and correcting the capability claim (threat model, section 6, item 11) |
| F6 | X | GAP | Fixed |
| F7 | H7 | GAP | Resolved as a delivery gate: claims marked pending; the open points stay open by design |
| F8 | X | GAP | Fixed |
| F9 | H7 | GAP | Fixed |

Pass 2 then found 5 new findings, N1 to N5, all fixed (section 4). Pass 3's
result is in section 5. No finding that breaks a written property is left
open: each is fixed, or, where the specification cannot deliver the outline's
exact words, the threat model now records the wording that can be defended,
which is what its section 6 exists for, and the gap is named for the founder.

## 3. Findings of pass 1

### F1: A later epoch can carry the commit block's own root

- **Class and severity.** H1, BREAKS-PROPERTY.
- **Where.** Spec 02, section 8; spec 05, section 4 and section 13, item 4.
- **Property.** "A wallet proves against a recent, widely shared tree state,
  never the one its own commit created" (outline, "Core protocol" 10; threat
  model C17).
- **Problem.** The epoch rule tested heights only (`h > h_leaf`). When no leaf
  of the type is added between the commit's block and the next epoch block,
  that epoch header carries the same root, byte for byte, as the commit's
  block, and the wallet would prove against it. The same holds for every
  remainder hop and for data. Separately, spec 05 let leaves of the block that
  filled a tree prove against that block's root.
- **Resolution.** Fixed for quiet epochs: spec 02, section 8 now also requires
  the epoch root to differ in value from the root of the leaf's own block, and
  the wallet waits otherwise; PS-18 and AV-11 test the no-traffic case. The
  rollover part cannot be fixed without a new header field or a change to the
  tree layout, both outside this review: the last block that appends to a tree
  always has the tree's final root as its own root, and no later root contains
  its leaves. In round 1 this part was rejected on the ground that it links
  nothing; pass 2 did not accept that, because the root is still byte-equal
  to the leaves' own block root, which the outline's words forbid. Round 2
  keeps the default and states it truthfully: the wallet waits until the next
  tree has started, and then every holder of every leaf of the full tree
  proves against the same final root, so it does not single out the filling
  block's leaves, though it is byte-equal to their block's root (spec 02,
  section 8, "A leaf of a full tree"; spec 05, section 13, item 4 and question
  5). The threat model records the wording that can be defended (section 6,
  item 12), for the founder to adopt in the outline or to reject in favour of
  a design change.

### F2: A clean restore after a reorganisation can pick a used number again

- **Class and severity.** H5, BREAKS-PROPERTY.
- **Where.** Spec 01, sections 7 and 8; spec 03, section 8; spec 05, section 7.
- **Property.** "Each remainder uses blinding that differs from every earlier
  one in its sequence" (spec 03, section 8; threat model C26).
- **Problem.** A remainder with number 1 is published, then removed by a
  reorganisation. A clean device that has only the digits sees number 0 on the
  canonical chain and picks number 1 again, so it derives the same `b_1`.
- **Resolution.** Fixed in round 2. Round 1 stated the property per chain and
  argued that reuse across branches links nothing; pass 2 showed that wrong
  (N3), because with "one above the highest number used" and its gaps, a clean
  device after a reorganisation could give one number to remainders of two
  different inputs. Spec 01, section 8 now numbers remainders by hop: a reveal
  creates number `k + 1` when it spends number `k`, a retry of the same input
  keeps the same number, and numbers have no gaps. On one chain each number is
  used once. Across branches, devices and retries, two remainders with the same
  number always come from reveals that publish the same input marker (the
  marker depends only on the key and the number), so sharing their blinding
  repeats only what that marker already shows: the same hop of the same key
  was revealed in both places (the commitments at that hop may differ in
  amount), as a fork replay shows (threat model T4).
  Restore from the digits alone is unchanged; the next number is one above the
  current remainder's (spec 01, section 8, step 7). Spec 03, section 8 and
  spec 05, section 7, item 4 follow.

### F3: Page checks do not cover the notes

- **Class and severity.** H7, GAP.
- **Where.** Spec 05, sections 8 and 9; spec 01, section 8.
- **Property.** The note lets the key recover its own details (C18); restore
  from the digits on a clean device (C21, C41).
- **Problem.** A page root covers the leaves only. An endpoint could serve the
  right leaves with an altered note; the wallet's own note would then fail to
  decrypt and be passed over as someone else's, so restore could report
  "nothing found" without noticing. A snap-synced node could pass such pages
  on as checked.
- **Resolution.** Fixed. The receipt of every transaction that appends a leaf
  (coin commit, data commit, coin reveal) now carries the leaf, its tree index
  and position, and its note bytes, and every reveal receipt carries its marker
  (spec 03, sections 6 and 7; spec 04, sections 4 and 6; spec 07, section 3;
  spec 05, section 12, item 5); round 2 narrowed this after N4.
  The wallet checks every note byte for byte against the receipts, fetched in
  bulk for every block from its scan start and checked against each header's
  `receiptsRoot`, and a restore result is final only after that (spec 05,
  section 8, item 5; spec 01, section 8, step 5). A snap-synced node serves
  only pages whose notes it checked the same way (spec 05, section 9). RT-9
  tests an altered note.

### F4: Agreeing marker pages do not prove status

- **Class and severity.** H7, GAP.
- **Where.** Spec 05, section 8 ("Marker status"); spec 01, section 8.
- **Property.** Restore finds the current remainder (spec 01, section 8; C21,
  C41).
- **Problem.** Marker pages cannot be checked against a header. The wallet
  trusted two agreeing peers, but an attacker who runs many peers (T8) can
  make them agree on a false answer.
- **Resolution.** Fixed. Marker pages are hints only. Status comes from the
  markers in the reveal receipts, checked against `receiptsRoot` in the same
  bulk fetch as the notes, and an unchecked status is "unknown" (spec 05,
  section 8 and section 12, item 4; spec 01, section 8, step 5). RT-9 tests
  three agreeing lying peers.

### F5: A proof of holding said nothing about which resource is held

- **Class and severity.** H6, GAP.
- **Where.** Spec 02, section 6 and AV-12; spec 04, section 5 and CR-D2.
- **Property.** A proof of holding is usable as a capability (C36); a proof
  for one commitment is not a proof for another (spec 04, CR-D2; spec 02,
  AV-12).
- **Problem.** S3 proved only that the prover holds *some* unspent data
  commitment. Anyone can make one, so after A was revoked its former holder
  could answer with a fresh commitment B and pass. The verifier had no public
  input that tied the hidden opening to what it was checking.
- **Resolution.** Round 1 added a public `subject` that the opened
  commitment's content fingerprint had to equal. Pass 2 showed that this can
  be faked (N1): the content fingerprint is a field the committer chooses and
  no proof checks it against content, so anyone who learns the subject can
  make a matching commitment. Round 2 withdrew `subject` and resolved the
  finding by stating the limit instead of claiming more. Spec 02, section 6
  ("What S3 shows") and spec 04, section 5 ("What it claims") now say that a
  proof of holding shows the prover holds some unrevealed commitment of the
  type, and names no particular commitment or resource; AV-12 and CR-D2 now
  test only that the revoked commitment's own proofs and marker can no longer
  be used, by challenge and marker-set freshness or by non-membership, and
  that another unspent commitment still verifies. Binding a proof of holding to a resource the
  prover cannot make for itself is the outline's later layer of granting
  access ("Core protocol" 12) and needs its own design and review, so it is
  not invented here. The threat model's C36 limit and section 6, item 11 give
  the wording that can be defended for the founder. A one-time reveal as a
  single-use ticket is unaffected.

### F6: Root eligibility depended on the validating node's branch

- **Class and severity.** X, GAP.
- **Where.** Spec 05, sections 5 and 7; spec 03, section 7, step 7; spec 04,
  section 6, step 8.
- **Property.** Two separate implementations get the same chain (spec 06);
  historical roots and reorganisation behaviour (C15, C42).
- **Problem.** A root was eligible if it was on "the node's canonical chain as
  it is when the check runs". A node following branch A validating a block of
  a heavier branch B would reject a reveal against B's own earlier root, while
  a node following B would accept it: a consensus split.
- **Resolution.** Fixed. Eligibility is now defined by the including block's
  own ancestry, and pool admission uses the next block on the canonical head
  (spec 05, section 5, items 1 and 2, and the lookup paragraph). Blocks of a new
  branch are validated against their own ancestry and parent state during a
  reorganisation (spec 05, section 7, item 2). Specs 03 and 04 now point to the
  exact rule. TH-9 adds the side-branch case.

### F7: The fail-closed points leave the promised lifecycle undelivered

- **Class and severity.** H7, GAP.
- **Where.** Spec 02, section 13; spec 05, section 12; spec 07, section 9.
- **Property.** The coin tree, the data tree, one-time reveal and proof of
  holding are in the chain from block one (outline, "Core protocol" 2; C4, C6,
  C11, C13, C36, C43).
- **Problem.** Every proof of holding is rejected, data reveals have no
  encoding or fee, and no commit, reveal or private-transaction block is valid
  until the reserved accounts and receipt layout are fixed. That is safe, but
  it is not the lifecycle the outline promises.
- **Resolution.** Fixed as a gate; the points themselves stay open by design,
  because each is a founder question or belongs to a later specification
  (transaction format, spent-marker set), and settling them here would decide
  for the founder. Spec 02, section 13 now lists which open points each
  milestone needs and says no milestone passes while they are open, and the
  threat model (section 8) marks C4, C6, C11, C13, C36 and C43 as pending, not
  met. Rejecting keeps them safe in the meantime.

### F8: The pool recheck would drop every pending reveal

- **Class and severity.** X, GAP.
- **Where.** Spec 07, section 6; spec 05, section 3.
- **Property.** "The pool keeps the transaction, unchanged, for a later block"
  (spec 05, section 3).
- **Problem.** The recheck on each new head runs admission step 6 ("no
  transaction with this marker is in the pool"), which a literal
  implementation would apply to the transaction being rechecked, dropping it.
- **Resolution.** Fixed. In the recheck, step 6 looks only at the other
  transactions in the pool, and a transaction held back only by the one tree
  index per block rule stays in the pool (spec 07, section 6, "Recheck").

### F9: No defined path for commitments to survive or migrate

- **Class and severity.** H7, GAP.
- **Where.** Spec 01, sections 10 and 12, item 7; spec 03, section 8.
- **Property.** "Existing commitments have a defined path to survive or
  migrate" (outline, "Upgrades and incidents"; C47).
- **Problem.** The remainder keeps the input's format version, so migration is
  not yet possible, and survival was described only as lasting "for as long as
  the chain accepts that scheme", with no rule that it must.
- **Resolution.** Fixed. Spec 01, section 10 now makes survival the defined
  path: no upgrade removes or disables a scheme the chain has accepted, or makes
  an unrevealed commitment of it unrevealable, unless a tested migration
  reveal into a newer scheme already exists, and an at-risk scheme may be
  restricted to reveals into a newer one but never cut off. Until a migration
  exists, commitments of scheme 1 therefore survive with no action by their
  holders; once one exists, an at-risk scheme may require its holders to
  reveal into the newer scheme.

### Considered and not a finding

The reviewing model checked these and found them handled:

- **Inflation and type confusion.** S1 constrains both commitment hashes, the
  `COIN` type, the marker, the remainder and integer conservation together;
  amounts are bounded and the limb carries end at zero; the accounting
  backstop applies (spec 02, sections 4, 9 and 10; spec 03, section 7).
- **Spent commitment and marker confusion** (the old design's main binding
  mistake). The marker is computed inside the proof from the same `r` and `b`
  that open the hidden leaf (spec 02, section 3).
- **Recipient, fee, remainder and note substitution.** All are bound through a
  digest the node computes itself, and spec 07 maps every payload field onto it
  (spec 02, section 7; spec 07, section 3).
- **Verifier and challenge replay.** Verifier identity and a fresh, issued,
  unanswered challenge are checked (spec 04, section 5).
- **Replay across forks that share genesis.** The threat model already allows
  fork double spending (T4, section 6 item 3); it is not a new break.
- **Earlier "tree full" defaults.** Spec 05 replaces them with rollover; spec 07
  supplies the type and empty rule its payload omits.
- **Bitcoin anchor inputs.** Spec 06, section 8.3 requires a fully validating
  Bitcoin node; that precondition must stay.

The claim-by-claim check of C1 to C48 found every claim consistent at
specification level except those named in the findings above (C3 and C17 in
F1, C18, C21 and C41 in F3 and F4, C26 in F2, C15 and C42 in F6, C36 in F5,
C47 in F9, and the pending claims of F7), and the launch and release claims
(C34, C40, C44 to C46), which need measurement or operational evidence rather
than specification text.

## 4. Pass 2: review of the fixes

Pass 2 read the edited chapters in full against its own pass 1 findings and
this record. It accepted the fixes of F3, F4, F6, F8 and F9 as closing their
findings, and accepted F7's deferral as sound. It did not accept F1's
rollover rejection, F2's cross-branch argument or F5's fix, and it found five
new problems. All were addressed in round 2; the F1, F2 and F5 entries above
describe their final resolution.

### N1: The public subject could be faked without the content

- **Class and severity.** H6, BREAKS-PROPERTY.
- **Where.** Spec 02, section 6 (round 1 text); spec 01, section 3; spec 04,
  section 5.
- **Property.** A proof of holding is usable as a capability (C36), as the
  round 1 limit claimed.
- **Problem.** The content fingerprint is a field the committer chooses, and
  no proof checks it against content in version 1. Anyone who learns the
  subject can commit with that fingerprint and answer fresh challenges, even
  if the real content holds a secret.
- **Resolution.** Fixed by withdrawing `subject` and correcting the claim (F5
  above). S3 and its binding are back to the layout before round 1, and the
  threat model no longer claims a capability that version 1 cannot deliver.

### N2: A full tree's leaves could not be checked against current revocations

- **Class and severity.** H7, GAP.
- **Where.** Spec 02, sections 6 and 8; spec 04, section 5, verifier check 5.
- **Property.** After a revocation, proofs of holding fail (C43, within the
  stated recent-state limit).
- **Problem.** S3 took the tree root and the spent-marker-set root from one
  header. After rollover, no header later than the tree's last block carries
  its final root, so a leaf of a full tree could only be checked against old
  marker status.
- **Resolution.** Fixed. The spent-marker-set root comes from a header the
  verifier accepts as current, and the tree root from a header of the same
  chain at or below it, so a leaf of a full tree is checked against current
  status (spec 02, section 6 and section 8; spec 04, section 5, check 5).
  AV-12 adds the case of a full-tree leaf revoked after the next tree started.

### N3: Cross-branch reuse of a number could link two reveals

- **Class and severity.** H5, BREAKS-PROPERTY.
- **Where.** Spec 01, section 8 (round 1 text).
- **Property.** Fresh blinding for every remainder; reusing blinding links
  reveals (C26).
- **Problem.** With gaps in the numbering, a reveal of `C0` on one branch could
  make number 5 while, after a reorganisation, a clean device makes number 5
  from number 4 on the canonical branch. Two remainders from different inputs
  then share blinding and, with equal amounts, are equal, linking two reveals
  with different input markers. A removed remainder may also have been revealed
  on its branch, publishing its marker.
- **Resolution.** Fixed with F2 by numbering remainders by hop, so equal
  numbers always mean the same input marker (spec 01, section 8).

### N4: The receipt rule did not fit data reveals

- **Class and severity.** X, GAP.
- **Where.** Spec 05, section 8, item 5 and section 12, item 5; spec 04,
  section 6, step 11.
- **Property.** Two separate implementations get the same chain (spec 06).
- **Problem.** Round 1 required every reveal receipt to carry an appended leaf
  and note, but a data reveal appends nothing; an implementation could fill the
  field with the spent commitment, which the reveal must hide.
- **Resolution.** Fixed. Only transactions that append a leaf carry leaf,
  position and note; every reveal carries its marker; a data reveal's receipt
  carries no leaf or note, and no receipt ever carries a spent commitment
  (spec 05, section 8, item 5 and section 12, item 5; spec 04, section 6,
  step 11).

### N5: Restore depended on receipts nobody had to keep

- **Class and severity.** H7, GAP.
- **Where.** Spec 05, section 9; threat model A9.
- **Property.** Restore from the digits alone on a clean device (C41).
- **Problem.** Round 1 made restore depend on historical receipts, but full
  nodes were only required to keep leaves, notes, page roots and markers.
- **Resolution.** Fixed. Full nodes keep and serve the receipts of every block
  by block range, with no pruning in version 1; snap-synced nodes download and
  check them; TH-21 and RT-12 cover them; and A9 now names them (spec 05,
  section 9; threat model A9).

Pass 2 also listed places where this record overstated the fixes; this version
of the record is written to match the final text.

## 5. Pass 3: review of the second round

Pass 3 read both rounds of edits and this record. Its verdict:

| Finding | Pass 3 |
|---|---|
| F1 | Closed; the full-tree exception accepted as recorded in threat model section 6, item 12 |
| F2 | Closed |
| F3 | Closed |
| F4 | Closed |
| F5 | Closed |
| F6 | Closed |
| F7 | Deferral accepted: the missing definitions remain, with dependent claims and milestones marked pending |
| F8 | Closed |
| F9 | Closed |
| N1 to N5 | Closed |

It found no new problem that breaks a property or leaves a gap. It concluded
that, under the threat model's stated qualifications, no finding that breaks a
written security property remains open, and noted that F7 means the lifecycle
is not yet executable or ready to launch. It listed wording that still claimed
more than the qualified text: a counter that "never repeats" (spec 01, section
1), own-block-root exclusions without the full-tree exception (spec 02,
sections 1, 4, 5 and 8), revocation summaries that read as ending every proof
of holding (spec 04, sections 1, 7 and 10), linkage exceptions that left out
the verifiers' own choices (spec 04, section 9 and CR-D15), CR-D2's account of
why an earlier proof fails, and two statements in this record. All were
corrected after pass 3; none changes a rule.

## 6. What remains

- **F7's open points** stay with the founder and the later specifications they
  name (spec 02, section 13): reserved accounts, receipt layout, the data
  reveal's fee and encoding, and the spent-marker set and its header root. No
  milestone passes until they are settled.
- **Threat model section 6, items 11 and 12** give the defensible wording for
  C36 and C17; the outline is not changed by this review.
- **A proof of holding bound to a particular resource** is part of the later
  layer of granting access and needs its own design and review.

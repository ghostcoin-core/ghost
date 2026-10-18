# Milestone 1 review: adversarial review of the custom code

Status: final for this review, 2026-10-18. This records the adversarial review
of the code written for the first milestone (full lifecycle), its findings and
how each was resolved. The specification itself had its own review earlier
([review 01](../spec/review-01.md)).

## 1. How the review was done

The outline requires that the custom code is reviewed by a different AI model
from the one that wrote it, so the two do not share blind spots. The code was
written with one AI model; this review was done with a different AI model, run
without a human in the loop. No outside firm and no human cryptographer has
reviewed the code; this is not an audit ([threat model](../threat-model.md),
"How to read this document").

- **Code reviewed.** `ghostcoin-core/ghost` at commit `35646d9` and
  `ghostcoin-core/ghost-node` at commit `c2990362d`, both the head of `main` on
  2026-10-18.
- **Scope.** The proof statements (`proofs/src`: the S1 coin reveal AIR, the
  hash schedule, binding digests, amount limbs and conservation, the STARK
  configuration and verifier); the coin accounting and origin rule
  (`core/ghostpriv` commit and reveal, the hidden-set totals and backstop);
  the native private transaction and its fee formula (`core/ghostpriv`,
  `core/types/tx_ghost_private.go`, the state-transition path); the Phantom Key
  derivation (`client/src` key, derivation, note, commit, reveal and restore);
  and the RandomX integration and Ghost consensus rules (`consensus/randomx`,
  `consensus/ghostrules`, the Ghost header fields and their validation).
- **Attacks tried.** Counterfeit creation, double reveal, proof replay or
  redirection, commit-to-reveal linkage, and consensus splits between nodes
  (non-determinism, build differences, header fields that some nodes accept
  and others reject, panics on attacker input).
- **Specification.** Every pass compared the code with `docs/spec/` (chapters
  01 to 07) and the node's own documents, and named which side looked wrong
  wherever they disagree.
- **Severity.** Critical and High: a written property is broken or money can
  be created, double spent, redirected or linked. Medium and Low: everything
  else. Under the project's rules only Critical and High findings are fixed in
  the review; each one gets a failing test first, then the fix, then a review
  of the fix. Medium and Low findings are recorded here in one line each.
- **Read-only passes.** The reviewing model read both repositories and changed
  nothing; `git status` of both checkouts was empty before and after every
  pass. The test suites of both repositories were run separately on the
  reviewed commits and passed: `cargo test --release` for `proofs` and
  `client`, and `go test` for `core/ghostpriv/...`, `core/ghosttree`,
  `consensus/randomx`, `consensus/ghostrules` and `params/ghost`.
- **Passes.** Pass 1 covered the five areas in four parallel reviews. Pass 2
  went deeper on three: a column-by-column soundness inventory of the S1
  trace, a byte-for-byte comparison of the Go node with the Rust crate (tagged
  hash, tree nodes, binding layout, commitments, header roots), and the key and
  marker derivations end to end.

## 2. Result

**No Critical and no High findings.** No pass found a way to create money, to
reveal one commitment twice, to replay or redirect a proof, to link a reveal to
its commit beyond what the specification permits, or to split honest nodes.

Totals: 0 Critical, 0 High, 5 Medium, 10 Low, and 7 places where the
specification was wrong and is corrected in this change (section 5).

What the passes confirmed, with the place each was checked:

- **One coin, one marker.** In S1 the marker is computed in the trace from the
  same `r` and `b` columns that open the leaf, carried as constants across all
  rows, so one opening has exactly one marker (`proofs/src/reveal.rs`,
  `proofs/src/air.rs`).
- **Membership.** Exactly 32 tree hashes with fixed level bytes; each node
  takes the previous digest on the side its Boolean direction bit picks, and
  the last digest equals the public root (`proofs/src/air.rs`).
- **Conservation over the integers.** Every amount limb is 16 bits, carries
  are 0, 1 or 2 with zero end carries, and both sides of every limb equation
  stay below the BabyBear modulus, so `v = out + v' + fee` holds without field
  or 96-bit wrap (`proofs/src/schedule.rs`, `proofs/src/air.rs`).
- **Nothing to redirect.** All 415 binding bytes (chain, version, domain,
  statement, type, purpose, root, marker, remainder, recipient, out, fee, rule,
  note) enter the binding hash, and all public bytes enter the Fiat-Shamir
  transcript. The Go node's 415-byte binding input matches the Rust layout
  field for field, and the node computes every verifier input itself, never
  from the proof (`proofs/src/binding.rs`, `core/ghostpriv/reveal.go`).
- **Verifier configuration.** The verifier fixes the zero-knowledge
  configuration, the trace size and the security floor; options in a proof
  cannot lower the queries or the grinding (`proofs/src/stark.rs`).
- **Same hashes in both implementations.** The Go tagged hash, tree nodes,
  empty leaves and coin commitment match the Rust crate byte for byte
  (`core/ghosttree`, `core/ghostpriv`, `proofs/src/hash.rs`).
- **Double reveal and accounting.** The marker is checked against the spent
  set, which also holds earlier reveals of the same block, and the reveal's
  state change is one snapshot: remainder append, marker, total out, credit
  and tip together or not at all. The backstop rejects `out + fee` above the
  hidden total (`core/ghostpriv/reveal.go`, `core/ghostpriv/ghostpriv.go`).
- **Header roots.** Block import recomputes both tree roots from the executed
  state and rejects a header whose roots differ, so a miner cannot plant a
  root for later reveals to prove against (`core/block_validator.go`).
- **Eligible roots.** The node accepts any coin root in a header strictly
  below the including block on its ancestry, which is the rule of spec 05,
  section 5; the epoch rule is the wallet's (spec 02, section 8).
- **Build differences.** A build without cgo has no RandomX and refuses to
  start the engine rather than accept seals (`consensus/randomx/binding_nocgo.go`).
- **Keys.** Every derivation in the client uses the tag and input order of
  spec 01; the client's marker is the proof crate's marker for the same key;
  the bearer path uses only hashes, no elliptic-curve step.

One limit stands: the node links no proof verifier yet. Its default verifier
rejects every reveal (`core/ghostpriv/verifier.go`) and the pool cannot admit
a reveal, which the node documents. So the review establishes that the node
cannot be tricked into a mint today, and that the Go and Rust sides agree on
every byte they share, but not that a real Rust proof is accepted end to end
by a running node. That is node-integration work, already planned.

## 3. Medium findings

Each is short, with where it is and what it would take. M1 is the only one
that contradicts the specification's text; it is recorded as open in
section 6.

- **M1. Reveal receipts index the marker as a log topic.**
  `core/ghostpriv/reveal.go:366` (ghost-node). Spec 05, section 12, item 5
  says no leaf, marker or note may be an indexed topic, so a log filter cannot
  become a per-commitment lookup. Code is wrong; carry the marker in the log
  data instead. **Open:** that file is being changed by work in progress, so
  the change waits for it.
- **M2. Root lookup walks the whole ancestry.** `core/ghostpriv/reveal.go:244`
  and `:284` (ghost-node). A reveal with an unknown root makes the node walk
  parent links to genesis before it is rejected, for fixed gas. This is cost
  amplification for whoever builds the block, not a way to accept a bad root;
  an index of eligible roots would fix it.
- **M3. Release builds accept the shared Ethash mode.**
  `eth/ethconfig/config.go:263`, `:277-279`, `:287` (ghost-node). An operator
  setting `PowMode=ModeShared` gets Ethash instead of RandomX and skips the
  Ghost consensus parameters. Needs operator action, not a hostile header;
  reject the mode on Ghost networks.
- **M4. Header sync samples seals.** `eth/downloader/downloader.go:56`,
  `:1487-1489`, `core/headerchain.go:329-346`,
  `consensus/randomx/consensus.go:235-236` (ghost-node). Inherited from the
  base client: header-only sync checks a sample of seals, so one bad seal in a
  batch can pass there while full validation rejects the block. The internal
  network runs at difficulty 1, so it is not exploitable today; require every
  seal before launch parameters.
- **M5. A claim to a reused key strands the remainder.**
  `client/src/reveal.rs:199-202` (ghost). The claim rejects only the input
  key; a destination key whose remainder number 0 is already spent produces a
  remainder that can never be revealed. Caller misuse of the "new key"
  contract of spec 01, section 5; generate the destination key inside the
  claim or check it.

## 4. Low findings

- **L1.** `proofs/src/binding.rs:176` and `proofs/src/reveal.rs:183-205`: the
  proof API binds any protocol version instead of rejecting all but `0x0001`
  (spec 02, section 3, item 6). The node fixes the version to 1 itself, so no
  cross-version replay exists; code should reject.
- **L2.** `proofs/src/reveal.rs:163-165`, `:267-268`: remainder blinding
  freshness is checked by the honest prover only, as spec 02 allows. A
  remainder that reuses the input's `r` and `b` carries the spent marker and
  harms only its holder. Spec 03 overstated this and is corrected (section 5).
- **L3.** `proofs/tests/properties.rs:483-775`: the adversarial tests change
  transactions and witnesses; only the public values and one carried byte are
  also mutated in the trace (`proofs/src/reveal.rs`, unit tests). No test
  mutates round flags, direction bits, limbs or carries, or feeds malformed
  proof shapes or too little grinding.
- **L4.** `client/src/note.rs:154-183`, `client/src/restore.rs:163-171`: a coin
  note with a non-zero content fingerprint or length decodes and restores,
  where spec 01, section 9 requires zeros. Code is wrong.
- **L5.** `core/ghostpriv/commit.go:82` (ghost-node), `client/src/restore.rs:165`,
  `:184` (ghost): anyone can copy a commit's public `F`, note and amount into a
  commit they pay for. Both leaves share one marker, so only one can be
  revealed and the copier loses the burn; restore shows both. Spec 01 said
  this needed key reuse and is corrected (section 5).
- **L6.** `core/ghostpriv/reveal.go:317` and `:340` (ghost-node): the proof is
  verified before the tree-room check, where spec 07, PT-12 puts every cheap
  check first. The outcome is the same rejection; only the cost differs. Code
  is wrong.
- **L7.** `core/ghostpriv/ghostpriv.go:162` (ghost-node): receipts hold the tree
  index in four bytes while the tree state holds eight (spec 05, section 3).
  Reaching the limit needs `2^64` leaves before it.
- **L8.** `core/types/header_ghost.go:245` and `:422` (ghost-node): the
  production header decoder is not the strict reference decoder of spec 05,
  section 10 (it accepts, for example, a nine-byte block number), and the
  base client's peer sanity check bounds difficulty at 80 bits. Later
  validation rejects every such header, so no split was found; spec 05 now
  records the 80-bit bound.
- **L9.** `params/ghost/treeaccounts.go:32`, `core/ghostpriv/commit.go:107`
  (ghost-node): commits are accepted with the internal-network reserved
  addresses, while spec 05, section 12, item 2 says no commit is valid until
  the addresses are fixed. Known and documented for the internal network;
  launch values come with the transaction-format work.
- **L10.** `core/txpool/validation.go:46`, `:59` (ghost-node): the pool cannot
  admit a reveal, so the pool rules of spec 07, section 6 are not implemented
  yet. Documented in the node's `docs/private-transactions.md`.

Wallet behaviour that spec 01 and spec 07 describe but the client library
leaves to its caller, one line each, none of them a property of the chain:
the library does not itself enforce a new key per commit or claim (spec 01,
section 5); restore has no "unknown" status before receipts are checked (spec
01, section 8); reveal takes a fee from the caller instead of reading the fee
window from headers (spec 07, section 5); and a zero `out` keeps whatever
recipient the caller gave, where spec 07 says wallets use the zero address.

## 5. Specification corrections

Where the specification was wrong and the code right, the specification is
corrected in the same change as this record:

| Where | What was wrong | Correction |
|---|---|---|
| Spec 03, section 6, step 4 | Required `F` to be a canonical field element; with Keccak-256 it is a 32-byte string (spec 01, section 12, item 2 had already resolved this) | States the byte-string encoding |
| Spec 03, section 7, step 2 | Same field-element wording for public inputs | Same |
| Spec 03, section 7, step 6 | The list of bound fields omitted the statement, purpose, rule and remainder note | Lists the fields of spec 02, sections 4 and 7, in order |
| Spec 03, section 7, step 10 | Said the proof shows fresh blinding; spec 02 leaves `s'`, `r'`, `b'` free | Fresh blinding is the wallet's duty; reuse harms only its holder |
| Spec 03, CR-7 | Said the field-wrap example fails the range check; `p - 10` is in range and the integer equation rejects it | Names the integer equation (as spec 02, section 9) |
| Spec 01, section 8, step 6 | Said two unspent entries for one key need key reuse | Adds a copied commit, which shares the marker and cannot be revealed twice |
| Spec 05, section 10 | Silent on the base client's 80-bit difficulty bound for announced blocks | Records it, and why in practice it never decides a block |

Where the code is wrong and the specification right (M1, L1, L4, L6, L7), the
code is not changed in this review: each is below High, and is listed above.

## 6. Open items

No Critical or High finding is open. These findings below High leave the code
short of the specification's text, and stay open under the rule that only
Critical and High findings are fixed in a review:

- **M1** (indexed marker topic, `core/ghostpriv/reveal.go:366`) and **L6**
  (check order, `core/ghostpriv/reveal.go:317`), both in a file that work in
  progress is changing.
- **L1** (the proof library binds any version, `proofs/src/binding.rs:176`);
  the node rejects every version but 1 before verification, so the chain's
  fail-closed rule holds.
- **L4** (non-zero coin note fields restore, `client/src/note.rs:154-183`), a
  wallet decoding rule.
- **L7** (four-byte tree index in receipts, `core/ghostpriv/ghostpriv.go:162`),
  out of reach before `2^64` leaves.
- **L9** and **L10** (internal-network reserved addresses; no pool admission
  of reveals), open points the node already documents for the internal
  network, closed by the transaction-format and node-phase work.

None of them lets anyone create, double spend, redirect or link a coin, or
splits two honest nodes.

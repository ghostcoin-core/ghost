# Specification 09: quantum-safe accounts and one security target

Status: draft for the founder's review, 2026-10-20. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the [outline](../ghost-outline.md)
(founder decision "Quantum-safe everywhere GHOST is held", 2026-10-20),
[decision 0001](../decisions/0001-base-client.md),
[decision 0003](../decisions/0003-proof-system.md), the
[commitments and keys](01-commitments-and-keys.md), the
[proof statements](02-proof-statements.md), the
[private transaction](07-private-transaction.md) or the
[threat model](../threat-model.md), and is cited to it, not decided again here.
Where a figure needs a measurement (a verification cost, a gas constant, a pool
limit), this document states the rule and marks the value **set by
measurement**: the build ticket that implements the rule measures it and
records it here. Until a value is set, the check it feeds rejects (fails
closed, section 13).

Ghost launches with quantum-safe accounts and wallets, not only quantum-safe
Phantom Keys. Before this document, ordinary accounts were Ethereum's:
secp256k1 signatures, which a quantum attacker who can run Shor's algorithm
breaks, so public GHOST could be taken from any account whose public key had
appeared on the chain. This document fixes one security target for every part
of Ghost and lists each part against it (sections 3 and 4); defines the account
signature schemes by scheme ID (section 5), the account transaction that
carries them (section 6), the precompiles a contract can use (section 7), the
gas and admission rules that keep signature checks from exhausting a node
(section 8), the wallet seed that derives accounts (section 9) and the node
transport (section 10); and lists the parts of other chapters it supersedes
(section 11).

It writes no code. The node, proof, wallet and transport build tickets do.

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Security target | At least NIST Category 1 for every component, counted as in section 3, classically and against a quantum attacker | Founder decision, 2026-10-20; counting rules **Proposed** |
| Account scheme at launch | ML-DSA-44 (FIPS 204), pure mode, scheme ID `0x0001` | Founder decision; ID **Proposed** |
| Second scheme | SLH-DSA-SHAKE-128s (FIPS 205), pure mode, scheme ID `0x0002`, accepted from genesis | Founder decision (defined by scheme ID); acceptance from genesis **Proposed** (question 2) |
| Refused schemes | Every unknown or reserved scheme ID; every stateful or one-time signature scheme; every elliptic-curve scheme | Founder decision |
| Account transaction | New EIP-2718 type `0x52` carrying scheme ID, public key and signature; canonical RLP | Founder decision; type byte front desk decision (question 6) |
| Sender | First 20 bytes of a domain-separated hash of (scheme ID, public key); no key registry | Founder decision; tag **Proposed** |
| Legacy transactions | Types `0x00` to `0x04` (every secp256k1 type) refused from genesis; the native reveals `0x50` (coin) and `0x51` (data) stay | Founder decision; spec 07 |
| Addresses | 20 bytes, unchanged; spec 02's `recipient` and spec 06's `coinbase` keep their width | Front desk decision (section 4.3) |
| Precompiles | ecrecover, BN254, the BLS12-381 point evaluation removed; BLS12-381 and P-256 never added; one signature-verify precompile added at `0x51` | Founder decision; address **Proposed** |
| Gas | Signature bytes in intrinsic gas at 16 gas per byte; a verification charge per scheme, set by measurement | Founder decision; byte price **Proposed** |
| Admission | Cheap checks first, bounded checks in flight, per-peer and RPC budgets, disconnect on an invalid signature | Founder decision; limits set by measurement |
| Wallet keys | A 256-bit wallet seed, shown as words, deriving account keys by hashing; never derived from or into Phantom Key digits | Founder decision; encoding **Proposed** |
| Transport | Hybrid X25519 + ML-KEM-768 handshake, ML-DSA-44 node identities, a node record that fits the larger keys | Founder decision; formats **Proposed** |
| Reveal proof | Today's configuration does not meet the target under a quantum Fiat–Shamir argument with any margin; the proof build ticket raises it by the rule of section 4.1 | **Proposed** rule; parameters set by measurement |
| Phantom Key length | The 12-group key (about 146 bits) meets the target against one key, not against all keys at once; 14 groups proposed | **Proposed** (question 1); spec 01 unchanged until decided |

## 2. Conventions and parameters

The conventions of [spec 01](01-commitments-and-keys.md), section 2 apply:
`K(tag, ...)` is tagged Keccak-256, `S(tag, ...)` is tagged SHA3-256,
`tagbytes(tag)` is the tag's length byte followed by its ASCII, integers are
unsigned big-endian at the stated width, and "reject" means the value or
transaction is invalid and changes no state. In addition:

- **`X(tag, n, x1, x2, ...)`** is SHAKE256 (FIPS 202) over
  `tagbytes(tag) || x1 || x2 || ...`, with `n` bytes of output.
- **Bits.** "`b` bits classical" means the best known classical attack costs
  about `2^b` evaluations of the primitive. "`b` bits quantum" means the best
  known quantum attack needs about `2^b` sequential quantum evaluations
  (Grover iterations or oracle queries), counted with no depth limit and no
  error-correction overhead. This is stricter than NIST's own accounting, which
  limits circuit depth (MAXDEPTH); a component that passes here passes there.
- **Scheme ID.** The 2-byte identifier of an account signature scheme
  (section 5). It is a different number space from the commitment scheme ID of
  spec 01, section 10, which names the commitment, derivation and note scheme.
- **Genesis hash.** The hash of this chain's genesis block, the `domain` of
  spec 02, section 2.
- **Uncertain means rejected,** as in spec 07, section 2: every check answers
  "yes" only on positive evidence.

**Parameters.**

| Name | Value | Meaning |
|---|---|---|
| `ACCOUNT_TX_TYPE` | `0x52` | EIP-2718 type of the account transaction (front desk decision, question 6) |
| `SIG_BYTE_GAS` | 16 | Gas per byte of scheme ID, public key and signature, the base client's price of a non-zero calldata byte (EIP-2028), as spec 07's `BYTE_GAS` (**Proposed**) |
| `GAS_PER_MS` | 10,000 | Spec 07, section 4: 30,000,000 gas mapped onto a 3,000 ms verification budget per block |
| `VERIFY_GAS[0x0001]` | Set by measurement | Gas for one ML-DSA-44 verification (section 8.2) |
| `VERIFY_GAS[0x0002]` | Set by measurement | Gas for one SLH-DSA-SHAKE-128s verification (section 8.2) |
| `SIGVERIFY_PRECOMPILE` | `0x0000000000000000000000000000000000000051` | The signature-verify precompile (**Proposed**, section 7) |
| `TX_MAX_BYTES` | The base client's per-transaction pool cap (128 KiB in go-ethereum's pool) | Largest account transaction the pool admits (section 8.3) |
| `MSG_MAX_BYTES` | 10 MiB (10,485,760 bytes) | The base client's cap on one `eth` protocol message |
| `NODE_RECORD_MAX` | 4,096 bytes | Largest node record (**Proposed**, section 10.3) |

## 3. The security target

**Target.** Every component of Ghost meets at least **NIST Category 1**: no
attack on it, classical or quantum, costs less than a key search on a block
cipher with a 128-bit key (AES-128). In the bits of section 2 a component meets
the target when its best known attack costs:

- at least 128 bits classical, and
- at least 64 bits quantum (Grover's search over 2^128 keys needs about 2^64
  iterations), and
- both of these **after the reduction an attacker gets from many targets**,
  wherever the attacker can attack many at once (every leaf on the chain, every
  funded address), counted for the largest number of targets the chain can
  hold. Where the speedup over many targets needs a quantum random-access
  memory, the figure is given both with and without it, and the target is
  checked against the figure with it.

One target is used everywhere, so no part of the system is the cheap way in.
A component that exceeds it (ML-DSA-44 is Category 2, ML-KEM-768 Category 3) is
not lowered to it. A component below it is either raised, or stated in the
threat model as an exception with the reason it does not matter where it is
used; section 4 lists both kinds.

**Collisions.** A 256-bit hash has 128 bits classical collision resistance
(NIST Category 2) and about 85 bits quantum (the Brassard–Høyer–Tapp search,
`2^(n/3)`, with as much quantum memory). A component that needs collision
resistance uses a 256-bit hash. The 20-byte address is the one exception
(section 4.3).

**What the target does not cover.** Mining is not a secrecy target: a quantum
speedup on RandomX is a question of mining power (threat model, A4), not of
this target. Cryptography that a contract implements in its own bytecode is
its author's (section 7). Web certificates are outside the chain (section 10.5).

## 4. Every component against the target

| Component | Today | Classical | Quantum | Against the target | What changes |
|---|---|---|---|---|---|
| Account signatures | ECDSA over secp256k1 (base client) | 128 bits | Broken (Shor) | Below | ML-DSA-44 (Category 2) and SLH-DSA-SHAKE-128s (Category 1); every secp256k1 type refused (sections 5 and 6) |
| Reveal STARK: queries and grinding | Rate 1/4, 57 queries, 16 grinding bits (decision 0003) | 128 conjectured, 72 proven | About 65 conjectured, about 36 proven (section 4.1) | Conjectured at the floor with no margin; proven below | Raised by the rule of section 4.1 |
| Reveal STARK: hash output | Keccak-256 digests in the Merkle commitments and the Fiat–Shamir transcript | 128 bits collision | About 85 bits collision; the quantum Fiat–Shamir hash term holds to about 2^85 queries | Meets | Nothing |
| Reveal STARK: challenge field | Degree-5 extension of BabyBear, about 2^155 elements | Each field term near or below 2^-128 by a rough count | Half of that | At the floor; the build ticket computes it | Section 4.1 |
| Reveal STARK: hiding | Hiding FRI, 5 random columns, 5 salt elements per opened row (about 155 bits) | Statistical for the masked openings; 155 bits for a salt | About 77 bits for a salt | Meets | Nothing |
| Tree and commitment hashes | Tagged Keccak-256 (spec 01) | 256 preimage, 128 collision | 128 preimage, about 85 collision | Meets | Nothing |
| Derivation and checksum hash | Tagged SHA3-256 (spec 01) | 256 preimage, 128 collision | 128 preimage, about 85 collision | Meets | Nothing |
| Phantom Key | 12 groups, about 146 bits (spec 01) | 146 bits against one key; about 113 against all leaves | 73 bits against one key; about 56 against all leaves with a quantum memory | Meets against one key; below against all at once | 14 groups proposed (section 4.2, question 1) |
| Note key and data key | 256-bit keys derived from the digits; ChaCha20-Poly1305 | 256 bits on the key, bounded by the digits | 128 bits on the key, bounded by the digits | As the Phantom Key | Follows the Phantom Key |
| Addresses | 20 bytes | 160 preimage, 80 collision | About 2^80 preimage, about 2^53 collision | Preimage meets; collision below | Unchanged; the collision gap is stated (section 4.3) |
| Wallet seed | None today | 256 bits | 128 bits | Meets | New (section 9) |
| Node transport key exchange | RLPx, secp256k1 ECIES | 128 bits | Broken (Shor) | Below | Hybrid X25519 + ML-KEM-768 (section 10.1) |
| Node identities and records | secp256k1 keys, ENR and discovery signatures | 128 bits | Broken (Shor) | Below | ML-DSA-44 (sections 10.2 and 10.3) |
| Session encryption | 256-bit symmetric keys | 256 bits | 128 bits | Meets | Keys come from the hybrid exchange |
| Release and installer signatures | Not fixed (outline, "Launch", "Maintenance") | Depends on the scheme | Depends on the scheme | Not fixed | SLH-DSA-SHAKE-128s (section 10.4) |
| Web app delivery | HTTPS with classical certificates | 128 bits | Authentication broken (Shor) | Below; outside the chain | Authenticated delivery of the build (section 10.5) |
| Contract-level cryptography | ecrecover, BN254 and others as precompiles | Varies | Elliptic-curve parts broken | Below | Removed; a contract's own cryptography is its author's risk (section 7) |

### 4.1 The reveal STARK, with a quantum Fiat–Shamir argument

The reveal proof is a Plonky3 STARK: an interactive oracle proof (the AIR
checked through DEEP-ALI and the FRI low-degree test) made non-interactive by
committing to every oracle with a Merkle tree and deriving every challenge from
a hash of the transcript (the Fiat–Shamir transformation in the form of
Ben-Sasson, Chiesa and Spooner, "BCS"). Decision 0003 reports two classical
figures: 128 conjectured bits and 72 proven bits. Neither is a quantum figure.

**Classical.** An attacker who makes `t` hash queries breaks a BCS proof with
probability about `t * e`, where `e` is the protocol's round-by-round
soundness error (the worst chance of one lucky round). The bits are
`-log2(e)`.

**Quantum.** Chiesa, Manohar and Spooner (TCC 2019) prove the BCS
transformation sound in the quantum random oracle model: an attacker who makes
`t` quantum queries succeeds with probability at most about
`t^2 * e + t^3 / 2^L`, where `L` is the hash output in bits. The bound is
matched by the obvious attack, a Grover search over transcripts for a lucky
challenge, which takes about `sqrt(1/e)` queries. So:

- the quantum bits are about **half** the round-by-round bits: Category 1
  (64 quantum bits) needs every round's error at most 2^-128;
- the hash term needs `t^3` well below `2^L`; with Keccak-256 (`L = 256`) it
  holds up to about 2^85 queries, so the hash is not the limit;
- **grinding counts half.** A `g`-bit proof of work adds `g` classical bits but
  only `g/2` quantum bits, because Grover finds a grinding nonce in about
  `2^(g/2)` evaluations.

**Today's configuration** (decision 0003: rate 1/4, 57 queries, 16 grinding
bits on the queries, a degree-5 extension of BabyBear for challenges,
Keccak-256):

| Term | Classical bits | Quantum bits |
|---|---|---|
| Queries, conjectured (2 bits per query at rate 1/4) | 114 | 57 |
| Queries, proven (about 1 bit per query, the Johnson bound) | 57 | 28.5 |
| Grinding | 16 | 8 |
| Query phase, conjectured, with grinding | 130, quoted as 128 | About 65 |
| Query phase, proven, with grinding | 73, quoted as 72 | About 36 |
| Extension-field terms (DEEP, batching, folding) | Near 2^-128 to 2^-141 per term by a rough count (about 3,800 columns batched over a 2^14-point domain in a field of about 2^155) | About half: 64 to 70 |
| Hash term | Not the limit | Not the limit up to about 2^85 queries |

So the conjectured quantum figure, about 65 bits, sits on the 64-bit floor
with grinding doing part of the work and no margin, and the proven figures are
far below it. The proof does not meet the target with the margin a target
needs.

**Rule (Proposed).** The configuration that ships meets all of:

1. **Queries alone reach 128 conjectured bits:** `log2(1/rate) * queries` is at
   least 128 without grinding, so the conjectured quantum figure is at least 64
   before grinding is counted. Grinding is margin, counted at half.
2. **Every extension-field term is at most 2^-128,** computed with the
   library's estimator for the shipped trace size, number of columns and
   constraint degree, not by the rough count above. If any term is larger, the
   challenge field moves to a larger extension of BabyBear, or the batching
   uses independent challenges, before the configuration ships.
3. **The hash is Keccak-256** with 256-bit digests in every Merkle commitment
   and in the transcript.
4. **Hiding stays on** (outline, "Privacy mode on"), with salts of at least 128
   bits, so a quantum attacker who records proofs today and searches later
   gets at least 64 bits against a salt.
5. **Both figures are stated** wherever a figure is quoted: conjectured and
   proven, classical and quantum. The proven quantum figure is a goal, not a
   gate (question 3).
6. **The prover's security gate** refuses a configuration that breaks items 1
   to 4, as it already refuses a trace over budget (spec 07, section 3), and a
   test fails if the shipped configuration breaks them.

Candidates the proof build ticket measures, by the arithmetic of the table
above (proof size and proving time are set by measurement):

| Rate | Queries | Grinding | Conjectured classical / quantum | Proven classical / quantum |
|---|---|---|---|---|
| 1/4 (today) | 57 | 16 | 130 / 65 | 73 / 36 |
| 1/4 | 64 | 16 | 144 / 72 | 80 / 40 |
| 1/8 | 43 | 16 | 145 / 72 | 80 / 40 |
| 1/8 | 86 | 16 | 274 / 137 | 145 / 72 |

Decision 0003 already measured blowup 2^3 (rate 1/8): smaller proofs than
rate 1/4 and about 1.6 times the proving time, within the 10-second target.
A change of proof length changes spec 07's `PROOF_BYTES`, which follows
spec 07's version rule (question 4).

### 4.2 Phantom Keys

A standard Phantom Key has 44 secret digits, about 146 bits (spec 01,
section 5). An attacker who guesses digits derives `s`, `r` and `b_0` and
compares the fingerprint with every fingerprint ever published, so one guess
tests every key on the chain at once. With both trees full, about 2^33 leaves:

| Key | Secret | One key, classical / quantum | All leaves, classical | All leaves, quantum, with / without quantum memory |
|---|---|---|---|---|
| 12 groups (today) | About 146 bits | 146 / 73 | About 113 | About 56 / about 73 |
| 14 groups (proposed) | 52 digits, about 172 bits | 172 / 86 | About 139 | About 70 / about 86 |
| 24 groups (spec 01 long key) | About 292 bits | 292 / 146 | About 259 | About 129 / about 146 |

Without a quantum memory, Grover over many targets gains little in total work
(Banegas and Bernstein, 2017), so the 12-group key keeps about 73 quantum
bits in practice. The classical figure over all leaves, about 113 bits, is
below the target whatever the quantum model, and the quantum figure with a
quantum memory is below it too. Thirteen groups (48 secret digits, about 159
bits) still falls short over all leaves (about 126 classical); fourteen groups
is the shortest that meets the target, with about 11 bits of room for later
trees after a rollover.

**Proposed** (question 1): the standard key becomes fourteen groups, thirteen
of secret digits and one checksum, a new key format code under spec 01,
section 10. Until the founder decides, spec 01's twelve-group key stands and
the threat model (C20) states the gap. The note key and data key are 256 bits
long but derived from the digits, so they are exactly as strong as the digits
and need no change of their own.

### 4.3 Addresses

Addresses stay 20 bytes (front desk decision). Making them longer would break
the EVM, every contract that stores an address, and every tool that reads one.

- **Preimage.** Finding a public key whose address is a given funded address
  costs 2^160 classical and about 2^80 quantum (Grover). Over 2^32 funded
  addresses at once, with a quantum memory, about 2^64: at the floor. An
  account whose public key has never appeared on the chain is protected by
  this hash as well as by its signature scheme.
- **Collision.** Finding two inputs with one address costs about 2^80
  classical (birthday search) and about 2^53 quantum
  (Brassard–Høyer–Tapp). This is below the target. It matters only where two
  parties agree on an address **before it is funded** and one of them chooses
  the inputs of one side: for example a CREATE2 address that a counterparty
  computes in advance from code the other party supplies, or a counterfactual
  wallet. An attacker searches for an account key whose address equals such a
  CREATE2 address, waits for the funding, and spends it with the key before or
  instead of deploying the contract.
- **Where Ghost depends on it.** Nowhere in consensus. A transaction's sender
  is fixed by the public key and the signature, not by the address alone
  (section 6). Spec 02's `recipient` is chosen by the holder, who has no reason
  to collide with themselves. The rule of EIP-3607 stays: a transaction whose
  sender has code is rejected.
- **Wording for users and contract authors.** Do not fund an address you have
  not seen deployed, or that someone else could have chosen inputs for; bind a
  pre-agreed destination with a 32-byte hash of the full init code and
  deployer, not with the address alone.

Spec 02's `recipient` (20 bytes, offset 143 of the coin reveal binding) and
spec 07's payload are unchanged; spec 02 records the confirmation.

## 5. Account signature schemes

A **scheme ID** names one complete signature scheme: the algorithm, the full
parameter set, the signing mode, the encoding of public keys and signatures,
and the context string used for transactions. Nothing about a scheme is
negotiated or read from the signature itself.

| Scheme ID | Scheme | Mode | Public key | Signature | NIST category | Status |
|---|---|---|---|---|---|---|
| `0x0000` | Reserved | | | | | Refused |
| `0x0001` | ML-DSA-44 (FIPS 204) | Pure ML-DSA (FIPS 204, algorithms 2 and 3), not HashML-DSA | 1,312 bytes | 2,420 bytes | 2 | Accepted from genesis; the wallet default |
| `0x0002` | SLH-DSA-SHAKE-128s (FIPS 205) | Pure SLH-DSA (FIPS 205, algorithms 22 and 24), not HashSLH-DSA | 32 bytes | 7,856 bytes | 1 | Accepted from genesis (**Proposed**, question 2) |
| Every other value | Unassigned | | | | | Refused |

**Rules.**

- **Exact lengths.** A public key or signature of any length other than its
  scheme's is rejected before any verification. The encodings are the FIPS
  byte strings, unmodified.
- **Unknown or reserved means refused,** in the pool, in a block, in the
  precompile and in the wallet. A node never guesses a scheme from a length.
- **Context string.** Both FIPS schemes take a context string of up to 255
  bytes. A transaction signature uses the context `ghost/tx/v1` (11 ASCII
  bytes). The precompile refuses any context that begins with `ghost/tx/`
  (section 7), so no contract that uses it can accept a transaction signature
  as a signature over its own message.
- **Signing randomness.** Wallets use the hedged variant of each scheme (fresh
  randomness mixed with the key), which FIPS 204 and 205 make the default.
  Verification is the same for hedged and deterministic signatures, so the
  scheme ID does not distinguish them; a signature is valid if it verifies.
- **Why SLH-DSA too.** ML-DSA rests on module lattices; SLH-DSA rests only on
  hash functions, the assumption the rest of Ghost already makes (threat model,
  A1). Accepting it from genesis lets a holder who distrusts lattices choose
  it, and gives every account a scheme to move to if ML-DSA is weakened, at
  about three times the signature bytes and a higher verification charge. The
  small variant (`128s`) is chosen over the fast one (`128f`, 17,088-byte
  signatures) because chain bytes cost more than signing time.
- **Refused for good.** Stateful hash-based schemes (XMSS, LMS) and one-time
  schemes (Lamport, WOTS on their own): their security fails if a state is
  reused, which happens when a wallet is restored from its seed on a second
  device, and the chain cannot detect it. Every elliptic-curve scheme
  (secp256k1, P-256, Ed25519, BLS12-381, BN254), since a quantum attacker
  breaks them.
- **New schemes.** A new parameter set or mode gets a new scheme ID, added at a
  set block height by the usual upgrade (outline, "Upgrades and incidents").
  A scheme ID is never reused with a different meaning. No upgrade disables a
  scheme that holds funds unless the same or an earlier upgrade lets those
  accounts move to another scheme, the rule spec 01, section 10 states for
  commitments.

## 6. The account transaction

Every public action from an account (a transfer, a contract call, a contract
creation, a commit) is an account transaction. It is a new EIP-2718 typed
transaction:

```text
tx = 0x52 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                 gas_limit, to, value, data, access_list,
                 scheme, public_key, signature])
```

| Field | Encoding | Meaning |
|---|---|---|
| `chain_id` | RLP integer | This chain's identifier, the value spec 02 carries as 8 bytes |
| `nonce` | RLP integer | The sender's account nonce, as in Ethereum |
| `max_priority_fee_per_gas`, `max_fee_per_gas` | RLP integers | The fee limits of EIP-1559 |
| `gas_limit` | RLP integer | At least the intrinsic gas of section 8.1 |
| `to` | 20-byte string, or empty for a contract creation | Destination |
| `value` | RLP integer | Wei transferred |
| `data` | Byte string | The calldata, or the init code of a creation |
| `access_list` | As EIP-2930 | Kept from the base client's type `0x02` |
| `scheme` | 2-byte string | The scheme ID of section 5 |
| `public_key` | Byte string of the scheme's exact length | The sender's public key |
| `signature` | Byte string of the scheme's exact length | The signature over `sighash` below |

There are no blob fields (decision 0001: blob transactions are off), no
authorization list, and no `v`, `r` or `s`.

**Canonical encoding.** One transaction has one encoding. The RLP is decoded
strictly: integers have no leading zero bytes (zero is the empty string),
lengths use the shortest form, single bytes below `0x80` are not wrapped, the
list has exactly twelve items, and nothing follows it. `scheme`, `public_key`
and `signature` have their exact widths. Anything else is rejected.

**What the signature binds.**

```text
unsigned = rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                gas_limit, to, value, data, access_list, scheme, public_key])
sighash  = K("ghost/account-tx/v1", 0x52, genesis_hash, keccak256(unsigned))
signature = Sign(secret_key, message = sighash, context = "ghost/tx/v1")
```

The signature therefore binds the transaction type, the chain (by identifier
and by genesis hash, so a copy of the chain that keeps the identifier still
gets different signatures), the nonce, the destination, the value, the
calldata, the fee limits and gas limit, the access list, and the exact scheme
and public key. A signature made for one scheme cannot be presented under
another: the scheme ID is inside the signed message and fixes the lengths.

**Sender.**

```text
sender = first 20 bytes of K("ghost/account-address/v1", scheme, public_key)
```

A domain-separated hash of the scheme ID and the public key, 20 bytes. The tag
is used for nothing else, so no other hash in Ghost (a commitment, a CREATE or
CREATE2 address, which hash without it) can be passed off as an account
address. There is **no key registry**: every transaction carries its public
key, and the node derives the sender from it each time. That costs the public
key's bytes in every transaction (section 8.1) and keeps the state free of key
records, rotation rules and a first-use special case.

**Hash.** The transaction hash is `keccak256(0x52 || rlp([...]))` over the
whole envelope, signature included, as for every typed transaction. Hedged
signing gives one transaction several valid signatures and so several hashes;
the pool keeps at most one transaction per sender and nonce, with the base
client's replacement rule, so this changes nothing.

**Order of checks.** The node checks an account transaction in this order, in
the pool and in a block, and stops at the first failure:

1. The type byte is `0x52`. Types `0x00` (legacy, with or without EIP-155),
   `0x01` (EIP-2930), `0x02` (EIP-1559), `0x03` (EIP-4844) and `0x04`
   (EIP-7702), every type the base client signs with secp256k1, are rejected
   from genesis. Types `0x50` and `0x51`, the native coin and data reveals,
   have no account and no signature and are checked by spec 07 instead; they
   stay. Every other type byte except `0x52` is rejected.
2. The envelope is at most `TX_MAX_BYTES` and decodes canonically.
3. `scheme` is a scheme accepted at this height, and `public_key` and
   `signature` have its lengths.
4. `chain_id` is this chain's.
5. The sender is derived; it has no code (EIP-3607); the nonce, the balance
   against `gas_limit * max_fee_per_gas + value`, and the intrinsic gas against
   `gas_limit` are checked as the base client checks them.
6. The signature verifies under the scheme, over `sighash`, with the context
   `ghost/tx/v1`. This is last because it is the most expensive check.

A block holding a transaction that fails any step is invalid. The node's
sender recovery (ecrecover over `v`, `r`, `s`) is replaced by step 5's
derivation; there is no elliptic-curve code on this path.

**Commit.** A commit is an account transaction to the commit entry point
(spec 03, section 6); its step 1, "ordinary transaction validity", is this
section.

**Genesis.** The genesis allocation is empty (spec 06, section 7), so no
account exists that was made under another scheme, and none needs migrating.

**JSON-RPC.** `eth_sendRawTransaction` accepts type `0x52`. Methods that sign
with a key held by the node (`eth_sign`, `eth_sendTransaction`,
`personal_*`) use secp256k1 keystores in the base client and are removed.
Responses show `scheme` and `public_key` and derive `from` as above.

## 7. Precompiles and contracts

| Address | In Ethereum (Cancun and later) | In Ghost |
|---|---|---|
| `0x01` | ecrecover (secp256k1) | **Removed** |
| `0x02` | SHA-256 | Kept |
| `0x03` | RIPEMD-160 | Kept (a 160-bit hash: collisions at about 2^80 classical and 2^53 quantum are the calling contract's concern) |
| `0x04` | Identity | Kept |
| `0x05` | modexp | Kept, as general arithmetic |
| `0x06`, `0x07`, `0x08` | BN254 addition, multiplication, pairing | **Removed** |
| `0x09` | BLAKE2 compression | Kept |
| `0x0a` | KZG point evaluation (BLS12-381, EIP-4844) | **Removed** (blobs are off, decision 0001) |
| `0x0b` to `0x11` | BLS12-381 operations (EIP-2537) | Never added |
| `0x100` | P-256 verification (EIP-7951, RIP-7212) | Never added |
| `0x51` | None | **Added:** signature verification (**Proposed** address) |

**Removed addresses fail.** Each removed address stays reserved as a precompile
that always fails: a call to it returns failure and uses all the gas given to
it, as a precompile does on invalid input, it cannot receive value, and it
keeps the precompile's warm status under EIP-2929. A contract that still calls
ecrecover gets a failed call, not an empty success that a careless contract
might read as the zero address.

**The signature-verify precompile.** Input:

```text
scheme (2) || ctx_len (1) || ctx (ctx_len bytes) || public_key || signature || message
```

with `public_key` and `signature` at the exact lengths of `scheme` and the
message being every remaining byte.

- **Output.** 32 bytes: `1` if the signature verifies over `message` with
  context `ctx`, `0` if it does not.
- **Failure** (the call fails and uses all its gas): an unknown, reserved or
  not yet accepted scheme ID; input shorter than its fixed parts; a context
  that begins with `ghost/tx/`.
- **Gas.** `VERIFY_GAS[scheme] + SIGVERIFY_WORD_GAS * ceil(len(message) / 32)`,
  charged before verifying, whether or not the signature verifies. Both
  constants are set by measurement (section 8.2).
- **Address.** A contract that wants the signer's address computes
  `K("ghost/account-address/v1", scheme, public_key)` with the `KECCAK256`
  opcode over `tagbytes || scheme || public_key` and takes the first 20 bytes;
  no second precompile is needed.

**Threat model statement.** The chain makes no claim about cryptography that a
contract implements in its own bytecode. A contract that checks secp256k1 or
any other elliptic-curve signature in EVM code, or RSA signatures through
modexp, is exactly as safe as that scheme, which a quantum attacker breaks,
and that is its author's risk. Patterns that depend on ecrecover (EIP-2612
permits, EIP-712 signed orders, EIP-1271 checks that end in ecrecover) must
use the signature-verify precompile instead. The [threat model](../threat-model.md)
carries this statement (section 2 and C35).

## 8. Gas and admission

### 8.1 Intrinsic gas

```text
intrinsic_gas(tx) = base_intrinsic_gas(tx)
                  + SIG_BYTE_GAS * (2 + len(public_key) + len(signature))
                  + VERIFY_GAS[scheme]
```

`base_intrinsic_gas` is the base client's intrinsic gas for the same fields as
a type `0x02` transaction: 21,000, the calldata price of EIP-2028 (4 gas per
zero byte, 16 per non-zero byte), the creation charge and EIP-3860 init-code
words, and the access list. The scheme ID, public key and signature bytes are
priced at 16 gas each whatever their value, as spec 07 prices the reveal,
because the chain stores every byte.

| Scheme | Signature bytes | Byte gas | Smallest transaction |
|---|---|---|---|
| `0x0001` ML-DSA-44 | 2 + 1,312 + 2,420 = 3,734 | 59,744 | 80,744 + `VERIFY_GAS[0x0001]` |
| `0x0002` SLH-DSA-SHAKE-128s | 2 + 32 + 7,856 = 7,890 | 126,240 | 147,240 + `VERIFY_GAS[0x0002]` |

At the default gas limit of 30,000,000 (spec 05, question 1) a block holds at
most 371 ML-DSA-44 transfers, about 1.4 MB, instead of about 1,428 Ethereum
transfers. That is the cost of quantum-safe signatures with no key registry.

### 8.2 Verification cost as consensus constants

`VERIFY_GAS[scheme]` and `SIGVERIFY_WORD_GAS` are consensus constants, fixed in
the frozen software, derived from measurements by the same rule as spec 07's
`VERIFY_GAS`:

```text
VERIFY_GAS[scheme] = ceil(t_ms * GAS_PER_MS)
```

where `t_ms` is the slowest of at least 1,000 verifications in milliseconds,
measured in the node's own verifier on the reference node hardware, over valid
and invalid signatures (an invalid signature must not be cheaper to refuse in
a way an attacker can exploit, nor dearer than the charge). The node build
ticket measures it and records the value here with the hardware, the library
and its pinned version. Because a block's gas maps onto spec 07's 3,000 ms
budget, a block full of signatures stays within that budget by construction.
Until a scheme's constant is set, the node accepts no transaction of that
scheme (section 13).

### 8.3 Admission: invalid signatures cannot exhaust a node

Anyone can copy a funded account's public key from an earlier transaction, so
a transaction that passes steps 1 to 5 of section 6 can still carry a junk
signature. The pool bounds what that costs.

1. **Cheap checks first.** Steps 1 to 5 of section 6 (type, size, encoding,
   scheme and lengths, chain, sender, code, nonce, balance, intrinsic gas) run
   before any signature is verified. A transaction already known by hash, or
   whose `sighash` and public key already failed verification, is dropped
   without verifying again (a bounded cache of recent failures).
2. **Input size.** An account transaction above `TX_MAX_BYTES` is dropped
   unread. The reveal keeps spec 07's own limits.
3. **Checks in flight.** Signature verification runs in a bounded worker pool
   with a bounded queue. When the queue is full, new transactions from peers are
   dropped, not queued without limit, and RPC submissions get a busy error.
   Peers and local RPC have separate shares of the queue, so neither can
   starve the other. The worker count and queue length are set by measurement.
4. **Per-peer budget.** Each peer has a budget of signature verifications per
   second, set by measurement; transactions over it are dropped unverified.
   Announced hashes are fetched only within the budget.
5. **Disconnect on an invalid signature.** An honest node verifies before it
   relays, and a signature's validity does not change with the chain state, so
   a peer that sends a transaction whose signature fails is misbehaving and is
   disconnected. A state failure (a stale nonce, a spent balance) is not
   misbehaviour and is not penalised. A transaction whose scheme becomes
   accepted at an upgrade height is not relayed before that height.
6. **RPC budget.** Each RPC connection, and the RPC interface as a whole, has a
   budget of verifications per second, set by measurement.
7. **Blocks.** A block's signatures are checked only after its seal (spec 08)
   and header checks pass, so making a node verify a block's signatures costs a
   valid proof of work. Signatures in a block may be verified in parallel.

The worst case a hostile peer can force is its per-peer budget until its
first invalid signature, and then a disconnect; the worst case from all peers
together is the worker pool's capacity, which is fixed.

### 8.4 Throughput against the 10 MiB message cap

The base client's `eth` protocol refuses any message over 10 MiB
(10,485,760 bytes). A block that cannot be sent in one message cannot spread.
The cheapest byte in a block is a zero calldata byte at 4 gas (signature and
reveal bytes cost 16), so a block's transaction bytes are at most
`gas_limit / 4`:

| Block gas limit | Largest transaction bytes | Fits under 10 MiB |
|---|---|---|
| 30,000,000 (default) | 7,500,000 (about 7.2 MiB) | Yes, with room for headers and RLP |
| 41,943,040 | 10,485,760 | No margin left |

So the rule is: **the block gas limit must stay below 41,943,040 minus the
header and RLP overhead,** or the price of a zero
byte must rise, or block propagation must split messages. Miners can move the
gas limit by 1/1024 per block, so this needs a consensus maximum, which belongs
to spec 05 (question 5). Signature bytes do not move the bound, because they
are dearer per byte than zero calldata. The node build ticket adds a test that
builds the block with the most bytes at the largest allowed gas limit and
checks that every message carrying it (a new block, a block bodies response)
is under 10 MiB, and that a pooled transactions message of `TX_MAX_BYTES`
transactions is too.

## 9. Wallet keys

A wallet holds accounts; a Phantom Key holds a commitment. The two never derive
each other: handing someone a bearer key must never hand them an account, and
an account's backup must never be a bearer key.

**Seed (Proposed).** A wallet seed is 32 bytes from a secure random source
(256 bits: 2^256 classical, 2^128 quantum). It is shown and backed up as 24
words of the BIP-39 English word list, which encode the 256 bits and an 8-bit
checksum. Only the word list and checksum are used: the seed is the 32 bytes
themselves, with no PBKDF2 stretching and no passphrase (the words are random,
not chosen by a person, and the outline refuses passphrase variants of keys).
A Ghost seed typed into an Ethereum wallet derives secp256k1 keys that Ghost
refuses, so it cannot be used by mistake on the wrong chain.

**Derivation.** Every account key is a hash of the seed, the scheme ID and an
account index:

```text
key_seed(scheme, i) = X("ghost/wallet-account/v1", n, seed, scheme, i as 4 bytes)
```

- ML-DSA-44 (`0x0001`): `n = 32`, and the key pair is
  `ML-DSA.KeyGen_internal(key_seed)` (FIPS 204, algorithm 6).
- SLH-DSA-SHAKE-128s (`0x0002`): `n = 48`, split into `SK.seed`, `SK.prf` and
  `PK.seed` of 16 bytes each, and the key pair is `slh_keygen_internal`
  (FIPS 205, algorithm 18).

Every index is hardened by construction: there is no public derivation (no
extended public key), because hash-based derivation has none. A watch-only
wallet is given the list of addresses, not a key that derives more. The scheme
is in the hash, so one index under two schemes gives unrelated keys. Signing
keeps no state (section 5), so a seed restored on two devices is safe.

**Separation from Phantom Key digits.**

1. **No derivation either way.** A Phantom Key is generated fresh from a secure
   random source for each commit (outline, "Phantom Keys"; spec 01), never from
   the wallet seed. No account key is derived from digits. The wallet tags
   (`ghost/wallet-*`) and the digit tags of spec 01 are disjoint.
2. **Different alphabets.** Digits are groups of four decimal digits; a seed is
   words. A wallet refuses digits in the seed field and words in the key field,
   so neither can be entered as the other.
3. **Different screens.** Summon and Claim ask only for digits; restoring a
   wallet asks only for words. No screen asks for both.
4. **What a Phantom Key gives away.** The holder of the digits can reveal the
   commitment to any address and read its note (threat model, T6). They learn
   nothing about the account that funded the commit beyond what the commit
   transaction already shows to everyone.

## 10. Transport

### 10.1 Handshake

The node's peer-to-peer handshake (RLPx in the base client, an ECIES exchange
over secp256k1) is replaced by a hybrid key exchange (**Proposed** layout; the
transport build ticket fixes the bytes):

1. The initiator sends an ephemeral X25519 public key (32 bytes) and an
   ephemeral ML-KEM-768 encapsulation key (FIPS 203, 1,184 bytes).
2. The responder sends its ephemeral X25519 public key and an ML-KEM-768
   ciphertext (1,088 bytes) encapsulated to the initiator's key.
3. Both compute
   `k = S("ghost/p2p-kex/v1", ss_mlkem, ss_x25519, transcript_hash)`,
   where `transcript_hash` covers both X25519 keys, the encapsulation key and
   the ciphertext, and expand `k` into one 256-bit key per direction with
   `X`. The key is secret as long as either X25519 (against a classical
   attacker) or ML-KEM-768 (against both) holds.
4. Under those keys each side sends its scheme ID, its node public key and an
   ML-DSA-44 signature over `transcript_hash` with the context
   `ghost/p2p-handshake/v1`. The initiator checks that the responder's public
   key hashes to the node ID it dialled. Identities travel encrypted, so a
   passive observer does not learn them.
5. Frames use an AEAD with 256-bit keys (ChaCha20-Poly1305 or AES-256-GCM,
   fixed by the build ticket) and a counter nonce per direction, with a rekey
   before the counter's bound.

A responder does one encapsulation and one signature check per handshake.
Pending handshakes, handshakes per source address per second, and the time a
handshake may take are bounded, with limits set by measurement.

### 10.2 Node identity

A node identity is an ML-DSA-44 key pair, generated at random by the node (not
from any wallet seed). The node ID is `K("ghost/node-id/v1", scheme,
public_key)`, 32 bytes, used for the discovery table's distances as the base
client uses the hash of its secp256k1 key.

### 10.3 Discovery and node records

The base client's node records (ENR, at most 300 bytes) and discovery packets
(at most 1,280 bytes over UDP) are signed with secp256k1 and cannot hold an
ML-DSA-44 public key and signature (3,732 bytes together). **Proposed:**

- **Node record:** `rlp([seq, scheme, public_key, ip, tcp_port, udp_port,
  fork_id, signature])`, signed by the node key over
  `K("ghost/node-record/v1", rlp of the fields before the signature)`, at most
  `NODE_RECORD_MAX` (4,096) bytes. A record of a larger size, an unknown scheme
  or a bad signature is dropped.
- **Discovery packets** carry node IDs and endpoints only, which fit in UDP
  packets. They are hints: a node never trusts an endpoint for an ID until it
  has fetched that ID's record and verified it.
- **Records are fetched over TCP** (or over an authenticated session), not
  over UDP, so the larger record needs no fragmentation and no UDP
  amplification is possible. Before sending anything larger than the request
  to an unverified UDP source, a node proves the source's endpoint, as
  discovery v4's ping and pong do.
- **Bounded resources.** A record is verified once and cached by node ID and
  `seq`; a node never relays an unverified record; the table, the record
  cache, the record verifications per second and the requests per source
  address are bounded, with limits set by measurement. Table buckets keep the
  base client's per-subnet limits against eclipse attacks (threat model, T8).

### 10.4 Release signatures

Releases and the one-command installer are signed (outline, "Launch",
"Maintenance"). **Proposed:** with SLH-DSA-SHAKE-128s, whose security rests on
hashes alone, since a release key signs rarely and must stay valid for years.
The installer command carries the hash of the release key, as the threat model
(section 6, item 6) asks.

### 10.5 The web app

The web app is reached over HTTPS. Browsers already use hybrid X25519 and
ML-KEM key exchange in TLS, which protects the connection's secrecy, but web
certificates are still RSA or ECDSA, so a quantum attacker can impersonate the
host and serve altered code (threat model, T5 and T7). The web app therefore
needs **authenticated delivery**: the build's hash, signed with the release key
of section 10.4, checked before the code runs, with the verifiable self-run
build as the strongest form (outline, "First product"). Chain data the app
reads from an endpoint is checked against headers, as the trees and headers
specification already requires. The web app redesign and its deployment are
not part of this document.

## 11. What this supersedes

Changed with this document:

- **[Outline](../ghost-outline.md).** The "Ordinary accounts" line in
  "Cryptography" now states quantum-safe accounts from genesis; core
  requirement 2, "Public transfers" and the wallet interfaces point here; the
  founder decision "Quantum-safe everywhere GHOST is held" is recorded.
- **[Threat model](../threat-model.md).** The section 2 statement that
  ordinary accounts are only as safe as Ethereum's is replaced by the scope of
  this document; T7, C2, C20 and C35 and section 6, item 1 are updated; a new
  assumption, A12, covers the signature and key-exchange schemes.
- **[Spec 02](02-proof-statements.md).** `recipient` stays 20 bytes;
  confirmed in its sections 10 and 14. Nothing in its bindings changes.
- **[Spec 06](06-consensus-and-emission.md).** The `coinbase` field stays 20
  bytes and must name an address a quantum-safe key controls; section 7 says
  so.

For other chapters to take when next revised:

- **Spec 01,** section 4: the new tags `ghost/account-tx/v1`,
  `ghost/account-address/v1`, `ghost/wallet-account/v1`, `ghost/node-id/v1`,
  `ghost/node-record/v1` and `ghost/p2p-kex/v1` join the tag table; section 5
  takes the founder's answer to question 1.
- **Spec 03,** section 6, step 1: "ordinary transaction validity" is section 6
  of this document.
- **Spec 05:** a consensus maximum block gas limit under the bound of section
  8.4.
- **Spec 07:** `PROOF_BYTES` and `VERIFY_GAS` follow the proof configuration
  chosen under section 4.1.
- **Decision 0001:** the EVM feature table lists the precompile changes of
  section 7 and the removed signing RPC methods; MetaMask is no longer a test
  target until it supports these scheme IDs.
- **Decision 0003:** the security level is stated with its quantum figures.
- **The first product** ([webapp](../webapp.md)): a "supported EVM wallet" must
  sign type `0x52` under a scheme ID of section 5; standard Ethereum wallets do
  not, so the app needs a wallet that does.

## 12. Properties

Each is numbered so that a build ticket's test can cite it. A test that still
passes with the check it names removed does not count (spec 03, section 10).

- **QS-1. Legacy types are refused.** Transactions of types `0x00` to `0x04`
  with valid secp256k1 signatures are rejected by the pool, and a block holding
  one is invalid, from genesis.
- **QS-2. Unknown schemes are refused.** Scheme IDs `0x0000`, `0x0003` and
  `0xffff` are rejected in a transaction and fail in the precompile.
- **QS-3. The signature binds every field.** Changing any one of the type,
  chain identifier, genesis hash, nonce, both fee limits, gas limit,
  destination, value, calldata, access list, scheme ID or public key makes the
  signature fail.
- **QS-4. No cross-scheme use.** A valid ML-DSA-44 signature presented under
  scheme `0x0002`, and the other way round, is rejected before verification.
- **QS-5. Sender derivation.** The sender equals the first 20 bytes of the
  tagged hash; the build ticket adds test vectors computed by an
  implementation independent of the node.
- **QS-6. Removed precompiles fail.** Calls to `0x01`, `0x06`, `0x07`, `0x08`
  and `0x0a` fail and use all their gas.
- **QS-7. No transaction signature as a message.** The precompile fails on a
  context beginning with `ghost/tx/`.
- **QS-8. Signature floods are bounded.** A peer that sends an invalid
  signature is disconnected, and a test flood from many peers keeps the
  node's verification work within the worker pool's capacity.
- **QS-9. Blocks fit the message cap.** The test of section 8.4 passes at the
  largest gas limit allowed.
- **QS-10. Seed and digits stay apart.** The wallet refuses digits as a seed
  and words as a Phantom Key, and no code path derives one from the other.
- **QS-11. Both halves of the key exchange count.** Changing either the
  X25519 or the ML-KEM shared secret changes the session keys.
- **QS-12. The proof meets the rule.** The prover's security gate refuses a
  configuration that breaks section 4.1's rule.

## 13. Not settled: fail closed

1. **Verification constants.** Until `VERIFY_GAS` for a scheme is set by
   measurement, transactions of that scheme are rejected; until
   `SIGVERIFY_WORD_GAS` is set, the precompile fails on every call.
2. **Admission limits.** Until the worker pool, queue, per-peer and RPC budgets
   are measured, the node uses the smallest values that still let it follow
   the chain, and documents them.
3. **Transport limits and formats.** Until the transport build ticket fixes
   the handshake bytes and limits, a node does not accept connections it cannot
   authenticate under section 10; it never falls back to the secp256k1
   handshake.
4. **The proof configuration.** Until a configuration meets section 4.1's
   rule, the chain is not launched.

## 14. Questions for the founder

Each has a default that this document already applies.

1. **Phantom Key length.** Fourteen groups (about 172 bits) meet the target
   against all keys at once; twelve (about 146) do not. Default: spec 01's
   twelve groups stand until decided, and the threat model states the gap.
2. **SLH-DSA from genesis.** Accept scheme `0x0002` from genesis, or define it
   now and accept it only at a later height? Default: accepted from genesis, so
   every holder has a hash-only scheme from day one.
3. **Proven security.** Gate the proof on conjectured figures (as decision
   0003 does) or require a proven quantum figure of 64 bits (rate 1/8 with
   about 86 queries, a larger proof)? Default: the conjectured gate of section
   4.1, with the proven figures stated.
4. **Proof length before genesis.** Spec 07 makes a change of `PROOF_BYTES` a
   new version. Nothing has launched: may version 1 be re-set before genesis?
   Default: yes, once, before the software freeze.
5. **Gas limit cap.** A consensus maximum gas limit under section 8.4's bound,
   or a higher zero-byte price? Default: a consensus maximum, set in spec 05.
6. **Numbers proposed here.** Scheme IDs `0x0001` and `0x0002`, the
   precompile at `0x51`, the tags of section 11 and the 24-word seed. Default:
   as proposed. The account transaction type byte is
   settled by the front desk: `0x52`, because the native coin and data
   reveals already hold `0x50` and `0x51` (section 6, step 1). A precompile
   address is not a transaction type, so the precompile keeps its address.

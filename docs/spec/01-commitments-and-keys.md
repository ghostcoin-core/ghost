# Specification 01: commitments and keys

Status: draft for the founder's review, 2026-10-17. Nothing here is built. The
rules marked **Proposed** are choices this document makes and the founder can
change; everything else follows from the [outline](../ghost-outline.md) ("Core
protocol", "Phantom Keys", "Extension points"), the front desk decision recorded
with this specification, the [benchmark results](../benchmarks/results.md) or
the [threat model](../threat-model.md), and is cited to it, not decided again
here.

This document is the first part of the lifecycle specification. It fixes what
a commitment is and how everything is derived from the digits: the one
commitment format, the tag of every hash use, the Phantom Key format and its
checksum, the derivation of every secret, the fresh blinding of each
remainder, the encrypted note and its key, and the version tags and scheme IDs
that allow a later migration. It names what a proof must establish only where
the format needs it; the proof statements themselves are the next
specification. Section 14 holds test vectors, and
`scripts/check_commitment_vectors.py` recomputes every one of them.

## 1. Decisions at a glance

| Topic | Choice | Status |
|---|---|---|
| Commitment format | One format with a type tag: secret `s`, reveal secret `r`, blinding `b`, salt, type tag, content fingerprint, rule; a coin commitment adds the amount | Outline ("Core protocol" 3) |
| Per-commitment salt | Every new commitment (commit, remainder, data) has a fresh random 16-byte salt from the wallet, public, inside `F` (so `C`) and the marker, so one guess at a key checks one leaf, never all of them (section 3) | Founder direction, 2026-10-20; front desk decision |
| Commitment format version | Version 2 is the salted format and the only one a wallet makes; version 1 (no salt) stays valid for leaves already on a chain, told apart by the version byte of the type tag and by the `v2` fingerprint and marker tags (section 10) | Front desk decision |
| Two-step commitment | The wallet's fingerprint, then the node's commitment over type tag, fingerprint and (for coins) amount | [Spec 03](03-coin-rules.md), section 5; [spec 04](04-data-commitments.md), section 3 |
| Hash for commitments, markers, tree nodes and anything checked inside a proof | Keccak-256, original padding | Front desk decision; [benchmark results](../benchmarks/results.md) |
| Hash for deriving secrets from the digits, the note key and the checksum | SHA3-256 (FIPS 202) | Front desk decision; use for the checksum **Proposed** |
| Tags | Explicit ASCII strings with a version suffix, one per use, prefixed by their length; all listed in section 4 | Front desk decision; prefix **Proposed** |
| Phantom Key | 24 words of the 2,048-word list: a 256-bit secret and an 8-bit check, about 128 bits against a quantum search; the same key can be shown as 21 groups of four digits. The default for new keys | Founder direction, 2026-10-20 (quantum-safe, easy to write down by hand); spec 09, section 4.2 |
| Standard Phantom Key | Twelve groups of four digits, the last a checksum: 44 secret digits, about 146 bits. Issued before the words format; still accepted | Outline ("Phantom Keys") |
| Long Phantom Key | Twenty-four groups: groups 12 and 24 are checksums, 88 secret digits, about 292 bits. Still accepted | Outline; layout **Proposed** |
| Checksum | Words: the first byte of a tagged SHA3-256 of the secret. Digits: the tagged SHA3-256 of the digits before it, reduced modulo 10,000 | Front desk decision (author's choice); **Proposed** |
| What the key holds | Only the secret digits and the checksum: no amount, tree position or extra secret | Outline ("Do not carry over") |
| Derivation | Each secret is the tagged SHA3-256 of the key bytes, one tag per secret | Outline ("Technical starting picks"); layout **Proposed** |
| Remainder blinding | Derived from the digits and the commitment's hop number, used once per key on any one chain (section 8) | Outline ("Coin rules"; "Do not carry over"); counter **Proposed** |
| Finding the current remainder | Bulk trial decryption of the notes, then the marker of each found commitment against the spent-marker set | Threat model, section 6 item 8; method **Proposed** |
| Encrypted note | 156 bytes on the chain: random nonce, ChaCha20-Poly1305 ciphertext of a fixed 128-byte plaintext, tag | Outline ("Core protocol" 11); scheme and layout **Proposed** |
| Versions | Version suffix on every tag, a version byte in every type tag, a key format code, a note version and a scheme ID | Outline ("Extension points" 1 and 4); values **Proposed** |

## 2. Conventions

- **Bytes.** Every value in this document is a byte string. Integers are
  unsigned and big-endian at the width stated. `||` is concatenation. Hex is
  lower case.
- **`K(tag, x1, x2, ...)`** is Keccak-256 with the original Keccak padding
  (the padding byte `0x01`, as Ethereum uses), over
  `tagbytes(tag) || x1 || x2 || ...`. This is the hash used inside proofs and
  trees ("H" in
  [spec 03](03-coin-rules.md) and [spec 04](04-data-commitments.md)). It is
  not `SHA3-256`: the two differ only in the padding byte and give different
  digests.
- **`S(tag, x1, x2, ...)`** is SHA3-256 (FIPS 202, padding byte `0x06`) over
  the same encoding.
- **`tagbytes(tag)`** is one byte holding the length of the tag in bytes,
  followed by the tag's ASCII bytes (section 4).
- **Digits** are a Phantom Key (outline, "Phantom Keys"), written as words or
  as digit groups (section 5); "derived from the digits" means derived from
  the key in either form. **Key bytes** are the encoding of the key that every
  derivation takes (section 7).
- `COIN` and `DATA` are the two type tags of the commitment's format version
  (section 10): `0x02 0x01` and `0x02 0x02` in version 2, the format every new
  commitment uses, and `0x01 0x01` and `0x01 0x02` in version 1, which stays
  valid for leaves already on a chain.
- "Reject" means the value is invalid and is not used; for a transaction it has
  the meaning of spec 03, section 2.

## 3. Commitment format

There is one commitment format with a type tag (outline, "Core protocol" 3).
Its fields, each a fixed width:

| Field | Width | Meaning |
|---|---|---|
| `s` | 32 bytes | The secret. Derived from the digits (section 7) |
| `r` | 32 bytes | The separate reveal secret. Derived from the digits; the marker is computed from it (below) |
| `b` | 32 bytes | Random blinding. Derived from the digits and a counter, fresh for every commitment the key makes (section 8) |
| `salt` | 16 bytes | Version 2: a fresh random value from the wallet's secure random source, new for every commitment (below). Public, not derived from the digits. Absent in version 1 |
| type tag | 2 bytes | The commitment format version, then the type: in version 2 `COIN` is `0x02 0x01` and `DATA` is `0x02 0x02`; in version 1 they are `0x01 0x01` and `0x01 0x02` (section 10) |
| `cf` | 32 bytes | The content fingerprint. For `DATA`, a tagged hash of the content (below). For `COIN`, 32 zero bytes: a coin has no content |
| `rule` | 32 bytes | The optional rule, as a 32-byte value. The empty rule is 32 zero bytes, and it is the only rule version 1 accepts ([spec 03](03-coin-rules.md), section 7, step 11; [spec 04](04-data-commitments.md), question 9) |
| `v` | 32 bytes | Coins only: the amount in wei, an integer in `[0, V_MAX]` with `V_MAX = 2^96 - 1` ([spec 03](03-coin-rules.md), section 2) |

The commitment is built in two steps, so that the chain, not the user, binds the
amount and the type ([spec 03](03-coin-rules.md), section 5; base client plan
7.3). The wallet computes a fingerprint and the commit carries it; the node
computes the commitment and writes it as the leaf.

```text
coin:  F   = K("ghost/coin-fingerprint/v2", s, r, b, salt, COIN, cf, rule)
       C   = K("ghost/coin-commitment/v1", COIN, F, v)

data:  F_d = K("ghost/data-fingerprint/v2", s, r, b, salt, DATA, cf, rule)
       C   = K("ghost/data-commitment/v1", DATA, F_d)
```

with `COIN` = `0x02 0x01` and `DATA` = `0x02 0x02`. This is commitment format
version 2, the only format a wallet makes. The salt sits right after `b`. The
commitment tags keep their `v1` suffix, because their input layout (type tag,
fingerprint, amount) does not change; the version byte inside the type tag
tells the two formats apart there.

`v` is the amount the node has just burned, and the type tag in the outer hash
is set by the node: for every new commit it is the version 2 type tag. A
remainder commitment is built the same way inside the reveal proof, from its
own fresh blinding, its own fresh salt and its own amount; it is always
version 2, whatever the version of the commitment it comes from.

**Version 1, still valid.** Commitments made before the salt was added are
version 1. They have no salt: it is absent, not zero, so they hash exactly as
before, under the `v1` fingerprint and marker tags with the version 1 type tag,
and every such leaf already on a chain stays valid and revealable (section 10):

```text
coin:  F   = K("ghost/coin-fingerprint/v1", s, r, b, COIN, cf, rule)     COIN = 0x01 0x01
       C   = K("ghost/coin-commitment/v1", COIN, F, v)

data:  F_d = K("ghost/data-fingerprint/v1", s, r, b, DATA, cf, rule)     DATA = 0x01 0x02
       C   = K("ghost/data-commitment/v1", DATA, F_d)
```

A wallet never makes a new version 1 commitment. A reader or verifier that
sees a version byte or a tag it does not know rejects it and never guesses
(section 10).

**Salt.** Every version 2 commitment, whether a commit, a remainder or a data
commitment, has its own salt: 16 bytes the wallet draws from its secure random
source when it makes the commitment (threat model, A6), never reused and never
computed from the digits or from another value. It is public: nothing rests on
keeping it hidden, and it is stored so that the holder can read it back from
the chain on restore (section 8). A commit publishes it with `F`; a remainder's
salt travels inside the remainder's encrypted note, because a reveal publishes
no field beyond those of [spec 02](02-proof-statements.md). Its exact place in
the commit transaction and in the note is fixed with those formats (section
11). The salt is not a replacement for `b`: `b` hides the commitment, the salt
makes every commitment a separate target (below).

**Content fingerprint.** For a data commitment,

```text
cf = K("ghost/content-fingerprint/v1", len(content) as 8 bytes, content)
```

over the plaintext bytes of the content ([spec 04](04-data-commitments.md),
section 3). **Proposed:** it is Keccak-256, not SHA3-256, so that a later proof
that shown bytes match a commitment (spec 04, question 8) can recompute it
inside a proof without a second hash. Version 1 never recomputes it inside a
proof; the proof only carries `cf` as a field.

**Marker.** The one-time marker of a commitment (outline, "Core protocol" 5) is

```text
coin marker:  m = K("ghost/coin-marker/v2", r, b, salt)
data marker:  m = K("ghost/data-marker/v2", r, b, salt)
```

with the same salt as the commitment, right after `b`. A version 1 commitment
keeps its version 1 marker, `K("ghost/coin-marker/v1", r, b)` or
`K("ghost/data-marker/v1", r, b)`. So one commitment has one marker, and a
remainder, which has fresh blinding and a fresh salt, has a different one. The
coin and data tags keep the coin and data spent-marker sets apart
([spec 04](04-data-commitments.md), section 2), and the `v1` and `v2` tags keep
a version 1 marker from ever equalling a version 2 marker. The version 1 marker
is the layout the [benchmark plan](../benchmarks/plan.md) costed (the tagged
hash of `r` and `b`); the 16 more bytes of the salt still fit in one Keccak
permutation (section 4).

**Multi-target guessing.** An attacker who guesses keys wants any key that
holds anything, not one key in particular. Without a salt, `F` depends only on
the key's derived values and fields every coin shares (`COIN`, a zero `cf`, the
empty rule), and the marker only on `r` and `b_i`. One guess at a key then
gives one `F` and one marker per commitment number, each of which can be looked
up at once against every
`F` ever published and every spent marker: one guess checks every leaf. With
`N` leaves that divides the work by `N`: about 2^33 leaves cost about 33 bits
classically and about 17 under a quantum search (threat model, C20). The salt
removes this shortcut. Each leaf's `F`, `C` and marker depend on its own salt,
so a guess has to be hashed again for each leaf it is tested against, and
testing a guess against all `N` leaves costs `N` times as much as testing it
against one. Classically, finding any one key among the `N` then costs as much
as finding one given key; under a quantum search over pairs of a key and a
leaf, the `N` targets are offset by the `N` times larger search space, so the
cost is again about the square root of the key space. So:

| Key | Version 2 leaf, one or all leaves | Version 1 leaf, all leaves at once (`N` about 2^33) |
|---|---|---|
| 24 words (256 bits) | about 256 bits classical, 128 quantum | about 223 classical, 111 quantum |
| Standard, 12 groups (about 146 bits) | about 146 classical, 73 quantum | about 113 classical, 56 quantum |
| Long, 24 groups (about 292 bits) | about 292 classical, 146 quantum | about 259 classical, 129 quantum |

Precomputation does not help either: no table built before a commit can hold
its salt. Salts are 128 bits drawn at random, so two leaves share one with
probability about 2^-63 even among 2^33 leaves, and a shared salt would only
put those two leaves back to the version 1 cost against each other. The notes
already have no shortcut, because each is checked under its own random nonce
and its own leaf as associated data (section 9). The salt does not raise the
cost of guessing one particular key, which the key's length alone sets (section
5); a version 1 leaf keeps the version 1 figures until its value is revealed
into a version 2 remainder.

**Why two secrets.** The outline's format has a secret and a separate reveal
secret. In version 1 both are derived from the digits and both are needed to
open a commitment; the marker uses `r` alone, so the value that names a
one-time reveal never depends on `s`. Version 1 gives neither out on its own,
and builds nothing else on the separation; later layers (granting access,
delegation) may.

**What a proof must establish (only where the format needs it).** The proof
statements are the next specification. The format needs these of them:

- A proof opens a commitment only through both steps above, with the type tag
  checked against the tree and the purpose, so a data leaf never opens as a
  coin and the other way round. The version byte of the type tag selects the
  fingerprint and marker tags: `v2` with the salt for version 2, `v1` without
  it for version 1; any other version is rejected.
- The marker it publishes or checks is computed from the same `r`, `b` and
  salt as the commitment it opens.
- A remainder keeps the input's type, `cf` and `rule`
  ([spec 03](03-coin-rules.md), section 8) and is always version 2, with its
  own salt; its `s`, `r`, `b` and salt are inputs the proof does not
  constrain, so the chain cannot tell a claim to a new key from a partial
  reveal under the same key. Freshness of `b` and of the salt is the wallet's
  rule (section 8), not something the proof can check.
- The salt is a private input of every proof that opens a version 2
  commitment, never a public input. It is not secret, but the commit published
  it, so a reveal that published it too would name its commit
  ([spec 02](02-proof-statements.md), section 3).
- Every value checked inside a proof is a Keccak-256 hash of section 4 with its
  own tag. No SHA3-256 value of section 7 is ever recomputed inside a proof;
  the proof takes `s`, `r`, `b` and the salt as private inputs.

**Hiding.** `F`, `C` and the marker hide `s`, `r`, `b`, `cf` and `v` because
`b` is 256 bits from a one-way derivation and Keccak-256 is a preimage-resistant
hash (threat model, A1). The salt adds nothing to hiding, since it is public;
it only makes each leaf a separate target. The commit publishes `F`, `C` and
the salt; a reveal publishes the marker and never `F`, `C` or the salt.

## 4. Tagged hashing

Every use of a hash carries its own explicit tag (outline, "Core protocol" 10),
so a value made for one use can never be passed off as another. A tag is an
ASCII string of the form `ghost/<use>/v<version>`. It is encoded as one byte
holding its length, then its bytes. The length byte makes the encoding prefix
free: no tag followed by data can read as another tag followed by other data.
Within one tag every input has a fixed width, so the inputs cannot be shifted
between fields either.

Every tag is in this table, those of commitment format version 2 and those of
version 1 that stay valid for leaves already on a chain. No other tag exists; a
new use gets a new row before it is used. Input bytes count the length byte and
the tag as well as the inputs.

| Tag | Hash | Use | Inputs after the tag | Input bytes | Keccak permutations |
|---|---|---|---|---|---|
| `ghost/key-check/v1` | SHA3-256 | Phantom Key checksum (section 6) | format code, part, then the digits before the checksum group as ASCII, or for the words check the 32 secret bytes | 21 + digits; 53 for the words check | not in a proof |
| `ghost/secret/v1` | SHA3-256 | Secret `s` (section 7) | key bytes | 16 + key bytes | not in a proof |
| `ghost/reveal-secret/v1` | SHA3-256 | Reveal secret `r` (section 7) | key bytes | 23 + key bytes | not in a proof |
| `ghost/blinding/v1` | SHA3-256 | Blinding `b_i` of the key's commitment number `i` (section 8) | key bytes, `i` as 8 bytes | 26 + key bytes | not in a proof |
| `ghost/note-key/v1` | SHA3-256 | Note key `k_note` (section 9) | key bytes | 18 + key bytes | not in a proof |
| `ghost/data-key/v1` | SHA3-256 | Data key `k_data` ([spec 04](04-data-commitments.md), section 4) | key bytes | 18 + key bytes | not in a proof |
| `ghost/coin-fingerprint/v2` | Keccak-256 | Coin fingerprint `F` of a version 2 commitment (section 3) | `s`, `r`, `b`, `salt`, `COIN`, `cf`, `rule` | 204 | 2 |
| `ghost/coin-fingerprint/v1` | Keccak-256 | Coin fingerprint `F` of a version 1 commitment, for leaves already on a chain (section 3) | `s`, `r`, `b`, `COIN`, `cf`, `rule` | 188 | 2 |
| `ghost/coin-commitment/v1` | Keccak-256 | Coin commitment `C`, the coin-tree leaf, of either version (section 3) | `COIN`, `F`, `v` | 91 | 1 |
| `ghost/data-fingerprint/v2` | Keccak-256 | Data fingerprint `F_d` of a version 2 commitment (section 3) | `s`, `r`, `b`, `salt`, `DATA`, `cf`, `rule` | 204 | 2 |
| `ghost/data-fingerprint/v1` | Keccak-256 | Data fingerprint `F_d` of a version 1 commitment, for leaves already on a chain (section 3) | `s`, `r`, `b`, `DATA`, `cf`, `rule` | 188 | 2 |
| `ghost/data-commitment/v1` | Keccak-256 | Data commitment `C`, the data-tree leaf, of either version (section 3) | `DATA`, `F_d` | 59 | 1 |
| `ghost/content-fingerprint/v1` | Keccak-256 | Content fingerprint `cf` (section 3) | content length as 8 bytes, content | 37 + content | not in a proof in version 1 |
| `ghost/coin-marker/v2` | Keccak-256 | One-time marker of a version 2 coin commitment (section 3) | `r`, `b`, `salt` | 101 | 1 |
| `ghost/coin-marker/v1` | Keccak-256 | One-time marker of a version 1 coin commitment (section 3) | `r`, `b` | 85 | 1 |
| `ghost/data-marker/v2` | Keccak-256 | One-time marker of a version 2 data commitment (section 3) | `r`, `b`, `salt` | 101 | 1 |
| `ghost/data-marker/v1` | Keccak-256 | One-time marker of a version 1 data commitment (section 3) | `r`, `b` | 85 | 1 |
| `ghost/coin-tree-node/v1` | Keccak-256 | Inner node of the coin tree | level as 1 byte, left child, right child | 89 | 1 per level |
| `ghost/data-tree-node/v1` | Keccak-256 | Inner node of the data tree | level as 1 byte, left child, right child | 89 | 1 per level |
| `ghost/empty-leaf/v1` | Keccak-256 | The value of an unused leaf position in either tree | none | 20 | a constant |
| `ghost/coin-reveal-binding/v1` | Keccak-256 | Binding digest of a coin reveal ([spec 03](03-coin-rules.md), section 7, step 6) | fixed by the proof-statement specification | | |
| `ghost/data-reveal-binding/v1` | Keccak-256 | Binding digest of a data reveal or revocation ([spec 04](04-data-commitments.md), section 6) | fixed by the proof-statement specification | | |
| `ghost/hold-binding/v1` | Keccak-256 | Binding digest of a proof of holding ([spec 04](04-data-commitments.md), section 5) | fixed by the proof-statement specification | | |

Notes on the table:

- **Two hashes, by use.** Everything that is a commitment, a marker, a tree
  node or checked inside a proof uses Keccak-256, the hash chosen by the
  [benchmark results](../benchmarks/results.md). Everything derived from the
  digits off the chain uses SHA3-256, a standard hash (front desk decision).
  The two share the Keccak permutation but differ in padding, and their tags
  are disjoint, so no value of one can stand for a value of the other.
- **Tree nodes.** The level is the height of the node above the leaves: 0 for
  a node whose children are leaves, up to 31 for the root of a tree of 2^32
  leaves (outline, "Core protocol" 8). A leaf is a commitment `C`, which already
  carries its own tag, so a node can never be presented as a leaf or a leaf as a
  node. The tree's shape, rollover and root rules are for the tree and header
  specification; this document fixes only the node and empty-leaf hashes.
- **Binding digests.** The three binding tags are reserved here so that the
  table is complete; their input layouts belong to the proof statements, and
  this document gives no vectors for them.
- **SHAKE256** is not used in version 1. Every derived value is 32 bytes, which
  SHA3-256 gives directly.
- **Cost.** With the tag strings in the input, the opening of a coin
  commitment costs 3 permutations (2 for `F`, 1 for `C`), its marker 1, the
  remainder 3 and the tree path 32, where the benchmark plan's one-byte tags
  cost slightly less for the opening. The salt does not change these counts:
  a version 2 fingerprint is 204 bytes, still under the 272 bytes that two
  permutations absorb, and a version 2 marker is 101 bytes, under the 136 of
  one. The difference is a few permutations per
  proof, against a measured worst case of about 5.2 seconds for the whole
  proof against a 10-second target ([benchmark results](../benchmarks/results.md)).

## 5. Phantom Key format

A Phantom Key is the digits returned on commit (outline, "Phantom Keys"). A new
key is shown and typed as 24 words; keys issued earlier as groups of four
decimal digits separated by spaces stay valid:

```text
abandon amount liar amount expire adjust cage candy arch gather drum bullet
absurd math era live bid rhythm alien crouch range attend journey trip

1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
```

- **Words key: 24 words, the default (founder direction, 2026-10-20).**
  Quantum-safe and still easy to write down by hand. The key is 264 bits: a
  256-bit secret followed by an 8-bit check (section 6), read as 24 indexes of
  11 bits each, most significant bit first, into the 2,048-word BIP-39 English
  list (`client/src/wordlist/english.txt`, the same list as the wallet's own
  recovery words of [spec 09](09-quantum-safe-accounts.md), section 9). The
  words are unique by their first four letters. This is the layout of
  BIP-39, with Ghost's own check tag and format code: about 256 bits of
  secret, about 128 bits against one key under a quantum search, and the same
  128 against all salted (version 2) leaves at once, about 111 for version 1
  leaves (section 3, "Multi-target guessing"; threat model, C20). 24 words is a length
  crypto users already write down for their backups. Scannable codes and file
  export stay conveniences, never the only way to back up a key.
- **The same key as digits.** For people who prefer digits, a words key is
  also shown as 21 groups of four: groups 1 to 20 are the secret as a decimal
  number, zero-padded to 80 digits, and group 21 is a checksum (section 6).
  A value of `2^256` or more in groups 1 to 20 is refused, since no words key
  has it. Words and digits give the same secret, the same key bytes and the
  same derived values (section 7).
- **Standard key: twelve groups.** Groups 1 to 11 are the secret: 44 digits,
  `10^44`, about 2^146.2 equally likely values, so about 146 bits of secret
  (outline). Group 12 is the checksum (section 6). Against a quantum search
  this gives about 73 bits, also against all its salted (version 2) leaves at
  once; against version 1 leaves an attacker who targets any one of billions of
  public commitments gets it down to about 56 (section 3, "Multi-target
  guessing"; threat model, C20). New keys are no longer issued in this
  format by default; every key already issued still restores and derives the
  same values.
- **Long key: twenty-four groups (Proposed layout).** The key is two halves of
  twelve groups. Groups 1 to 11 and 13 to 23 are the secret: 88 digits, about
  2^292.3 values, so about 292 bits, about 146 against a quantum search (threat
  model, C20). Group 12 is a checksum over groups 1 to 11, and group 24 a
  checksum over all 22 secret groups, so a mistyped half is found and named
  before the second half is typed.
- **Format code.** Words select code `0x20`, and so do 21 digit groups; for
  other digits the number of groups selects the format: code `0x0C` for twelve
  groups, `0x18` for twenty-four. The code enters the checksum and every
  derivation, so the same secret in two formats gives unrelated secrets, and
  the first half of a long key does not pass as a standard key (vector
  `checksum-long-first-half` in section 14).
- **Generation.** Always by the app from a secure random source (outline;
  threat model, A6). A words key takes 32 bytes from the secure source as its
  secret, then its check. For a digit key each secret digit is drawn
  independently and uniformly: take one byte from the secure source, discard
  it if it is 250 or more, and otherwise use its value modulo 10. Then append
  the checksum groups. Any other method must produce the same uniform
  distribution over all `2^256` (or `10^44`, or `10^88`) secret values. New
  keys are words keys unless the caller asks for another format.
- **Entry.** Text with a letter and no ASCII digit is read as words; any other
  text as digits. Words are case-insensitive and separated by any mix of
  spaces and hyphens. Only whole words of the list count: a word the list does
  not contain is rejected and named to the person (its number and the text
  typed), never corrected to a near word and never completed from a prefix;
  any character that is neither a letter nor a separator is rejected. There
  must be exactly 24 words, an error of its own, and then the check must pass,
  a separate error. Digits are accepted with any mix of spaces and hyphens
  between them; any other character, including a letter or a non-ASCII digit,
  is rejected. After separators are removed there must be exactly 48, 84 or
  96 digits. In every case the check is verified before anything is derived.
- **No fifteen-word key.** A shorter fallback of fifteen words (160 bits,
  about 80 against a quantum search) was considered and is not adopted: it
  would miss the target of [spec 09](09-quantum-safe-accounts.md), section 4,
  and 24 words is already a length people write down.
- **What the key carries.** The secret digits and the checksum, nothing else.
  It holds no amount, no tree position, no extra secret and no version field
  beyond its length (outline, "Do not carry over": the old key was about 34
  groups because it held these). The amount, position, index and salt of the
  current remainder are found on the chain (section 8).
- **No passphrase variant.** There is no passphrase-protected key, which would
  allow offline guessing (outline, "Do not carry over"), no master number and
  no receiving address (outline, "Phantom Keys").
- **One key, one first commitment.** The app generates a new key for every
  commit and for every claim to a new key, and never makes a second first
  commitment under a key that already has one, because two leaves with the
  same blinding would share `s`, `r` and `b_0`, and under version 1 also a
  marker (section 8). Their different salts keep version 2 markers apart, but
  the rule stays.

## 6. Checksum

**Words key.** The check is the last 8 bits of the 24 words:

```text
check = first byte of S("ghost/key-check/v1", 0x20, 0x01, secret)
```

with `secret` the 32 secret bytes. Any wrong key, whatever the mistake (one
wrong word, two swapped words, a word from another key), passes with
probability 1 in 256; a word not in the list is caught before the check, so
the check only has to catch real words in the wrong place. The tag is
Ghost's own, not BIP-39's SHA-256 check, so the wallet's recovery words of
[spec 09](09-quantum-safe-accounts.md), section 9, typed into a key field fail
the check with probability 255 in 256, and the screens that ask for one or the
other never share a field (spec 09, section 9). The words key shown as digits
carries a check group of its own, `check(0x20, 0x01, digits)` below over its
80 secret digits, as group 21.

**Digit keys.** The checksum is the last group of four digits (front desk
decision), and for a long key also group 12. Each check group is

```text
check(code, part, digits) = int(S("ghost/key-check/v1", code, part, digits)) mod 10000
```

written as four digits with leading zeros. `code` is the format code as one
byte, `part` is one byte (`0x01` for group 12 and for group 21 of a words key,
`0x02` for group 24), `digits` are the ASCII digits of the secret groups
before the check group (groups 1 to 11 for group 12; groups 1 to 11 and 13 to
23 for group 24; groups 1 to 20 for group 21), and `int` reads
the 32-byte digest as a big-endian integer. The bias from reducing a 256-bit
integer modulo 10,000 is below 2^-240.

**Why this algorithm (Proposed).** It is a truncated standard hash, the same
construction that BIP-39 mnemonics and Base58Check addresses use (a prefix of
SHA-256 over the payload), with SHA3-256 and a reduction to four decimal
digits:

- **It catches every kind of mistake at the same rate.** A wrong key passes
  with probability 1 in 10,000, whatever the mistake: one digit, two swapped
  digits, two swapped or repeated groups, a missing group, or several
  mistakes at once. The standard digit-check schemes (Luhn, Verhoeff, Damm,
  ISO/IEC 7064 MOD 97-10) guarantee to catch a single wrong digit or an
  adjacent swap, but they produce one or two check digits and miss other
  errors far more often: with two check digits, as in MOD 97-10, about 1 in
  100 random errors passes, against 1 in 10,000 here. With twelve groups to type, group
  swaps and multiple typos are the errors that matter, and four digits of
  check spent on a single-error guarantee would buy less.
- **No second algorithm.** SHA3-256 is already needed for derivation
  (section 7), so the checksum adds no primitive to implement or review.
- **No secret in the checksum.** The check is a function of the secret digits
  and costs none of the 146 bits. It does let a guesser discard 9,999 in
  10,000 wrong guesses offline, but the guesser still has `10^44` candidates
  to run through, and the same guesses can be checked against the chain
  anyway.

**Residual risk.** A single typo slips through 1 time in 10,000. The wallet
then derives secrets that match nothing on the chain, finds no note on
restore, and says so; it never creates value or a commitment from a mistyped
key. The save check before a commit (outline, "First product") catches a
wrongly recorded key before anything is sent.

**Residual risk of the words check.** A wrong set of 24 real words slips
through 1 time in 256, with the same outcome: nothing matches on the chain and
restore says so. Every word must be a whole word of the list, so most
misspellings and misread letters are caught as unknown words before the check
is reached.

**Where it is checked.** Only in the wallet, when words or digits are entered.
The checksum never reaches the chain and no proof checks it.

## 7. Derivation

Every secret is derived from the digits with standard hashing (outline,
"Technical starting picks": "Every secret derived from the digits with standard
hashing"). The digits are all that is needed; nothing else is stored.

**Key bytes.** The input to every derivation is

```text
words key:  key_bytes = 0x20 || the 32 secret bytes
digit key:  key_bytes = code || secret digits as ASCII
```

A words key gives 33 key bytes, the same whether it was typed as words or as
its 21 digit groups. For a digit key, `code` is the format code (`0x0C` or
`0x18`) and the secret digits are the 44 or 88 digits of the secret groups in
order, without the checksum groups and without separators. A standard key
gives 45 key bytes, a long key 89. The derived-value tags below are the same
for every format.

**Derived values (Proposed layout).**

```text
s      = S("ghost/secret/v1",        key_bytes)
r      = S("ghost/reveal-secret/v1", key_bytes)
b_i    = S("ghost/blinding/v1",      key_bytes, i as 8 bytes)
k_note = S("ghost/note-key/v1",      key_bytes)
k_data = S("ghost/data-key/v1",      key_bytes)
```

Each is 32 bytes and used as is. Keccak-256 inside the proof takes any 32-byte
value, so there is no reduction step and no value to reject.

- **Separate tags.** No derived value can be computed from another: each is a
  one-way function of the key bytes under its own tag. In particular `k_data`
  and `k_note` reveal nothing about `s`, `r` or `b_i`, so showing `k_data` lets
  a viewer read data but not prove holding, reveal or revoke
  ([spec 04](04-data-commitments.md), section 4; threat model, C14).
- **Nothing else in the key.** No derivation takes an amount, a tree position,
  a chain value or a second secret; the outline's "Do not carry over" list rules
  them out. The counter `i` is not in the key either: it is recovered from the
  notes (section 8). No derivation produces a commitment's salt: the wallet
  draws it at random for each commitment (section 3) and reads it back from
  the chain on restore.
- **No stretching.** The key is random, not chosen by a person, so a slow
  password hash would add little: at about 146 bits an exhaustive search is out
  of reach either way. An optional slow hash before derivation was considered
  for the words key and is not adopted: with a 256-bit secret there is nothing
  for it to add, and it would slow restore on a phone.

## 8. Remainder and the current commitment

A partial reveal uses a commitment up and creates one fresh commitment for the
remainder (outline, "Coin rules"; [spec 03](03-coin-rules.md), section 8). The
old design derived the same remainder blinding on every partial reveal and
guessed the remainder's tree position; both are on the outline's "Do not carry
over" list.

**Fresh blinding on every commitment (Proposed).** The commitments a key makes
are numbered `i = 0, 1, 2, ...`. Number 0 is the key's first commitment: the
commit, or the remainder of a claim into a new key. Commitment number `i` uses
the blinding `b_i` of section 7 and, in version 2, a salt drawn fresh for that
commitment (section 3), never reused. A reveal under the key creates its
remainder with the number one above the commitment it spends (review 01, F2
and N3):

```text
i_next = 1 + the number of the commitment being spent
```

So a key's numbers count its hops: number `k` is always the remainder of a
reveal of number `k - 1`. A retry after a dropped or reorganised reveal of the
same input takes the same number again, and numbers have no gaps.

- **Never the same value twice on one chain.** Distinct numbers give distinct
  `b_i` (the collision resistance of SHA3-256), and a version 2 remainder also
  has its own random salt, so every remainder has a commitment and a marker
  that differ from every earlier one in its sequence on the same chain (threat
  model, C26). A key's commitments on one chain form a
  single line, because each one after number 0 is made by spending the key's
  one unspent commitment, so the numbers on one chain are 0, 1, 2, ... once
  each. Two included reveals that made the same number `k` would both spend the
  key's number `k - 1` on that chain, publish the same input marker, and only
  one of them is included.
- **Equal numbers, different salts.** A version 2 marker
  `K(tag, r, b_i, salt)` depends on the key, the number and the commitment's
  own salt. Two remainders numbered `k`, made on one chain, on two branches, by
  two devices or by a retry, come from reveals that publish the same input
  marker, the marker of number `k - 1` (that marker is the input's, fixed when
  the input was made). They share their blinding but not their salt, so their
  commitments and their own markers are unrelated, and revealing them in turn
  ties nothing together. One chain still accepts one reveal per input marker,
  so nothing is doubled.
- **Equal numbers mean the same input marker, on every branch (version 1).** A
  version 1 commitment's marker `K(tag, r, b_i)` depends only on the key and
  the number, not on the amount or the branch. Version 1 leaves made before the
  salt keep this behaviour. So any two version 1 remainders numbered `k`, made on
  one chain, on two branches, by two devices or by a retry, come from reveals
  that publish the same input marker, the marker of number `k - 1`. Two such
  remainders share their blinding, and if their amounts are equal their
  commitments are equal, but that only repeats what the shared input marker
  already shows: the same commitment of the key was revealed in both places.
  When they are revealed in turn they publish the same marker, which again only
  shows the same number of the same key revealed in both places, as a fork that
  replays a reveal does (threat model T4). It never ties a reveal to another
  number of the key, and it cannot double anything, because one chain accepts
  one reveal per marker. A rule of "one above the highest number used", with
  gaps, would not have this property: after a reorganisation a clean device
  could give one number to remainders of two different inputs and so link two
  reveals with different input markers.
- **Same key by default.** By default the remainder keeps `s` and `r`, so the
  same key controls it. A claim uses a newly generated key, whose own
  commitment number 0 holds the remainder (outline, "Coin rules").
- **A key used for two first commitments.** Both are number 0. Under version 1
  they share a marker, so only one can ever be revealed; under version 2 their
  salts differ, so both can be, but they still share `s`, `r` and `b_0`. The
  wallet never does this (section 5, "Generation").
- **Data commitments** have no remainder in version 1
  ([spec 04](04-data-commitments.md), question 3), so a data key uses only
  `b_0`.

**How the same key finds its current remainder (Proposed).** On a clean device,
from the digits alone (outline, "First milestone" 4; threat model, C21 and
C41):

1. Check the checksum and derive `s`, `r` and `k_note` (sections 6 and 7).
2. Fetch the note history of the coin tree in bulk: every leaf with its
   position, its note and, for a leaf made by a commit, the salt published
   with it. Never ask an endpoint for one commitment, one
   position or one marker (threat model, section 6 item 8).
3. Try `k_note` on every note (section 9). Under authenticated encryption only
   the key's own notes decrypt; every other note fails and is passed over.
4. For each note that decrypts, read its number `i`, amount `v`, type tag,
   `cf` and `rule`, and for a version 2 type tag the commitment's salt (the
   one published with a commit's leaf, or the one inside a remainder's note);
   compute `b_i`, then `F` and `C` under the tags of the type tag's version
   (section 3). A version 1 type tag has no salt. If `C` is not
   the leaf the note is stored with, discard that note and report it; never
   trust a note's contents without this check.
5. Compute each found commitment's marker and look it up in the coin
   spent-marker set, also fetched in bulk. Notes and markers count only once
   checked against the block receipts and their headers' `receiptsRoot`
   ([spec 05](05-trees-and-headers.md), section 8, item 5 and "Marker
   status"); until then the result is "unknown" (review 01, F3 and F4).
6. The current remainder is the found commitment whose marker is unspent. Its
   tree position is the position of its leaf, read from the chain, never
   guessed. If none is unspent, the key's value has been fully revealed or
   claimed away. If more than one is unspent, the wallet shows each. That
   happens when a key was wrongly used for two first commitments, or when
   someone else copies a commit's public `F`, note and amount into a commit
   they pay for: the copy is the same commitment with the same marker, so
   only one of the two can ever be revealed, and the copier loses what they
   burned (milestone 1 review).
7. The next number to use is one more than the current remainder's `i`.

Every note ciphertext uses a fresh random nonce, every marker is a hash of a
different `b_i` (and in version 2 of a different salt), and no request names a
single value, so restore publishes and
requests nothing that ties the sequence together (outline, "First milestone" 4).
The same steps restore a data key from the data tree ([spec 04](04-data-commitments.md),
section 8), with `DATA` and the data marker.

## 9. Encrypted note

A small note is stored with every commitment so that the key can recover the
commitment's details (outline, "Core protocol" 11). It is written by whoever
creates the commitment: the wallet for a commit, the revealing wallet for a
remainder, the claiming wallet (with the new key) for a claim.

**Note key.** `k_note = S("ghost/note-key/v1", key_bytes)` (section 7). One
note key serves every note of a key, so restore tries one key per note.

**Encryption (Proposed).** ChaCha20-Poly1305 as defined in RFC 8439, a
standard authenticated encryption scheme with a 256-bit key (outline,
"Foundation": standard encryption). The nonce is 12 bytes from a secure random
source, new for every note. A key writes few notes, so the chance of a nonce
repeating under one note key is negligible (about 2^-57 even for a million
notes under one key).
The scheme uses only symmetric primitives, so the note is not a quantum
weakness beyond the square-root search on its 256-bit key (threat model, C2).

**Associated data.** `chain_id as 8 bytes || C`, the chain identifier and the
leaf the note is stored with. A note copied to another leaf or another chain
fails to decrypt.

**Plaintext: 128 bytes, fixed.**

| Offset | Width | Field |
|---|---|---|
| 0 | 1 | Note version, `0x01` |
| 1 | 1 | Scheme ID, `0x01` (section 10) |
| 2 | 2 | Type tag, `COIN` or `DATA` |
| 4 | 8 | Commitment number `i` (section 8) |
| 12 | 32 | Amount `v` in wei; zero for data |
| 44 | 32 | Content fingerprint `cf`; 32 zero bytes for a coin |
| 76 | 8 | Content length in bytes; zero for a coin |
| 84 | 32 | Rule; 32 zero bytes for the empty rule |
| 116 | 12 | Zero padding |

The plaintext holds only what the key cannot derive. It never holds `s`, `r`,
`b_i`, `k_note`, `k_data`, the digits, a storage location or a tree position
([spec 04](04-data-commitments.md), section 4). A wallet rejects a note whose
version, scheme ID or type tag it does not know, or whose padding is not zero.

**On the chain: 156 bytes, fixed.**
`nonce (12 bytes) || ciphertext (128 bytes) || tag (16 bytes)`. Every note has this one length, coin or data, so its length is not a
fingerprint (threat model, C18); the commit and reveal checks reject any other
length ([spec 03](03-coin-rules.md), section 6, step 5).

**What it gives away.** Without the digits, nothing beyond its fixed length.
Anyone shown the digits can read every note of the key (threat model, T6).

**The salt and the note.** A version 2 commitment can be opened only with its
salt, so the holder must be able to read the salt back from the chain. A
commit publishes it with `F`. A remainder's salt has nowhere public to go,
because a reveal publishes no field for it, so the remainder's note carries
it, under the reveal's binding of the note ([spec 02](02-proof-statements.md),
section 7). The plaintext above has 12 free bytes, fewer than 16, so the note
that carries a salt is a new note version, fixed with the next revision of the
note (section 11). Until then the plaintext above is the note of a version 1
commitment, and a wallet rejects a note version it does not know.

## 10. Version tags and scheme IDs

Everything that is hashed, stored or encrypted carries a version, so that a
later scheme can be added and old commitments migrated safely (outline,
"Extension points" 1 and 4).

| Item | Value | Where it sits |
|---|---|---|
| Tag version | suffix `/v1`; `/v2` for the fingerprint and marker tags of commitment format version 2 | Every tag of section 4 |
| Commitment format version | `0x02` salted, the only version a wallet makes; `0x01` without salt, valid for leaves already on a chain | First byte of every type tag; inside `F` and `C` |
| Type | `0x01` coin, `0x02` data | Second byte of the type tag |
| Type tags | Version 2: `COIN` `0x02 0x01`, `DATA` `0x02 0x02`. Version 1: `COIN` `0x01 0x01`, `DATA` `0x01 0x02` | Inside `F` and `C`; the note |
| Key format code | `0x20` words (24 words, or 21 digit groups), `0x0C` standard, `0x18` long | Implied by words or the number of groups; first byte of the key bytes and the checksum input |
| Note version | `0x01` | Byte 0 of the note plaintext |
| Scheme ID | `0x01` | Byte 1 of the note plaintext; implied by commitment format versions 1 and 2 |

**Scheme 1** is this whole document: Keccak-256 with the tags of section 4 for
commitments, markers and trees; SHA3-256 for the checksum and derivation;
ChaCha20-Poly1305 for notes; the key formats of section 5. Commitment format
version 2 adds the salt to the fingerprint and the marker and changes nothing
else, so it stays inside scheme 1: same hashes, same derivation, same note
encryption. "Version 1" elsewhere in this document, without "commitment
format", means the first protocol version, which has both commitment formats.

**Telling the formats apart.** The version byte of the type tag says which
format a commitment has, and the type tag is inside both `F` and `C`. A
version 2 commitment is opened only with the `v2` fingerprint and marker tags
and a 16-byte salt right after `b`; a version 1 commitment only with the `v1`
tags and no salt. The tags differ, so a version 1 fingerprint or marker can
never equal a version 2 one, and the salt can be neither added to a version 1
commitment nor dropped from a version 2 one. The commitment tags are shared,
and the type tag inside them keeps the two versions' leaves apart.

**Rules (Proposed).**

- A type tag, note version or scheme ID the reader does not know is rejected
  everywhere it is checked. Nothing is read with a guessed version.
- A reader or verifier that sees a commitment format version byte or a tag it
  does not know rejects it and never guesses (front desk decision). A type tag
  of version 2 with a `v1` fingerprint or marker tag, or of version 1 with a
  `v2` one or a salt, is rejected the same way.
- Version 1 type tags and tags stay valid for leaves already on a chain: a
  version 1 leaf can always be revealed and its marker recorded, as the
  survival rule below requires. A wallet makes only version 2 commitments:
  every commit, remainder and data commitment it creates has a fresh salt.
- A new scheme gets a new scheme ID, a new commitment format version, and new
  tags with a new suffix (`/v2`) for every use whose rule changes. A tag is never
  reused with a different input layout.
- The same digits under a new scheme derive new, unrelated secrets, because the
  derivation tags differ. A key never needs to change format to move to a new
  scheme.
- A commitment never changes scheme in place. It is opened under the scheme it
  was made with for as long as the chain accepts that scheme; moving its value
  to a new scheme means revealing it and creating the remainder under the new
  one, which the proof-statement and upgrade specifications must allow (see
  section 12, item 7).
- **Survival is the defined path (review 01, F9).** No upgrade removes or
  disables the verification of a scheme the chain has accepted, and no upgrade
  makes an unrevealed commitment of that scheme unrevealable, unless the same
  upgrade, or an earlier one, already provides a tested reveal that opens a
  commitment of the old scheme and creates its remainder under a new one
  (migration). Until such a migration exists, every commitment of scheme 1
  stays revealable under scheme 1 on every later version of the chain, so it
  survives without any action by its holder (threat model C47). A scheme that
  is at risk may be restricted only to reveals into a newer scheme, never cut
  off.
- A new key format (for example a different group count) gets a new format
  code. A new checksum rule gets a new check tag, so a wallet can tell versions
  apart by which checksum the digits pass.

## 11. What this document does not fix

- The proof statements, their public inputs and constraints, and the binding
  digest layouts (next specification).
- The tree's shape, rollover and root rules beyond the node and empty-leaf
  hashes (tree and header specification).
- The transaction formats, including where `F`, the salt and the note sit in
  a commit (transaction-format specification).
- The note version that carries a version 2 commitment's salt (section 9).
- The data encryption itself: [spec 04](04-data-commitments.md), section 4 sets
  its rules; this document fixes only `k_data`.
- Chain identifier values.

## 12. Conflicts with other chapters

This document does not edit other chapters. Where they differ from it, the
difference is listed here for the founder's review.

1. **Who fixes the tag strings.** [Spec 03](03-coin-rules.md), section 2 and
   section 12, and [spec 04](04-data-commitments.md), sections 2 and 14, leave
   the tag strings to the proof-statement specification, and the derivation of
   `s`, `r`, `b`, `k_note` and `k_data` to a key derivation specification. This
   document fixes both (section 4 and section 7); the binding-digest layouts
   stay with the proof statements.
2. **Field-element encoding of the fingerprint.** [Spec 03](03-coin-rules.md),
   section 6, step 4, and section 7, step 2, require every element of `F` and
   of the public inputs to be a canonical field element below the modulus. With
   Keccak-256, `F`, `C`, markers and roots are 32-byte strings and every value
   is canonical, so there is no modulus check on them. The amount and range
   checks of spec 03 are unchanged, and the field-wrap example of its CR-7
   still applies to the proof's internal arithmetic.
3. **Tag encoding in the benchmark plan.** The
   [benchmark plan](../benchmarks/plan.md) used a one-byte tag and a one-byte
   level as the first input bytes. This document uses length-prefixed ASCII
   tags (front desk decision), at the cost of a few permutations (section 4).
   The plan's single-hash commitment already yields to spec 03, section 5.
4. **Content fingerprint hash.** [Spec 04](04-data-commitments.md), section 3,
   leaves open whether `cf` uses the in-proof hash or a standard hash. This
   document picks Keccak-256 (section 3).
5. **Contents of the data note.** [Spec 04](04-data-commitments.md), section 4,
   proposes that the data note holds `cf`, the length and the version. The note
   of section 9 holds those and also the scheme ID, type tag, commitment number,
   a zero amount and the rule, in the one layout shared with coins.
6. **Restore of `b` for data.** [Spec 04](04-data-commitments.md), section 8,
   step 1, derives a single `b`. Here `b` is per commitment number; for data,
   which has no remainder, it is always `b_0`, so the two agree.
7. **Remainder type tag and migration.** [Spec 03](03-coin-rules.md), section
   8, carried the type tag unchanged into the remainder, which would have kept
   a version 1 leaf's value unsalted forever. It now keeps the input's type,
   `cf` and `rule` and makes every remainder commitment format version 2 with
   a fresh salt, so the first reveal of a version 1 leaf moves its value into a
   salted remainder. Moving a commitment to a later scheme (section 10) still
   needs that rule revisited when a second scheme exists.
8. **Phantom Key length.** [Spec 09](09-quantum-safe-accounts.md), section 4.2
   and question 1, proposes a 14-group key (about 172 bits) to meet its target
   against all leaves at once, and leaves this document unchanged until that
   is decided. This document instead makes the 24-word key the default
   (section 5): about 128 bits against one key and, with the salt, about 128
   against all version 2 leaves at once under a quantum search (about 111
   against version 1 leaves), above that target. The 12-group and 24-group
   keys stay valid with the limits spec 09 states for them.

## 13. Questions for the founder

Each has a default that this document already applies.

1. **Checksum algorithm.** Truncated SHA3-256 catches every kind of mistake at 1
   in 10,000, but does not guarantee to catch a single wrong digit. Default:
   truncated SHA3-256 (section 6).
2. **Long key layout.** Two checksum groups, so about 292 bits as the threat
   model states, or one checksum group and 23 secret groups (about 305 bits)?
   Default: two checksum groups.
3. **Note scheme.** ChaCha20-Poly1305 with a random nonce, or another standard
   authenticated encryption scheme? Default: ChaCha20-Poly1305.
4. **Coin content fingerprint.** 32 zero bytes for coins, or a fixed tagged
   constant? Default: 32 zero bytes.

## 14. Test vectors

The blocks below are the test vectors of this document. Run

```sh
python3 scripts/check_commitment_vectors.py
```

from the repository root: it reads every block in this section, recomputes
every value with Python's standard library and a short Keccak-256 written in
the script, checks that Keccak-256 against known values first, and exits
nonzero on any mismatch. It also checks that the tag table of section 4 lists
exactly the tags it uses, with the input sizes and permutation counts of their
fixed layouts, and that every set of salted vectors of one secret under
different salts has unrelated fingerprints, commitments and markers.

The vectors of the words key (section 5: words, digit view, key bytes and
derived values) are in `client/tests/word_key.rs`, not here, so the checker
above covers the digit formats only.

The keys below are examples only, published here, and must never hold value.
Each block starts with `[name]`; each line is `field = value`; byte values are
hex. The chain identifier 1234 is an example, not Ghost's.

### Keccak-256

The script checks these against its own copy of the same known values.

```text
[keccak-empty]
kind = keccak256
message-hex =
digest = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470

[keccak-abc]
kind = keccak256
message-ascii = abc
digest = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
```

### Checksum vectors

`check` is the correct check group (or groups) for the key's secret digits;
`valid` says whether the key as written passes.

```text
[checksum-standard]
kind = checksum
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
format = 0c
check = 0417
valid = yes

[checksum-standard-zero]
kind = checksum
key = 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 4156
format = 0c
check = 4156
valid = yes

[checksum-standard-data]
kind = checksum
key = 2718 2818 2845 9045 2353 6028 7471 3526 6249 7757 2470 4457
format = 0c
check = 4457
valid = yes

[checksum-long]
kind = checksum
key = 3141 5926 5358 9793 2384 6264 3383 2795 0288 4197 1693 6390 9937 5105 8209 7494 4592 3078 1640 6286 2089 9862 8034 8042
format = 18
check = 6390 8042
valid = yes

[checksum-one-digit-wrong]
kind = checksum
key = 1111 2222 3333 4444 5555 6666 7777 8889 9999 0000 1234 0417
format = 0c
check = 6577
valid = no

[checksum-groups-swapped]
kind = checksum
key = 1111 2222 3333 4444 5555 6666 8888 7777 9999 0000 1234 0417
format = 0c
check = 8222
valid = no

[checksum-long-first-half]
kind = checksum
key = 3141 5926 5358 9793 2384 6264 3383 2795 0288 4197 1693 6390
format = 0c
check = 2381
valid = no

[checksum-long-second-half-wrong]
kind = checksum
key = 3141 5926 5358 9793 2384 6264 3383 2795 0288 4197 1693 6390 9937 5105 8209 7494 4592 3078 1640 6286 2089 9862 8043 8042
format = 18
check = 6390 6040
valid = no
```

### Derivation vectors

```text
[derivation-standard]
kind = derivation
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
key-bytes = 0c3131313132323232333333333434343435353535363636363737373738383838393939393030303031323334
s = cf74f6d8438c806c9fb1e814fe921f44cae6657274f4ad505a95ad28775a54f7
r = 260574c847e0aa966daf8113c0422810dacf0c7c2b97e3afeaa9cfb8d10f8d81
b0 = 88aa9d7486e66f669702559ae9fbe6e47f8ce5425d952333072e40ee8e1d5390
b1 = 77a45d61a119616538478c057c5c8617ba7546934513c9656b5d1e90a3bde7e2
b2 = 6ae675ea465681bc4d186e93f4c9893339a7b083a67fe29174aa24df111b6fe4
note-key = 341f623d5f8c5239b00d43d801a5ce6ac47baa32bd14177f29d91ebe01217b7b
data-key = 82322ccb18c0d69c25554edaa215797987ae70e181c74283c33b76c5d3ba75e3

[derivation-long]
kind = derivation
key = 3141 5926 5358 9793 2384 6264 3383 2795 0288 4197 1693 6390 9937 5105 8209 7494 4592 3078 1640 6286 2089 9862 8034 8042
key-bytes = 1833313431353932363533353839373933323338343632363433333833323739353032383834313937313639333939333735313035383230393734393434353932333037383136343036323836323038393938363238303334
s = 6ebf2d70178aec5bdffda8a95d3fbe816b7a42e2633e0b53addbe7624102337a
r = e8e58b2ed573e76c5f9dba2866bab953962dadd92ed344f00cf382fcae567f96
b0 = f52b208010a84fc45a918588af13bf5c40ceccf1f57cb90cff80d7ae961944fb
b1 = d7ef83c098a2447a71132b5285e1704ea9b2e04cf86886a9ca68c914120938d1
b2 = e4084e6f1bcdb5d1939bac47381a4f714e2e51e56b9e521d10d0d80828495ab8
note-key = 1430146b4d1a70234ac81b1126277834842cbf647aba07abe809279bf0e67703
data-key = f5449234f3f6d8e3e61723dfafc7e68a92a5128c1e9893df8bf33a4afc312b36
```

### Commitment vectors

`version` is the commitment format version (section 10). The first block is
version 1, without a salt, as on a chain before the salt was added: a commit of
1 GHOST under the standard example key (number 0), then the remainder of a
reveal that leaves 0.7 GHOST (number 1), then a data commitment. These leaves
stay valid, so their vectors stay.

```text
[coin-commit]
kind = coin-commitment
version = 1
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 0
amount = 1000000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
type-tag = 0101
fingerprint = b44338ab6f6dcb3d63772c457737afd38a841207725e1440d235c4f6be0c4d8b
commitment = 562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458
marker = 671b869daf27c895e24a009e3d471e893e8e6ffe62f0309b4e5402c94c47ec85

[coin-remainder]
kind = coin-commitment
version = 1
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 1
amount = 700000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
type-tag = 0101
fingerprint = 06917a6f382fb7dabd47f6461319883f17f2bf3a8ebc1f00cbb1183b168389be
commitment = 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15
marker = 5d48e3dc546948dd0950d37c35573b383dfb111d88da4eebd88e98bfbb615d80

[data-commit]
kind = data-commitment
version = 1
key = 2718 2818 2845 9045 2353 6028 7471 3526 6249 7757 2470 4457
index = 0
content-ascii = Ghost example data
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
type-tag = 0102
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
fingerprint = a7450331b78ed2a6cf4864e6fdf58c1147e0cb4c8608e0dc0b37ec94f67e5b41
commitment = 39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06
marker = 2e6197db3367a4096dc6d75046a80af0d53a6842ad868d95b141adcbc1b6f349
```

### Salted commitment vectors

Version 2, the format a wallet makes. The same keys, numbers, amounts and
content as above, each under two example salts. The salts here are fixed so
that the vectors can be repeated; a wallet draws every salt fresh from its
secure random source. The same secret under two salts gives unrelated
fingerprints, commitments and markers, and neither matches the version 1 value
above, so one guess at a key no longer checks every leaf (section 3,
"Multi-target guessing"). Their kinds, `salted-coin-commitment` and
`salted-data-commitment`, are their own: a `coin-commitment` or
`data-commitment` vector is always version 1, so a reader that knows only
version 1 never meets a salt.

```text
[coin-commit-salted]
kind = salted-coin-commitment
version = 2
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 0
amount = 1000000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 00112233445566778899aabbccddeeff
type-tag = 0201
fingerprint = 6f7edf086ae8451b86811fcc222a6c3b77e1010705b57d64fd336a9f114c11a3
commitment = 72ab16e25e13d2101dbfad21972605641aa4f2ea369b7173edd4d3ba2678689d
marker = 3c282d093fe067c0b1c5a006ad8b63d3f39c7474875a344d403f4c90f67147d7

[coin-commit-salted-other]
kind = salted-coin-commitment
version = 2
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 0
amount = 1000000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = f0e1d2c3b4a5968778695a4b3c2d1e0f
type-tag = 0201
fingerprint = 03c501af5675709301cff4e93da4140792f4ccfff3b2b2a16ff55b2bf1ecc5ab
commitment = be9a0db30dbd08f5af50b766ceafd3c15f3f843d9cf5122682e002448380bd74
marker = 9dfea129ee1bc7ed31a2b88898d46086fb3f809cd82c49bffa21f8e08da28a1b

[coin-remainder-salted]
kind = salted-coin-commitment
version = 2
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 1
amount = 700000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 0123456789abcdeffedcba9876543210
type-tag = 0201
fingerprint = 8d8f86ffe5d0c251cfe7d8cfa9e49287e8e83fc6cb3dd3345213c812d67cf81a
commitment = 7b2269649fa191df18cf80dde1e81f5cf61bb00a7faf17f58aafc197251393ab
marker = 7815b5757618c80fc7dcc8e65ff2c88a988a44e9a64b1da24442609e81a13c6f

[coin-remainder-salted-other]
kind = salted-coin-commitment
version = 2
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 1
amount = 700000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 89abcdef0123456776543210fedcba98
type-tag = 0201
fingerprint = bdd18c032eef7bfc6aec7268f7fe4446beafefd12a6808c1b6e24687eee0acac
commitment = c07b2ff99412387057a171046120ac0d57f63d9516a0bc612089a7cdf0200bf2
marker = c1a31a5f9b7a063f7fde8892a6ce0ec7633e5a7dd0911865c4b6f9c5b305db4c

[data-commit-salted]
kind = salted-data-commitment
version = 2
key = 2718 2818 2845 9045 2353 6028 7471 3526 6249 7757 2470 4457
index = 0
content-ascii = Ghost example data
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 00112233445566778899aabbccddeeff
type-tag = 0202
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
fingerprint = c5248f5ae13e74d2ecd2ee324068ae947012a76b5a44d66bf6f59830a366a7e2
commitment = 324c90dbad0fbecfd82331d087ea216b525e68b8dcb64891aa59322565ebb8b5
marker = a76b9995583a8c40de091ddd470487840e5f04c77c5944ba62092ea6dc591991

[data-commit-salted-other]
kind = salted-data-commitment
version = 2
key = 2718 2818 2845 9045 2353 6028 7471 3526 6249 7757 2470 4457
index = 0
content-ascii = Ghost example data
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = f0e1d2c3b4a5968778695a4b3c2d1e0f
type-tag = 0202
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
fingerprint = 72ac806d9e8c49284e2cc0e10fff283fadeff8d0345954770960f68b1d0df358
commitment = 91e0e4460c6ffd42b5efcbd8a94e4fa91eb6a5e4aa17b1e8faf8eb38c6779f2f
marker = 9f8247164357d5578d6916d91f3e94b6acd09da806fdac9e4424fba722a47d70
```

### Tree vectors

```text
[empty-leaf]
kind = empty-leaf
leaf = e050b25c8ab09717b0a6846b688b5047b93c0d37e18599cc7deec37f914bcca4

[coin-tree-node]
kind = tree-node
tree = coin
level = 0
left = 562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458
right = 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15
node = cc8b5b4159cc8853fc72d43b3c64807607386b732abf9fbaa93a6ee9ef574026

[data-tree-node]
kind = tree-node
tree = data
level = 0
left = 39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06
right = e050b25c8ab09717b0a6846b688b5047b93c0d37e18599cc7deec37f914bcca4
node = 758f3cd54a14569d259552727fb0c8d19d41b8a15ae6305559fcd6502a105a4a
```

### Note vectors

The plaintext and associated data of the notes stored with `[coin-remainder]`
and `[data-commit]`. Encryption itself follows RFC 8439 and its own vectors.

```text
[note-coin-remainder]
kind = note
type = COIN
index = 1
amount = 700000000000000000
content-fingerprint = 0000000000000000000000000000000000000000000000000000000000000000
content-length = 0
rule = 0000000000000000000000000000000000000000000000000000000000000000
chain-id = 1234
leaf = 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15
plaintext = 01010101000000000000000100000000000000000000000000000000000000000000000009b6e64a8ec60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
associated-data = 00000000000004d293312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15

[note-data-commit]
kind = note
type = DATA
index = 0
amount = 0
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
chain-id = 1234
leaf = 39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06
plaintext = 01010102000000000000000000000000000000000000000000000000000000000000000000000000000000007da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c00000000000000120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
associated-data = 00000000000004d239c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06
```

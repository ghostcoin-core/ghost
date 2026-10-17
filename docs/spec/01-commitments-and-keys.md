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
| Commitment format | One format with a type tag: secret `s`, reveal secret `r`, blinding `b`, type tag, content fingerprint, rule; a coin commitment adds the amount | Outline ("Core protocol" 3) |
| Two-step commitment | The wallet's fingerprint, then the node's commitment over type tag, fingerprint and (for coins) amount | [Spec 03](03-coin-rules.md), section 5; [spec 04](04-data-commitments.md), section 3 |
| Hash for commitments, markers, tree nodes and anything checked inside a proof | Keccak-256, original padding | Front desk decision; [benchmark results](../benchmarks/results.md) |
| Hash for deriving secrets from the digits, the note key and the checksum | SHA3-256 (FIPS 202) | Front desk decision; use for the checksum **Proposed** |
| Tags | Explicit ASCII strings with a version suffix, one per use, prefixed by their length; all listed in section 4 | Front desk decision; prefix **Proposed** |
| Phantom Key | Twelve groups of four digits, the last a checksum: 44 secret digits, about 146 bits | Outline ("Phantom Keys") |
| Long Phantom Key | Twenty-four groups: groups 12 and 24 are checksums, 88 secret digits, about 292 bits | Outline; layout **Proposed** |
| Checksum | The tagged SHA3-256 of the digits before it, reduced modulo 10,000 | Front desk decision (author's choice); **Proposed** |
| What the key holds | Only the secret digits and the checksum: no amount, tree position or extra secret | Outline ("Do not carry over") |
| Derivation | Each secret is the tagged SHA3-256 of the key bytes, one tag per secret | Outline ("Technical starting picks"); layout **Proposed** |
| Remainder blinding | Derived from the digits and a counter that never repeats for the key | Outline ("Coin rules"; "Do not carry over"); counter **Proposed** |
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
- **Digits** are a Phantom Key (outline, "Phantom Keys"). **Key bytes** are
  the encoding of the digits that every derivation takes (section 7).
- `COIN` and `DATA` are the two type tags of version 1 (section 10).
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
| type tag | 2 bytes | The commitment format version, then the type: `COIN` is `0x01 0x01`, `DATA` is `0x01 0x02` (section 10) |
| `cf` | 32 bytes | The content fingerprint. For `DATA`, a tagged hash of the content (below). For `COIN`, 32 zero bytes: a coin has no content |
| `rule` | 32 bytes | The optional rule, as a 32-byte value. The empty rule is 32 zero bytes, and it is the only rule version 1 accepts ([spec 03](03-coin-rules.md), section 7, step 11; [spec 04](04-data-commitments.md), question 9) |
| `v` | 32 bytes | Coins only: the amount in wei, an integer in `[0, V_MAX]` with `V_MAX = 2^96 - 1` ([spec 03](03-coin-rules.md), section 2) |

The commitment is built in two steps, so that the chain, not the user, binds the
amount and the type ([spec 03](03-coin-rules.md), section 5; base client plan
7.3). The wallet computes a fingerprint and the commit carries it; the node
computes the commitment and writes it as the leaf.

```text
coin:  F   = K("ghost/coin-fingerprint/v1", s, r, b, COIN, cf, rule)
       C   = K("ghost/coin-commitment/v1", COIN, F, v)

data:  F_d = K("ghost/data-fingerprint/v1", s, r, b, DATA, cf, rule)
       C   = K("ghost/data-commitment/v1", DATA, F_d)
```

`v` is the amount the node has just burned, and the type tag in the outer hash
is set by the node. A remainder commitment is built the same way inside the
reveal proof, from its own fresh blinding and its own amount.

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
coin marker:  m = K("ghost/coin-marker/v1", r, b)
data marker:  m = K("ghost/data-marker/v1", r, b)
```

so one commitment has one marker, and a remainder, which has fresh blinding,
has a different one. The two tags keep the coin and data spent-marker sets
apart ([spec 04](04-data-commitments.md), section 2). This is the layout the
[benchmark plan](../benchmarks/plan.md) costed (the tagged hash of `r` and
`b`).

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
  coin and the other way round.
- The marker it publishes or checks is computed from the same `r` and `b` as
  the commitment it opens.
- A remainder keeps the input's type tag, `cf` and `rule`
  ([spec 03](03-coin-rules.md), section 8); its `s`, `r` and `b` are inputs the
  proof does not constrain, so the chain cannot tell a claim to a new key from
  a partial reveal under the same key. Freshness of `b` is the wallet's rule
  (section 8), not something the proof can check.
- Every value checked inside a proof is a Keccak-256 hash of section 4 with its
  own tag. No SHA3-256 value of section 7 is ever recomputed inside a proof;
  the proof takes `s`, `r` and `b` as private inputs.

**Hiding.** `F`, `C` and the marker hide `s`, `r`, `b`, `cf` and `v` because
`b` is 256 bits from a one-way derivation and Keccak-256 is a preimage-resistant
hash (threat model, A1). The commit publishes `F` and `C`; a reveal publishes
the marker and never `F` or `C`.

## 4. Tagged hashing

Every use of a hash carries its own explicit tag (outline, "Core protocol" 10),
so a value made for one use can never be passed off as another. A tag is an
ASCII string of the form `ghost/<use>/v<version>`. It is encoded as one byte
holding its length, then its bytes. The length byte makes the encoding prefix
free: no tag followed by data can read as another tag followed by other data.
Within one tag every input has a fixed width, so the inputs cannot be shifted
between fields either.

Every tag of version 1 is in this table. No other tag exists; a new use gets a
new row before it is used.

| Tag | Hash | Use | Inputs after the tag | Input bytes | Keccak permutations |
|---|---|---|---|---|---|
| `ghost/key-check/v1` | SHA3-256 | Phantom Key checksum (section 6) | format code, part, the digits before the checksum group as ASCII | 21 + digits | not in a proof |
| `ghost/secret/v1` | SHA3-256 | Secret `s` (section 7) | key bytes | 16 + key bytes | not in a proof |
| `ghost/reveal-secret/v1` | SHA3-256 | Reveal secret `r` (section 7) | key bytes | 23 + key bytes | not in a proof |
| `ghost/blinding/v1` | SHA3-256 | Blinding `b_i` of the key's commitment number `i` (section 8) | key bytes, `i` as 8 bytes | 26 + key bytes | not in a proof |
| `ghost/note-key/v1` | SHA3-256 | Note key `k_note` (section 9) | key bytes | 18 + key bytes | not in a proof |
| `ghost/data-key/v1` | SHA3-256 | Data key `k_data` ([spec 04](04-data-commitments.md), section 4) | key bytes | 18 + key bytes | not in a proof |
| `ghost/coin-fingerprint/v1` | Keccak-256 | Coin fingerprint `F` (section 3) | `s`, `r`, `b`, `COIN`, `cf`, `rule` | 188 | 2 |
| `ghost/coin-commitment/v1` | Keccak-256 | Coin commitment `C`, the coin-tree leaf (section 3) | `COIN`, `F`, `v` | 91 | 1 |
| `ghost/data-fingerprint/v1` | Keccak-256 | Data fingerprint `F_d` (section 3) | `s`, `r`, `b`, `DATA`, `cf`, `rule` | 188 | 2 |
| `ghost/data-commitment/v1` | Keccak-256 | Data commitment `C`, the data-tree leaf (section 3) | `DATA`, `F_d` | 59 | 1 |
| `ghost/content-fingerprint/v1` | Keccak-256 | Content fingerprint `cf` (section 3) | content length as 8 bytes, content | 37 + content | not in a proof in version 1 |
| `ghost/coin-marker/v1` | Keccak-256 | One-time marker of a coin commitment (section 3) | `r`, `b` | 85 | 1 |
| `ghost/data-marker/v1` | Keccak-256 | One-time marker of a data commitment (section 3) | `r`, `b` | 85 | 1 |
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
  cost slightly less for the opening. The difference is a few permutations per
  proof, against a measured worst case of about 5.2 seconds for the whole
  proof against a 10-second target ([benchmark results](../benchmarks/results.md)).

## 5. Phantom Key format

A Phantom Key is the digits returned on commit (outline, "Phantom Keys"). It is
shown and typed as groups of four decimal digits separated by spaces:

```text
1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
```

- **Standard key: twelve groups.** Groups 1 to 11 are the secret: 44 digits,
  `10^44`, about 2^146.2 equally likely values, so about 146 bits of secret
  (outline). Group 12 is the checksum (section 6). Against a quantum search
  this gives about 73 bits, less when an attacker targets any one of billions of
  public commitments (threat model, C20).
- **Long key: twenty-four groups (Proposed layout).** The key is two halves of
  twelve groups. Groups 1 to 11 and 13 to 23 are the secret: 88 digits, about
  2^292.3 values, so about 292 bits, about 146 against a quantum search (threat
  model, C20). Group 12 is a checksum over groups 1 to 11, and group 24 a
  checksum over all 22 secret groups, so a mistyped half is found and named
  before the second half is typed.
- **Format code.** The number of groups selects the format: code `0x0C` for
  twelve groups, `0x18` for twenty-four. The code enters the checksum and every
  derivation, so the same secret digits in the two formats give unrelated
  secrets, and the first half of a long key does not pass as a standard key
  (vector `checksum-long-first-half` in section 14).
- **Generation.** Always by the app from a secure random source (outline;
  threat model, A6). Each secret digit is drawn independently and uniformly:
  take one byte from the secure source, discard it if it is 250 or more, and
  otherwise use its value modulo 10. Then append the checksum groups. Any
  other method must produce the same uniform distribution over all `10^44` (or
  `10^88`) secret values.
- **Entry.** A wallet accepts the digits with any mix of spaces and hyphens
  between them and rejects any other character, including non-ASCII digits.
  After separators are removed there must be exactly 48 or 96 digits. It then
  checks the checksum groups before deriving anything.
- **What the key carries.** The secret digits and the checksum, nothing else.
  It holds no amount, no tree position, no extra secret and no version field
  beyond its length (outline, "Do not carry over": the old key was about 34
  groups because it held these). The amount, position and index of the current
  remainder are found on the chain (section 8).
- **No passphrase variant.** There is no passphrase-protected key, which would
  allow offline guessing (outline, "Do not carry over"), no master number and
  no receiving address (outline, "Phantom Keys").
- **One key, one first commitment.** The app generates a new key for every
  commit and for every claim to a new key, and never makes a second first
  commitment under a key that already has one, because two leaves with the
  same blinding would share a marker (section 8).

## 6. Checksum

The checksum is the last group of four digits (front desk decision), and for a
long key also group 12. Each check group is

```text
check(code, part, digits) = int(S("ghost/key-check/v1", code, part, digits)) mod 10000
```

written as four digits with leading zeros. `code` is the format code as one
byte, `part` is one byte (`0x01` for group 12, `0x02` for group 24), `digits`
are the ASCII digits of the secret groups before the check group (groups 1 to
11 for group 12; groups 1 to 11 and 13 to 23 for group 24), and `int` reads
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

**Where it is checked.** Only in the wallet, when digits are entered. The
checksum never reaches the chain and no proof checks it.

## 7. Derivation

Every secret is derived from the digits with standard hashing (outline,
"Technical starting picks": "Every secret derived from the digits with standard
hashing"). The digits are all that is needed; nothing else is stored.

**Key bytes.** The input to every derivation is

```text
key_bytes = code || secret digits as ASCII
```

with `code` the format code (`0x0C` or `0x18`) and the secret digits being the
44 or 88 digits of the secret groups in order, without the checksum groups and
without separators. A standard key gives 45 key bytes, a long key 89.

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
  notes (section 8).
- **No stretching.** The digits are random, not chosen by a person, so a slow
  password hash would add little: at about 146 bits an exhaustive search is out
  of reach either way.

## 8. Remainder and the current commitment

A partial reveal uses a commitment up and creates one fresh commitment for the
remainder (outline, "Coin rules"; [spec 03](03-coin-rules.md), section 8). The
old design derived the same remainder blinding on every partial reveal and
guessed the remainder's tree position; both are on the outline's "Do not carry
over" list.

**Fresh blinding on every commitment (Proposed).** The commitments a key makes
are numbered `i = 0, 1, 2, ...`. Number 0 is the key's first commitment: the
commit, or the remainder of a claim into a new key. Commitment number `i` uses
the blinding `b_i` of section 7. Every reveal under the key creates its
remainder with the next unused number:

```text
i_next = 1 + the highest number this key has used
```

where "used" counts every number found in the key's notes on the chain
(spent or not) and every number in a transaction this wallet has broadcast,
included or not. A retry after a dropped or reorganised reveal therefore takes
a new number too. Numbers may have gaps; restore does not need them to be
consecutive.

- **Never the same value twice.** Distinct numbers give distinct `b_i` (the
  collision resistance of SHA3-256), so every remainder has a commitment and a
  marker that differ from every earlier one in its sequence (threat model,
  C26). No two published values of the sequence are equal.
- **Same key by default.** By default the remainder keeps `s` and `r`, so the
  same key controls it. A claim uses a newly generated key, whose own
  commitment number 0 holds the remainder (outline, "Coin rules").
- **If a number is reused anyway.** A wallet on a second device that has not
  seen a pending reveal of the first can pick the same number. Both reveals
  spend the same input, so they publish the same input marker and at most one is
  included ([spec 03](03-coin-rules.md), section 8: two competing reveals), so
  only one of the two remainders ever exists on a chain. The two remainders
  would also share a marker, so neither could be revealed twice. Reuse links
  nothing the shared input marker did not already link and cannot double
  anything, but the wallet still avoids it as above.
- **Data commitments** have no remainder in version 1
  ([spec 04](04-data-commitments.md), question 3), so a data key uses only
  `b_0`.

**How the same key finds its current remainder (Proposed).** On a clean device,
from the digits alone (outline, "First milestone" 4; threat model, C21 and
C41):

1. Check the checksum and derive `s`, `r` and `k_note` (sections 6 and 7).
2. Fetch the note history of the coin tree in bulk: every leaf with its
   position and its note. Never ask an endpoint for one commitment, one
   position or one marker (threat model, section 6 item 8).
3. Try `k_note` on every note (section 9). Under authenticated encryption only
   the key's own notes decrypt; every other note fails and is passed over.
4. For each note that decrypts, read its number `i`, amount `v`, type tag,
   `cf` and `rule`; compute `b_i`, then `F` and `C` (section 3). If `C` is not
   the leaf the note is stored with, discard that note and report it; never
   trust a note's contents without this check.
5. Compute each found commitment's marker and look it up in the coin
   spent-marker set, also fetched in bulk.
6. The current remainder is the found commitment whose marker is unspent. Its
   tree position is the position of its leaf, read from the chain, never
   guessed. If none is unspent, the key's value has been fully revealed or
   claimed away. If more than one is unspent (only possible if a key was
   wrongly used for two first commitments), the wallet shows each.
7. The next number to use is one more than the highest `i` found.

Every note ciphertext uses a fresh random nonce, every marker is a hash of a
different `b_i`, and no request names a single value, so restore publishes and
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

## 10. Version tags and scheme IDs

Everything that is hashed, stored or encrypted carries a version, so that a
later scheme can be added and old commitments migrated safely (outline,
"Extension points" 1 and 4).

| Item | Version 1 value | Where it sits |
|---|---|---|
| Tag version | suffix `/v1` | Every tag of section 4 |
| Commitment format version | `0x01` | First byte of every type tag; inside `F` and `C` |
| Type | `0x01` coin, `0x02` data | Second byte of the type tag |
| Key format code | `0x0C` standard, `0x18` long | Implied by the number of groups; first byte of the key bytes and the checksum input |
| Note version | `0x01` | Byte 0 of the note plaintext |
| Scheme ID | `0x01` | Byte 1 of the note plaintext; implied by commitment format version 1 |

**Scheme 1** is this whole document: Keccak-256 with the tags of section 4 for
commitments, markers and trees; SHA3-256 for the checksum and derivation;
ChaCha20-Poly1305 for notes; the key formats of section 5.

**Rules (Proposed).**

- A type tag, note version or scheme ID the reader does not know is rejected
  everywhere it is checked. Nothing is read with a guessed version.
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
- A new key format (for example a different group count) gets a new format
  code. A new checksum rule gets a new check tag, so a wallet can tell versions
  apart by which checksum the digits pass.

## 11. What this document does not fix

- The proof statements, their public inputs and constraints, and the binding
  digest layouts (next specification).
- The tree's shape, rollover and root rules beyond the node and empty-leaf
  hashes (tree and header specification).
- The transaction formats, including where `F` and the note sit in the commit
  payload (transaction-format specification).
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
   8, carries the type tag unchanged into the remainder. Moving a commitment to
   a later scheme (section 10) needs a remainder at a new commitment format
   version, which that rule forbids. Nothing is needed for version 1; the rule
   must be revisited when a second scheme exists.

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
exactly the tags it uses.

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

A commit of 1 GHOST under the standard example key (number 0), then the
remainder of a reveal that leaves 0.7 GHOST (number 1), then a data commitment.

```text
[coin-commit]
kind = coin-commitment
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 0
amount = 1000000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
fingerprint = b44338ab6f6dcb3d63772c457737afd38a841207725e1440d235c4f6be0c4d8b
commitment = 562d92a92bb8f2b3b772b55220a5ee26f189bedc0f4bfa513205df1545029458
marker = 671b869daf27c895e24a009e3d471e893e8e6ffe62f0309b4e5402c94c47ec85

[coin-remainder]
kind = coin-commitment
key = 1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417
index = 1
amount = 700000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
fingerprint = 06917a6f382fb7dabd47f6461319883f17f2bf3a8ebc1f00cbb1183b168389be
commitment = 93312061656298f41cd5a9f116d070b38b0acf5f8d968c58e32170f70e7aed15
marker = 5d48e3dc546948dd0950d37c35573b383dfb111d88da4eebd88e98bfbb615d80

[data-commit]
kind = data-commitment
key = 2718 2818 2845 9045 2353 6028 7471 3526 6249 7757 2470 4457
index = 0
content-ascii = Ghost example data
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
fingerprint = a7450331b78ed2a6cf4864e6fdf58c1147e0cb4c8608e0dc0b37ec94f67e5b41
commitment = 39c4e1e8edca6f366db5125e1bc9484063fa9f35da539638207f03732d913b06
marker = 2e6197db3367a4096dc6d75046a80af0d53a6842ad868d95b141adcbc1b6f349
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

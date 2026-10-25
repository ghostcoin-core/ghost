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
| Commitment format version | Version 2, the salted format, the only one: the version byte of the type tag and the `v2` fingerprint and marker tags (section 10) | Front desk decision |
| Two-step commitment | The wallet's fingerprint, then the node's commitment over type tag, fingerprint and (for coins) amount | [Spec 03](03-coin-rules.md), section 5; [spec 04](04-data-commitments.md), section 3 |
| Hash for commitments, markers, tree nodes and anything checked inside a proof | Keccak-256, original padding | Front desk decision; [benchmark results](../benchmarks/results.md) |
| Hash for deriving secrets from the digits, the note key and the checksum | SHA3-256 (FIPS 202) | Front desk decision; use for the checksum **Proposed** |
| Tags | Explicit ASCII strings with a version suffix, one per use, prefixed by their length; all listed in section 4 | Front desk decision; prefix **Proposed** |
| Phantom Key | 24 words of the 2,048-word list: a 256-bit secret and an 8-bit check, about 128 bits against a quantum search; the same key can be shown as 21 groups of four digits. The only key format: the twelve- and twenty-four-group digit keys are refused | Founder direction, 2026-10-20 (quantum-safe, easy to write down by hand); spec 09, section 4.2; digit keys removed, front desk decision 2026-10-25 |
| Binding | Rests on a Keccak-256 collision: 128 classical bits, 85 quantum bits ([security](../scale/security.md)), distinct from the key's 128 bits against guessing (section 5) | Front desk decision, 2026-10-25; the 320-bit digest stays a founder call |
| Checksum | Words: the first byte of a tagged SHA3-256 of the secret. Digit view: the tagged SHA3-256 of the 80 secret digits, reduced modulo 10,000 | Front desk decision (author's choice); **Proposed** |
| What the key holds | Only the secret digits and the checksum: no amount, tree position or extra secret | Outline ("Do not carry over") |
| Derivation | Each secret is the tagged SHA3-256 of the key bytes, one tag per secret | Outline ("Technical starting picks"); layout **Proposed** |
| Remainder blinding | Derived from the digits and the commitment's hop number, used once per key on any one chain (section 8) | Outline ("Coin rules"; "Do not carry over"); counter **Proposed** |
| Finding the current remainder | Bulk trial decryption of the notes, then the marker of each found commitment against the spent-marker set | Threat model, section 6 item 8; method **Proposed** |
| Encrypted note | 156 bytes on the chain: random nonce, ChaCha20-Poly1305 ciphertext of a fixed 128-byte plaintext, tag. Note version 2 carries the commitment's salt (section 9) | Outline ("Core protocol" 11); scheme and layout **Proposed**; note version 2 front desk decision |
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
- `COIN` and `DATA` are the two type tags of commitment format version 2
  (section 10): `0x02 0x01` and `0x02 0x02`.
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
| `salt` | 16 bytes | A fresh random value from the wallet's secure random source, new for every commitment (below). Public, not derived from the digits |
| type tag | 2 bytes | The commitment format version, then the type: `COIN` is `0x02 0x01` and `DATA` is `0x02 0x02` (section 10) |
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
       C   = K("ghost/data-commitment/v1", DATA, DATA_RESERVE, F_d)
```

with `COIN` = `0x02 0x01` and `DATA` = `0x02 0x02`. This is commitment format
version 2, the only format. The salt sits right after `b`. The commitment tags
keep their `v1` suffix; the version byte inside the type tag names the format
there.

`v` is the amount the node has just burned, and the type tag in the outer hash
is set by the node: for every new commit it is the version 2 type tag.
`DATA_RESERVE` is the data commitment's fee reserve, the protocol constant
250,000,000,000,000,000 wei (2.5 x 10^17 wei, 0.25 GHOST) of
[spec 04](04-data-commitments.md), section 3, "The fee reserve": a data commit
sends exactly that value, the node burns it and puts it in the outer hash as
a 32-byte big-endian amount word, the same word format as a coin's `v`. The
wallet chooses no amount for data, and `F_d` has no amount field. A
remainder commitment is built the same way inside the reveal proof, from its
own fresh blinding, its own fresh salt and its own amount.

A reader or verifier that sees a version byte or a tag it does not know
rejects it and never guesses (section 10).

**Salt.** Every commitment, whether a commit, a remainder or a data
commitment, has its own salt: 16 bytes the wallet draws from its secure random
source when it makes the commitment (threat model, A6), never reused and never
computed from the digits or from another value. It is public: nothing rests on
keeping it hidden, and it is stored so that the holder can read it back from
the chain on restore (section 8). A commit publishes it with `F`; a remainder's
salt travels inside the remainder's encrypted note, because a reveal publishes
no field beyond those of [spec 02](02-proof-statements.md). Its place in the
note is fixed by note version 2 (section 9); its place in the commit
transaction is fixed with that format (section 11). The salt is not a replacement for `b`: `b` hides the commitment, the salt
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

with the same salt as the commitment, right after `b`. So one commitment has
one marker, and a remainder, which has fresh blinding and a fresh salt, has a
different one. The coin and data tags keep the coin and data spent-marker sets
apart ([spec 04](04-data-commitments.md), section 2). The
[benchmark plan](../benchmarks/plan.md) costed the tagged hash of `r` and `b`;
the 16 more bytes of the salt still fit in one Keccak permutation (section 4).

**Multi-target guessing.** An attacker who guesses keys wants any key that
holds anything, not one key in particular (threat model, C20). The salt keeps
one guess from being looked up at once against every `F` ever published and
every spent marker. Each leaf's `F`, `C` and marker depend on its own salt,
so a guess has to be hashed again for each leaf it is tested against, and
testing a guess against all `N` leaves costs `N` times as much as testing it
against one. Classically, finding any one key among the `N` then costs as much
as finding one given key; under a quantum search over pairs of a key and a
leaf, the `N` targets are offset by the `N` times larger search space, so the
cost is again about the square root of the key space. So:

| Key | One leaf or all leaves |
|---|---|
| 24 words (256 bits) | about 256 bits classical, 128 quantum |

The twelve-group digit key (about 146 bits, 73 quantum) and the
twenty-four-group one fell short of this or doubled every format, and are no
longer accepted (section 5).

Precomputation does not help either: no table built before a commit can hold
its salt. Salts are 128 bits drawn at random, so two leaves share one with
probability about 2^-63 even among 2^33 leaves, and a shared salt would only
let one guess be tested against those two leaves at once. The notes already
have no shortcut, because each is checked under its own random nonce and its
own leaf as associated data (section 9). The salt does not raise the cost of
guessing one particular key, which the key's length alone sets (section 5).

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
  coin and the other way round. The version byte of the type tag must be 2,
  opened with the `v2` fingerprint and marker tags and the salt; any other
  version is rejected.
- The marker it publishes or checks is computed from the same `r`, `b` and
  salt as the commitment it opens.
- A remainder keeps the input's type, `cf` and `rule`
  ([spec 03](03-coin-rules.md), section 8) and has its own salt; its `s`, `r`, `b` and salt are inputs the proof does not
  constrain, so the chain cannot tell a claim to a new key from a partial
  reveal under the same key. Freshness of `b` and of the salt is the wallet's
  rule (section 8), not something the proof can check.
- The salt is a private input of every proof that opens a commitment, never a
  public input. It is not secret, but the commit published
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

Every tag is in this table. No other tag exists; a new use gets a new row
before it is used. Input bytes count the length byte and
the tag as well as the inputs.

| Tag | Hash | Use | Inputs after the tag | Input bytes | Keccak permutations |
|---|---|---|---|---|---|
| `ghost/key-check/v1` | SHA3-256 | Phantom Key checksum (section 6) | format code, part, then the digits before the checksum group as ASCII, or for the words check the 32 secret bytes | 21 + digits; 53 for the words check | not in a proof |
| `ghost/secret/v1` | SHA3-256 | Secret `s` (section 7) | key bytes | 16 + key bytes | not in a proof |
| `ghost/reveal-secret/v1` | SHA3-256 | Reveal secret `r` (section 7) | key bytes | 23 + key bytes | not in a proof |
| `ghost/blinding/v1` | SHA3-256 | Blinding `b_i` of the key's commitment number `i` (section 8) | key bytes, `i` as 8 bytes | 26 + key bytes | not in a proof |
| `ghost/note-key/v1` | SHA3-256 | Note key `k_note` (section 9) | key bytes | 18 + key bytes | not in a proof |
| `ghost/data-key/v1` | SHA3-256 | Data key `k_data` ([spec 04](04-data-commitments.md), section 4) | key bytes | 18 + key bytes | not in a proof |
| `ghost/coin-fingerprint/v2` | Keccak-256 | Coin fingerprint `F` (section 3) | `s`, `r`, `b`, `salt`, `COIN`, `cf`, `rule` | 204 | 2 |
| `ghost/coin-commitment/v1` | Keccak-256 | Coin commitment `C`, the coin-tree leaf (section 3) | `COIN`, `F`, `v` | 91 | 1 |
| `ghost/data-fingerprint/v2` | Keccak-256 | Data fingerprint `F_d` (section 3) | `s`, `r`, `b`, `salt`, `DATA`, `cf`, `rule` | 204 | 2 |
| `ghost/data-commitment/v1` | Keccak-256 | Data commitment `C`, the data-tree leaf (section 3) | `DATA`, `DATA_RESERVE`, `F_d` | 91 | 1 |
| `ghost/content-fingerprint/v1` | Keccak-256 | Content fingerprint `cf` (section 3) | content length as 8 bytes, content | 37 + content | not in a proof in version 1 |
| `ghost/coin-marker/v2` | Keccak-256 | One-time marker of a coin commitment (section 3) | `r`, `b`, `salt` | 101 | 1 |
| `ghost/data-marker/v2` | Keccak-256 | One-time marker of a data commitment (section 3) | `r`, `b`, `salt` | 101 | 1 |
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
  a fingerprint is 204 bytes, still under the 272 bytes that two permutations
  absorb, and a marker is 101 bytes, under the 136 of one. Nor does the data
  fee reserve: a data commitment is 91 bytes, one permutation. The difference is a few permutations per
  proof, against a measured worst case of about 5.2 seconds for the whole
  proof against a 10-second target ([benchmark results](../benchmarks/results.md)).

## 5. Phantom Key format

A Phantom Key is the key returned on commit (outline, "Phantom Keys"). It is
shown and typed as 24 words, or as its digit view of 21 groups of four decimal
digits separated by spaces; both are the same key:

```text
abandon amount liar amount expire adjust cage candy arch gather drum bullet
absurd math era live bid rhythm alien crouch range attend journey trip

0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
```

- **Words key: 24 words, the only format (founder direction, 2026-10-20).**
  Quantum-safe and still easy to write down by hand. The key is 264 bits: a
  256-bit secret followed by an 8-bit check (section 6), read as 24 indexes of
  11 bits each, most significant bit first, into the 2,048-word BIP-39 English
  list (`client/src/wordlist/english.txt`, the same list as the wallet's own
  recovery words of [spec 09](09-quantum-safe-accounts.md), section 9). The
  words are unique by their first four letters. This is the layout of
  BIP-39, with Ghost's own check tag and format code: about 256 bits of
  secret, about 128 bits against one key under a quantum search, and the same
  128 against all leaves at once (section 3, "Multi-target guessing"; threat
  model, C20). 24 words is a length
  crypto users already write down for their backups. Scannable codes and file
  export stay conveniences, never the only way to back up a key.
- **The same key as digits.** For people who prefer digits, a words key is
  also shown as 21 groups of four: groups 1 to 20 are the secret as a decimal
  number, zero-padded to 80 digits, and group 21 is a checksum (section 6).
  A value of `2^256` or more in groups 1 to 20 is refused, since no words key
  has it. Words and digits give the same secret, the same key bytes and the
  same derived values (section 7).
- **No digit keys of twelve or twenty-four groups.** The digit keys issued
  before the words format, twelve groups (44 secret digits, about 146 bits, so
  about 73 against a quantum search) and twenty-four groups (88 secret digits),
  are no longer generated or accepted. The twelve-group key fell below the
  quantum-safe target of [spec 09](09-quantum-safe-accounts.md), section 4, and
  both doubled every format code, checksum and derivation. A new chain holds no
  leaf under them. Typed digits of 48 or 96, or of any count other than 84, are
  refused before anything is derived.
- **Format code.** The words format has code `0x20`, whether typed as words or
  as its 21 digit groups. The code enters the checksum and every derivation.
  The codes `0x0C` and `0x18` of the old digit keys are not used again.
- **Binding.** The key's 128 bits against a quantum search are its strength
  against guessing. Binding, that a commitment cannot be opened to two
  different values, is a different property and has a different level: it
  rests on finding a Keccak-256 collision: 128 classical bits and about 85
  quantum bits (85.3 by the `t^3 / 2^L` term of
  [security](../scale/security.md), modeled). A longer key does not raise it.
  A longer digest would, for example 320 bits squeezed from the same sponge
  (a 160-bit classical collision term); that changes the proof configuration
  and stays a founder call recorded in [security](../scale/security.md). Until
  it is taken, binding is stated at 128 classical bits and 85 quantum bits.
- **Generation.** Always by the app from a secure random source (outline;
  threat model, A6). A key takes 32 bytes from the secure source as its
  secret, then its check. Any other method must produce the same uniform
  distribution over all `2^256` secret values. No other format can be asked
  for.
- **Entry.** Text with a letter and no ASCII digit is read as words; any other
  text as digits. Words are case-insensitive and separated by any mix of
  spaces and hyphens. Only whole words of the list count: a word the list does
  not contain is rejected and named to the person (its number and the text
  typed), never corrected to a near word and never completed from a prefix;
  any character that is neither a letter nor a separator is rejected. There
  must be exactly 24 words, an error of its own, and then the check must pass,
  a separate error. Digits are accepted with any mix of spaces and hyphens
  between them; any other character, including a letter or a non-ASCII digit,
  is rejected. After separators are removed there must be exactly 84 digits;
  any other count, the 48 and 96 of the old digit keys among them, is refused.
  In every case the check is verified before anything is derived.
- **No fifteen-word key.** A shorter fallback of fifteen words (160 bits,
  about 80 against a quantum search) was considered and is not adopted: it
  would miss the target of [spec 09](09-quantum-safe-accounts.md), section 4,
  and 24 words is already a length people write down.
- **What the key carries.** The secret and its check, nothing else.
  It holds no amount, no tree position, no extra secret and no version field
  (outline, "Do not carry over": the old key was about 34
  groups because it held these). The amount, position, index and salt of the
  current remainder are found on the chain (section 8).
- **No passphrase variant.** There is no passphrase-protected key, which would
  allow offline guessing (outline, "Do not carry over"), no master number and
  no receiving address (outline, "Phantom Keys").
- **One key, one first commitment.** The app generates a new key for every
  commit and for every claim to a new key, and never makes a second first
  commitment under a key that already has one, because two leaves with the
  same blinding would share `s`, `r` and `b_0` (section 8). Their different
  salts keep their markers apart, but the rule stays.

## 6. Checksum

**Words key.** The check is the last 8 bits of the 24 words:

```text
check = first byte of S("ghost/key-check/v1", 0x20, 0x01, secret)
```

with `secret` the 32 secret bytes. Any wrong key, whatever the mistake (one
wrong word, two swapped words, a word from another key), passes with
probability 1 in 256; a word not in the list is caught before the check, so
the check only has to catch real words in the wrong place. The tag is
Ghost's own, not BIP-39's SHA-256 check. On its own that would let the
wallet's recovery words of [spec 09](09-quantum-safe-accounts.md), section 9,
pass a key field 1 time in 256, so the wallet closes the gap both ways (spec
09, section 9, rule 2): it never generates a seed whose words pass this check,
and its seed field refuses any words that do pass it. A seed the wallet
generates, typed into a key field, always fails the check; a words key typed into a seed field is refused as
a Phantom Key, and the screens that ask for one or the other never share a
field.

**Digit view.** The key shown as digits carries a check group of its own,
the last group of four digits, group 21 (front desk decision):

```text
check = int(S("ghost/key-check/v1", 0x20, 0x01, digits)) mod 10000
```

written as four digits with leading zeros. `0x20` is the format code as one
byte, `0x01` one byte, `digits` the 80 ASCII digits of groups 1 to 20, and
`int` reads the 32-byte digest as a big-endian integer. The bias from reducing
a 256-bit integer modulo 10,000 is below 2^-240.

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
  100 random errors passes, against 1 in 10,000 here. With 21 groups to type, group
  swaps and multiple typos are the errors that matter, and four digits of
  check spent on a single-error guarantee would buy less.
- **No second algorithm.** SHA3-256 is already needed for derivation
  (section 7), so the checksum adds no primitive to implement or review.
- **No secret in the checksum.** The check is a function of the secret digits
  and costs none of the 256 bits. It does let a guesser discard 9,999 in
  10,000 wrong guesses offline, but the guesser still has `2^256` candidates
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
key_bytes = 0x20 || the 32 secret bytes
```

A key gives 33 key bytes, the same whether it was typed as words or as its 21
digit groups.

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
  password hash would add little: at 256 bits an exhaustive search is out
  of reach either way. An optional slow hash before derivation was considered
  and is not adopted: with a 256-bit secret there is nothing
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
the blinding `b_i` of section 7 and a salt drawn fresh for that
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
  `b_i` (the collision resistance of SHA3-256), and a remainder also has its
  own random salt, so every remainder has a commitment and a marker
  that differ from every earlier one in its sequence on the same chain (threat
  model, C26). A key's commitments on one chain form a
  single line, because each one after number 0 is made by spending the key's
  one unspent commitment, so the numbers on one chain are 0, 1, 2, ... once
  each. Two included reveals that made the same number `k` would both spend the
  key's number `k - 1` on that chain, publish the same input marker, and only
  one of them is included.
- **Equal numbers, different salts.** A marker `K(tag, r, b_i, salt)` depends on the key, the number and the commitment's
  own salt. Two remainders numbered `k`, made on one chain, on two branches, by
  two devices or by a retry, come from reveals that publish the same input
  marker, the marker of number `k - 1` (that marker is the input's, fixed when
  the input was made). They share their blinding but not their salt, so their
  commitments and their own markers are unrelated, and revealing them in turn
  ties nothing together. One chain still accepts one reveal per input marker,
  so nothing is doubled.
- **Same key by default.** By default the remainder keeps `s` and `r`, so the
  same key controls it. A claim uses a newly generated key, whose own
  commitment number 0 holds the remainder (outline, "Coin rules").
- **A key used for two first commitments.** Both are number 0. Their salts
  differ, so both can be revealed, but they still share `s`, `r` and `b_0`.
  The wallet never does this (section 5, "Generation").
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
   `cf` and `rule`, and the commitment's salt, which note version 2 carries
   (section 9; a commit also publishes it with its leaf); compute `b_i`, then
   `F` and `C` (section 3). If `C` is not the leaf the note is stored with, discard that note and report it; never
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
different `b_i` and a different salt, and no request names a
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

**Plaintext: 128 bytes, fixed.** Note version 2, told apart by byte 0, the
note a wallet writes for every commitment:

| Offset | Width | Field |
|---|---|---|
| 0 | 1 | Note version, `0x02` |
| 1 | 1 | Scheme ID, `0x01` (section 10) |
| 2 | 2 | Type tag: `COIN` `0x02 0x01` or `DATA` `0x02 0x02` |
| 4 | 8 | Commitment number `i` (section 8) |
| 12 | 12 | Amount `v` in wei, 12 bytes big-endian; zero for data |
| 24 | 32 | Content fingerprint `cf`; 32 zero bytes for a coin |
| 56 | 8 | Content length in bytes; zero for a coin |
| 64 | 32 | Rule; 32 zero bytes for the empty rule |
| 96 | 16 | The commitment's salt (section 3) |
| 112 | 16 | Zero padding |

The amount is 12 bytes because `V_MAX` is `2^96 - 1`
([spec 03](03-coin-rules.md), section 2), so no amount needs more.

The plaintext holds only what the key cannot derive. It never holds `s`, `r`,
`b_i`, `k_note`, `k_data`, the digits, a storage location or a tree position
([spec 04](04-data-commitments.md), section 4). The salt is public and is not
derived from the digits, so it belongs here.

A wallet rejects a note whose version, scheme ID or type tag it does not know,
or whose padding is not zero. Note version 2 is read only with a version 2
type tag; a note with any other type tag is rejected, never read with a
guessed layout.

**On the chain: 156 bytes, fixed.**
`nonce (12 bytes) || ciphertext (128 bytes) || tag (16 bytes)`. Every note has this one length, coin or data, so its length is not a
fingerprint (threat model, C18); the commit and reveal checks reject any other
length ([spec 03](03-coin-rules.md), section 6, step 5).

**What it gives away.** Without the digits, nothing beyond its fixed length.
Anyone shown the digits can read every note of the key (threat model, T6).

**The salt and the note.** A commitment can be opened only with its salt, so
the holder must be able to read the salt back from the chain. A commit
publishes it with `F`. A remainder's salt has nowhere public to go, because a
reveal publishes no field for it, so the remainder's note carries it, at
offset 96, under the reveal's binding of the note
([spec 02](02-proof-statements.md), section 7). A wallet writes note version 2
for every commitment, a commit's as well as a remainder's, so restore reads
every salt the same way; a commit's note carries
the same salt the commit publishes with `F`. On restore, the salt read from a
note is checked like every other field of the note: the commitment computed
with it must be the leaf the note is stored with (section 8, step 4).

## 10. Version tags and scheme IDs

Everything that is hashed, stored or encrypted carries a version, so that a
later scheme can be added and old commitments migrated safely (outline,
"Extension points" 1 and 4).

| Item | Value | Where it sits |
|---|---|---|
| Tag version | suffix `/v1`; `/v2` for the fingerprint and marker tags of commitment format version 2 | Every tag of section 4 |
| Commitment format version | `0x02` salted, the only version | First byte of every type tag; inside `F` and `C` |
| Type | `0x01` coin, `0x02` data | Second byte of the type tag |
| Type tags | `COIN` `0x02 0x01`, `DATA` `0x02 0x02` | Inside `F` and `C`; the note |
| Key format code | `0x20` words (24 words, or 21 digit groups), the only code; `0x0C` and `0x18` of the removed digit keys are not reused | First byte of the key bytes and the checksum input |
| Note version | `0x02` with the salt, the only version; read only with a version 2 type tag | Byte 0 of the note plaintext |
| Scheme ID | `0x01` | Byte 1 of the note plaintext; implied by commitment format version 2 |

**Scheme 1** is this whole document: Keccak-256 with the tags of section 4 for
commitments, markers and trees; SHA3-256 for the checksum and derivation;
ChaCha20-Poly1305 for notes; the key formats of section 5. Commitment format
version 2, with the salt in the fingerprint and the marker, is part of scheme
1. "Version 1" elsewhere in this document, without "commitment format", means
the first protocol version.

**The format version.** The version byte of the type tag says which format a
commitment has, and the type tag is inside both `F` and `C`. A commitment is
opened only with the `v2` fingerprint and marker tags and a 16-byte salt right
after `b`.

**The data fee reserve.** Data format version 2 (type tag `0x02 0x02`, tags
`v2`) now has `DATA_RESERVE` in the outer hash of `C` (section 3;
[spec 04](04-data-commitments.md), section 3, "The fee reserve"), so the
`ghost/data-commitment/v1` input is 91 bytes (section 4). The reserve re-sets
data format version 2 rather than adding a version 3: no recorded network or
fixture held a version 2 data leaf made without the reserve, and the vectors
of section 14 are computed with it. The coin format is unchanged.
`DATA_RESERVE` belongs to the version: changing it later is a new commitment
format version.

**Rules (Proposed).**

- A type tag, note version or scheme ID the reader does not know is rejected
  everywhere it is checked. Nothing is read with a guessed version.
- A reader or verifier that sees a commitment format version byte or a tag it
  does not know rejects it and never guesses (front desk decision). A type tag
  of version 2 opened without the `v2` fingerprint and marker tags or without
  a salt is rejected the same way.
- A note of note version 2 with a type tag of another version is rejected
  (section 9).
- Every commit, remainder and data commitment a wallet creates has a fresh
  salt.
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
  a commit (transaction-format specification). The note version that carries
  a commitment's salt is fixed here: note version 2 (section 9).
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
   8, keeps the input's type, `cf` and `rule` in the remainder and makes every
   remainder commitment format version 2 with a fresh salt. Moving a
   commitment to a later scheme (section 10) still needs that rule revisited
   when a second scheme exists.
8. **Phantom Key length.** [Spec 09](09-quantum-safe-accounts.md), section 4.2
   and question 1, proposes a 14-group key (about 172 bits) to meet its target
   against all leaves at once, and leaves this document unchanged until that
   is decided. This document instead makes the 24-word key the only format
   (section 5): about 128 bits against one key and, with the salt, about 128
   against all leaves at once under a quantum search, above that target. The 12-group and 24-group
   digit keys that spec 09 still describes are no longer generated or
   accepted.

## 13. Questions for the founder

Each has a default that this document already applies.

1. **Checksum algorithm.** Truncated SHA3-256 catches every kind of mistake at 1
   in 10,000, but does not guarantee to catch a single wrong digit. Default:
   truncated SHA3-256 (section 6).
2. **Binding digest length.** Binding rests on a Keccak-256 collision, 128
   classical and 85 quantum bits; a 320-bit digest would raise it, at the cost
   of a change to the proof configuration. Default: the 256-bit digest, stated
   at 85 quantum bits (section 5); the call is recorded in
   [security](../scale/security.md).
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

Every key below is a words key (section 5) written as its digit view of 21
groups: the checker reads the 80 secret digits and check group 21 (format code
`0x20`) and derives from the 32 secret bytes. The example key is
`abandon amount liar ... trip` of section 5 (secret `00 01 .. 1f`); the data
example key is `legal winner thank ... various` (secret `7f 7f .. 7f`). The
vectors that relate words to digits are in `client/tests/word_key.rs`.

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

`check` is the correct check group 21 for the key's 80 secret digits; `valid`
says whether the key as written passes. The example key, zero, the data
example key and `2^256 - 1` pass; one wrong digit, two swapped groups and
`2^256` (right check group, secret out of range) do not.

```text
[checksum-words]
kind = checksum
key = 0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
format = 20
check = 6812
valid = yes

[checksum-words-zero]
kind = checksum
key = 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0700
format = 20
check = 0700
valid = yes

[checksum-words-data]
kind = checksum
key = 0005 7669 0013 0642 8065 9560 5300 0376 8759 3842 1040 3453 0406 4124 0510 2397 3211 7841 8613 4399 8027
format = 20
check = 8027
valid = yes

[checksum-words-largest]
kind = checksum
key = 0011 5792 0892 3731 6195 4235 7098 5008 6879 0785 3269 9846 6564 0564 0394 5758 4007 9131 2963 9935 6994
format = 20
check = 6994
valid = yes

[checksum-one-digit-wrong]
kind = checksum
key = 0000 0001 7807 3186 0627 7000 4496 0723 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
format = 20
check = 4451
valid = no

[checksum-groups-swapped]
kind = checksum
key = 0000 0001 7807 3186 0627 7000 0722 4496 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
format = 20
check = 4660
valid = no

[checksum-words-too-large]
kind = checksum
key = 0011 5792 0892 3731 6195 4235 7098 5008 6879 0785 3269 9846 6564 0564 0394 5758 4007 9131 2963 9936 0340
format = 20
check = 0340
valid = no
```

### Derivation vectors

```text
[derivation-words]
kind = derivation
key = 0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
key-bytes = 20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
s = 62cff2e8a7db58fd67f745c8b24b75280335b28b88106384c735da7888ded4d1
r = 8fa3bd9e5bb56a3698801b1f016d08de1c883f178d1c3f6d544706d6cb4e1abe
b0 = 209f9782c7e6b7f64a0b0e0e1deda56dfae96af10eebe33aee50d6c5aa1144ea
b1 = 270868c5961cb6a126290431a569f33baa59cb5017d0dc6e2965e5cb63aacf8e
b2 = c3fd9b712431920e9baf30949ef7400ad02609ffcbb2a274ea15691d089bab38
note-key = 35136c4a7bdccb4b26159c15f86567a483ac58e1b2c40dca49a5d099272c4181
data-key = 97f75e4a033cf853da070528681b5af557e75070c54c9cd599b2b879915351af

[derivation-words-data]
kind = derivation
key = 0005 7669 0013 0642 8065 9560 5300 0376 8759 3842 1040 3453 0406 4124 0510 2397 3211 7841 8613 4399 8027
key-bytes = 207f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
s = 71346e4c283b18e2f1a77d5920f65d0848305b59764accadd7c49779b0eab58b
r = e1e807d15b2d02e98c2b5b1948535fa358c45b1679ef7e5195644d07a2b32f39
b0 = 2da9fad9db8f4e8f8b9897f02d2814e97c9811c89103473fc8762ae6dee35b0d
b1 = e4f33eac55470fc11d63503efa6184c858922c3586e77b7d53c3af2b36732557
b2 = c55cf5f0cfacf72c5e0942a7f4e7c59a3c433bff8db6a95f96d478803547c9f9
note-key = 08f3c586fe83f60374f0551ad5a25ddab61fd4fc70ab71572c0aae3b042c82ab
data-key = 8656f5cbfdecd73bb29f88309564a1610be34a6e12db2e6152778df15dc7cca3
```

### Salted commitment vectors

`version` is the commitment format version (section 10), always 2. The
vectors are a commit of 1 GHOST under the example key (number 0), then the
remainder of a reveal that leaves 0.7 GHOST (number 1), then a data
commitment under the data example key, each under two example salts. Their
kinds are `salted-coin-commitment` and `salted-data-commitment`. The salts
here are fixed so that the vectors can be repeated; a wallet draws every salt
fresh from its secure random source. The same secret under two salts gives
unrelated fingerprints, commitments and markers, so one guess at a key checks
one leaf (section 3, "Multi-target guessing").

```text
[coin-commit-salted]
kind = salted-coin-commitment
version = 2
key = 0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
index = 0
amount = 1000000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 00112233445566778899aabbccddeeff
type-tag = 0201
fingerprint = 8b4163e74a80b77f5cb3ca11a10a4482299d86193290c0dbe126eed33fadcf13
commitment = 1525d1f6caa2f9314988542a3dcb7ab5a76a9ba5dd3fef97a1ecf72ddeb516bc
marker = d93e36255156ef29b2e0785719a1a22ec2b03a8500013c94f5277aa1cb6daf78

[coin-commit-salted-other]
kind = salted-coin-commitment
version = 2
key = 0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
index = 0
amount = 1000000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = f0e1d2c3b4a5968778695a4b3c2d1e0f
type-tag = 0201
fingerprint = f0d8df5bafcd237f6ce079cca85ee24f6d8c9f8d27c3c7da1d5a5d9b2f4dcee2
commitment = ad1dc91acf32d8300693a5ed9d0c70dfc1e52d1721df648a19be869f7cf5db1f
marker = 8a674db2fa27d946788e49f4bfa33d5b39fd1f738164fea4490b4266ab71e621

[coin-remainder-salted]
kind = salted-coin-commitment
version = 2
key = 0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
index = 1
amount = 700000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 0123456789abcdeffedcba9876543210
type-tag = 0201
fingerprint = 47cd0d41d685ed61766f9c8a2475e04c33b2d8c75b25647210f482ad8ce2c26a
commitment = a1f0774fc85bd02f9661ce63b14484abc808950848b3797a980c201a2946af72
marker = f7476caa827fa1478d8f2a561e2638a7d4817793176eaced88798bf7d28fa806

[coin-remainder-salted-other]
kind = salted-coin-commitment
version = 2
key = 0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812
index = 1
amount = 700000000000000000
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 89abcdef0123456776543210fedcba98
type-tag = 0201
fingerprint = da130c26dc4beba75cff9ac5a0fd290eafbea8c4d9956b1daac36cfb728ff8a6
commitment = 44d90289fe50570b498537b5c4da8dabc46b7703dba96751da8eb16868a9af7e
marker = e76d066c481bbbc4fa3a67b5aeb5fab6675156207982ca03d8098985befa22b7

[data-commit-salted]
kind = salted-data-commitment
version = 2
key = 0005 7669 0013 0642 8065 9560 5300 0376 8759 3842 1040 3453 0406 4124 0510 2397 3211 7841 8613 4399 8027
index = 0
content-ascii = Ghost example data
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 00112233445566778899aabbccddeeff
type-tag = 0202
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
fingerprint = 166302e38b333317b6aa9cf4d62cf53ff15809a6180192333cb078c10e7eae7a
commitment = cb3181bcb1a051e9b2e9eb947f4dfe6aa30b70f37f1518153de92b15d5049e44
marker = c340c4a3020d70f72ed289d4e5fcc0c41cd41224d69bea229f0f8a6ecbb77e3b

[data-commit-salted-other]
kind = salted-data-commitment
version = 2
key = 0005 7669 0013 0642 8065 9560 5300 0376 8759 3842 1040 3453 0406 4124 0510 2397 3211 7841 8613 4399 8027
index = 0
content-ascii = Ghost example data
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = f0e1d2c3b4a5968778695a4b3c2d1e0f
type-tag = 0202
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
fingerprint = 9791d56e38696d267ba64caa54c3d5d9caa4dd00fb96c6caf7b8ade65724b660
commitment = a19fe2b42a927bf7c3d832c6650184166a52847c4218f021d84cd6d61346652b
marker = 40b6aa08963fee7e02d69cf4d7c5e9d2ba775d28991f4e08e27ed97c8a38acc8
```

### Tree vectors

The node vectors hash fixed example leaf values; any 32-byte values would do.

```text
[empty-leaf]
kind = empty-leaf
leaf = e050b25c8ab09717b0a6846b688b5047b93c0d37e18599cc7deec37f914bcca4

[coin-tree-node]
kind = tree-node
tree = coin
level = 0
left = 9cadb00df6812a83ff2525fbaef0b634a020d600dc3bf3315efc3b20bfdb876c
right = 5530014e689c4a5a4b494f49a4a5be5a08a2c4d78e66128b824e5c1309c00503
node = df419dcb5b0e8b93b8bc2dffb17e8257e0b8b7d5d177a69f1b6cd18acffaee6d

[data-tree-node]
kind = tree-node
tree = data
level = 0
left = 5bc2c9ef3f27a49943b7885eb8babf9be3dda232a41894f3ca5a09b0129340c1
right = e050b25c8ab09717b0a6846b688b5047b93c0d37e18599cc7deec37f914bcca4
node = 0de6f3bbe8f76caac7b160081a5eaca1dc70c1858774fe3cad999681b2ef4fdc
```

### Salted note vectors

The plaintext and associated data of the notes stored with
`[coin-remainder-salted]` and `[data-commit-salted]`. Encryption itself
follows RFC 8439 and its own vectors. `version` is the note version (section
9), always 2, and each note carries its commitment's salt at offset 96 after
a 12-byte amount. Their kind is `salted-note`, and the checker refuses one
whose type tag is not of version 2. Every note vector's `leaf` is the
commitment of a commitment vector above, and its fields are that
commitment's.

```text
[note-coin-remainder-salted]
kind = salted-note
version = 2
type = COIN
type-tag = 0201
index = 1
amount = 700000000000000000
content-fingerprint = 0000000000000000000000000000000000000000000000000000000000000000
content-length = 0
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 0123456789abcdeffedcba9876543210
chain-id = 1234
leaf = a1f0774fc85bd02f9661ce63b14484abc808950848b3797a980c201a2946af72
plaintext = 0201020100000000000000010000000009b6e64a8ec600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000123456789abcdeffedcba987654321000000000000000000000000000000000
associated-data = 00000000000004d2a1f0774fc85bd02f9661ce63b14484abc808950848b3797a980c201a2946af72

[note-data-commit-salted]
kind = salted-note
version = 2
type = DATA
type-tag = 0202
index = 0
amount = 0
content-fingerprint = 7da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c
content-length = 18
rule = 0000000000000000000000000000000000000000000000000000000000000000
salt = 00112233445566778899aabbccddeeff
chain-id = 1234
leaf = cb3181bcb1a051e9b2e9eb947f4dfe6aa30b70f37f1518153de92b15d5049e44
plaintext = 0201020200000000000000000000000000000000000000007da4cd394ac5e0c0054e0ae3b73f031cf36ece8091b8f877da1847ce5709398c0000000000000012000000000000000000000000000000000000000000000000000000000000000000112233445566778899aabbccddeeff00000000000000000000000000000000
associated-data = 00000000000004d2cb3181bcb1a051e9b2e9eb947f4dfe6aa30b70f37f1518153de92b15d5049e44
```

# Specification 08: the RandomX block seal

Status: draft for the founder's review, 2026-10-18. Nothing here is a new
choice. This chapter writes down the seal that ghost-node already implements:
its decision 0002 ("RandomX binding", settled 2026-10-17) and its
`consensus/randomx` package, with the difficulty comparison of its
`ghostrules` package. Where the two disagree with an earlier chapter, the
node's behaviour is recorded and the earlier chapter is updated to point
here ([spec 05](05-trees-and-headers.md), section 4, "Seal coverage";
[spec 06](06-consensus-and-emission.md), sections 2 and 10). The
[RandomX survey](../surveys/randomx.md) measured the options; its
recommendations for the salt, the epoch and the lag are the node's values
and are settled here. Section 13 names each place where the node's
behaviour is not pinned down well enough to write down, and what a
verifier does there.

This document fixes the RandomX version and configuration, the seal hash, the
bytes RandomX hashes, the target comparison, the mix digest, the key schedule
and how the key block is found. It also states what the client library's
light verification mode computes (section 10). It changes no consensus rule,
no constant and no node code. Mining, sealing and pools are outside it.

## 1. Decisions at a glance

| Topic | Choice | Source |
|---|---|---|
| Algorithm | RandomX v1; the v2 flag is never set | ghost-node decision 0002 |
| Reference | `tevador/RandomX` at commit `418f5497e60215fcd8a7cff2a16be835135833e5` | ghost-node decision 0002; survey |
| Configuration | The reference's defaults, except the Argon2 salt | ghost-node decision 0002 |
| Salt | 14 bytes: the ASCII text `Ghost-RandomX` followed by the byte `0x01` | ghost-node decision 0002; front desk decision |
| Verification mode | Light mode (256 MiB cache, no dataset), no large pages | ghost-node decision 0002 |
| Seal hash | Keccak-256 of the header's RLP with `mixDigest` and `nonce` set to zero | ghost-node `SealHash` |
| RandomX input | The 32-byte seal hash followed by the 8-byte nonce, big-endian (40 bytes) | ghost-node |
| Target | The 32-byte output, read big-endian, is at most `M // difficulty`, `M = 2^256 - 1` | ghost-node `SealValid`; spec 06, section 4.4 |
| Mix digest | Must be 32 zero bytes | ghost-node |
| Key | The 32-byte hash of the ancestor at `seedHeight(h)` on the header's own branch | ghost-node |
| Epoch and lag | `E = 8192`, `L = 256` | ghost-node; front desk decision |

## 2. Conventions

- `M = 2^256 - 1`. `a // b` is floor division, as in spec 06, section 2.
- "Big-endian" means the first byte is the most significant.
- `keccak256` is Keccak-256 with the original Keccak padding, as for the
  header hash (spec 05, section 10).
- Byte strings are written in hexadecimal; text in backquotes is ASCII.
- `RandomX(K, x)` is the 32-byte output of the reference's
  `randomx_calculate_hash` for key `K` and input `x`, in the configuration of
  section 3. `K` and `x` are byte strings of any length.

## 3. RandomX version and configuration

**Version.** RandomX v1. The pinned commit carries both algorithm versions
behind the run-time flag `RANDOMX_FLAG_V2`; a Ghost implementation never sets
it. Four of the reference's v1 test vectors (`src/tests/tests.cpp`) are
repeated in section 11.

**Configuration.** Every value of the reference's `src/configuration.h`
keeps its default except one:

| Constant | Value | Changed |
|---|---|---|
| `RANDOMX_ARGON_SALT` | `"Ghost-RandomX\x01"`: the 13 ASCII bytes of `Ghost-RandomX`, then `0x01`, 14 bytes, no terminating zero | **yes** (the reference's is `"RandomX\x03"`) |
| `RANDOMX_ARGON_MEMORY` | 262,144 (KiB; the 256 MiB cache) | no |
| `RANDOMX_ARGON_ITERATIONS` | 3 | no |
| `RANDOMX_ARGON_LANES` | 1 | no |
| `RANDOMX_CACHE_ACCESSES` | 8 | no |
| `RANDOMX_SUPERSCALAR_LATENCY` | 170 | no |
| `RANDOMX_DATASET_BASE_SIZE` | 2,147,483,648 | no |
| `RANDOMX_DATASET_EXTRA_SIZE` | 33,554,368 | no |
| `RANDOMX_PROGRAM_SIZE` | 256 | no |
| `RANDOMX_PROGRAM_ITERATIONS` | 2048 | no |
| `RANDOMX_PROGRAM_COUNT` | 8 | no |
| `RANDOMX_SCRATCHPAD_L3`, `_L2`, `_L1` | 2,097,152, 262,144, 16,384 | no |
| `RANDOMX_JUMP_BITS`, `RANDOMX_JUMP_OFFSET` | 8, 8 | no |
| Instruction frequencies | the reference's | no |

The node applies the salt as a one-line patch to `src/configuration.h`
(`librandomx/ghost-salt.patch`) and holds the same 14 bytes as
`randomx.Salt`; its test `TestSaltMatchesVendoredHeader` checks that the two
agree. Argon2 receives the salt's length as 14: the salt is the 14 bytes
above, with nothing after them.

**Mode.** Verification uses light mode: the 256 MiB Argon2d cache, with each
dataset item computed from the cache when a program reads it. Fast mode (the
2 GiB dataset) gives the same output and is a local choice of a node with
memory to spare. Large pages are not used. JIT, hardware AES and the
interpreter are local choices too; every combination gives the same output,
and only the output is consensus.

## 4. Seal hash

The header is the RLP list of spec 05, section 10: 19 fields, every one
required. The seal hash is

```text
sealHash(header) = keccak256(rlp(header with mixDigest = 32 zero bytes and nonce = 8 zero bytes))
```

Both seal fields keep their fixed sizes when they are zeroed, so `mixDigest`
is still encoded as `a0` and 32 zero bytes and `nonce` as `88` and 8 zero
bytes. No length in the encoding changes: the seal hash is the Keccak-256 of
the header's own bytes with the 32 bytes of the `mixDigest` value and the 8
bytes of the `nonce` value cleared.

The seal hash therefore covers every field except the two seal fields:
`parentHash`, `uncleHash`, `coinbase`, the three base roots, `logsBloom`,
`difficulty`, `number`, `gasLimit`, `gasUsed`, `timestamp`, `extraData`,
`baseFee`, both tree roots, `coinTreeRoot` and `dataTreeRoot`, and
`dataMarkerRoot`. This is
the seal coverage spec 05, section 4 requires: no relay can change a root
without redoing the work.

A header with zero `mixDigest` and zero `nonce` has a seal hash equal to its
header hash; the genesis example of spec 05 is one (section 11).

## 5. RandomX input

```text
input(header) = sealHash(header) || nonce
```

40 bytes: the 32-byte seal hash, then the 8 bytes of the header's `nonce`
field as they are encoded, which is the nonce as a big-endian 64-bit
integer. The RandomX output is `RandomX(key(header), input(header))`, with
the key of section 8.

## 6. Target

The 32-byte RandomX output, read as a big-endian 256-bit integer `x`, must
satisfy

```text
x <= M // D
```

where `D` is the header's `difficulty`. This is spec 06, section 4.4, with the
byte order spec 06, section 2 asked for. The bound is inclusive. A difficulty
that is not positive never validates; with the header encoding of spec 05 a
difficulty is never negative, so this means a difficulty of zero.

For integers, `x <= M // D` holds exactly when `x * D <= M`, that is, when the
512-bit product `x * D` is below `2^256`; an implementation may compare either
way.

`D` itself must already be the difficulty spec 06, section 4.3 requires of
the header (`required_difficulty`); the seal compares against the header's own
field, and the difficulty rule checks that field.

## 7. Mix digest

The header's `mixDigest` must be 32 zero bytes. RandomX has no separate
mix value: the output is recomputed by every verifier, so the field carries
nothing, and a non-zero value makes the header invalid. Requiring zero leaves
the field no room to carry data the seal does not cover.

## 8. Key schedule and the key block

For a header at height `h`:

```python
E = 8192
L = 256

def seed_height(h):
    if h <= E + L:
        return 0
    return (h - L - 1) // E * E      # (h - L - 1) rounded down to a multiple of E
```

`E` is a power of two, so the rounding is `(h - L - 1) & ~(E - 1)` as in
Monero's `rx_seedheight`. The key is the 32-byte hash (spec 05, section 10)
of the block at height `seed_height(h)` **on the header's own branch**: the
ancestor reached by following `parentHash` from the header,
`h - seed_height(h)` steps. It is never looked up by number in a canonical index,
which may hold a different block at that height on another branch.

- Heights 0 to `E + L` = 8448 use the genesis block's hash as the key; the
  first epoch is longer than the rest (spec 06, section 10 asked for the
  genesis hash as the first epoch's key).
- Key block `kE` (for `k >= 1`) is the key from height `kE + L + 1` to
  `(k + 1)E + L`. There are `L` blocks strictly between a key block and the
  first header that uses it.
- `seed_height(h) <= h - L - 1` for every `h > E + L`, so the key block is
  always a proper ancestor and never the header itself.
- The genesis header, height 0, carries a zero `nonce` and `mixDigest`
  (spec 06, section 8.3) and is accepted by its derivation, not by a seal.
  Its key would be its own hash. The seal check applies from height 1 on.

| Height `h` | `seed_height(h)` |
|---|---|
| 1 | 0 |
| 8192 | 0 |
| 8448 | 0 |
| 8449 | 8192 |
| 16640 | 8192 |
| 16641 | 16384 |
| 1000000 | 999424 |

Two branches that disagree on the key block have different keys for the same
height. Caches are therefore identified by the key itself, not by the epoch
number.

## 9. The seal check

A header that has decoded (spec 05, section 10) has a valid seal when all of
these hold:

1. Its `difficulty` is positive, and it is the difficulty required of the
   header (spec 06, section 4.4, checked by the difficulty rule).
2. Its `mixDigest` is 32 zero bytes.
3. The key `K` is the hash of its ancestor at `seed_height(h)` (section 8).
4. `RandomX(K, sealHash(header) || nonce)`, read big-endian, is at most
   `M // difficulty`.

The result is valid or invalid; the order in which an implementation tests
the conditions does not change it (section 13, item 1).

## 10. Light verification in the client

The client library checks a seal itself so that a client can refuse headers
an endpoint made up: a chain of headers with correct hashes and parent links
but no work behind them fails at step 4. Its seal module takes the header's
RLP bytes, the difficulty the caller requires of the header (big-endian), and
the key, and returns whether the seal is valid; it also refuses a header that
does not decode or does not carry that difficulty.

- **Implementation.** A Rust port of RandomX v1 light-mode hashing inside the
  client library: Argon2d with the Ghost salt, Blake2b, the AES generators and
  hash in software, the Blake2 generator, SuperscalarHash and dataset items
  from the cache, and the program VM as an interpreter, with the four
  rounding modes of `CFROUND` computed exactly in integer arithmetic (the
  WebAssembly and Rust floating-point operations round to nearest only). No
  JIT, no C source, no system library: it builds for
  `wasm32-unknown-unknown`. Keccak-256 comes from the `tiny-keccak` crate the
  library already uses.
- **Key.** Building the cache for one key fills 256 MiB and is the expensive
  step; one cache serves every header whose key block is the same. The
  caller finds the key block by following parent hashes over headers it has
  already checked (section 8); a client that cannot reach the key block has no
  key and cannot accept the header.
- **Cost.** On the machine that ran the tests, the optimised native build
  takes about 0.3 seconds to build a cache and about 0.2 seconds per hash.
  WebAssembly in a browser is slower. A client checks the seals of the headers
  it uses, not of the whole chain.
- **Agreement.** The port reproduces the reference's v1 test vectors with the
  reference's salt and the Ghost vector with the Ghost salt (section 11).
  Where the port and the node disagree, the node and the test vectors win.

## 11. Test vectors

**RandomX with the Ghost salt.** Key `test key 000` (12 ASCII bytes), input
`Ghost survey test input` (23 ASCII bytes), Ghost salt:

```text
253de6bf1004419ac11fdb08b5a8efd7fa0269d82ea8bb39db173ba43d6cf8ee
```

The same key and input with the reference's salt `"RandomX\x03"` give

```text
6038f21009dd6fd7aeb2c6e50a2ea8e2a228b13ac4c921e4d508275078c6765e
```

(both measured in the survey with the reference, compiled with and without
the salt patch).

**RandomX with the reference's salt.** The reference's own v1 vectors, which
an implementation run with the reference's salt reproduces before it switches
to Ghost's:

| Key | Input | Output |
|---|---|---|
| `test key 000` | `This is a test` | `639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f` |
| `test key 000` | `Lorem ipsum dolor sit amet` | `300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969` |
| `test key 000` | `sed do eiusmod tempor incididunt ut labore et dolore magna aliqua` | `c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8` |
| `test key 001` | `sed do eiusmod tempor incididunt ut labore et dolore magna aliqua` | `e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc` |

**Seal hashes.** The header vectors are spec 05's, section 11.

```text
[seal-hash-genesis-example]
header = header-genesis-example
seal-hash = 039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4

[seal-hash-block-one-example]
header = header-block-one-example
seal-hash = 1b5f20c1bc9d0cf05025a7e74451c1bd6015c400bc5743742ccdcd90ef4a64dd
```

The genesis example has zero seal fields, so its seal hash is its header hash.
The block one example's seal hash is the hash of the same header with
`mixDigest` and `nonce` zero; it does not depend on either.

**A sealed header.** `header-block-one-example` with difficulty 256 (a test
difficulty: one output in 256 passes), a zero mix digest and the first nonce
that seals it, under the key of height 1: the genesis example's hash.

```text
[sealed-example]
base = header-block-one-example
difficulty = 256
mixDigest = 0000000000000000000000000000000000000000000000000000000000000000
nonce = 000000000000006d
key = 039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4
rlp = f90262a0039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479400000000000000000000000000000000000004d2a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222a03333333333333333333333333333333333333333333333333333333333333333b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000820100018401c9c3808301ec30846b37040e80a0000000000000000000000000000000000000000000000000000000000000000088000000000000006d84342770c0a0142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5a0dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237aa0f121b372119409a7d6fda684a14ab815c7ef9a07ba48f50ff59ea5fc62d36e4f
hash = 88bd3adc11b2e9c2e40770b2c8297e9bfc6ea8088889d12e73bafa0ed65e2f38
seal-hash = e4a9a151ec8247dbacf2f023ccf401fdfb6cb70e0e2a9094d4699e0da5a7362a
output = 00a57fd17fd62cf6f7a40cf476c4618bd37dab9ae2017442d48d1b1fe6e6d9d7
valid = yes
```

The output is below `M // 256 = 2^248 - 1` (its first byte is zero). The nonce
is 109. The seal hash, output and validity were computed by the client's port
(section 10); section 13, item 5 asks for the node to reproduce them.

## 12. Conformance tests

Each test states its expected result. RS-1 to RS-9 run in the client library
(`client/tests/seal_check.rs`); every one also applies to the node.

- **RS-1. Ghost vector.** RandomX with the Ghost salt on the Ghost vector of
  section 11. Expected: `253de6bf...cf8ee` exactly.
- **RS-2. Reference vectors.** The four reference vectors of section 11, run
  with the reference's salt. Expected: each output exactly.
- **RS-3. Wrong salt.** The Ghost vector's key and input with the reference's
  salt, and the sealed example checked under a cache built with the
  reference's salt. Expected: the output `6038f210...c6765e`, which differs
  from the Ghost value, and the seal check fails.
- **RS-4. Seal hash.** The seal-hash vectors of section 11, and the block one
  example with any other `mixDigest` and `nonce`. Expected: the stated seal
  hashes; changing either seal field leaves the seal hash unchanged, and
  changing any other field, either tree root and `dataMarkerRoot` included,
  changes it.
- **RS-5. Valid seal.** The sealed example under its key. Expected: the stated
  output and a valid seal.
- **RS-6. Roots are sealed (TH-6).** The sealed example with one bit of
  `coinTreeRoot` changed, and with one bit of `dataMarkerRoot` changed.
  Expected: each time the seal hash changes, the output is above
  the target and the seal check fails.
- **RS-7. Wrong key.** The sealed example checked with the cache of another
  block's hash (the block one example's hash). Expected: the seal check fails.
- **RS-8. Checks before the hash.** The sealed example with a non-zero
  `mixDigest`; checked against a difficulty its header does not carry; with a
  difficulty of zero; with a byte appended, a 31-byte `coinTreeRoot`, a
  twentieth field or a block number with a leading zero byte. Expected: each
  is invalid, with the reason given (mix digest, difficulty, zero difficulty,
  or spec 05's `trailing-bytes`, `field-size`, `item-count`,
  `non-canonical-integer`).
- **RS-9. Target and key schedule.** `x = 0x5555...55` (32 bytes) with
  difficulty 3 passes and `0x5555...56` fails; any `x` passes at difficulty 1;
  a difficulty of zero never passes; `x` with first byte `01` fails at
  difficulty 256 and with first two bytes `00ff` passes. The heights of the
  table in section 8 give the stated key heights.
- **RS-10. Branch walk.** On a test network with two branches that fork below
  a key block height and each mine past `kE + L + 1`, a node validates each
  branch's headers with its own branch's key block. Expected: both branches
  validate; checking a header of one branch with the other branch's key block
  fails.
- **RS-11. Node agreement.** The node's `SealHash` and seal check run on the
  vectors of section 11. Expected: the same seal hashes, the same output and
  `valid = yes` for the sealed example.

## 13. Not pinned down

Each point is where the node's behaviour is not written down well enough to
specify. Where it matters to a verifier, the verifier fails closed.

1. **Which check fails first.** The node's order of the difficulty, mix
   digest and seal checks, and the error it reports, are not recorded. Only
   the verdict is consensus; this chapter fixes none of the order.
2. **The genesis header.** The node's handling of a seal on the genesis
   header is not written down. This chapter applies the seal check from
   height 1 and takes the genesis header from its derivation (spec 06,
   section 8), never from a seal.
3. **A missing ancestor.** What the node does with a header whose key block
   it does not hold (wait for it, or reject) is not written down. A client
   without the key block on the header's own branch does not accept the
   header.
4. **The key's bytes with a real block hash.** The only test vector with
   Ghost's salt uses the 12-byte ASCII key `test key 000`. That the node
   passes a block hash as its 32 raw bytes, and not as text, is read from the
   node's code but no vector from the node pins it. Section 11's sealed
   example uses the 32 raw bytes.
5. **Vectors from the node.** The seal hashes, the sealed example's output
   and its validity in section 11 were computed by the client's port; no
   header sealed by the node has been compared with them. RS-11 is that
   comparison. Until it runs, the seal-hash rule of section 4 and the vectors
   of spec 05 are what both sides share.
6. **Very large difficulty.** The base client refuses a `difficulty` longer
   than 80 bits on a block a peer announces (spec 05, section 10) before any
   seal check. The seal rule itself accepts any positive difficulty below
   `2^256`, and the client checks it that way.
7. **Cache count and lifetime.** How many caches the node keeps and when it
   builds the next epoch's cache are local choices (the survey suggests at
   most three); they are not consensus and not specified.

## 14. Checking this document

From the repository root, run

```sh
RUSTUP_HOME=/usr/local/rustup cargo test --locked --manifest-path client/Cargo.toml --test seal_check
```

It runs RS-1 to RS-9 against the client's port and checks that every vector
in section 11 that the tests compute is written in this document.

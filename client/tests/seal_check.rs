//! The RandomX seal check of spec 08: the port against the RandomX reference
//! vectors and the Ghost-salt vector, the seal hash against spec 05's
//! header vectors, and the seal check on a header sealed at a test
//! difficulty, including TH-6 and a wrong key and a wrong salt.
//!
//! Each RandomX cache takes 256 MiB, so the tests build them one at a time.

use std::sync::{Mutex, MutexGuard};

use ghost_client::randomx::{self, Cache, GHOST_SALT, REFERENCE_SALT};
use ghost_client::seal::{
    check_seal, meets_target, seal_hash, seal_input, seed_height, verify_seal, HeaderError, SealError,
    SealKey, EPOCH_BLOCKS, EPOCH_LAG,
};
use tiny_keccak::{Hasher, Keccak};

const SPEC: &str = include_str!("../../docs/spec/08-randomx-seal.md");

static ONE_CACHE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn one_cache() -> MutexGuard<'static, ()> {
    ONE_CACHE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn bytes32(text: &str) -> [u8; 32] {
    unhex(text).try_into().unwrap()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// A test-side RLP encoder, written apart from the client's decoder.
fn int(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[first..].to_vec()
}

fn rlp_length(len: usize, base: u8) -> Vec<u8> {
    if len < 56 {
        return vec![base + len as u8];
    }
    let digits = int(len as u64);
    let mut out = vec![base + 55 + digits.len() as u8];
    out.extend(digits);
    out
}

fn rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for field in fields {
        if field.len() == 1 && field[0] < 0x80 {
            payload.push(field[0]);
        } else {
            payload.extend(rlp_length(field.len(), 0x80));
            payload.extend(field);
        }
    }
    let mut out = rlp_length(payload.len(), 0xc0);
    out.extend(payload);
    out
}

/// Spec 05, section 11: `header-genesis-example` and its hash.
const GENESIS_RLP: &str = "f90260a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008401000000808401c9c38080846b3703f0a0000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26fa00000000000000000000000000000000000000000000000000000000000000000880000000000000000843b9aca00a08e66512042388a7863d500c4f96861466ae48b9d64ea1e10ec382c31aa61b5a8a03d5cea4ec4750f6e39c05a6464043afed27b95090a4d93a304d88204e9a3fe03";
const GENESIS_HASH: &str = "ffc501cc30c42da020a29cce3823251ca1c110c250bfed5a3d752e262bb86af7";
/// Spec 05, section 11: the hash of `header-block-one-example`.
const BLOCK_ONE_HASH: &str = "943182f201b34dae77dc5c8efb5c84083dda907eac51f8ac3fc6f6c36a791c23";

/// Spec 05's `header-block-one-example` fields, with the given difficulty,
/// mix digest and nonce.
fn block_one(difficulty: u64, mix: [u8; 32], nonce: u64) -> Vec<Vec<u8>> {
    let mut coinbase = vec![0u8; 20];
    coinbase[18..].copy_from_slice(&[0x04, 0xd2]);
    vec![
        unhex(GENESIS_HASH),
        unhex("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
        coinbase,
        vec![0x11; 32],
        vec![0x22; 32],
        vec![0x33; 32],
        vec![0; 256],
        int(difficulty),
        int(1),
        int(30_000_000),
        int(126_000),
        int(1_798_767_630),
        vec![],
        mix.to_vec(),
        nonce.to_be_bytes().to_vec(),
        int(875_000_000),
        unhex("142c6bdf0882396330f9942ddd49df5d860b05a5218dad1ce6ef8e69238b6ec5"),
        unhex("dfc2bf39581c30d2cf1f025586af2f821524daa2e496fea9f950731202f3237a"),
    ]
}

const COIN_TREE_ROOT: usize = 16;

/// The test difficulty of the sealed example: one hash in 256 passes.
const SEALED_DIFFICULTY: u64 = 256;
/// A nonce that seals `block_one` at that difficulty with a zero mix digest
/// under the genesis example's hash as the key (found by searching up from
/// zero; the first one is 325).
const SEALED_NONCE: u64 = 325;
/// The RandomX output for that header.
const SEALED_OUTPUT: &str = "0080d7962273d605552b5d8191d22d2decdc90e14626aa97ddd3e05a718c0ced";

fn sealed_header() -> Vec<u8> {
    rlp_list(&block_one(SEALED_DIFFICULTY, [0; 32], SEALED_NONCE))
}

fn difficulty() -> Vec<u8> {
    int(SEALED_DIFFICULTY)
}

fn genesis_key() -> SealKey {
    SealKey::new(&bytes32(GENESIS_HASH))
}

#[test]
fn reference_vectors_with_the_reference_salt() {
    let _one = one_cache();
    // The reference's own test vectors (`src/tests/tests.cpp`).
    let cases: [(&[u8], &str); 3] = [
        (b"This is a test", "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"),
        (b"Lorem ipsum dolor sit amet", "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969"),
        (
            b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
            "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
        ),
    ];
    let cache = Cache::with_salt(b"test key 000", REFERENCE_SALT);
    for (input, expected) in cases {
        assert_eq!(hex(&randomx::hash(&cache, input)), expected);
    }
    drop(cache);
    let cache = Cache::with_salt(b"test key 001", REFERENCE_SALT);
    assert_eq!(
        hex(&randomx::hash(&cache, b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua")),
        "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc"
    );
}

/// Spec 08's test vector: key `test key 000`, input `Ghost survey test
/// input`, Ghost's salt.
#[test]
fn ghost_salt_test_vector() {
    let _one = one_cache();
    assert_eq!(GHOST_SALT, b"Ghost-RandomX\x01");
    assert_eq!(GHOST_SALT.len(), 14);
    let cache = Cache::new(b"test key 000");
    assert_eq!(
        hex(&randomx::hash(&cache, b"Ghost survey test input")),
        "253de6bf1004419ac11fdb08b5a8efd7fa0269d82ea8bb39db173ba43d6cf8ee"
    );
}

/// The same key and input under the reference's salt give another value:
/// the salt reaches the hash.
#[test]
fn wrong_salt_gives_another_hash() {
    let _one = one_cache();
    let cache = Cache::with_salt(b"test key 000", REFERENCE_SALT);
    assert_eq!(
        hex(&randomx::hash(&cache, b"Ghost survey test input")),
        "6038f21009dd6fd7aeb2c6e50a2ea8e2a228b13ac4c921e4d508275078c6765e"
    );
}

#[test]
fn seal_hash_covers_every_field_but_the_seal_fields() {
    // With a zero mix digest and nonce, the seal hash is the header hash.
    let genesis = unhex(GENESIS_RLP);
    assert_eq!(hex(&keccak(&genesis)), GENESIS_HASH);
    assert_eq!(hex(&seal_hash(&genesis).unwrap()), GENESIS_HASH);

    // The test encoder reproduces spec 05's block one example.
    let example = rlp_list(&block_one(16_777_216, [0x44; 32], 0x0102030405060708));
    assert_eq!(hex(&keccak(&example)), BLOCK_ONE_HASH);

    // Its seal hash is the hash of the same header with both seal fields zero,
    // and changing either seal field leaves it unchanged.
    let zeroed = rlp_list(&block_one(16_777_216, [0; 32], 0));
    let expected = keccak(&zeroed);
    assert_eq!(seal_hash(&example).unwrap(), expected);
    assert_eq!(hex(&expected), SEAL_HASH_BLOCK_ONE);
    let other = rlp_list(&block_one(16_777_216, [0x55; 32], 7));
    assert_eq!(seal_hash(&other).unwrap(), expected);

    // Every other field changes it.
    let base = block_one(16_777_216, [0; 32], 0);
    for index in (0..18).filter(|&i| i != 13 && i != 14) {
        let mut fields = base.clone();
        // One bit, kept canonical: the block number 1 becomes 3, not 0.
        match fields[index].as_mut_slice() {
            [] => fields[index] = vec![1],
            [only] => *only ^= 2,
            [.., last] => *last ^= 1,
        }
        assert_ne!(seal_hash(&rlp_list(&fields)).unwrap(), expected, "field {index}");
    }

    // The RandomX input is the seal hash followed by the nonce, big-endian.
    let input = seal_input(&example).unwrap();
    assert_eq!(input[..32], expected);
    assert_eq!(input[32..], [1, 2, 3, 4, 5, 6, 7, 8]);
}

/// The seal hash of spec 05's `header-block-one-example`.
const SEAL_HASH_BLOCK_ONE: &str = "df9d13552b8f461df2e6476eb4e8b758d32f0b44b349e163e05fc3620c9197c0";
/// The seal hash of the sealed example.
const SEALED_SEAL_HASH: &str = "a341aa5fc1ff4f2704f85ff96b812b4348069458892c0a2d02e46d41657d9798";

#[test]
fn sealed_header_is_valid() {
    let _one = one_cache();
    let key = genesis_key();
    let header = sealed_header();
    let output = key.hash(&seal_input(&header).unwrap());
    assert_eq!(hex(&output), SEALED_OUTPUT);
    assert_eq!(verify_seal(&header, &difficulty(), &key), Ok(()));
    assert!(check_seal(&header, &difficulty(), &key));
    // Leading zero bytes in the caller's difficulty are allowed.
    assert!(check_seal(&header, &[0, 0, 1, 0], &key));
}

/// TH-6 (spec 05, section 4): one bit of `coinTreeRoot` changed on a valid
/// sealed header fails the seal check.
#[test]
fn th6_one_bit_of_the_coin_tree_root() {
    let _one = one_cache();
    let key = genesis_key();
    let mut fields = block_one(SEALED_DIFFICULTY, [0; 32], SEALED_NONCE);
    fields[COIN_TREE_ROOT][31] ^= 0x01;
    let header = rlp_list(&fields);
    assert_ne!(seal_hash(&header).unwrap(), seal_hash(&sealed_header()).unwrap());
    assert_ne!(hex(&key.hash(&seal_input(&header).unwrap())), SEALED_OUTPUT);
    assert_eq!(verify_seal(&header, &difficulty(), &key), Err(SealError::AboveTarget));
    assert!(!check_seal(&header, &difficulty(), &key));
}

/// The seal checked with another key block's hash fails.
#[test]
fn wrong_key_fails() {
    let _one = one_cache();
    let key = SealKey::new(&bytes32(BLOCK_ONE_HASH));
    let header = sealed_header();
    assert_ne!(hex(&key.hash(&seal_input(&header).unwrap())), SEALED_OUTPUT);
    assert_eq!(verify_seal(&header, &difficulty(), &key), Err(SealError::AboveTarget));
}

/// The seal checked under the reference's salt instead of Ghost's fails.
#[test]
fn wrong_salt_fails() {
    let _one = one_cache();
    let key = SealKey::with_salt(&bytes32(GENESIS_HASH), REFERENCE_SALT);
    let header = sealed_header();
    assert_ne!(hex(&key.hash(&seal_input(&header).unwrap())), SEALED_OUTPUT);
    assert_eq!(verify_seal(&header, &difficulty(), &key), Err(SealError::AboveTarget));
}

/// The checks that come before RandomX: a non-zero mix digest, a header
/// that does not carry the required difficulty, a zero difficulty and
/// headers that do not decode.
#[test]
fn rejected_before_hashing() {
    let _one = one_cache();
    let key = genesis_key();

    let mixed = rlp_list(&block_one(SEALED_DIFFICULTY, [0x44; 32], SEALED_NONCE));
    assert_eq!(verify_seal(&mixed, &difficulty(), &key), Err(SealError::MixDigestNotZero));

    assert_eq!(verify_seal(&sealed_header(), &int(257), &key), Err(SealError::DifficultyMismatch));
    assert_eq!(verify_seal(&sealed_header(), &[0], &key), Err(SealError::ZeroDifficulty));
    let zero = rlp_list(&block_one(0, [0; 32], SEALED_NONCE));
    assert_eq!(verify_seal(&zero, &[], &key), Err(SealError::ZeroDifficulty));

    let mut trailing = sealed_header();
    trailing.push(0);
    assert_eq!(verify_seal(&trailing, &difficulty(), &key), Err(SealError::Header(HeaderError::TrailingBytes)));

    let mut short = block_one(SEALED_DIFFICULTY, [0; 32], SEALED_NONCE);
    short[COIN_TREE_ROOT].pop();
    assert_eq!(
        verify_seal(&rlp_list(&short), &difficulty(), &key),
        Err(SealError::Header(HeaderError::FieldSize))
    );

    let mut extra = block_one(SEALED_DIFFICULTY, [0; 32], SEALED_NONCE);
    extra.push(vec![]);
    assert_eq!(
        verify_seal(&rlp_list(&extra), &difficulty(), &key),
        Err(SealError::Header(HeaderError::ItemCount))
    );

    let mut padded = block_one(SEALED_DIFFICULTY, [0; 32], SEALED_NONCE);
    padded[8] = vec![0, 1];
    assert_eq!(
        verify_seal(&rlp_list(&padded), &difficulty(), &key),
        Err(SealError::Header(HeaderError::NonCanonicalInteger))
    );
}

/// The target is `(2^256 - 1) // difficulty`, inclusive, big-endian.
#[test]
fn target_comparison() {
    let mut third = [0x55u8; 32];
    assert!(meets_target(&third, &[3]));
    third[31] = 0x56;
    assert!(!meets_target(&third, &[3]));
    assert!(meets_target(&[0xff; 32], &[1]));
    assert!(!meets_target(&[0; 32], &[0]));
    assert!(!meets_target(&[0; 32], &[]));

    // Big-endian: the first byte is the most significant.
    let mut low = [0u8; 32];
    low[31] = 0xff;
    assert!(meets_target(&low, &int(1 << 40)));
    let mut high = [0u8; 32];
    high[0] = 0x01;
    assert!(!meets_target(&high, &[0x01, 0x00]));
    high[0] = 0x00;
    high[1] = 0xff;
    assert!(meets_target(&high, &[0x01, 0x00]));
}

#[test]
fn key_schedule() {
    assert_eq!((EPOCH_BLOCKS, EPOCH_LAG), (8192, 256));
    let cases = [
        (0, 0),
        (1, 0),
        (8192, 0),
        (8448, 0),
        (8449, 8192),
        (16_640, 8192),
        (16_641, 16_384),
        (1_000_000, 999_424),
    ];
    for (height, expected) in cases {
        assert_eq!(seed_height(height), expected, "height {height}");
    }
}

/// Spec 08's vectors are the values these tests check.
#[test]
fn spec_states_these_vectors() {
    let header = sealed_header();
    let vectors = [
        hex(&header),
        hex(&keccak(&header)),
        SEALED_SEAL_HASH.to_string(),
        SEALED_OUTPUT.to_string(),
        SEAL_HASH_BLOCK_ONE.to_string(),
        "253de6bf1004419ac11fdb08b5a8efd7fa0269d82ea8bb39db173ba43d6cf8ee".to_string(),
        "6038f21009dd6fd7aeb2c6e50a2ea8e2a228b13ac4c921e4d508275078c6765e".to_string(),
        format!("nonce = {SEALED_NONCE:016x}"),
    ];
    assert_eq!(hex(&seal_hash(&header).unwrap()), SEALED_SEAL_HASH);
    for vector in vectors {
        assert!(SPEC.contains(&vector), "spec 08 does not state {vector}");
    }
}

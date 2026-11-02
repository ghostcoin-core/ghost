//! Keccak-256 with the original padding, the tags of spec 01, section 4, and
//! the commitment, marker and tree hashes built from them: the salted format
//! version 2 (the `_v2` functions) of spec 01, section 3, the only one.
//!
//! `K(tag, x1, x2, ...)` is Keccak-256 over `tagbytes(tag) || x1 || x2 || ...`,
//! where `tagbytes` is one length byte followed by the tag's ASCII bytes. It is
//! the only hash in this crate, inside and outside the proofs.

use alloc::vec::Vec;

use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

/// Bytes absorbed per Keccak-256 permutation.
pub const RATE_BYTES: usize = 136;

/// Depth of both trees: 2^32 leaves, 32 sibling hashes per path.
pub const TREE_DEPTH: usize = 32;

/// Type tag of a salted coin commitment (format version 2, type 1).
pub const COIN_V2: [u8; 2] = [0x02, 0x01];
/// Type tag of a salted data commitment (format version 2, type 2).
pub const DATA_V2: [u8; 2] = [0x02, 0x02];

/// Length of the salt of a version 2 commitment (spec 01, section 3).
pub const SALT_BYTES: usize = 16;

/// The fee reserve of a data commitment in wei, 2.5 x 10^17 (0.25 GHOST): a
/// protocol constant the node burns at commit and binds into the outer hash
/// of every data leaf (spec 04, section 3, "The fee reserve").
pub const DATA_RESERVE: u128 = 250_000_000_000_000_000;

/// [`DATA_RESERVE`] as a 32-byte big-endian amount word, the format of a
/// coin's `v`: the word the data commitment's outer hash takes.
pub const DATA_RESERVE_WORD: [u8; 32] = crate::amount::amount_word(DATA_RESERVE);

/// The empty rule, the only rule version 1 accepts.
pub const EMPTY_RULE: [u8; 32] = [0; 32];

pub const TAG_COIN_COMMITMENT: &str = "ghost/coin-commitment/v1";
pub const TAG_DATA_COMMITMENT: &str = "ghost/data-commitment/v1";
pub const TAG_COIN_FINGERPRINT_V2: &str = "ghost/coin-fingerprint/v2";
pub const TAG_DATA_FINGERPRINT_V2: &str = "ghost/data-fingerprint/v2";
pub const TAG_COIN_MARKER_V2: &str = "ghost/coin-marker/v2";
pub const TAG_DATA_MARKER_V2: &str = "ghost/data-marker/v2";
pub const TAG_COIN_TREE_NODE: &str = "ghost/coin-tree-node/v1";
pub const TAG_DATA_TREE_NODE: &str = "ghost/data-tree-node/v1";
pub const TAG_EMPTY_LEAF: &str = "ghost/empty-leaf/v1";
pub const TAG_COIN_REVEAL_BINDING: &str = "ghost/coin-reveal-binding/v1";
/// The binding of the ordinary class, S1 version 2 (spec 10, section 4.2).
pub const TAG_COIN_REVEAL_BINDING_V2: &str = "ghost/coin-reveal-binding/v2";
/// The rule hash of spec 10, section 3.1.
pub const TAG_REVEAL_POLICY_V2: &str = "ghost/reveal-policy/v2";
/// The override hash of spec 10, section 3.1.
pub const TAG_POLICY_OVERRIDE_V1: &str = "ghost/policy-override/v1";
/// The binding of the policy class, S4 (spec 10, section 5.1).
pub const TAG_POLICY_REVEAL_BINDING_V1: &str = "ghost/policy-reveal-binding/v1";
/// The binding of `KNOW_ACTION_v1` (spec 10, section 8.2).
pub const TAG_ACTION_BINDING_V1: &str = "ghost/action-binding/v1";
/// The binding of `KNOW_PREIMAGE_v1` (spec 10, section 9.2).
pub const TAG_PREIMAGE_BINDING_V1: &str = "ghost/preimage-binding/v1";
/// The action tag of a slot: `K(tag, action_root, action_salt)` (spec 10,
/// section 8.2).
pub const TAG_POLICY_ACTION_V1: &str = "ghost/policy-action/v1";
/// The preimage hash of `KNOW_PREIMAGE_v1`: `y = K(tag, x)` (spec 10,
/// section 9.2).
pub const TAG_POLICY_PREIMAGE_V1: &str = "ghost/policy-preimage/v1";
/// The calldata hash of an action (spec 10, section 8.2).
pub const TAG_ACTION_CALLDATA_V1: &str = "ghost/action-calldata/v1";
pub const TAG_DATA_REVEAL_BINDING: &str = "ghost/data-reveal-binding/v1";
pub const TAG_HOLD_BINDING: &str = "ghost/hold-binding/v1";
pub const TAG_DATA_MARKER_SET_LEAF: &str = "ghost/data-marker-set-leaf/v1";
pub const TAG_DATA_MARKER_SET_NODE: &str = "ghost/data-marker-set-node/v1";

/// Depth of the data marker-set tree (spec 05, section 6): 2^40 positions,
/// 40 sibling hashes per path.
pub const MARKER_SET_DEPTH: usize = 40;

/// Width of a marker-set `nextIndex` and of a position in the `absence`
/// witness: a 40-bit big-endian integer.
pub const MARKER_SET_INDEX_BYTES: usize = 5;

/// Width of a policy address (spec 10, section 3.1).
pub const POLICY_ADDRESS_BYTES: usize = 20;

/// One tree per commitment type, each with its own node tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tree {
    Coin,
    Data,
}

impl Tree {
    pub const fn node_tag(self) -> &'static str {
        match self {
            Self::Coin => TAG_COIN_TREE_NODE,
            Self::Data => TAG_DATA_TREE_NODE,
        }
    }
}

/// The length byte followed by the tag's ASCII bytes.
pub fn tag_bytes(tag: &str) -> Vec<u8> {
    let len = u8::try_from(tag.len()).expect("a tag is shorter than 256 bytes");
    let mut out = Vec::with_capacity(1 + tag.len());
    out.push(len);
    out.extend_from_slice(tag.as_bytes());
    out
}

/// The message padded to whole blocks with the original Keccak padding
/// (`0x01`, zeros, `0x80`).
pub(crate) fn pad(msg: &[u8]) -> Vec<u8> {
    let blocks = msg.len() / RATE_BYTES + 1;
    let mut out = msg.to_vec();
    out.resize(blocks * RATE_BYTES, 0);
    out[msg.len()] ^= 0x01;
    out[blocks * RATE_BYTES - 1] ^= 0x80;
    out
}

/// The round constants of Keccak-f[1600], one per round.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The chi step on one plane of five lanes.
#[inline(always)]
fn chi(b: [u64; 5]) -> [u64; 5] {
    [
        b[0] ^ (!b[1] & b[2]),
        b[1] ^ (!b[2] & b[3]),
        b[2] ^ (!b[3] & b[4]),
        b[3] ^ (!b[4] & b[0]),
        b[4] ^ (!b[0] & b[1]),
    ]
}

/// One round of Keccak-f[1600]: theta, then rho and pi folded into the lanes
/// chi reads, then chi and iota. Lane `(x, y)` is `a[x + 5 * y]`; output
/// plane `y` reads input lanes `(x + 3y, x)` for `x` in `0..5`.
#[inline(always)]
fn round(a: &[u64; 25], round_constant: u64) -> [u64; 25] {
    let c: [u64; 5] = core::array::from_fn(|x| a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);
    let d: [u64; 5] = core::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
    let lane = |x: usize, y: usize, rotation: u32| (a[x + 5 * y] ^ d[x]).rotate_left(rotation);
    let mut p0 = chi([lane(0, 0, 0), lane(1, 1, 44), lane(2, 2, 43), lane(3, 3, 21), lane(4, 4, 14)]);
    let p1 = chi([lane(3, 0, 28), lane(4, 1, 20), lane(0, 2, 3), lane(1, 3, 45), lane(2, 4, 61)]);
    let p2 = chi([lane(1, 0, 1), lane(2, 1, 6), lane(3, 2, 25), lane(4, 3, 8), lane(0, 4, 18)]);
    let p3 = chi([lane(4, 0, 27), lane(0, 1, 36), lane(1, 2, 10), lane(2, 3, 15), lane(3, 4, 56)]);
    let p4 = chi([lane(2, 0, 62), lane(3, 1, 55), lane(4, 2, 39), lane(0, 3, 41), lane(1, 4, 2)]);
    p0[0] ^= round_constant;
    let mut out = [0; 25];
    for (y, plane) in [p0, p1, p2, p3, p4].into_iter().enumerate() {
        out[5 * y..5 * y + 5].copy_from_slice(&plane);
    }
    out
}

/// Keccak-f[1600], the permutation of Keccak-256, on 25 lanes.
///
/// The same function as `p3_keccak::KeccakF` (the gate of `stark.rs` checks
/// it), written round by round on a local copy of the state so the compiler
/// keeps every lane in a register. The Merkle commitments of a proof run it
/// several million times, most of the prover's time.
pub(crate) fn keccak_f(state: &mut [u64; 25]) {
    *state = keccak_f_inline(*state);
}

/// [`keccak_f`] on a state held by value and inlined into its caller, so
/// that a caller absorbing block after block keeps the state in registers
/// rather than storing and reloading it around every permutation.
#[inline(always)]
pub(crate) fn keccak_f_inline(mut a: [u64; 25]) -> [u64; 25] {
    for round_constant in ROUND_CONSTANTS {
        a = round(&a, round_constant);
    }
    a
}

/// Number of permutations Keccak-256 spends on a message of this length.
pub const fn permutations(len: usize) -> usize {
    len / RATE_BYTES + 1
}

/// XOR a 136-byte block into the rate of a state.
pub(crate) fn absorb(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), RATE_BYTES);
    for (lane, chunk) in block.chunks_exact(8).enumerate() {
        state[lane] ^= u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
    }
}

/// The first 32 bytes of a state: the digest.
pub(crate) fn squeeze(state: &[u64; 25]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (i, lane) in state[..4].iter().enumerate() {
        digest[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    digest
}

/// The rate of a state as 136 bytes.
pub(crate) fn rate_bytes(state: &[u64; 25]) -> [u8; RATE_BYTES] {
    let mut out = [0u8; RATE_BYTES];
    for (i, lane) in state[..RATE_BYTES / 8].iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// Keccak-256 with the original padding.
pub fn keccak256(msg: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    for block in pad(msg).chunks_exact(RATE_BYTES) {
        absorb(&mut state, block);
        KeccakF.permute_mut(&mut state);
    }
    squeeze(&state)
}

/// `K(tag, parts...)`.
pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut msg = tag_bytes(tag);
    for part in parts {
        msg.extend_from_slice(part);
    }
    keccak256(&msg)
}

/// `F = K("ghost/coin-fingerprint/v2", s, r, b, salt, COIN_V2, 0^32, rule)`.
pub fn coin_fingerprint_v2(
    s: &[u8; 32],
    r: &[u8; 32],
    b: &[u8; 32],
    salt: &[u8; SALT_BYTES],
    rule: &[u8; 32],
) -> [u8; 32] {
    tagged(TAG_COIN_FINGERPRINT_V2, &[s, r, b, salt, &COIN_V2, &[0u8; 32], rule])
}

/// `C = K("ghost/coin-commitment/v1", COIN_V2, F, v)`, `v` an amount word.
pub fn coin_commitment_v2(fingerprint: &[u8; 32], v: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_COIN_COMMITMENT, &[&COIN_V2, fingerprint, v])
}

/// `F_d = K("ghost/data-fingerprint/v2", s, r, b, salt, DATA_V2, cf, rule)`.
pub fn data_fingerprint_v2(
    s: &[u8; 32],
    r: &[u8; 32],
    b: &[u8; 32],
    salt: &[u8; SALT_BYTES],
    cf: &[u8; 32],
    rule: &[u8; 32],
) -> [u8; 32] {
    tagged(TAG_DATA_FINGERPRINT_V2, &[s, r, b, salt, &DATA_V2, cf, rule])
}

/// `C = K("ghost/data-commitment/v1", DATA_V2, DATA_RESERVE, F_d)`, the
/// reserve as its amount word.
pub fn data_commitment_v2(fingerprint: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_DATA_COMMITMENT, &[&DATA_V2, &DATA_RESERVE_WORD, fingerprint])
}

/// `m = K("ghost/coin-marker/v2", r, b, salt)`.
pub fn coin_marker_v2(r: &[u8; 32], b: &[u8; 32], salt: &[u8; SALT_BYTES]) -> [u8; 32] {
    tagged(TAG_COIN_MARKER_V2, &[r, b, salt])
}

/// `m = K("ghost/data-marker/v2", r, b, salt)`.
pub fn data_marker_v2(r: &[u8; 32], b: &[u8; 32], salt: &[u8; SALT_BYTES]) -> [u8; 32] {
    tagged(TAG_DATA_MARKER_V2, &[r, b, salt])
}

/// The policy address as the rule hash takes it: 12 zero bytes, then the 20
/// address bytes.
pub fn padded_policy_address(policy_address: &[u8; POLICY_ADDRESS_BYTES]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[32 - POLICY_ADDRESS_BYTES..].copy_from_slice(policy_address);
    word
}

/// The rule of spec 10, section 3.1:
/// `K("ghost/reveal-policy/v2", policy_address (left-padded to 32),
/// policy_codehash, params_hash, override_hash, action_tag, action_salt)`,
/// 215 input bytes, two permutations. Never zero for any known input, so
/// never the empty rule.
pub fn reveal_policy_rule(
    policy_address: &[u8; POLICY_ADDRESS_BYTES],
    policy_codehash: &[u8; 32],
    params_hash: &[u8; 32],
    override_hash: &[u8; 32],
    action_tag: &[u8; 32],
    action_salt: &[u8; 32],
) -> [u8; 32] {
    tagged(
        TAG_REVEAL_POLICY_V2,
        &[
            &padded_policy_address(policy_address),
            policy_codehash,
            params_hash,
            override_hash,
            action_tag,
            action_salt,
        ],
    )
}

/// `override_hash = K("ghost/policy-override/v1", override_secret)` (spec 10,
/// section 3.1), 57 input bytes, one permutation. A rule with no override
/// carries 32 zero bytes instead.
pub fn policy_override_hash(override_secret: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_POLICY_OVERRIDE_V1, &[override_secret])
}

/// `action_tag = K("ghost/policy-action/v1", action_root, action_salt)`
/// (spec 10, section 8.2), 87 input bytes, one permutation.
pub fn policy_action_tag(action_root: &[u8; 32], action_salt: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_POLICY_ACTION_V1, &[action_root, action_salt])
}

/// `y = K("ghost/policy-preimage/v1", x)` (spec 10, section 9.2), 57 input
/// bytes, one permutation.
pub fn policy_preimage_hash(x: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_POLICY_PREIMAGE_V1, &[x])
}

/// An inner node at `level` (0 just above the leaves, 31 for the root).
pub fn tree_node(tree: Tree, level: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    tagged(tree.node_tag(), &[&[level], left, right])
}

/// The value of an unused leaf position in either tree.
pub fn empty_leaf() -> [u8; 32] {
    tagged(TAG_EMPTY_LEAF, &[])
}

/// The root over a leaf at `position` with its 32 siblings. Bit `l` of the
/// position says whether the node at level `l - 1` (the leaf for `l = 0`) is a
/// right child (spec 05, section 3).
pub fn merkle_root(tree: Tree, leaf: &[u8; 32], position: u32, path: &[[u8; 32]; TREE_DEPTH]) -> [u8; 32] {
    let mut current = *leaf;
    for (level, sibling) in path.iter().enumerate() {
        current = if position >> level & 1 == 1 {
            tree_node(tree, level as u8, sibling, &current)
        } else {
            tree_node(tree, level as u8, &current, sibling)
        };
    }
    current
}

/// A leaf of the data marker-set tree (spec 05, section 6):
/// `K("ghost/data-marker-set-leaf/v1", value, nextValue, nextIndex)`, 99
/// input bytes.
pub fn marker_set_leaf(
    value: &[u8; 32],
    next_value: &[u8; 32],
    next_index: &[u8; MARKER_SET_INDEX_BYTES],
) -> [u8; 32] {
    tagged(TAG_DATA_MARKER_SET_LEAF, &[value, next_value, next_index])
}

/// An inner node of the data marker-set tree at `level` (0 just above the
/// leaves, 39 for the root): `K("ghost/data-marker-set-node/v1", level,
/// left, right)`, 95 input bytes.
pub fn marker_set_node(level: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_DATA_MARKER_SET_NODE, &[&[level], left, right])
}

/// The marker-set root over a leaf hash at `position` with its 40 siblings,
/// from level 0 up. Bit `l` of the position says whether the node at level
/// `l - 1` (the leaf for `l = 0`) is a right child; bits above 39 are not
/// read.
pub fn marker_set_root(leaf: &[u8; 32], position: u64, siblings: &[[u8; 32]; MARKER_SET_DEPTH]) -> [u8; 32] {
    let mut current = *leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if position >> level & 1 == 1 {
            marker_set_node(level as u8, sibling, &current)
        } else {
            marker_set_node(level as u8, &current, sibling)
        };
    }
    current
}

#[cfg(test)]
mod tests {
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::CryptographicHasher;

    use super::*;

    #[test]
    fn sponge_is_keccak_256() {
        for len in [0, 1, 85, 135, 136, 137, 188, 271, 272, 444] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let expected = Keccak256Hash {}.hash_iter(msg.iter().copied());
            assert_eq!(keccak256(&msg), expected, "length {len}");
        }
    }

    /// Three applications from the zero state, each against the library's
    /// Keccak-f[1600].
    #[test]
    fn keccak_f_is_the_library_permutation() {
        let mut state = [0u64; 25];
        let mut library = state;
        for _ in 0..3 {
            keccak_f(&mut state);
            KeccakF.permute_mut(&mut library);
            assert_eq!(state, library);
        }
    }

    #[test]
    fn tag_lengths_give_the_spec_input_sizes() {
        assert_eq!(tag_bytes(TAG_COIN_COMMITMENT).len() + 2 + 64, 91);
        assert_eq!(tag_bytes(TAG_DATA_COMMITMENT).len() + 2 + 32 + 32, 91);
        assert_eq!(permutations(91), 1);
        assert_eq!(tag_bytes(TAG_COIN_TREE_NODE).len() + 1 + 64, 89);
        assert_eq!(tag_bytes(TAG_EMPTY_LEAF).len(), 20);
        assert_eq!(tag_bytes(TAG_COIN_FINGERPRINT_V2).len() + 32 * 5 + SALT_BYTES + 2, 204);
        assert_eq!(tag_bytes(TAG_DATA_FINGERPRINT_V2).len() + 32 * 5 + SALT_BYTES + 2, 204);
        assert_eq!(tag_bytes(TAG_COIN_MARKER_V2).len() + 64 + SALT_BYTES, 101);
        assert_eq!(tag_bytes(TAG_DATA_MARKER_V2).len() + 64 + SALT_BYTES, 101);
        assert_eq!((permutations(204), permutations(101)), (2, 1));
        assert_eq!(tag_bytes(TAG_DATA_MARKER_SET_LEAF).len() + 64 + MARKER_SET_INDEX_BYTES, 99);
        assert_eq!(tag_bytes(TAG_DATA_MARKER_SET_NODE).len() + 1 + 64, 95);
        assert_eq!((permutations(99), permutations(95)), (1, 1));
        assert_eq!(tag_bytes(TAG_REVEAL_POLICY_V2).len() + 6 * 32, 215);
        assert_eq!(tag_bytes(TAG_POLICY_OVERRIDE_V1).len() + 32, 57);
        assert_eq!((permutations(215), permutations(57)), (2, 1));
        assert_eq!(tag_bytes(TAG_POLICY_ACTION_V1).len() + 64, 87);
        assert_eq!(tag_bytes(TAG_POLICY_PREIMAGE_V1).len() + 32, 57);
        assert_eq!(tag_bytes(TAG_ACTION_BINDING_V1).len(), 24);
        assert_eq!(tag_bytes(TAG_PREIMAGE_BINDING_V1).len(), 26);
        assert_eq!(permutations(87), 1);
    }

    /// The rule hash takes the address left-padded with zeros, and each field
    /// changes it.
    #[test]
    fn the_rule_hash_pads_the_address_on_the_left() {
        let address = [0xab; POLICY_ADDRESS_BYTES];
        let fields = [[1u8; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&address);
        let mut msg = tag_bytes(TAG_REVEAL_POLICY_V2);
        msg.extend_from_slice(&padded);
        for field in &fields {
            msg.extend_from_slice(field);
        }
        assert_eq!(msg.len(), 215);
        let rule = reveal_policy_rule(&address, &fields[0], &fields[1], &fields[2], &fields[3], &fields[4]);
        assert_eq!(rule, keccak256(&msg));
        assert_ne!(rule, EMPTY_RULE);
        let mut other = address;
        other[0] ^= 1;
        assert_ne!(reveal_policy_rule(&other, &fields[0], &fields[1], &fields[2], &fields[3], &fields[4]), rule);
        assert_eq!(policy_override_hash(&[7; 32]), tagged(TAG_POLICY_OVERRIDE_V1, &[&[7; 32]]));
    }
}

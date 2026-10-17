//! Keccak-256 with the original padding, the tags of spec 01, section 4, and
//! the commitment, marker and tree hashes built from them.
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

/// Type tag of a coin commitment (format version 1, type 1).
pub const COIN: [u8; 2] = [0x01, 0x01];
/// Type tag of a data commitment (format version 1, type 2).
pub const DATA: [u8; 2] = [0x01, 0x02];

/// The empty rule, the only rule version 1 accepts.
pub const EMPTY_RULE: [u8; 32] = [0; 32];

pub const TAG_COIN_FINGERPRINT: &str = "ghost/coin-fingerprint/v1";
pub const TAG_COIN_COMMITMENT: &str = "ghost/coin-commitment/v1";
pub const TAG_DATA_FINGERPRINT: &str = "ghost/data-fingerprint/v1";
pub const TAG_DATA_COMMITMENT: &str = "ghost/data-commitment/v1";
pub const TAG_COIN_MARKER: &str = "ghost/coin-marker/v1";
pub const TAG_DATA_MARKER: &str = "ghost/data-marker/v1";
pub const TAG_COIN_TREE_NODE: &str = "ghost/coin-tree-node/v1";
pub const TAG_DATA_TREE_NODE: &str = "ghost/data-tree-node/v1";
pub const TAG_EMPTY_LEAF: &str = "ghost/empty-leaf/v1";
pub const TAG_COIN_REVEAL_BINDING: &str = "ghost/coin-reveal-binding/v1";
pub const TAG_DATA_REVEAL_BINDING: &str = "ghost/data-reveal-binding/v1";
pub const TAG_HOLD_BINDING: &str = "ghost/hold-binding/v1";

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

/// `F = K("ghost/coin-fingerprint/v1", s, r, b, COIN, 0^32, rule)`.
pub fn coin_fingerprint(s: &[u8; 32], r: &[u8; 32], b: &[u8; 32], rule: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_COIN_FINGERPRINT, &[s, r, b, &COIN, &[0u8; 32], rule])
}

/// `C = K("ghost/coin-commitment/v1", COIN, F, v)`, `v` an amount word.
pub fn coin_commitment(fingerprint: &[u8; 32], v: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_COIN_COMMITMENT, &[&COIN, fingerprint, v])
}

/// `F_d = K("ghost/data-fingerprint/v1", s, r, b, DATA, cf, rule)`.
pub fn data_fingerprint(
    s: &[u8; 32],
    r: &[u8; 32],
    b: &[u8; 32],
    cf: &[u8; 32],
    rule: &[u8; 32],
) -> [u8; 32] {
    tagged(TAG_DATA_FINGERPRINT, &[s, r, b, &DATA, cf, rule])
}

/// `C = K("ghost/data-commitment/v1", DATA, F_d)`.
pub fn data_commitment(fingerprint: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_DATA_COMMITMENT, &[&DATA, fingerprint])
}

/// `m = K("ghost/coin-marker/v1", r, b)`.
pub fn coin_marker(r: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_COIN_MARKER, &[r, b])
}

/// `m = K("ghost/data-marker/v1", r, b)`.
pub fn data_marker(r: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    tagged(TAG_DATA_MARKER, &[r, b])
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

    #[test]
    fn tag_lengths_give_the_spec_input_sizes() {
        assert_eq!(tag_bytes(TAG_COIN_FINGERPRINT).len() + 32 * 5 + 2, 188);
        assert_eq!(tag_bytes(TAG_COIN_COMMITMENT).len() + 2 + 64, 91);
        assert_eq!(tag_bytes(TAG_DATA_COMMITMENT).len() + 2 + 32, 59);
        assert_eq!(tag_bytes(TAG_COIN_MARKER).len() + 64, 85);
        assert_eq!(tag_bytes(TAG_COIN_TREE_NODE).len() + 1 + 64, 89);
        assert_eq!(tag_bytes(TAG_EMPTY_LEAF).len(), 20);
    }
}

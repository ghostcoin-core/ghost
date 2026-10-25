//! Choosing the tree state a reveal proves against (spec 02, section 8).
//!
//! By default the wallet proves against the newest root of the tree of its
//! type in a canonical header whose height `h` satisfies
//!
//! ```text
//! h <= tip - SETTLE_DEPTH   and   h > h_leaf
//! ```
//!
//! and whose root is not byte-equal to the root of block `h_leaf`, the block
//! that added the wallet's leaf. A later header carries that same root
//! whenever no leaf of the type was added in between, so the value test is
//! needed as well as the height test. A reveal is possible as soon as such a
//! header exists: there is no forced wait. If none exists yet (nobody added a
//! leaf of the type since the wallet's block, or that block is not yet
//! settled), the wallet waits rather than prove against its own block's
//! root, which would tie the reveal to its commit.
//!
//! How much cover a root gives is the number of leaves under it; the holder
//! may wait for more before revealing. That choice is the holder's, not this
//! rule's.
//!
//! The caller supplies the candidate canonical headers; this module fetches
//! nothing. The one exception, the final root of a full tree once the next
//! tree has started, is used only when the caller passes it explicitly.

use core::fmt;

/// A root the wallet proves against is at least this many blocks below the
/// tip, so that a short reorganisation of the newest blocks does not drop it.
pub const SETTLE_DEPTH: u64 = 2;

/// The root of the tree of the reveal's type in one canonical header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HeaderRoot {
    /// The block height.
    pub height: u64,
    /// The header's coin root (or data root, for a data reveal).
    pub root: [u8; 32],
}

/// The tree state to prove against.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TreeStateChoice {
    /// The newest settled root that holds a leaf added after the wallet's
    /// block.
    Settled(HeaderRoot),
    /// The final root of the full tree that holds the leaf (spec 02,
    /// section 8, "A leaf of a full tree"), given by the caller.
    FinalRoot(HeaderRoot),
    /// No eligible root yet: wait until a later leaf is added and settled.
    Wait,
}

impl fmt::Debug for HeaderRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeaderRoot({}, ", self.height)?;
        for byte in &self.root {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Debug for TreeStateChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Settled(header) => write!(f, "Settled({header:?})"),
            Self::FinalRoot(header) => write!(f, "FinalRoot({header:?})"),
            Self::Wait => f.write_str("Wait"),
        }
    }
}

/// Picks the tree state for a reveal of the leaf added in block `leaf_block`.
///
/// `candidates` are canonical headers the caller holds, in any order; `tip` is
/// the wallet's current best height. `full_tree_final_root` is the final root
/// of the tree that holds the leaf, and the caller passes it only once that
/// tree is full and the next tree has started; it is used when it is at least
/// as high as the leaf's block and buried by the same depth. The root of
/// `leaf_block` is never chosen as a settled root, whatever height carries it.
pub fn choose_tree_state(
    candidates: &[HeaderRoot],
    tip: u64,
    leaf_block: &HeaderRoot,
    full_tree_final_root: Option<&HeaderRoot>,
) -> TreeStateChoice {
    let Some(deepest) = tip.checked_sub(SETTLE_DEPTH) else {
        return TreeStateChoice::Wait;
    };
    if let Some(final_root) = full_tree_final_root {
        if final_root.height >= leaf_block.height && final_root.height <= deepest {
            return TreeStateChoice::FinalRoot(*final_root);
        }
        return TreeStateChoice::Wait;
    }
    candidates
        .iter()
        .filter(|header| {
            header.height <= deepest
                && header.height > leaf_block.height
                && header.root != leaf_block.root
        })
        .max_by_key(|header| header.height)
        .map_or(TreeStateChoice::Wait, |header| TreeStateChoice::Settled(*header))
}

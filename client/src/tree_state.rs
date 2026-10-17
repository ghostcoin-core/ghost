//! Choosing the tree state a reveal proves against (spec 02, section 8).
//!
//! The wallet proves against the epoch root: the root of the tree of its type
//! in the header of the most recent canonical block whose height `h` satisfies
//!
//! ```text
//! h mod 32 = 0   and   h <= tip - 12   and   h > h_leaf
//! ```
//!
//! and whose root is not byte-equal to the root of block `h_leaf`, the block
//! that added the wallet's leaf. A later header carries that same root
//! whenever no leaf of the type was added in between, so the value test is
//! needed as well as the height test. If no such block exists yet, the wallet
//! waits.
//!
//! The caller supplies the candidate canonical headers; this module fetches
//! nothing. The one exception, the final root of a full tree once the next
//! tree has started, is used only when the caller passes it explicitly.

use core::fmt;

/// Every epoch root is at a height that is a multiple of this.
pub const EPOCH_BLOCKS: u64 = 32;
/// An epoch root is at least this many blocks below the tip.
pub const EPOCH_DEPTH: u64 = 12;

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
    /// The epoch root.
    Epoch(HeaderRoot),
    /// The final root of the full tree that holds the leaf (spec 02,
    /// section 8, "A leaf of a full tree"), given by the caller.
    FinalRoot(HeaderRoot),
    /// No eligible root yet: wait for the next epoch.
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
            Self::Epoch(header) => write!(f, "Epoch({header:?})"),
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
/// `leaf_block` is never chosen as an epoch root, whatever height carries it.
pub fn choose_tree_state(
    candidates: &[HeaderRoot],
    tip: u64,
    leaf_block: &HeaderRoot,
    full_tree_final_root: Option<&HeaderRoot>,
) -> TreeStateChoice {
    let Some(deepest) = tip.checked_sub(EPOCH_DEPTH) else {
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
            header.height % EPOCH_BLOCKS == 0
                && header.height <= deepest
                && header.height > leaf_block.height
                && header.root != leaf_block.root
        })
        .max_by_key(|header| header.height)
        .map_or(TreeStateChoice::Wait, |header| TreeStateChoice::Epoch(*header))
}

//! What a statement hashes, as data.
//!
//! A statement is a list of Keccak-256 hashes computed one after another.
//! Each hash is a list of segments; each segment says where its bytes come
//! from. The same description drives both sides:
//!
//! - the AIR ([`crate::air`]) turns it into constraints, without any witness;
//! - the prover ([`execute`]) turns it, with the witness, into the permutation
//!   inputs and message bytes of the trace.
//!
//! Byte sources:
//!
//! | Segment | Bytes | Constrained to |
//! |---|---|---|
//! | `Const` | fixed bytes | the constant |
//! | `Public` | a run of public values | those public values |
//! | `Carried` | a run of carried columns | those columns, constant over the trace |
//! | `Free` | witness bytes | nothing beyond being bytes |
//! | `Prev` | 32 bytes | the digest of the hash just before |
//! | `Node` | 64 bytes | the digest just before, left or right by the direction bit; the other half is free |
//! | `Amount` | a 32-byte amount word | 20 zero bytes, then the six carried limbs |
//!
//! `Prev` and `Node` must lie in the first block of their hash, and the hash
//! they follow must be the one just before in the list, so the two
//! permutations are adjacent in the trace.

use alloc::vec;
use alloc::vec::Vec;

use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

use crate::amount::{AMOUNT_HIGH_BYTES, AMOUNT_LIMBS, limb_bytes};
use crate::hash::{RATE_BYTES, absorb, rate_bytes, squeeze};

/// Where the bytes of a segment come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    Const(Vec<u8>),
    Public { offset: usize, len: usize },
    Carried { col: usize, len: usize },
    Free(usize),
    Prev,
    Node,
    Amount { col: usize },
}

impl Seg {
    fn len(&self) -> usize {
        match self {
            Self::Const(bytes) => bytes.len(),
            Self::Public { len, .. } | Self::Carried { len, .. } => *len,
            Self::Free(len) => *len,
            Self::Prev | Self::Amount { .. } => 32,
            Self::Node => 64,
        }
    }
}

/// One hash: its segments in order, and the public offset its digest must
/// equal, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HashSpec {
    pub segs: Vec<Seg>,
    pub output: Option<usize>,
}

/// Conservation of value on carried limbs and public amounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Conservation {
    /// Carried column of limb `a0` of `v` (six columns, least significant first).
    pub v: usize,
    /// Carried column of limb `a0` of `v'`.
    pub remainder: usize,
    /// Carried column of the first carry bit (two bits per carry, `c1 .. c5`).
    pub carries: usize,
    /// Public offset of the `out` word.
    pub out: usize,
    /// Public offset of the `fee` word.
    pub fee: usize,
}

/// A statement as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Schedule {
    pub hashes: Vec<HashSpec>,
    /// Number of public values, each one byte.
    pub num_public: usize,
    /// Number of carried columns.
    pub carried: usize,
    pub conservation: Option<Conservation>,
    /// Public bytes that must hold a fixed value.
    pub public_consts: Vec<(usize, u8)>,
}

/// The source of one byte of a block, after expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Src {
    Const(u8),
    Public(usize),
    Carried(usize),
    Free,
    /// Byte `k` of the previous digest.
    Prev(usize),
    /// Byte `k` of the 64-byte node pair.
    Node(usize),
}

/// One permutation of the trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PermSpec {
    /// The first block of its hash (else it continues the permutation before).
    pub first: bool,
    pub bytes: [Src; RATE_BYTES],
    /// Carried limb columns tied to two bytes: `(column, high byte, low byte)`.
    pub limb_ties: Vec<(usize, usize, usize)>,
    /// Offset of the 32 `Prev` bytes, if the block has them.
    pub prev_at: Option<usize>,
    /// Offset of the 64 `Node` bytes, if the block has them.
    pub node_at: Option<usize>,
    /// Public offset of the digest, on the last permutation of a hash.
    pub output: Option<usize>,
}

impl Schedule {
    /// The permutations of the trace, in order.
    pub(crate) fn expand(&self) -> Vec<PermSpec> {
        let mut perms = Vec::new();
        for (h, hash) in self.hashes.iter().enumerate() {
            let mut srcs: Vec<Src> = Vec::new();
            let mut ties = Vec::new();
            let mut prev_at = None;
            let mut node_at = None;
            for seg in &hash.segs {
                let start = srcs.len();
                match seg {
                    Seg::Const(bytes) => srcs.extend(bytes.iter().map(|&b| Src::Const(b))),
                    Seg::Public { offset, len } => srcs.extend((0..*len).map(|k| Src::Public(offset + k))),
                    Seg::Carried { col, len } => srcs.extend((0..*len).map(|k| Src::Carried(col + k))),
                    Seg::Free(len) => srcs.extend((0..*len).map(|_| Src::Free)),
                    Seg::Prev => {
                        assert!(h > 0, "a Prev segment needs a hash before it");
                        prev_at = Some(start);
                        srcs.extend((0..32).map(Src::Prev));
                    }
                    Seg::Node => {
                        assert!(h > 0, "a Node segment needs a hash before it");
                        node_at = Some(start);
                        srcs.extend((0..64).map(Src::Node));
                    }
                    Seg::Amount { col } => {
                        srcs.extend((0..AMOUNT_HIGH_BYTES).map(|_| Src::Const(0)));
                        srcs.extend((AMOUNT_HIGH_BYTES..32).map(|_| Src::Free));
                        for j in 0..AMOUNT_LIMBS {
                            let (hi, lo) = limb_bytes(j);
                            ties.push((col + j, start + hi, start + lo));
                        }
                    }
                }
            }
            let len = srcs.len();
            let blocks = crate::hash::permutations(len);
            srcs.resize(blocks * RATE_BYTES, Src::Const(0));
            let pad_last = blocks * RATE_BYTES - 1;
            srcs[len] = Src::Const(0x01);
            srcs[pad_last] = Src::Const(if len == pad_last { 0x81 } else { 0x80 });
            for (n, block) in srcs.chunks_exact(RATE_BYTES).enumerate() {
                let range = n * RATE_BYTES..(n + 1) * RATE_BYTES;
                let inside = |at: Option<usize>, width: usize| {
                    at.filter(|&a| range.contains(&a)).inspect(|&a| {
                        assert!(a + width <= range.end, "a linked digest must not cross a block");
                        assert_eq!(n, 0, "a linked digest must be in the first block");
                    })
                };
                let block_ties = ties
                    .iter()
                    .filter(|(_, hi, _)| range.contains(hi))
                    .map(|&(col, hi, lo)| {
                        assert!(range.contains(&lo), "an amount limb must not cross a block");
                        (col, hi - range.start, lo - range.start)
                    })
                    .collect();
                perms.push(PermSpec {
                    first: n == 0,
                    bytes: block.try_into().expect("one block"),
                    limb_ties: block_ties,
                    prev_at: inside(prev_at, 32).map(|a| a - range.start),
                    node_at: inside(node_at, 64).map(|a| a - range.start),
                    output: if n + 1 == blocks { hash.output } else { None },
                });
            }
        }
        perms
    }
}

/// The witness side of a schedule.
pub(crate) struct Assignment {
    /// Public values, one byte each.
    pub public: Vec<u8>,
    /// Carried column values.
    pub carried: Vec<u32>,
    /// Per hash: the free bytes in segment order (a node's sibling included).
    pub free: Vec<Vec<u8>>,
    /// Per hash: the direction bit of a node hash (`true`: the child is the
    /// right half).
    pub dirs: Vec<bool>,
}

/// What the prover computed: everything the trace needs.
pub(crate) struct Execution {
    /// Per permutation: the input state.
    pub inputs: Vec<[u64; 25]>,
    /// Per permutation: the message block absorbed.
    pub blocks: Vec<[u8; RATE_BYTES]>,
    /// Per permutation: the rate of the state before absorbing (the output of
    /// the permutation before, for a continuation block).
    pub prev_rate: Vec<[u8; RATE_BYTES]>,
    /// Per permutation: the direction bit.
    pub dirs: Vec<bool>,
    /// Per hash: the digest.
    pub digests: Vec<[u8; 32]>,
}

/// Run the schedule natively on an assignment.
pub(crate) fn execute(schedule: &Schedule, a: &Assignment) -> Execution {
    assert_eq!(a.public.len(), schedule.num_public);
    assert_eq!(a.carried.len(), schedule.carried);
    assert_eq!(a.free.len(), schedule.hashes.len());
    assert_eq!(a.dirs.len(), schedule.hashes.len());
    let mut ex = Execution {
        inputs: Vec::new(),
        blocks: Vec::new(),
        prev_rate: Vec::new(),
        dirs: Vec::new(),
        digests: Vec::new(),
    };
    let mut state = [0u64; 25];
    let mut prev = [0u8; 32];
    for (h, hash) in schedule.hashes.iter().enumerate() {
        let mut free = a.free[h].iter().copied();
        let mut take = |n: usize| -> Vec<u8> {
            let bytes: Vec<u8> = free.by_ref().take(n).collect();
            assert_eq!(bytes.len(), n, "free bytes of hash {h} run short");
            bytes
        };
        let mut msg = Vec::new();
        for seg in &hash.segs {
            match seg {
                Seg::Const(bytes) => msg.extend_from_slice(bytes),
                Seg::Public { offset, len } => msg.extend_from_slice(&a.public[*offset..offset + len]),
                Seg::Carried { col, len } => {
                    msg.extend(a.carried[*col..col + len].iter().map(|&x| x as u8));
                }
                Seg::Free(len) => msg.extend(take(*len)),
                Seg::Prev => msg.extend_from_slice(&prev),
                Seg::Node => {
                    let sibling = take(32);
                    if a.dirs[h] {
                        msg.extend(sibling);
                        msg.extend_from_slice(&prev);
                    } else {
                        msg.extend_from_slice(&prev);
                        msg.extend(sibling);
                    }
                }
                Seg::Amount { col } => {
                    let mut word = [0u8; 32];
                    for j in 0..AMOUNT_LIMBS {
                        let (hi, lo) = limb_bytes(j);
                        let limb = a.carried[col + j];
                        word[hi] = (limb >> 8) as u8;
                        word[lo] = limb as u8;
                    }
                    msg.extend_from_slice(&word);
                }
            }
        }
        assert_eq!(free.next(), None, "free bytes of hash {h} left over");
        debug_assert_eq!(msg.len(), hash.segs.iter().map(Seg::len).sum::<usize>());
        for (n, block) in crate::hash::pad(&msg).chunks_exact(RATE_BYTES).enumerate() {
            if n == 0 {
                state = [0u64; 25];
            }
            ex.prev_rate.push(rate_bytes(&state));
            absorb(&mut state, block);
            ex.inputs.push(state);
            ex.blocks.push(block.try_into().expect("one block"));
            ex.dirs.push(a.dirs[h]);
            KeccakF.permute_mut(&mut state);
        }
        prev = squeeze(&state);
        ex.digests.push(prev);
    }
    ex
}

/// Builds the segments of one hash, and its free bytes when a witness is
/// present, side by side so the two cannot drift apart.
pub(crate) struct HashBuilder {
    segs: Vec<Seg>,
    free: Vec<u8>,
    dir: bool,
    output: Option<usize>,
}

impl HashBuilder {
    pub(crate) fn new(tag: &str) -> Self {
        Self {
            segs: vec![Seg::Const(crate::hash::tag_bytes(tag))],
            free: Vec::new(),
            dir: false,
            output: None,
        }
    }

    pub(crate) fn constant(mut self, bytes: &[u8]) -> Self {
        self.segs.push(Seg::Const(bytes.to_vec()));
        self
    }

    pub(crate) fn public(mut self, offset: usize, len: usize) -> Self {
        self.segs.push(Seg::Public { offset, len });
        self
    }

    pub(crate) fn carried(mut self, col: usize, len: usize) -> Self {
        self.segs.push(Seg::Carried { col, len });
        self
    }

    /// Witness bytes with no constraint beyond being bytes. `bytes` is `None`
    /// on the verifier's side.
    pub(crate) fn free(mut self, len: usize, bytes: Option<&[u8]>) -> Self {
        self.segs.push(Seg::Free(len));
        if let Some(bytes) = bytes {
            assert_eq!(bytes.len(), len);
            self.free.extend_from_slice(bytes);
        }
        self
    }

    pub(crate) fn prev(mut self) -> Self {
        self.segs.push(Seg::Prev);
        self
    }

    /// The previous digest and a sibling, ordered by `right` (the previous
    /// digest is the right child).
    pub(crate) fn node(mut self, sibling: Option<(&[u8; 32], bool)>) -> Self {
        self.segs.push(Seg::Node);
        if let Some((sibling, right)) = sibling {
            self.free.extend_from_slice(sibling);
            self.dir = right;
        }
        self
    }

    pub(crate) fn amount(mut self, col: usize) -> Self {
        self.segs.push(Seg::Amount { col });
        self
    }

    pub(crate) fn output(mut self, offset: usize) -> Self {
        self.output = Some(offset);
        self
    }
}

/// Collects hashes into a schedule and, for the prover, an assignment.
pub(crate) struct ScheduleBuilder {
    hashes: Vec<HashSpec>,
    free: Vec<Vec<u8>>,
    dirs: Vec<bool>,
}

impl ScheduleBuilder {
    pub(crate) fn new() -> Self {
        Self {
            hashes: Vec::new(),
            free: Vec::new(),
            dirs: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, hash: HashBuilder) {
        self.hashes.push(HashSpec {
            segs: hash.segs,
            output: hash.output,
        });
        self.free.push(hash.free);
        self.dirs.push(hash.dir);
    }

    /// The schedule and the free bytes and direction bits per hash.
    pub(crate) fn finish(
        self,
        num_public: usize,
        carried: usize,
        conservation: Option<Conservation>,
        public_consts: Vec<(usize, u8)>,
    ) -> (Schedule, Vec<Vec<u8>>, Vec<bool>) {
        (
            Schedule {
                hashes: self.hashes,
                num_public,
                carried,
                conservation,
                public_consts,
            },
            self.free,
            self.dirs,
        )
    }
}

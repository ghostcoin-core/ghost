//! Ghost client library: Phantom Keys, derivation from the digits, building a
//! commit, the encrypted note, building and proving a coin reveal, restore
//! from the digits and the choice of tree state.
//!
//! This crate implements specification 01 (`docs/spec/01-commitments-and-keys.md`):
//!
//! - [`key`]: generating, formatting and parsing a Phantom Key, with its
//!   checksum groups (sections 5 and 6).
//! - [`derive`]: every secret derived from the digits: the key bytes, `s`,
//!   `r`, the blinding `b_i`, the note key and the data key (section 7).
//! - [`commit`]: the content fingerprint, the fingerprint, the commitment and
//!   the marker of a coin or data commitment (sections 3 and 8).
//! - [`hash`]: the tagged Keccak-256 and SHA3-256 of sections 2 and 4.
//! - [`note`]: the encrypted note, ChaCha20-Poly1305 under the note key
//!   (section 9).
//! - [`reveal`]: a partial reveal, a full reveal and a claim to a new key,
//!   proved by the proofs crate (section 8; spec 02, section 4).
//! - [`restore`]: finding the key's current coin from the digits and the
//!   chain's leaves, notes and spent markers (section 8).
//! - [`tree_state`]: the tree state a reveal proves against, the newest
//!   settled root that holds a later leaf (spec 02, section 8).
//! - [`seal`]: the RandomX block seal of a header, checked in light
//!   verification mode (spec 08), on [`randomx`], a Rust port of RandomX v1
//!   light-mode hashing.
//!
//! # Secrets
//!
//! The library never stores a key or a secret: it writes nothing to a file,
//! to browser storage or to any other store. Every type that holds a key or a
//! secret value has no `Debug`, `Display`, `Clone` or serialisation, and
//! overwrites its bytes with zeros when it is dropped. The hash state of
//! `tiny-keccak` and the cipher state of `chacha20poly1305` are not wiped
//! after use; those crates offer no way to do so here.
//!
//! # Randomness
//!
//! Key generation and note encryption take the caller's cryptographically
//! secure generator (any [`rand_core::CryptoRng`]), and proving takes 32
//! random bytes from the caller. The crate never reads the operating system's
//! random source itself, so it builds for `wasm32-unknown-unknown` without one;
//! the web app passes the browser's source.
//!
//! # Network
//!
//! The crate has no network code. Restore and the choice of tree state are
//! pure functions over data the caller fetched in bulk.

pub mod commit;
pub mod derive;
pub mod hash;
pub mod key;
pub mod note;
pub mod randomx;
pub mod restore;
pub mod reveal;
pub mod seal;
pub mod tree_state;
mod wipe;

pub use commit::{
    Amount, CoinCommit, Commitment, CommitError, Content, ContentFingerprint, DataCommit,
    Fingerprint, Marker, Rule, TypeTag, COIN, DATA, V_MAX,
};
pub use derive::{Blinding, DataKey, KeyBytes, NoteKey, RevealSecret, Secret};
pub use key::{check_groups, FormattedKey, KeyError, KeyFormat, PhantomKey};
pub use note::{decrypt_note, encrypt_note, NoteContents, NoteError, NOTE_BYTES};
pub use restore::{restore_coins, Current, DiscardReason, DiscardedNote, FoundCoin, Restored, TreeLeaf};
pub use reveal::{
    claim_to_new_key, full_reveal, partial_reveal, prove_reveal, BuiltReveal, OwnedCoin,
    RemainderCoin, RevealError, RevealTerms,
};
pub use seal::{check_seal, seal_hash, seed_height, verify_seal, HeaderError, SealError, SealKey};
pub use tree_state::{choose_tree_state, HeaderRoot, TreeStateChoice, SETTLE_DEPTH};

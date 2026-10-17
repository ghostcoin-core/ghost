//! Ghost client library: Phantom Keys, derivation from the digits and building
//! a commit.
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
//!
//! # Secrets
//!
//! The library never stores a key or a secret: it writes nothing to a file,
//! to browser storage or to any other store. Every type that holds a key or a
//! secret value has no `Debug`, `Display`, `Clone` or serialisation, and
//! overwrites its bytes with zeros when it is dropped. The hash state of
//! `tiny-keccak` is not wiped after use; that crate offers no way to do so.
//!
//! # Randomness
//!
//! Key generation takes the caller's cryptographically secure generator (any
//! [`rand_core::CryptoRng`]). The crate never reads the operating system's
//! random source itself, so it builds for `wasm32-unknown-unknown` without one;
//! the web app passes the browser's source.

pub mod commit;
pub mod derive;
pub mod hash;
pub mod key;
mod wipe;

pub use commit::{
    Amount, CoinCommit, Commitment, CommitError, Content, ContentFingerprint, DataCommit,
    Fingerprint, Marker, Rule, TypeTag, COIN, DATA, V_MAX,
};
pub use derive::{Blinding, DataKey, KeyBytes, NoteKey, RevealSecret, Secret};
pub use key::{check_groups, FormattedKey, KeyError, KeyFormat, PhantomKey};

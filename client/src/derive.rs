//! Every secret derived from the digits (spec 01, section 7).
//!
//! ```text
//! key_bytes = code || secret digits as ASCII
//! s      = S("ghost/secret/v1",        key_bytes)
//! r      = S("ghost/reveal-secret/v1", key_bytes)
//! b_i    = S("ghost/blinding/v1",      key_bytes, i as 8 bytes)
//! k_note = S("ghost/note-key/v1",      key_bytes)
//! k_data = S("ghost/data-key/v1",      key_bytes)
//! ```
//!
//! Every type here holds a secret: none has `Debug`, `Display`, `Clone` or
//! serialisation, and each overwrites its bytes with zeros when dropped.

use crate::hash::{self, TAG_BLINDING, TAG_DATA_KEY, TAG_NOTE_KEY, TAG_REVEAL_SECRET, TAG_SECRET};
use crate::key::PhantomKey;
use crate::wipe::wipe;

/// The longest key bytes: the format code and 88 secret digits.
const MAX_KEY_BYTES: usize = 89;

macro_rules! secret_32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name([u8; 32]);

        impl $name {
            /// The 32 secret bytes. Pass them on; never store or log them.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                wipe(&mut self.0);
            }
        }
    };
}

secret_32! {
    /// The secret `s` of every commitment the key makes.
    Secret
}

secret_32! {
    /// The reveal secret `r`; the marker is computed from it.
    RevealSecret
}

secret_32! {
    /// The blinding `b_i` of the key's commitment number `i`.
    Blinding
}

secret_32! {
    /// The note key `k_note`, which encrypts the notes of the key.
    NoteKey
}

secret_32! {
    /// The data key `k_data`, which encrypts the key's data.
    DataKey
}

/// The key bytes every derivation takes: the format code, then the secret
/// digits as ASCII, without the checksum groups. 45 bytes for a standard key,
/// 89 for a long key.
pub struct KeyBytes {
    bytes: [u8; MAX_KEY_BYTES],
    len: usize,
}

impl Drop for KeyBytes {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl KeyBytes {
    /// The key bytes of a key whose checksum has been checked.
    pub fn of(key: &PhantomKey) -> Self {
        let mut out = Self {
            bytes: [0; MAX_KEY_BYTES],
            len: 0,
        };
        out.bytes[0] = key.key_format().code();
        out.len = 1 + key.copy_secret_digits(&mut out.bytes[1..]);
        out
    }

    /// The bytes. Pass them on; never store or log them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// `s = S("ghost/secret/v1", key_bytes)`.
    pub fn secret(&self) -> Secret {
        Secret(hash::s(TAG_SECRET, &[self.as_bytes()]))
    }

    /// `r = S("ghost/reveal-secret/v1", key_bytes)`.
    pub fn reveal_secret(&self) -> RevealSecret {
        RevealSecret(hash::s(TAG_REVEAL_SECRET, &[self.as_bytes()]))
    }

    /// `b_i = S("ghost/blinding/v1", key_bytes, i as 8 bytes)`, the blinding
    /// of the key's commitment number `index` (its hop number, spec 01,
    /// section 8).
    pub fn blinding(&self, index: u64) -> Blinding {
        Blinding(hash::s(TAG_BLINDING, &[self.as_bytes(), &index.to_be_bytes()]))
    }

    /// `k_note = S("ghost/note-key/v1", key_bytes)`.
    pub fn note_key(&self) -> NoteKey {
        NoteKey(hash::s(TAG_NOTE_KEY, &[self.as_bytes()]))
    }

    /// `k_data = S("ghost/data-key/v1", key_bytes)`.
    pub fn data_key(&self) -> DataKey {
        DataKey(hash::s(TAG_DATA_KEY, &[self.as_bytes()]))
    }
}

impl PhantomKey {
    /// The key bytes of this key.
    pub fn key_bytes(&self) -> KeyBytes {
        KeyBytes::of(self)
    }

    /// The secret `s`.
    pub fn secret(&self) -> Secret {
        self.key_bytes().secret()
    }

    /// The reveal secret `r`.
    pub fn reveal_secret(&self) -> RevealSecret {
        self.key_bytes().reveal_secret()
    }

    /// The blinding `b_i` of the key's commitment number `index`.
    pub fn blinding(&self, index: u64) -> Blinding {
        self.key_bytes().blinding(index)
    }

    /// The note key `k_note`.
    pub fn note_key(&self) -> NoteKey {
        self.key_bytes().note_key()
    }

    /// The data key `k_data`.
    pub fn data_key(&self) -> DataKey {
        self.key_bytes().data_key()
    }
}

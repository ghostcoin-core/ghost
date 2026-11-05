//! Ghost client library: Phantom Keys, derivation from the digits, building a
//! commit, the encrypted note, building and proving a coin reveal, restore
//! from the digits and the choice of tree state.
//!
//! This crate implements specification 01 (`docs/spec/01-commitments-and-keys.md`):
//!
//! - [`account`]: the wallet seed and its 24 words, the quantum-safe account
//!   keys it derives (plain ML-DSA-44 and rescue-key accounts), the account
//!   address and the signed account transaction (spec 09, sections 5, 6
//!   and 9).
//! - [`slh_dsa`]: SLH-DSA-SHAKE-128s (FIPS 205), the rescue key of a
//!   rescue-key account (spec 09, section 5.1).
//! - [`key`]: generating, formatting and parsing a Phantom Key, 24 words that
//!   can also be shown as 21 digit groups, with its check (sections 5 and 6).
//! - [`derive`]: every secret derived from the digits: the key bytes, `s`,
//!   `r`, the blinding `b_i`, the note key and the data key (section 7).
//! - [`commit`]: the content fingerprint, the fingerprint, the commitment and
//!   the marker of a coin or data commitment, salted (version 2, a fresh salt
//!   from the caller's generator for every new commitment), and the data of a
//!   salted commit (sections 3 and 8). The unsalted version 1 format is
//!   neither made nor read.
//! - [`guard`]: Ghost Guard in the wallet (spec 10, sections 3.1, 12 and
//!   13): the Guard rule under a fresh action salt, the commit, the normal
//!   spend with the override, the words-only spend in the policy class,
//!   release, cancel, transfer, restore and the warnings. The guard secret
//!   comes from the wallet seed and the stop root from the stop card; neither
//!   from a Phantom Key.
//! - [`hash`]: the tagged Keccak-256 and SHA3-256 of sections 2 and 4.
//! - [`note`]: the encrypted note, ChaCha20-Poly1305 under the note key
//!   (section 9): note version 3, 380 bytes for every commitment, with the
//!   capsule that opens its rule (spec 10, section 3.2), and the 156-byte
//!   note version 2 of the data reveal's slot and of the remainders of the
//!   version 1 reveal, which is no longer built.
//! - [`lookup`]: the 16-byte lookup tag of a commitment number, membership,
//!   first-entry and absence witnesses of the coin and data lookup indices,
//!   membership and absence witnesses of the coin spent-marker set tree, the
//!   trees rebuilt from a block's lists, and the block lookup digest (spec 01,
//!   section 7; spec 05, section 6; decision 0004).
//! - [`note_tag`]: the key-derived lookup tag at the start of every note's
//!   nonce, the bucket rule, and restore from the note buckets of the key's
//!   own tags (sections 8 and 9; spec 05, section 8).
//! - [`reveal`]: a partial reveal, a full reveal and a claim to a new key,
//!   the ordinary reveal of spec 10, section 4 (type `0x50`, version
//!   `0x0002`, a 380-byte note version 3 remainder note with the empty
//!   rule's capsule), proved by the proofs crate (section 8; spec 02,
//!   section 4).
//! - [`restore`]: finding the key's current coin from the digits and the
//!   chain's leaves, notes and spent markers (section 8).
//! - [`restore_requests`]: the requests of a restore by private lookup, the
//!   same 31 queries in the same order for every key (22 padded probes of
//!   the lookup hints, then the fetches for the highest number found),
//!   against a lookup source the caller implements (stage 2 design, "Wallet
//!   restore volume").
//! - [`restore_checks`]: the checks of those answers before use, against a
//!   snapshot header that must be one of the wallet's checked tail headers:
//!   the note decrypts and recomputes its leaf, the coin, marker-set and
//!   lookup witnesses reach the snapshot's roots, and the bulk lists of the
//!   later blocks match their lookup digests; then the decision (the current
//!   commitment, a second session after a spent marker, or "never made a
//!   commitment" with an absence witness), against any restore server.
//! - [`receipts`]: a block's receipts checked against its header's
//!   `receiptsRoot`, and the coin tree's leaves, notes and spent markers
//!   checked against the records in them (spec 05, section 8, item 5).
//! - [`tree_state`]: the tree state a reveal proves against, the newest
//!   settled root that holds a later leaf (spec 02, section 8).
//! - [`seal`]: the RandomX block seal of a header, checked in light
//!   verification mode (spec 08), on [`randomx`], a Rust port of RandomX v1
//!   light-mode hashing.
//! - [`header_chain`]: a header chain checked from a trusted start: the ASERT
//!   difficulty of every header (spec 06, section 4.3), its seal under the key
//!   block on its own branch, total work, the best chain and reorganisations.
//! - [`header_sample`]: the header chain checked by sampling (stage 2 design,
//!   "Wallet restore volume"): the last 64 headers in full and headers drawn
//!   by cumulative work with the caller's generator, each with its seal, its
//!   key block and its path to a Merkle mountain range root the caller gives;
//!   the sample count from an attacker ratio and an assurance target, and a
//!   full check of every header as an option. A sampled check credits only
//!   the linked tail's work; the work below it is returned unauthenticated.
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
//! Key generation, the salt of every new commitment, note encryption and the
//! header samples take the caller's cryptographically secure generator (any
//! [`rand_core::CryptoRng`]), and proving takes 32
//! random bytes from the caller. The crate never reads the operating system's
//! random source itself, so it builds for `wasm32-unknown-unknown` without one;
//! the web app passes the browser's source.
//!
//! # Network
//!
//! The crate has no network code. Restore and the choice of tree state are
//! pure functions over data the caller fetched in bulk; the requests of a
//! restore by private lookup go to a lookup source the caller implements.

pub mod account;
pub mod commit;
pub mod derive;
pub mod guard;
pub mod hash;
pub mod header_chain;
pub mod header_sample;
pub mod key;
mod key_words;
pub mod lookup;
pub mod note;
pub mod note_tag;
pub mod randomx;
pub mod receipts;
pub mod restore;
pub mod restore_checks;
pub mod restore_requests;
pub mod reveal;
pub mod seal;
pub mod slh_dsa;
pub mod tree_state;
mod wipe;
pub mod wordlist;

pub use account::{
    account_address, AccountKey, AccountTx, AccountTxError, RescueAccountKey, SeedError, SeedWords, SignedAccountTx,
    VerifiedAccountTx, WalletSeed, RESCUE_PUBLIC_KEY_BYTES, SCHEME_RESCUE, SCHEME_RESCUE_KEY,
    SLH_DSA_SIGNATURE_BYTES,
};
pub use commit::{
    check_data_commit_value, salted_commit_data, Amount, CoinCommit, Commitment, CommitError, Content,
    ContentFingerprint, DataCommit, Fingerprint, Marker, Rule, Salt, TypeTag, COIN_V2, DATA_RESERVE_WEI, DATA_V2,
    SALTED_COMMIT_DATA_BYTES, SALTED_COMMIT_FORMAT_VERSION, SALT_BYTES, V_MAX,
};
pub use derive::{Blinding, DataKey, KeyBytes, NoteKey, RevealSecret, Secret};
pub use guard::{
    guard_cancel, guard_commit, guard_release, guard_spend, guard_transfer, restore_guard_coins, words_only_spend,
    ActionSalt, BuiltCancel, BuiltGuardSpend, BuiltWordsOnlySpend, CancelTerms, ChainHead, EscrowSlot, GuardChain,
    GuardCommit, GuardError, GuardFound, GuardPolicy, GuardRemainder, GuardRestored, GuardRule, GuardSecret,
    GuardWarning, ReleaseCall, RemainderRule, StopRoot, TreeRoom, HOLD_BLOCKS, HOLD_SECONDS,
};
pub use header_chain::{
    required_difficulty, Added, ChainError, ChainParams, HeaderChain, PinnedStart, StartError, U256,
};
pub use header_sample::{
    bits_per_sample, draw_point, mmr_root, sample_count, verify_mmr_path, CheckedChain, CheckedTail, Fault,
    HeaderCheck, HeaderSampler, LeafPosition, MmrNode, MmrPath, PathError, ProvenHeader, ProvenSample, Request,
    SampleError, SampleSettings, MMR_NODE_BYTES, TAIL_HEADERS,
};
pub use key::{check_groups, FormattedKey, KeyError, KeyFormat, PhantomKey};
pub use lookup::{
    check_lookup_digest, global_position, key_lookup_tag, verify_lookup, verify_lookup_membership,
    verify_marker_absence, verify_marker_membership, BlockLookupList, CoinMarkerSet, LookupAnswer, LookupIndex,
    LookupTree, WitnessError,
};
pub use note::{
    decrypt_note, decrypt_note_v2, decrypt_note_with_capsule, encrypt_note, encrypt_note_v2, pad_reveal_note, Capsule,
    NoteContents, NoteError, CAPSULE_BYTES, NOTE_BYTES, REVEAL_NOTE_BYTES,
};
pub use receipts::{
    check_block_receipts, check_block_receipts_against_header, check_leaves, check_markers, receipts_root,
    AppendedLeaf, CheckedBlock, CoinRecord, ReceiptError, REVEAL_V2_LOG_BYTES,
};
pub use restore::{
    restore_coins, restore_coins_at, Current, DiscardReason, DiscardedNote, FoundCoin, RestoreError, Restored, TreeLeaf,
    MAX_TREE_LEAVES,
};
pub use restore_checks::{
    check_anchor, check_anchor_on, check_continued, check_session, continue_requests, restore_with_checks, Anchor,
    CheckError, CheckedRestore, CurrentCoin, Decision, NextFrom, NextLeaf,
};
pub use reveal::{
    claim_to_new_key, full_reveal, partial_reveal, prove_reveal, reveal_params, BuiltReveal, OwnedCoin,
    RemainderCoin, RevealError, RevealTerms, REVEAL_TX_TYPE, REVEAL_VERSION,
};
pub use seal::{
    check_seal, header_fields, seal_hash, seed_height, verify_seal, HeaderError, HeaderFields, SealError,
    SealKey,
};
pub use tree_state::{choose_tree_state, HeaderRoot, TreeStateChoice, SETTLE_DEPTH};

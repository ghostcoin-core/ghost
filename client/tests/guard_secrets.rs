//! The two Guard secrets are independent of the words (spec 10, sections 3.1
//! and 12; property RP-28): the guard secret comes from the wallet seed under
//! its own tag and index, the stop root from the caller's random source or
//! the stop card's bytes, and no code path derives either from a Phantom Key.

use std::any::TypeId;
use std::fs;
use std::path::{Path, PathBuf};

use ghost_client::guard::TAG_GUARD_SECRET;
use ghost_client::{
    decrypt_note_with_capsule, guard_commit, Amount, GuardPolicy, GuardRule, GuardSecret, KeyFormat, PhantomKey,
    StopRoot, TreeRoom, WalletSeed,
};
use ghost_proofs::{policy_action_tag, policy_override_hash};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tiny_keccak::{Hasher, Shake};

const CHAIN_ID: u64 = 1234;

fn policy() -> GuardPolicy {
    GuardPolicy::new([0x47; 20], [0x5a; 32]).unwrap()
}

/// `X(tag, 32, parts...)`: SHAKE256 over the tag's length byte, the tag and
/// the parts, written out here rather than taken from the crate.
fn shake_32(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake::v256();
    hasher.update(&[tag.len() as u8]);
    hasher.update(tag.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[test]
fn the_guard_secret_is_a_hash_of_the_wallet_seed_and_an_index() {
    assert_eq!(TAG_GUARD_SECRET, "ghost/wallet-guard-secret/v1");
    let bytes = [0x3c; 32];
    let seed = WalletSeed::from_bytes(bytes);
    for index in [0u32, 1, 7, u32::MAX] {
        let secret = GuardSecret::from_seed(&seed, index);
        let expected = shake_32(TAG_GUARD_SECRET, &[&bytes, &index.to_be_bytes()]);
        assert_eq!(secret.as_bytes(), &expected);
        assert_eq!(secret.override_hash(), policy_override_hash(&expected));
    }
    // One seed gives the same secret again (a restored wallet has it back);
    // another index or another seed gives another.
    let a = GuardSecret::from_seed(&seed, 0);
    assert_eq!(a.as_bytes(), GuardSecret::from_seed(&WalletSeed::from_bytes(bytes), 0).as_bytes());
    assert_ne!(a.as_bytes(), GuardSecret::from_seed(&seed, 1).as_bytes());
    assert_ne!(a.as_bytes(), GuardSecret::from_seed(&WalletSeed::from_bytes([0x3d; 32]), 0).as_bytes());
    // It is not the seed's account key seed under the account tag either.
    let account = shake_32("ghost/wallet-account/v1", &[&bytes, &[0, 1], &0u32.to_be_bytes()]);
    assert_ne!(a.as_bytes(), &account);
}

#[test]
fn the_words_never_give_a_guard_secret_or_a_stop_root() {
    let mut rng = StdRng::seed_from_u64(28);
    let seed = WalletSeed::from_bytes([0x3c; 32]);
    let secret = GuardSecret::from_seed(&seed, 0);
    for _ in 0..8 {
        let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
        // The words and the digits of a Phantom Key are refused as a wallet
        // seed, the only source of a guard secret.
        let words = key.format_words().unwrap();
        assert!(WalletSeed::from_words(words.as_str()).is_err());
        assert!(WalletSeed::from_words(key.format_groups().as_str()).is_err());
        // No value the words derive is the guard secret or opens its
        // override hash.
        let kb = key.key_bytes();
        let mut derived: Vec<[u8; 32]> = vec![
            *kb.secret().as_bytes(),
            *kb.reveal_secret().as_bytes(),
            *kb.note_key().as_bytes(),
            *kb.data_key().as_bytes(),
        ];
        derived.extend((0..4).map(|i| *kb.blinding(i).as_bytes()));
        derived.push(kb.as_bytes()[1..].try_into().unwrap());
        for value in &derived {
            assert_ne!(value, secret.as_bytes());
            assert_ne!(policy_override_hash(value), secret.override_hash());
        }
    }
}

#[test]
fn the_stop_root_is_the_callers_random_bytes() {
    let mut rng = StdRng::seed_from_u64(0x570);
    let mut copy = StdRng::seed_from_u64(0x570);
    let mut expected = [0u8; 32];
    copy.fill_bytes(&mut expected);
    let root = StopRoot::generate(&mut rng).unwrap();
    assert_eq!(root.as_bytes(), &expected);
    let other = StopRoot::generate(&mut rng).unwrap();
    assert_ne!(root.as_bytes(), other.as_bytes());
    // The card's bytes are taken as they are.
    let card = StopRoot::from_bytes([0x5c; 32]).unwrap();
    assert_eq!(card.as_bytes(), &[0x5c; 32]);
}

#[test]
fn the_rule_note_and_capsule_hold_only_hashes_of_the_secrets() {
    let mut rng = StdRng::seed_from_u64(0xca9);
    let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
    let secret = GuardSecret::from_seed(&WalletSeed::from_bytes([0x3c; 32]), 0);
    let stop = StopRoot::generate(&mut rng).unwrap();
    let rule = GuardRule::new(&policy(), &secret, &stop, &mut rng).unwrap();
    assert_eq!(rule.override_hash(), &policy_override_hash(secret.as_bytes()));
    assert_eq!(rule.action_tag(), &policy_action_tag(stop.as_bytes(), rule.action_salt().as_bytes()));

    let room = TreeRoom {
        filled_leaves: 0,
        leaves_per_block: 64,
    };
    let commit = guard_commit(&key, CHAIN_ID, Amount::new(10_000).unwrap(), &rule, &room, &mut rng).unwrap();
    let (_, capsule) =
        decrypt_note_with_capsule(&key.note_key(), CHAIN_ID, &commit.commit.commitment, &commit.note).unwrap();
    let bytes = capsule.to_bytes();
    for hidden in [secret.as_bytes(), stop.as_bytes()] {
        assert!(!bytes.windows(32).any(|w| w == hidden));
        assert!(!commit.data.windows(32).any(|w| w == hidden));
    }
    // The rule takes no key: the same secret, stop root and salt give the
    // same rule whichever Phantom Key holds the coin.
    let mut a = StdRng::seed_from_u64(5);
    let mut b = StdRng::seed_from_u64(5);
    let ra = GuardRule::new(&policy(), &secret, &stop, &mut a).unwrap();
    let rb = GuardRule::new(&policy(), &secret, &stop, &mut b).unwrap();
    assert!(ra == rb);
}

#[test]
fn the_two_secrets_are_different_types() {
    assert_ne!(TypeId::of::<GuardSecret>(), TypeId::of::<StopRoot>());
    assert_ne!(TypeId::of::<GuardSecret>(), TypeId::of::<ghost_client::Secret>());
    assert_ne!(TypeId::of::<StopRoot>(), TypeId::of::<ghost_client::KeyBytes>());
}

// A scan of the client's source: no function that makes a guard secret or a
// stop root, and no impl block of either type, names a Phantom Key or one of
// its derivations.

/// What a derivation from the words is written with.
const FROM_THE_WORDS: &[&str] = &[
    "PhantomKey",
    "KeyBytes",
    "key_bytes",
    "copy_key_secret",
    "note_key",
    "data_key",
    "reveal_secret",
    "blinding",
    ".secret()",
    "format_groups",
    "format_words",
    "key_words",
];

/// The guarded types.
const GUARDED: &[&str] = &["GuardSecret", "StopRoot"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The source without comment lines (doc comments hold prose and examples).
fn code(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text from `start` to the brace that closes the first `{` at or after
/// it, or to the first `;` outside brackets if that comes first (so the `;`
/// of an array type such as `[u8; 32]` does not end a signature).
fn item(text: &str, start: usize) -> &str {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut nest = 0usize;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        match b {
            b'(' | b'[' => nest += 1,
            b')' | b']' => nest = nest.saturating_sub(1),
            b';' if depth == 0 && nest == 0 => return &text[start..=i],
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[start..=i];
                }
            }
            _ => {}
        }
    }
    &text[start..]
}

fn is_word_start(text: &str, at: usize) -> bool {
    at == 0 || !text.as_bytes()[at - 1].is_ascii_alphanumeric() && text.as_bytes()[at - 1] != b'_'
}

/// Every item of `text` that makes a guarded value: an `impl` block whose
/// header names a guarded type, and a `fn` whose return type names one.
fn makers(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (at, _) in text.match_indices("impl") {
        if !is_word_start(text, at) {
            continue;
        }
        let whole = item(text, at);
        let header = &whole[..whole.find('{').unwrap_or(whole.len())];
        if GUARDED.iter().any(|ty| header.contains(ty)) {
            found.push(whole.to_owned());
        }
    }
    for (at, _) in text.match_indices("fn ") {
        if !is_word_start(text, at) {
            continue;
        }
        let whole = item(text, at);
        let signature = &whole[..whole.find('{').unwrap_or(whole.len())];
        let returns = signature.split("->").nth(1).unwrap_or("");
        if GUARDED.iter().any(|ty| returns.contains(ty)) {
            found.push(whole.to_owned());
        }
    }
    found
}

fn names_the_words(item: &str) -> Option<&'static str> {
    FROM_THE_WORDS.iter().copied().find(|word| item.contains(word))
}

#[test]
fn the_scan_finds_a_derivation_from_the_words() {
    // The scan is not blind: a maker that reads a key is caught, one that
    // reads the seed is not.
    let bad = concat!(
        "impl GuardSecret {\n",
        "    pub fn of(key: &PhantomKey) -> Self {\n",
        "        Self(*key.key_bytes().secret().as_bytes())\n",
        "    }\n}\n",
    );
    let items = makers(bad);
    assert_eq!(items.len(), 1);
    assert!(names_the_words(&items[0]).is_some());
    let bad_fn = concat!(
        "pub fn card(k: &KeyBytes) -> StopRoot {\n",
        "    StopRoot::from_bytes(*k.note_key().as_bytes()).unwrap()\n}\n",
    );
    assert!(makers(bad_fn).iter().any(|i| names_the_words(i).is_some()));
    let bad_array = "fn card(k: [u8; 33], key: &PhantomKey) -> StopRoot {\n    todo!()\n}\n";
    assert!(makers(bad_array).iter().any(|i| names_the_words(i).is_some()));
    let bad_from ="impl From<&PhantomKey> for StopRoot {\n    fn from(k: &PhantomKey) -> Self { todo!() }\n}\n";
    assert!(makers(bad_from).iter().any(|i| names_the_words(i).is_some()));
    let good = concat!(
        "impl GuardSecret {\n",
        "    pub fn from_seed(seed: &WalletSeed, index: u32) -> Self {\n",
        "        Self(x(TAG, &[seed.as_bytes()]))\n",
        "    }\n}\n",
    );
    assert!(makers(good).iter().all(|i| names_the_words(i).is_none()));
}

#[test]
fn no_code_path_derives_either_secret_from_a_phantom_key() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.iter().any(|f| f.ends_with("guard.rs")));
    let mut makers_seen = 0;
    for file in &files {
        let text = code(&fs::read_to_string(file).unwrap());
        for found in makers(&text) {
            makers_seen += 1;
            if let Some(word) = names_the_words(&found) {
                panic!("{} makes a Guard secret with `{word}`:\n{found}", file.display());
            }
        }
    }
    // The scan saw the real makers: both impl blocks, their drops, and more.
    assert!(makers_seen >= 4, "the scan found only {makers_seen} makers");
    let guard = code(&fs::read_to_string(src.join("guard.rs")).unwrap());
    let found = makers(&guard);
    assert!(found.iter().any(|i| i.contains("fn from_seed(seed: &WalletSeed, index: u32) -> Self")));
    assert!(found.iter().any(|i| i.contains("fn generate<")));
    assert!(found.iter().any(|i| i.contains("fn from_bytes(bytes: [u8; 32]) -> Result<Self, GuardError>")));
}

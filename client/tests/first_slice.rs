//! Phantom Keys, derivation and building a commit, checked against the
//! vectors of spec 01, section 14: words keys written as their digit view.

use std::collections::HashSet;
use std::convert::Infallible;

use ghost_client::{
    check_groups, Amount, Content, KeyError, KeyFormat, PhantomKey, Rule,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const SPEC: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");

/// One `[name]` block.
struct Vector {
    name: String,
    fields: Vec<(String, String)>,
}

impl Vector {
    fn get(&self, field: &str) -> &str {
        self.fields
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("vector {} has no field {field}", self.name))
    }

    fn hex(&self, field: &str) -> Vec<u8> {
        decode_hex(self.get(field))
    }

    fn hex32(&self, field: &str) -> [u8; 32] {
        self.hex(field)
            .try_into()
            .unwrap_or_else(|_| panic!("{}.{field} is not 32 bytes", self.name))
    }
}

/// Every vector in the `text` blocks of `section`.
fn parse_vectors(section: &str) -> Vec<Vector> {
    let mut out: Vec<Vector> = Vec::new();
    let mut in_vectors = false;
    let mut in_other_block = false;
    for line in section.lines() {
        let line = line.trim_end();
        if line.starts_with("```") {
            if in_vectors || in_other_block {
                in_vectors = false;
                in_other_block = false;
            } else if line == "```text" {
                in_vectors = true;
            } else {
                in_other_block = true;
            }
            continue;
        }
        if !in_vectors || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Vector {
                name: name.to_string(),
                fields: Vec::new(),
            });
            continue;
        }
        let (field, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("vector line without '=': {line}"));
        out.last_mut()
            .expect("a field line belongs to a vector")
            .fields
            .push((field.trim().to_string(), value.trim().to_string()));
    }
    out
}

/// The vectors of spec 01, section 14.
fn vectors() -> Vec<Vector> {
    let (_, section) = SPEC
        .split_once("## 14. Test vectors")
        .expect("spec 01 has a test vector section");
    parse_vectors(section)
}

fn vector(name: &str) -> Vector {
    vectors()
        .into_iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("no vector [{name}]"))
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digits"))
        .collect()
}

/// The ASCII digits of typed text, separators removed.
fn digits_of(text: &str) -> Vec<u8> {
    text.bytes().filter(u8::is_ascii_digit).collect()
}

/// The 80 secret digits of a digit view: group 21 removed.
fn secret_digits_of(digits: &[u8]) -> Vec<u8> {
    assert_eq!(digits.len(), 84);
    digits[..80].to_vec()
}

/// A typed rendering of digits as space-separated groups.
fn groups_of(digits: &[u8]) -> String {
    digits
        .chunks(4)
        .map(|g| std::str::from_utf8(g).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse(text: &str) -> PhantomKey {
    PhantomKey::parse(text).unwrap_or_else(|e| panic!("{text:?} does not parse: {e}"))
}

/// The valid keys of the checksum vectors of spec 01: the example key, zero, the
/// second example key and `2^256 - 1`, each as its digit view.
const VALID_KEYS: [&str; 4] = [
    "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812",
    "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0700",
    "0005 7669 0013 0642 8065 9560 5300 0376 8759 3842 1040 3453 0406 4124 0510 2397 3211 7841 8613 4399 8027",
    "0011 5792 0892 3731 6195 4235 7098 5008 6879 0785 3269 9846 6564 0564 0394 5758 4007 9131 2963 9935 6994",
];

#[test]
fn phantom_key_round_trip() {
    let mut rng = StdRng::seed_from_u64(1);
    for _ in 0..100 {
        let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
        assert_eq!(key.key_format(), KeyFormat::Words);
        let shown = key.format_groups();
        let text = shown.as_str();

        let groups: Vec<&str> = text.split(' ').collect();
        assert_eq!(groups.len(), 21, "{text}");
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_digit())),
            "{text}"
        );

        let parsed = parse(text);
        assert_eq!(parsed.key_format(), KeyFormat::Words);
        assert_eq!(parsed.format_groups().as_str(), text);
        assert_eq!(parsed.key_bytes().as_bytes(), key.key_bytes().as_bytes());
        assert_eq!(parsed.secret().as_bytes(), key.secret().as_bytes());

        // The same digits typed with hyphens, no separators or extra
        // spaces are the same key.
        for typed in [
            text.replace(' ', "-"),
            text.replace(' ', ""),
            format!("  {}  ", text.replace(' ', " - ")),
        ] {
            assert_eq!(parse(&typed).format_groups().as_str(), text);
        }
    }
}

#[test]
fn checksum_rejects_one_digit_change() {
    // A four-digit checksum lets a single wrong secret digit through about one
    // time in 10,000 (spec 01, section 13, question 1). For these valid keys
    // no single-digit change passes, so every one must be rejected.
    for key in VALID_KEYS {
        let digits = digits_of(key);
        assert!(PhantomKey::parse(key).is_ok(), "{key}");
        for position in 0..digits.len() {
            for digit in b'0'..=b'9' {
                if digit == digits[position] {
                    continue;
                }
                let mut changed = digits.clone();
                changed[position] = digit;
                let text = groups_of(&changed);
                assert!(
                    matches!(
                        PhantomKey::parse(&text),
                        Err(KeyError::ChecksumMismatch { .. })
                    ),
                    "one digit changed at {position} passes the check: {text}"
                );
            }
        }
    }
}

#[test]
fn checksum_matches_vectors() {
    let checksum_vectors: Vec<Vector> = vectors()
        .into_iter()
        .filter(|v| v.name.starts_with("checksum-"))
        .collect();
    assert_eq!(checksum_vectors.len(), 7, "seven checksum vectors");
    for v in &checksum_vectors {
        assert_eq!(v.get("kind"), "checksum");
        assert_eq!(v.get("format"), "20", "{}", v.name);
        let format = KeyFormat::Words;
        let digits = digits_of(v.get("key"));
        assert_eq!(digits.len(), format.digit_count(), "{}", v.name);

        let expected: u16 = v.get("check").parse().expect("a check group");
        let computed = check_groups(format, &secret_digits_of(&digits)).unwrap();
        assert_eq!(computed, vec![expected], "{}", v.name);

        let written: u16 = std::str::from_utf8(&digits[80..]).unwrap().parse().unwrap();
        let result = PhantomKey::parse(v.get("key"));
        match v.get("valid") {
            "yes" => {
                let key = result.unwrap_or_else(|e| panic!("{} should pass: {e}", v.name));
                assert_eq!(key.key_format().code(), 0x20);
                assert_eq!(written, expected, "{}", v.name);
            }
            "no" if written != expected => {
                assert_eq!(
                    result.err(),
                    Some(KeyError::ChecksumMismatch { group: 21 }),
                    "{}",
                    v.name
                );
            }
            "no" => {
                // Group 21 is right, so the secret is out of range.
                assert_eq!(result.err(), Some(KeyError::SecretOutOfRange), "{}", v.name);
            }
            other => panic!("{}: valid = {other}", v.name),
        }
    }
}

#[test]
fn key_parse_rejects_bad_characters_and_lengths() {
    let valid = VALID_KEYS[0];
    assert!(PhantomKey::parse(valid).is_ok());
    let one = valid.find('1').unwrap();

    // Any character other than an ASCII digit, a space or a hyphen.
    for (bad, position) in [
        (valid.replacen(' ', "\t", 1), 4),
        (valid.replacen(' ', "_", 1), 4),
        (valid.replacen(' ', ".", 1), 4),
        (valid.replacen(' ', "/", 1), 4),
        (valid.replacen(' ', "\u{2013}", 1), 4),
        (valid.replacen(' ', "\u{a0}", 1), 4),
        (format!("{valid}\n"), 104),
        (valid.replacen('1', "l", 1), one),
        (valid.replacen('1', "a", 1), one),
        // Non-ASCII digits: Arabic-Indic, fullwidth, superscript, Devanagari.
        (valid.replacen('1', "\u{661}", 1), one),
        (valid.replacen('1', "\u{ff11}", 1), one),
        (valid.replacen('1', "\u{b9}", 1), one),
        (valid.replacen('1', "\u{967}", 1), one),
    ] {
        assert_eq!(
            PhantomKey::parse(&bad).err(),
            Some(KeyError::InvalidCharacter { position }),
            "{bad:?}"
        );
    }

    // Exactly 84 digits after separators are removed: the 48 and 96 of the
    // old digit keys are refused like any other count.
    let digits = digits_of(VALID_KEYS[3]);
    for count in [0, 1, 44, 47, 48, 49, 52, 60, 72, 80, 83, 85, 88, 92, 96, 100, 144, 200] {
        let typed: Vec<u8> = digits.iter().copied().cycle().take(count).collect();
        let text = groups_of(&typed);
        assert_eq!(
            PhantomKey::parse(&text).err(),
            Some(KeyError::WrongLength { digits: count }),
            "{count} digits"
        );
    }
    assert_eq!(
        PhantomKey::parse("  - - ").err(),
        Some(KeyError::WrongLength { digits: 0 })
    );

    // Separators in any mix are accepted.
    let bare = valid.replace(' ', "");
    for typed in [
        bare.clone(),
        valid.replace(' ', "-"),
        format!("-{valid}-"),
        valid.replacen(' ', " -- ", 3),
        bare.chars()
            .enumerate()
            .flat_map(|(i, c)| [c, if i % 2 == 0 { '-' } else { ' ' }])
            .collect(),
    ] {
        assert!(PhantomKey::parse(&typed).is_ok(), "{typed:?}");
    }
}

#[test]
fn derivation_matches_vector_derivation_words() {
    let v = vector("derivation-words");
    assert_eq!(v.get("kind"), "derivation");
    let key = parse(v.get("key"));
    assert_eq!(key.key_format(), KeyFormat::Words);
    assert_eq!(key.key_bytes().as_bytes(), v.hex("key-bytes").as_slice());
    assert_eq!(key.secret().as_bytes(), &v.hex32("s"));
    assert_eq!(key.reveal_secret().as_bytes(), &v.hex32("r"));
    assert_eq!(key.blinding(0).as_bytes(), &v.hex32("b0"));
    assert_eq!(key.blinding(1).as_bytes(), &v.hex32("b1"));
    assert_eq!(key.blinding(2).as_bytes(), &v.hex32("b2"));
    assert_eq!(key.note_key().as_bytes(), &v.hex32("note-key"));
    assert_eq!(key.data_key().as_bytes(), &v.hex32("data-key"));
}

#[test]
fn spec_vector_keys_are_all_words_keys() {
    // Every key of spec 01, section 14 is the 84-digit view of a words key;
    // none is of the retired twelve- or twenty-four-group digit formats.
    let mut keys = HashSet::new();
    for v in vectors().iter().filter(|v| v.fields.iter().any(|(f, _)| f == "key")) {
        assert_eq!(digits_of(v.get("key")).len(), 84, "{}", v.name);
        keys.insert(v.get("key").to_string());
    }
    for key in VALID_KEYS {
        assert!(keys.contains(key), "{key} is not a spec 01 vector key");
    }
    for name in ["derivation-standard", "derivation-long", "checksum-standard", "checksum-long"] {
        assert!(!vectors().iter().any(|v| v.name == name), "[{name}] is still in spec 01");
    }
}

fn check_coin_commit(name: &str) {
    let v = vector(name);
    assert_eq!(v.get("kind"), "coin-commitment");
    let key = parse(v.get("key"));
    let index: u64 = v.get("index").parse().unwrap();
    let amount = Amount::new(v.get("amount").parse().unwrap()).unwrap();
    let rule = Rule::from_bytes(v.hex32("rule"));
    let commit = key.coin_commit(index, amount, rule).unwrap();
    assert_eq!(commit.fingerprint.as_bytes(), &v.hex32("fingerprint"));
    assert_eq!(commit.commitment.as_bytes(), &v.hex32("commitment"));
    assert_eq!(commit.marker.as_bytes(), &v.hex32("marker"));
}

#[test]
fn commit_matches_vector_coin_commit() {
    check_coin_commit("coin-commit");
}

#[test]
fn commit_matches_vector_coin_remainder() {
    check_coin_commit("coin-remainder");

    // The remainder differs from the first commitment in every public value.
    let key = parse(VALID_KEYS[0]);
    let amount = Amount::new(700_000_000_000_000_000).unwrap();
    let first = key.coin_commit(0, amount, Rule::EMPTY).unwrap();
    let remainder = key.coin_commit(1, amount, Rule::EMPTY).unwrap();
    assert_ne!(first.fingerprint, remainder.fingerprint);
    assert_ne!(first.commitment, remainder.commitment);
    assert_ne!(first.marker, remainder.marker);
}

#[test]
fn commit_matches_vector_data_commit() {
    let v = vector("data-commit");
    assert_eq!(v.get("kind"), "data-commitment");
    assert_eq!(v.get("index"), "0", "a data commitment uses b_0");
    let key = parse(v.get("key"));
    let content = Content::new(v.get("content-ascii").as_bytes().to_vec());
    assert_eq!(
        content.len(),
        v.get("content-length").parse::<usize>().unwrap()
    );
    let rule = Rule::from_bytes(v.hex32("rule"));
    let commit = key.data_commit(&content, rule).unwrap();
    assert_eq!(
        content.fingerprint().as_bytes(),
        &v.hex32("content-fingerprint")
    );
    assert_eq!(
        commit.content_fingerprint.as_bytes(),
        &v.hex32("content-fingerprint")
    );
    assert_eq!(commit.fingerprint.as_bytes(), &v.hex32("fingerprint"));
    assert_eq!(commit.commitment.as_bytes(), &v.hex32("commitment"));
    assert_eq!(commit.marker.as_bytes(), &v.hex32("marker"));
}

#[test]
fn commit_rejects_amount_above_maximum_and_non_empty_rule() {
    assert!(Amount::new(ghost_client::V_MAX).is_ok());
    assert_eq!(
        Amount::new(ghost_client::V_MAX + 1),
        Err(ghost_client::CommitError::AmountTooLarge)
    );
    let key = parse(VALID_KEYS[0]);
    let mut rule = [0u8; 32];
    rule[31] = 1;
    assert_eq!(
        key.coin_commit(0, Amount::new(1).unwrap(), Rule::from_bytes(rule))
            .err(),
        Some(ghost_client::CommitError::RuleNotSupported)
    );
    assert!(
        key.data_commit(&Content::new(b"x".to_vec()), Rule::from_bytes(rule))
            .is_err()
    );
}

#[test]
fn generated_keys_differ() {
    let mut rng = StdRng::seed_from_u64(3);
    let count = 2000;
    let mut seen = HashSet::new();
    for _ in 0..count {
        let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let text = key.format_groups().as_str().to_string();
        assert!(PhantomKey::parse(&text).is_ok(), "{text}");
        assert!(seen.insert(text), "a generated key repeated");
    }
    assert_eq!(seen.len(), count);
}

/// A generator that returns the given bytes in order, then repeats them.
struct ScriptedBytes {
    bytes: Vec<u8>,
    next: usize,
}

impl rand_core::TryRng for ScriptedBytes {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut out = [0u8; 4];
        self.try_fill_bytes(&mut out)?;
        Ok(u32::from_le_bytes(out))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut out = [0u8; 8];
        self.try_fill_bytes(&mut out)?;
        Ok(u64::from_le_bytes(out))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for slot in dst {
            *slot = self.bytes[self.next % self.bytes.len()];
            self.next += 1;
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ScriptedBytes {}

#[test]
fn generation_takes_32_bytes_as_the_secret() {
    // The bytes 00 to 1f are the secret of the example words key, and every
    // byte value is used as it is, none discarded.
    let mut rng = ScriptedBytes {
        bytes: (0u8..32).collect(),
        next: 0,
    };
    let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
    assert_eq!(rng.next, 32);
    assert_eq!(key.format_groups().as_str(), VALID_KEYS[0]);
    let mut expected = vec![0x20];
    expected.extend(0u8..32);
    assert_eq!(key.key_bytes().as_bytes(), expected.as_slice());

    let mut high = ScriptedBytes {
        bytes: vec![0xff],
        next: 0,
    };
    let key = PhantomKey::generate_default(&mut high);
    assert_eq!(key.format_groups().as_str(), VALID_KEYS[3]);
    let digits = digits_of(key.format_groups().as_str());
    assert_eq!(
        check_groups(KeyFormat::Words, &secret_digits_of(&digits)).unwrap(),
        vec![std::str::from_utf8(&digits[80..]).unwrap().parse::<u16>().unwrap()]
    );
}

//! Phantom Keys, derivation and building a commit, checked against the test
//! vectors of spec 01, section 14, read from the specification itself.

use std::collections::HashSet;
use std::convert::Infallible;

use ghost_client::{
    check_groups, Amount, Content, KeyError, KeyFormat, PhantomKey, Rule,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const SPEC: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");

/// One `[name]` block of section 14.
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

/// Every vector in the `text` blocks of section 14.
fn vectors() -> Vec<Vector> {
    let (_, section) = SPEC
        .split_once("## 14. Test vectors")
        .expect("spec 01 has a test vector section");
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

fn vector(name: &str) -> Vector {
    vectors()
        .into_iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("spec 01 has no vector [{name}]"))
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digits"))
        .collect()
}

fn format_from_code(code: &str) -> KeyFormat {
    match code {
        "0c" => KeyFormat::Standard,
        "18" => KeyFormat::Long,
        other => panic!("unknown format code {other}"),
    }
}

/// The ASCII digits of typed text, separators removed.
fn digits_of(text: &str) -> Vec<u8> {
    text.bytes().filter(u8::is_ascii_digit).collect()
}

/// The secret digits of all digits: groups 12 and 24 removed.
fn secret_digits_of(digits: &[u8]) -> Vec<u8> {
    digits
        .chunks(4)
        .enumerate()
        .filter(|(index, _)| index % 12 != 11)
        .flat_map(|(_, group)| group.iter().copied())
        .collect()
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

const SPEC_VALID_KEYS: [&str; 4] = [
    "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417",
    "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 4156",
    "2718 2818 2845 9045 2353 6028 7471 3526 6249 7757 2470 4457",
    "3141 5926 5358 9793 2384 6264 3383 2795 0288 4197 1693 6390 9937 5105 8209 7494 4592 3078 1640 6286 2089 9862 8034 8042",
];

#[test]
fn phantom_key_round_trip() {
    let mut rng = StdRng::seed_from_u64(1);
    for format in [KeyFormat::Standard, KeyFormat::Long] {
        for _ in 0..50 {
            let key = PhantomKey::generate(format, &mut rng);
            assert_eq!(key.key_format(), format);
            let shown = key.format_groups();
            let text = shown.as_str();

            let groups: Vec<&str> = text.split(' ').collect();
            assert_eq!(groups.len(), format.groups(), "{text}");
            assert!(
                groups
                    .iter()
                    .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_digit())),
                "{text}"
            );

            let parsed = parse(text);
            assert_eq!(parsed.key_format(), format);
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
}

#[test]
fn checksum_rejects_one_digit_change() {
    // A four-digit checksum lets a single wrong secret digit through about one
    // time in 10,000 (spec 01, section 13, question 1). For the spec's valid
    // keys no single-digit change passes, so every one must be rejected.
    for key in SPEC_VALID_KEYS {
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
fn checksum_matches_spec_vectors() {
    let checksum_vectors: Vec<Vector> = vectors()
        .into_iter()
        .filter(|v| v.name.starts_with("checksum-"))
        .collect();
    assert_eq!(checksum_vectors.len(), 8, "spec 01 has eight checksum vectors");
    for v in &checksum_vectors {
        assert_eq!(v.get("kind"), "checksum");
        let format = format_from_code(v.get("format"));
        let digits = digits_of(v.get("key"));
        assert_eq!(digits.len(), format.digit_count(), "{}", v.name);

        let expected: Vec<u16> = v
            .get("check")
            .split(' ')
            .map(|g| g.parse().expect("a check group"))
            .collect();
        let computed = check_groups(format, &secret_digits_of(&digits)).unwrap();
        assert_eq!(computed, expected, "{}", v.name);

        let written: Vec<u16> = digits
            .chunks(4)
            .skip(11)
            .step_by(12)
            .map(|g| std::str::from_utf8(g).unwrap().parse().unwrap())
            .collect();
        let result = PhantomKey::parse(v.get("key"));
        match v.get("valid") {
            "yes" => {
                assert!(result.is_ok(), "{} should pass", v.name);
                assert_eq!(written, expected, "{}", v.name);
            }
            "no" => {
                // The first checksum group that differs is the one named.
                let index = written
                    .iter()
                    .zip(&expected)
                    .position(|(w, e)| w != e)
                    .expect("an invalid vector has a wrong check group");
                assert_eq!(
                    result.err(),
                    Some(KeyError::ChecksumMismatch {
                        group: 12 * (index + 1)
                    }),
                    "{}",
                    v.name
                );
            }
            other => panic!("{}: valid = {other}", v.name),
        }
    }
}

#[test]
fn key_parse_rejects_bad_characters_and_lengths() {
    let valid = SPEC_VALID_KEYS[0];
    assert!(PhantomKey::parse(valid).is_ok());

    // Any character other than an ASCII digit, a space or a hyphen.
    for (bad, position) in [
        (valid.replacen(' ', "\t", 1), 4),
        (valid.replacen(' ', "_", 1), 4),
        (valid.replacen(' ', ".", 1), 4),
        (valid.replacen(' ', "/", 1), 4),
        (valid.replacen(' ', "\u{2013}", 1), 4),
        (valid.replacen(' ', "\u{a0}", 1), 4),
        (format!("{valid}\n"), 59),
        (valid.replacen('1', "l", 1), 0),
        (valid.replacen('1', "a", 1), 0),
        // Non-ASCII digits: Arabic-Indic, fullwidth, superscript, Devanagari.
        (valid.replacen('1', "\u{661}", 1), 0),
        (valid.replacen('1', "\u{ff11}", 1), 0),
        (valid.replacen('1', "\u{b9}", 1), 0),
        (valid.replacen('1', "\u{967}", 1), 0),
    ] {
        assert_eq!(
            PhantomKey::parse(&bad).err(),
            Some(KeyError::InvalidCharacter { position }),
            "{bad:?}"
        );
    }

    // Exactly 48 or 96 digits after separators are removed.
    let digits = digits_of(SPEC_VALID_KEYS[3]);
    for count in [0, 1, 44, 47, 49, 52, 60, 72, 88, 92, 95, 97, 100, 144, 200] {
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

fn check_derivation(name: &str, format: KeyFormat) {
    let v = vector(name);
    assert_eq!(v.get("kind"), "derivation");
    let key = parse(v.get("key"));
    assert_eq!(key.key_format(), format);
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
fn derivation_matches_spec_vector_derivation_standard() {
    check_derivation("derivation-standard", KeyFormat::Standard);
}

#[test]
fn derivation_matches_spec_vector_derivation_long() {
    check_derivation("derivation-long", KeyFormat::Long);
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
fn commit_matches_spec_vector_coin_commit() {
    check_coin_commit("coin-commit");
}

#[test]
fn commit_matches_spec_vector_coin_remainder() {
    check_coin_commit("coin-remainder");

    // The remainder differs from the first commitment in every public value.
    let key = parse(SPEC_VALID_KEYS[0]);
    let amount = Amount::new(700_000_000_000_000_000).unwrap();
    let first = key.coin_commit(0, amount, Rule::EMPTY).unwrap();
    let remainder = key.coin_commit(1, amount, Rule::EMPTY).unwrap();
    assert_ne!(first.fingerprint, remainder.fingerprint);
    assert_ne!(first.commitment, remainder.commitment);
    assert_ne!(first.marker, remainder.marker);
}

#[test]
fn commit_matches_spec_vector_data_commit() {
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
    let key = parse(SPEC_VALID_KEYS[0]);
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
    for (format, count) in [(KeyFormat::Standard, 2000), (KeyFormat::Long, 500)] {
        let mut seen = HashSet::new();
        for _ in 0..count {
            let key = PhantomKey::generate(format, &mut rng);
            let text = key.format_groups().as_str().to_string();
            assert!(PhantomKey::parse(&text).is_ok(), "{text}");
            assert!(seen.insert(text), "a generated key repeated");
        }
        assert_eq!(seen.len(), count);
    }
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
fn generation_discards_bytes_of_250_or_more_and_reduces_modulo_10() {
    // 250 to 255 are discarded; 249 gives 9, 13 gives 3, 0 gives 0.
    let mut rng = ScriptedBytes {
        bytes: vec![250, 255, 249, 13, 251, 0, 252, 253, 254, 120],
        next: 0,
    };
    let key = PhantomKey::generate(KeyFormat::Standard, &mut rng);
    let digits = digits_of(key.format_groups().as_str());
    let secret = secret_digits_of(&digits);
    let pattern = b"9300";
    let expected: Vec<u8> = pattern.iter().copied().cycle().take(44).collect();
    assert_eq!(secret, expected);
    assert_eq!(
        check_groups(KeyFormat::Standard, &secret).unwrap(),
        vec![std::str::from_utf8(&digits[44..]).unwrap().parse::<u16>().unwrap()]
    );
}

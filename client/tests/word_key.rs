//! The words format of a Phantom Key (spec 01, sections 5 to 7): 24 words of
//! the BIP-39 English list holding a 256-bit secret and an 8-bit check, the
//! same key as 21 groups of digits, and the digit keys issued before it.
//!
//! The vectors of the words format live here, not in spec 01, section 14.
//! The keys below are examples only, published here, and must never hold
//! value.

use ghost_client::hash::{self, TAG_KEY_CHECK, TAG_SECRET};
use ghost_client::wordlist::WORDLIST;
use ghost_client::{check_groups, KeyError, KeyFormat, PhantomKey, Rule, Amount};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const SPEC: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digits"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse(text: &str) -> PhantomKey {
    PhantomKey::parse(text).unwrap_or_else(|e| panic!("{text:?} does not parse: {e}"))
}

fn words_of(key: &PhantomKey) -> String {
    key.format_words()
        .expect("a words key has words")
        .as_str()
        .to_owned()
}

fn digits_of(key: &PhantomKey) -> String {
    key.format_groups().as_str().to_owned()
}

fn index_of(word: &str) -> usize {
    WORDLIST
        .iter()
        .position(|w| *w == word)
        .unwrap_or_else(|| panic!("{word} is not in the list"))
}

fn join(indexes: &[usize]) -> String {
    indexes
        .iter()
        .map(|&i| WORDLIST[i])
        .collect::<Vec<_>>()
        .join(" ")
}

/// The check byte, computed here from the hash directly:
/// `S("ghost/key-check/v1", 0x20, 0x01, secret)[0]`.
fn check_byte(secret: &[u8; 32]) -> u8 {
    hash::s(TAG_KEY_CHECK, &[&[0x20], &[0x01], secret])[0]
}

/// The words of a secret, computed here bit by bit: the 264 bits of the
/// secret and its check byte, 11 to a word, most significant first.
fn words_from_secret(secret: &[u8; 32]) -> String {
    let mut bytes = secret.to_vec();
    bytes.push(check_byte(secret));
    let bit = |n: usize| usize::from((bytes[n / 8] >> (7 - n % 8)) & 1);
    let indexes: Vec<usize> = (0..24)
        .map(|w| (0..11).fold(0, |acc, b| acc * 2 + bit(w * 11 + b)))
        .collect();
    join(&indexes)
}

/// The secret as 80 decimal digits, computed here by long division in base
/// 10,000.
fn decimal_80(secret: &[u8; 32]) -> String {
    let mut number: Vec<u32> = secret.iter().map(|&b| u32::from(b)).collect();
    let mut groups = Vec::new();
    for _ in 0..20 {
        let mut remainder = 0u32;
        for limb in number.iter_mut() {
            let current = remainder * 256 + *limb;
            *limb = current / 10_000;
            remainder = current % 10_000;
        }
        groups.push(format!("{remainder:04}"));
    }
    assert!(number.iter().all(|&l| l == 0));
    groups.reverse();
    groups.concat()
}

/// The digit view of 80 secret digits: 20 groups and the check group 21.
fn digit_view(secret_digits: &str) -> String {
    assert_eq!(secret_digits.len(), 80);
    let check = check_groups(KeyFormat::Words, secret_digits.as_bytes()).unwrap();
    assert_eq!(check.len(), 1);
    let mut groups: Vec<String> = secret_digits
        .as_bytes()
        .chunks(4)
        .map(|g| String::from_utf8(g.to_vec()).unwrap())
        .collect();
    groups.push(format!("{:04}", check[0]));
    groups.join(" ")
}

/// Asserts everything a words key derives, recomputed here from the 32
/// secret bytes: key bytes `0x20 || secret`, and `s` under its own tag.
fn assert_derives_from(key: &PhantomKey, secret: &[u8; 32]) {
    let mut expected = vec![0x20];
    expected.extend_from_slice(secret);
    assert_eq!(key.key_format(), KeyFormat::Words);
    assert_eq!(key.key_bytes().as_bytes(), expected.as_slice());
    assert_eq!(key.secret().as_bytes(), &hash::s(TAG_SECRET, &[&expected]));
}

#[test]
fn words_and_digits_round_trip() {
    assert_eq!(KeyFormat::DEFAULT, KeyFormat::Words);
    assert_eq!(KeyFormat::Words.code(), 0x20);
    assert_eq!(KeyFormat::Words.word_count(), Some(24));
    assert_eq!(KeyFormat::Words.groups(), 21);
    assert_eq!(KeyFormat::Words.digit_count(), 84);
    assert_eq!(KeyFormat::from_digit_count(84), Some(KeyFormat::Words));

    let mut rng = StdRng::seed_from_u64(20261020);
    for round in 0..500 {
        let key = if round % 2 == 0 {
            PhantomKey::generate_default(&mut rng)
        } else {
            PhantomKey::generate(KeyFormat::Words, &mut rng)
        };
        assert_eq!(key.key_format(), KeyFormat::Words);
        let key_bytes = key.key_bytes().as_bytes().to_vec();
        assert_eq!(key_bytes.len(), 33);
        assert_eq!(key_bytes[0], 0x20);
        let secret: [u8; 32] = key_bytes[1..].try_into().unwrap();

        // Words: 24 whole words of the list, the ones computed here.
        let words = words_of(&key);
        assert_eq!(words.split(' ').count(), 24, "{words}");
        assert_eq!(words, words_from_secret(&secret));

        // Digits: 21 groups of four, the secret in decimal then the check.
        let digits = digits_of(&key);
        let groups: Vec<&str> = digits.split(' ').collect();
        assert_eq!(groups.len(), 21, "{digits}");
        assert!(groups.iter().all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_digit())));
        assert_eq!(digits, digit_view(&decimal_80(&secret)));

        // Words to digits to words.
        let from_words = parse(&words);
        assert_eq!(digits_of(&from_words), digits);
        let from_digits = parse(&digits);
        assert_eq!(from_digits.key_format(), KeyFormat::Words);
        assert_eq!(words_of(&from_digits), words);

        // Both give the same secret and the same derived values.
        for parsed in [&from_words, &from_digits] {
            assert_derives_from(parsed, &secret);
            assert_eq!(parsed.reveal_secret().as_bytes(), key.reveal_secret().as_bytes());
            assert_eq!(parsed.blinding(3).as_bytes(), key.blinding(3).as_bytes());
            assert_eq!(parsed.note_key().as_bytes(), key.note_key().as_bytes());
            assert_eq!(parsed.data_key().as_bytes(), key.data_key().as_bytes());
        }

        // Any case, any mix of spaces and hyphens.
        let mixed: String = words
            .split(' ')
            .enumerate()
            .map(|(i, w)| {
                let w = if i % 3 == 0 { w.to_uppercase() } else if i % 3 == 1 { w.to_owned() } else {
                    let mut c = w.chars();
                    let first = c.next().unwrap().to_ascii_uppercase();
                    format!("{first}{}", c.as_str())
                };
                let sep = ["-", " ", " - ", "--", "  "][i % 5];
                format!("{w}{sep}")
            })
            .collect();
        for typed in [
            words.to_uppercase(),
            words.replace(' ', "-"),
            format!("  {}  ", words.replace(' ', "   ")),
            format!("-{mixed}"),
        ] {
            assert_eq!(words_of(&parse(&typed)), words, "{typed:?}");
        }
        assert_eq!(words_of(&parse(&digits.replace(' ', "-"))), words);
        assert_eq!(words_of(&parse(&digits.replace(' ', ""))), words);
    }

    // The digit formats keep working when asked for, and have no words.
    for format in [KeyFormat::Standard, KeyFormat::Long] {
        let key = PhantomKey::generate(format, &mut rng);
        assert_eq!(key.key_format(), format);
        assert!(key.format_words().is_none());
        assert_eq!(parse(&digits_of(&key)).key_bytes().as_bytes(), key.key_bytes().as_bytes());
    }
}

/// The keys the check is tested on, as seeds of the secret. Each was chosen
/// so that none of its 24 one-word replacements (the word after it in the
/// list) and none of its adjacent swaps falls in the 1 in 256 chance of
/// passing the check; seeds 4, 5 and 9 were left out because one of theirs
/// does.
const CHECKED_SECRETS: [u64; 8] = [1, 2, 3, 6, 7, 8, 10, 11];

#[test]
fn checksum_catches_a_wrong_or_swapped_word() {
    let mut tried = 0;
    for seed in CHECKED_SECRETS {
        let mut secret = [0u8; 32];
        StdRng::seed_from_u64(seed).fill_bytes(&mut secret);
        let words = words_from_secret(&secret);
        assert!(PhantomKey::parse(&words).is_ok(), "{words}");
        let indexes: Vec<usize> = words.split(' ').map(index_of).collect();

        for position in 0..24 {
            let mut replaced = indexes.clone();
            replaced[position] = (replaced[position] + 1) % 2048;
            let text = join(&replaced);
            assert_eq!(
                PhantomKey::parse(&text).err(),
                Some(KeyError::WordCheckMismatch),
                "word {} replaced passes the check: {text}",
                position + 1
            );
            tried += 1;
        }
        for position in 0..23 {
            if indexes[position] == indexes[position + 1] {
                continue;
            }
            let mut swapped = indexes.clone();
            swapped.swap(position, position + 1);
            let text = join(&swapped);
            assert_eq!(
                PhantomKey::parse(&text).err(),
                Some(KeyError::WordCheckMismatch),
                "words {} and {} swapped pass the check: {text}",
                position + 1,
                position + 2
            );
            tried += 1;
        }
    }
    assert!(tried >= 8 * 46);

    // The 24-word wordlist mnemonic of BIP-39 for this secret ends in a check
    // built with SHA-256, not Ghost's tag: it is not a Phantom Key.
    let bip39_all_7f = "legal winner thank year wave sausage worth useful legal winner thank \
        year wave sausage worth useful legal winner thank year wave sausage worth title";
    assert_eq!(
        PhantomKey::parse(bip39_all_7f).err(),
        Some(KeyError::WordCheckMismatch)
    );
}

/// One block of spec 01, section 14.
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
}

fn spec_vectors() -> Vec<Vector> {
    let (_, section) = SPEC
        .split_once("## 14. Test vectors")
        .expect("spec 01 has a test vector section");
    let mut out: Vec<Vector> = Vec::new();
    let mut in_text = false;
    let mut in_other = false;
    for line in section.lines().map(str::trim_end) {
        if line.starts_with("```") {
            if in_text || in_other {
                in_text = false;
                in_other = false;
            } else if line == "```text" {
                in_text = true;
            } else {
                in_other = true;
            }
            continue;
        }
        if !in_text || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Vector { name: name.to_owned(), fields: Vec::new() });
        } else if let Some((field, value)) = line.split_once('=') {
            out.last_mut()
                .expect("a field belongs to a vector")
                .fields
                .push((field.trim().to_owned(), value.trim().to_owned()));
        }
    }
    out
}

#[test]
fn old_digit_keys_still_derive_the_same_values() {
    let vectors = spec_vectors();
    let mut checked = 0;
    for v in vectors.iter().filter(|v| v.get("kind") == "derivation") {
        let key = parse(v.get("key"));
        let expected_format = match v.name.as_str() {
            "derivation-standard" => KeyFormat::Standard,
            "derivation-long" => KeyFormat::Long,
            other => panic!("unknown derivation vector {other}"),
        };
        assert_eq!(key.key_format(), expected_format);
        assert!(key.format_words().is_none());
        assert_eq!(key.key_bytes().as_bytes(), decode_hex(v.get("key-bytes")).as_slice());
        assert_eq!(hex(key.secret().as_bytes()), v.get("s"), "{}", v.name);
        assert_eq!(hex(key.reveal_secret().as_bytes()), v.get("r"), "{}", v.name);
        assert_eq!(hex(key.blinding(0).as_bytes()), v.get("b0"), "{}", v.name);
        assert_eq!(hex(key.blinding(1).as_bytes()), v.get("b1"), "{}", v.name);
        assert_eq!(hex(key.blinding(2).as_bytes()), v.get("b2"), "{}", v.name);
        assert_eq!(hex(key.note_key().as_bytes()), v.get("note-key"), "{}", v.name);
        assert_eq!(hex(key.data_key().as_bytes()), v.get("data-key"), "{}", v.name);
        assert_eq!(digits_of(&key), v.get("key"));
        checked += 1;
    }
    assert_eq!(checked, 2, "spec 01 has a standard and a long derivation vector");

    for v in vectors.iter().filter(|v| v.get("kind") == "coin-commitment") {
        let key = parse(v.get("key"));
        assert_eq!(key.key_format(), KeyFormat::Standard);
        let amount = Amount::new(v.get("amount").parse().unwrap()).unwrap();
        let commit = key
            .coin_commit(v.get("index").parse().unwrap(), amount, Rule::EMPTY)
            .unwrap();
        assert_eq!(hex(commit.commitment.as_bytes()), v.get("commitment"), "{}", v.name);
        assert_eq!(hex(commit.marker.as_bytes()), v.get("marker"), "{}", v.name);
        checked += 1;
    }
    assert_eq!(checked, 4);

    for v in vectors.iter().filter(|v| v.get("kind") == "checksum") {
        let result = PhantomKey::parse(v.get("key"));
        match v.get("valid") {
            "yes" => {
                let key = result.unwrap_or_else(|e| panic!("{}: {e}", v.name));
                assert_eq!(format!("{:02x}", key.key_format().code()), v.get("format"));
            }
            _ => assert!(
                matches!(result, Err(KeyError::ChecksumMismatch { .. })),
                "{}",
                v.name
            ),
        }
    }
}

/// A fixed words key: its 256 secret bits in hex, words, digits and derived
/// values.
struct WordsVector {
    bits: &'static str,
    words: &'static str,
    digits: &'static str,
    s: &'static str,
    r: &'static str,
    b0: &'static str,
    note_key: &'static str,
    data_key: &'static str,
}

const WORDS_VECTORS: [WordsVector; 5] = [
    WordsVector {
        bits: "0000000000000000000000000000000000000000000000000000000000000000",
        words: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon buyer",
        digits: "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0700",
        s: "b7d01f25d2466346d55ed32114a247067068f77c62e259421effca384cb4cc38",
        r: "fca76fa8e6055cbf14db6e8ab316945ab87c20238e138a4d1237faa3d39dd146",
        b0: "5d510674e95beb4b59cf222d7bdae3c67954d3b122e68524c03a31aa0877a373",
        note_key: "61c39e8ed39e6ddc3d67c489b126247388d97f3b4b6758da03d20b989724cae2",
        data_key: "88feeef08c0f77ab4b68b1e8340e45a7936d6b99cf57e379be8a7b1ad025f5d2",
    },
    WordsVector {
        bits: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        words: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth various",
        digits: "0005 7669 0013 0642 8065 9560 5300 0376 8759 3842 1040 3453 0406 4124 0510 2397 3211 7841 8613 4399 8027",
        s: "71346e4c283b18e2f1a77d5920f65d0848305b59764accadd7c49779b0eab58b",
        r: "e1e807d15b2d02e98c2b5b1948535fa358c45b1679ef7e5195644d07a2b32f39",
        b0: "2da9fad9db8f4e8f8b9897f02d2814e97c9811c89103473fc8762ae6dee35b0d",
        note_key: "08f3c586fe83f60374f0551ad5a25ddab61fd4fc70ab71572c0aae3b042c82ab",
        data_key: "8656f5cbfdecd73bb29f88309564a1610be34a6e12db2e6152778df15dc7cca3",
    },
    WordsVector {
        bits: "8080808080808080808080808080808080808080808080808080808080808080",
        words: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic border",
        digits: "0005 8123 0879 3088 8129 4675 1798 4631 8119 6943 2229 6393 6157 6439 9884 3361 0796 1289 4350 5536 6129",
        s: "77dd4fa5af625ab0de89a4ca2bdbecad7a7c9de2e9c6c8faf7fe9bc136406649",
        r: "c4e021e4490e1c023421fa85fbd77605d8092bec66f39ffc84bf686eeba68a17",
        b0: "18b5ad629d4e64858514de0debe0250e6c2189357062b567bd1ca9113c6f5cb6",
        note_key: "af037c096885e5f0e9c2627d0bac3b115bf223b91a56b550018e06f3593b4d82",
        data_key: "acfbd5ae7434fd3743c4c3b33dbc9a84165a93a722e2e362b4817b01e021ad9d",
    },
    WordsVector {
        bits: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        words: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo unfold",
        digits: "0011 5792 0892 3731 6195 4235 7098 5008 6879 0785 3269 9846 6564 0564 0394 5758 4007 9131 2963 9935 6994",
        s: "496649ad14484ae29dcf11fcd32da1263534888a5407405b0b2dc90ad8609920",
        r: "8674f7be91744c1118b761f1e7e661321ac48d82fd3510cb2df77d421fbfa208",
        b0: "dddaba9b33b2afa20a173a717c3a544f7cf27aac3d262c0138745e9a225e646f",
        note_key: "b8874c29991865b41a05a5651c7864c7bdfea367bc240cda6752bf241575639e",
        data_key: "bdac0b9311dfaf4f5d8524808d957480da39ce99d25cf9b8b0b9e8eb43cea3e1",
    },
    WordsVector {
        bits: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        words: "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey trip",
        digits: "0000 0001 7807 3186 0627 7000 4496 0722 5683 7659 2200 7423 2963 7303 1997 5454 7598 3699 7944 0671 6812",
        s: "62cff2e8a7db58fd67f745c8b24b75280335b28b88106384c735da7888ded4d1",
        r: "8fa3bd9e5bb56a3698801b1f016d08de1c883f178d1c3f6d544706d6cb4e1abe",
        b0: "209f9782c7e6b7f64a0b0e0e1deda56dfae96af10eebe33aee50d6c5aa1144ea",
        note_key: "35136c4a7bdccb4b26159c15f86567a483ac58e1b2c40dca49a5d099272c4181",
        data_key: "97f75e4a033cf853da070528681b5af557e75070c54c9cd599b2b879915351af",
    },
];

#[test]
fn words_key_vectors() {
    let mut report = String::new();
    for v in &WORDS_VECTORS {
        let secret: [u8; 32] = decode_hex(v.bits).try_into().unwrap();
        // Words and digits computed here agree with the fixed ones.
        assert_eq!(words_from_secret(&secret), v.words, "words of {}", v.bits);
        assert_eq!(digit_view(&decimal_80(&secret)), v.digits, "digits of {}", v.bits);

        let from_words = parse(v.words);
        let from_digits = parse(v.digits);
        for key in [&from_words, &from_digits] {
            assert_derives_from(key, &secret);
            assert_eq!(words_of(key), v.words);
            assert_eq!(digits_of(key), v.digits);
            let computed = [
                hex(key.secret().as_bytes()),
                hex(key.reveal_secret().as_bytes()),
                hex(key.blinding(0).as_bytes()),
                hex(key.note_key().as_bytes()),
                hex(key.data_key().as_bytes()),
            ];
            let fixed = [v.s, v.r, v.b0, v.note_key, v.data_key];
            if computed != fixed {
                report.push_str(&format!("{}\n{computed:#?}\n", v.bits));
            }
        }
    }
    assert!(report.is_empty(), "derived values differ:\n{report}");

    // The first 23 words hold only secret bits, so they are those of the
    // published BIP-39 vectors for the same 256 bits; only the last word,
    // which holds the check, differs.
    for (index, bip39) in [
        (1, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
        (2, "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
        (3, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
    ] {
        let ours: Vec<&str> = WORDS_VECTORS[index].words.split(' ').collect();
        let theirs: Vec<&str> = bip39.split(' ').collect();
        assert_eq!(ours[..23], theirs[..23]);
    }
    assert!(WORDS_VECTORS[0].words.starts_with(&"abandon ".repeat(23)));

    // 2^256 - 1 is the largest secret, and its digits are known.
    assert!(WORDS_VECTORS[3].digits.replace(' ', "").starts_with(
        "00115792089237316195423570985008687907853269984665640564039457584007913129639935"
    ));

    // 2^256 with a correct check group is still refused.
    let too_large = digit_view("00115792089237316195423570985008687907853269984665640564039457584007913129639936");
    assert_eq!(PhantomKey::parse(&too_large).err(), Some(KeyError::SecretOutOfRange));
    let largest = digit_view("99999999999999999999999999999999999999999999999999999999999999999999999999999999");
    assert_eq!(PhantomKey::parse(&largest).err(), Some(KeyError::SecretOutOfRange));

    // A wrong check group of the digit view is group 21.
    let mut wrong: Vec<u8> = WORDS_VECTORS[4].digits.bytes().collect();
    let last = wrong.len() - 1;
    wrong[last] = if wrong[last] == b'0' { b'1' } else { b'0' };
    assert_eq!(
        PhantomKey::parse(std::str::from_utf8(&wrong).unwrap()).err(),
        Some(KeyError::ChecksumMismatch { group: 21 })
    );

    // The wrong number of words is its own error, apart from the check.
    let words: Vec<&str> = WORDS_VECTORS[4].words.split(' ').collect();
    for count in [0usize, 1, 12, 23, 25, 48] {
        let text = words.iter().cycle().take(count).copied().collect::<Vec<_>>().join(" ");
        // No letters and no digits is read as digits: none of them.
        let expected = if count == 0 {
            KeyError::WrongLength { digits: 0 }
        } else {
            KeyError::WrongWordCount { words: count }
        };
        assert_eq!(PhantomKey::parse(&text).err(), Some(expected), "{count} words");
    }
}

#[test]
fn unknown_word_is_named() {
    let words: Vec<String> = WORDS_VECTORS[4].words.split(' ').map(str::to_owned).collect();
    let valid = words.join(" ");
    assert!(PhantomKey::parse(&valid).is_ok());

    // A misspelling, a prefix (even the four letters that make a word
    // unique), a word with an extra letter and a word in another script are
    // all named, never corrected.
    for (number, typed) in [
        (1usize, "abandn"),
        (5, &words[4][..4]),
        (12, "abandonn"),
        (24, "acress"),
        (7, "über"),
        (9, "ABANDOM"),
    ] {
        let mut changed = words.clone();
        changed[number - 1] = typed.to_owned();
        let text = changed.join(" - ");
        match PhantomKey::parse(&text).err() {
            Some(KeyError::UnknownWord { word, start, end }) => {
                assert_eq!(word, number, "{text}");
                assert_eq!(&text[start..end], typed, "{text}");
            }
            other => panic!("{text:?}: expected an unknown word, got {other:?}"),
        }
        let error = PhantomKey::parse(&text).err().unwrap().to_string();
        assert_eq!(error, format!("word {number} is not in the word list"));
    }

    // The first unknown word is named even when the count is also wrong.
    let short = format!("{} zzzz", words[..10].join(" "));
    assert!(matches!(
        PhantomKey::parse(&short).err(),
        Some(KeyError::UnknownWord { word: 11, .. })
    ));

    // A character that is neither a letter nor a separator is named by
    // position; a digit makes the text digits, where a letter is invalid.
    let underscore = valid.replacen(' ', "_", 1);
    let position = underscore.find('_').unwrap();
    assert_eq!(
        PhantomKey::parse(&underscore).err(),
        Some(KeyError::InvalidCharacter { position })
    );
    let with_digit = valid.replacen(' ', "1", 1);
    assert_eq!(
        PhantomKey::parse(&with_digit).err(),
        Some(KeyError::InvalidCharacter { position: 0 })
    );
}

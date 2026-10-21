//! Property and adversarial tests of spec 02 (sections 9 to 12).
//!
//! The vectors come from the specification files themselves, read at compile
//! time, so the code cannot drift from them: the amount and conservation
//! vectors of spec 02, the derivation and commitment vectors of spec 01 and
//! the tree vectors of spec 05. The example witness is the spec 01 example:
//! a commit of 1 GHOST under the standard example key, revealed against the
//! two-leaf coin tree of spec 05.
//!
//! Every negative test first builds a valid proof and asserts that it
//! verifies, then changes one thing, so it cannot pass by failing for another
//! reason. Proving runs one test at a time to bound memory.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Mutex, MutexGuard};

use ghost_proofs::adversary::prove_coin_reveal_claiming;
use ghost_proofs::*;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;

const SPEC_01: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");
const SPEC_02: &str = include_str!("../../docs/spec/02-proof-statements.md");
const SPEC_05: &str = include_str!("../../docs/spec/05-trees-and-headers.md");

/// The BabyBear modulus, for the field-wrap attempt.
const BABY_BEAR_MODULUS: u128 = 2_013_265_921;

static PROVING: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only zero-knowledge randomness; a real prover draws it from a secure
/// random source.
fn zk(n: u8) -> [u8; 32] {
    let mut seed = [0x5au8; 32];
    seed[0] = n;
    seed
}

// ---------------------------------------------------------------------------
// Reading the specification.

/// Every `[name]` block of a document whose name starts with `prefix`, as
/// key-value maps.
fn vector_blocks(doc: &str, prefix: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, BTreeMap<String, String>)> = None;
    for line in doc.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            let name = &line[1..line.len() - 1];
            if name.starts_with(prefix) {
                current = Some((name.to_string(), BTreeMap::new()));
            }
        } else if line.is_empty() || line.starts_with("```") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
        } else if let Some((_, map)) = current.as_mut() {
            let (key, value) = line.split_once('=').expect("key = value");
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }
    blocks
}

fn vector(doc: &str, name: &str) -> BTreeMap<String, String> {
    vector_blocks(doc, name)
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no vector {name}"))
        .1
}

fn hex32(s: &str) -> [u8; 32] {
    let bytes = hex(s);
    bytes.try_into().expect("32 bytes")
}

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A decimal integer as a 32-byte big-endian word, by the schoolbook method.
fn decimal_word(s: &str) -> [u8; 32] {
    let mut word = [0u8; 32];
    for digit in s.bytes() {
        assert!(digit.is_ascii_digit());
        let mut carry = u32::from(digit - b'0');
        for byte in word.iter_mut().rev() {
            let x = u32::from(*byte) * 10 + carry;
            *byte = x as u8;
            carry = x >> 8;
        }
        assert_eq!(carry, 0, "{s} does not fit 256 bits");
    }
    word
}

fn yes(map: &BTreeMap<String, String>) -> bool {
    match map["valid"].as_str() {
        "yes" => true,
        "no" => false,
        other => panic!("valid = {other}"),
    }
}

/// SHA3-256 (padding `0x06`), only to derive the example keys' secrets as
/// spec 01, section 7 does; the crate itself never uses it.
fn sha3_256(msg: &[u8]) -> [u8; 32] {
    let mut padded = msg.to_vec();
    let blocks = msg.len() / 136 + 1;
    padded.resize(blocks * 136, 0);
    padded[msg.len()] ^= 0x06;
    padded[blocks * 136 - 1] ^= 0x80;
    let mut state = [0u64; 25];
    for block in padded.chunks_exact(136) {
        for (lane, chunk) in block.chunks_exact(8).enumerate() {
            state[lane] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        KeccakF.permute_mut(&mut state);
    }
    let mut out = [0u8; 32];
    for (i, lane) in state[..4].iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// `S(tag, parts...)` of spec 01.
fn derive(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut msg = tag_bytes(tag);
    for part in parts {
        msg.extend_from_slice(part);
    }
    sha3_256(&msg)
}

/// `(s, r, b_0, b_1)` of a standard Phantom Key.
fn key_secrets(key: &str) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let digits: String = key.chars().filter(char::is_ascii_digit).collect();
    assert_eq!(digits.len(), 48);
    let mut key_bytes = vec![0x0c];
    key_bytes.extend_from_slice(&digits.as_bytes()[..44]);
    (
        derive("ghost/secret/v1", &[&key_bytes]),
        derive("ghost/reveal-secret/v1", &[&key_bytes]),
        derive("ghost/blinding/v1", &[&key_bytes, &0u64.to_be_bytes()]),
        derive("ghost/blinding/v1", &[&key_bytes, &1u64.to_be_bytes()]),
    )
}

/// The empty subtree roots `Z_0 .. Z_31` of a tree.
fn empty_subtrees(tree: Tree) -> [[u8; 32]; TREE_DEPTH] {
    let mut z = [[0u8; 32]; TREE_DEPTH];
    z[0] = empty_leaf();
    for level in 1..TREE_DEPTH {
        z[level] = tree_node(tree, (level - 1) as u8, &z[level - 1], &z[level - 1]);
    }
    z
}

/// Whether `haystack` contains any 16-byte window of a needle.
fn shares_window(haystack: &[u8], needles: &[[u8; 32]]) -> bool {
    let windows: HashSet<&[u8]> = needles.iter().flat_map(|n| n.windows(16)).collect();
    haystack.windows(16).any(|w| windows.contains(w))
}

// ---------------------------------------------------------------------------
// The example witness.

fn params() -> ChainParams {
    // Example chain constants, not Ghost's.
    ChainParams {
        chain_id: 1234u64.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [0x47; 32],
    }
}

const ONE_GHOST: u128 = 1_000_000_000_000_000_000;
const FEE: u128 = 21_000_000_000_000;

struct Coin {
    opening: CoinOpening,
    remainder: CoinRemainder,
    request: RevealRequest,
}

/// The spec 01 example coin (1 GHOST, number 0) at position 0 of the
/// two-leaf coin tree of spec 05, revealed with the given amounts. The
/// remainder is number 1 of the same key.
fn example_coin(v: u128, out: u128, remainder: u128, fee: u128) -> Coin {
    let key = vector(SPEC_01, "derivation-standard")["key"].clone();
    let (s, r, b0, b1) = key_secrets(&key);
    let mut path = empty_subtrees(Tree::Coin);
    path[0] = hex32(&vector(SPEC_01, "coin-remainder")["commitment"]);
    let opening = CoinOpening {
        s,
        r,
        b: b0,
        v: amount_word(v),
        position: 0,
        path,
    };
    let leaf = coin_commitment(&coin_fingerprint(&s, &r, &b0, &EMPTY_RULE), &opening.v);
    let request = RevealRequest {
        root: merkle_root(Tree::Coin, &leaf, 0, &opening.path),
        recipient: [0x11; 20],
        out: amount_word(out),
        fee: amount_word(fee),
        rule: EMPTY_RULE,
        remainder_note: [0x33; NOTE_BYTES],
    };
    let remainder = CoinRemainder {
        s,
        r,
        b: b1,
        v: amount_word(remainder),
    };
    Coin {
        opening,
        remainder,
        request,
    }
}

/// The partial reveal of `[conservation-partial-reveal]`.
fn partial_reveal() -> Coin {
    example_coin(ONE_GHOST, 299_979_000_000_000_000, 700_000_000_000_000_000, FEE)
}

/// A valid proof of a coin, asserted to verify.
fn valid_reveal(coin: &Coin, seed: u8) -> (CoinReveal, Proof) {
    let (tx, proof) =
        prove_coin_reveal(&params(), &coin.opening, &coin.remainder, &coin.request, zk(seed)).expect("honest proof");
    assert_eq!(verify_coin_reveal(&params(), &tx, &proof), Ok(()));
    (tx, proof)
}

fn rejected(tx: &CoinReveal, proof: &Proof) -> bool {
    verify_coin_reveal(&params(), tx, proof) == Err(ProofError::Rejected)
}

/// A lying prover's proof for `claimed`, asserted not to verify.
fn forged_fails(coin: &Coin, claimed: &CoinReveal, seed: u8) {
    let proof = prove_coin_reveal_claiming(&params(), &coin.opening, &coin.remainder, claimed, zk(seed))
        .expect("the lying prover still produces bytes");
    assert_eq!(verify_coin_reveal(&params(), claimed, &proof), Err(ProofError::Rejected));
}

fn add_one(word: &[u8; 32]) -> [u8; 32] {
    amount_word(amount_value(word).unwrap() + 1)
}

fn sub_one(word: &[u8; 32]) -> [u8; 32] {
    amount_word(amount_value(word).unwrap() - 1)
}

#[cfg_attr(not(feature = "unsettled-points-test"), allow(dead_code))]
struct Data {
    s: [u8; 32],
    r: [u8; 32],
    b: [u8; 32],
    cf: [u8; 32],
    path: [[u8; 32]; TREE_DEPTH],
    root: [u8; 32],
}

/// The spec 01 example data commitment, alone in a data tree (spec 05,
/// `[data-tree-one-leaf]`).
fn example_data() -> Data {
    let commit = vector(SPEC_01, "data-commit");
    let (s, r, b, _) = key_secrets(&commit["key"]);
    let cf = hex32(&commit["content-fingerprint"]);
    let path = empty_subtrees(Tree::Data);
    let leaf = data_commitment(&data_fingerprint(&s, &r, &b, &cf, &EMPTY_RULE));
    assert_eq!(leaf, hex32(&commit["commitment"]));
    let root = merkle_root(Tree::Data, &leaf, 0, &path);
    assert_eq!(root, hex32(&vector(SPEC_05, "data-tree-one-leaf")["root"]));
    Data { s, r, b, cf, path, root }
}

#[cfg(feature = "unsettled-points-test")]
fn hold_opening(d: &Data) -> HoldOpening {
    HoldOpening {
        s: d.s,
        r: d.r,
        b: d.b,
        cf: d.cf,
        rule: EMPTY_RULE,
        position: 0,
        path: d.path,
    }
}

fn hold_context(d: &Data, verifier: u8, challenge: [u8; 32]) -> HoldContext {
    HoldContext {
        type_tag: DATA,
        root: d.root,
        marker_set_root: [0x6d; 32],
        verifier: [verifier; 32],
        challenge,
    }
}

// ---------------------------------------------------------------------------
// Configuration, layouts and vectors.

/// PS-22: the shipped configuration is zero-knowledge and reaches the target.
#[test]
fn zero_knowledge_mode_is_on_in_shipped_configuration() {
    let config = shipped_configuration().expect("the shipped configuration builds");
    assert!(config.zero_knowledge, "the library reports the configuration as not zero-knowledge");
    assert_eq!(config.log_blowup, 3);
    assert_eq!(config.num_queries, 43);
    assert_eq!(config.query_pow_bits, 16);
    assert_eq!(config.batch_pow_bits, 16);
    assert_eq!(config.extension_degree, 5);
    assert_eq!(config.commitment_collision_bits, 128);
    for (statement, estimate) in config.statements {
        assert!(
            estimate.conjectured_bits_half_grinding >= 128,
            "{statement:?}: {} conjectured bits with grinding counted at half",
            estimate.conjectured_bits_half_grinding
        );
        assert!(estimate.constraint_degree <= 1 << config.log_blowup, "{statement:?}");
        assert!(estimate.trace_height.is_power_of_two(), "{statement:?}");
    }
}

/// QS-12: the shipped configuration meets every item of the rule of spec 09,
/// section 4.1, and its report states the conjectured and proven figures,
/// classical and quantum.
#[test]
fn shipped_configuration_meets_quantum_rule() {
    let config = shipped_configuration().expect("the security gate takes the shipped configuration");

    // 1. The queries alone reach 128 conjectured bits, before grinding:
    // rate 1/8 and 43 queries, 129.
    assert_eq!((config.log_blowup, config.num_queries), (3, 43));
    assert_eq!(config.query_bits, config.log_blowup * config.num_queries);
    assert!(config.query_bits >= 128, "the queries alone give {} bits", config.query_bits);
    // Grinding is margin, at most 16 bits at a site.
    assert!(config.query_pow_bits <= MAX_GRINDING_BITS && config.batch_pow_bits <= MAX_GRINDING_BITS);

    // 2. Every estimator term reaches 128 for every statement with grinding
    // counted at half; the figures are stated in both regimes.
    let reported: Vec<Statement> = config.statements.iter().map(|(s, _)| *s).collect();
    assert_eq!(reported, Statement::ALL);
    for (statement, e) in config.statements {
        assert!(
            e.conjectured_bits_half_grinding >= 128,
            "{statement:?}: {} bits with grinding at half",
            e.conjectured_bits_half_grinding
        );
        assert!(e.conjectured_bits >= e.conjectured_bits_half_grinding, "{statement:?}: {e:?}");
        assert_eq!(e.conjectured_quantum_bits, e.conjectured_bits / 2, "{statement:?}");
        assert!(e.conjectured_quantum_bits >= 64, "{statement:?}: {e:?}");
        assert_eq!(e.proven_quantum_bits, e.proven_bits / 2, "{statement:?}");
        assert!(e.proven_bits > 0 && e.proven_bits <= e.conjectured_bits, "{statement:?}: {e:?}");
    }

    // 3. Keccak-256 with 256-bit digests in the commitments and the transcript.
    assert!(config.commitment_hash_is_keccak256);
    assert_eq!(config.merkle_digest_bits, 256);
    assert_eq!(config.transcript_digest_bits, 256);
    assert_eq!(config.commitment_collision_bits, 128);

    // 4. Hiding on, with salts of at least 128 bits.
    assert!(config.zero_knowledge);
    assert!(config.salt_bits >= MIN_SALT_BITS && MIN_SALT_BITS >= 128, "{}-bit salts", config.salt_bits);
}

// ---------------------------------------------------------------------------
// The proof field and its budget (spec 07, section 3).

/// The gate's estimate of one statement, from the shipped configuration.
fn statement_trace(statement: Statement) -> SecurityEstimate {
    let config = shipped_configuration().expect("the shipped configuration builds");
    config
        .statements
        .into_iter()
        .find(|(s, _)| *s == statement)
        .unwrap_or_else(|| panic!("{statement:?} is not in the report"))
        .1
}

/// Every statement the crate knows fits the coin reveal's trace budget, so
/// none can outgrow the proof field.
#[test]
fn proof_budget_holds_for_every_statement() {
    assert_eq!((MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH), (2048, 3824));
    // The salted coin reveal is the widest statement and sets the budget.
    assert_eq!(statement_trace(Statement::SaltedCoinReveal).trace_width, MAX_TRACE_WIDTH);
    assert_eq!(statement_trace(Statement::CoinReveal).trace_width, 3808);
    // The salted data statements: the version 1 ones and 16 salt columns.
    for (v1, v2) in [
        (Statement::DataReveal, Statement::SaltedDataReveal),
        (Statement::Hold, Statement::SaltedHold),
    ] {
        assert_eq!(statement_trace(v1).trace_width, 3786, "{v1:?}");
        assert_eq!(statement_trace(v2).trace_width, 3786 + SALT_BYTES, "{v2:?}");
        assert!(Statement::ALL.contains(&v2));
    }
    let config = shipped_configuration().expect("the shipped configuration builds");
    let reported: Vec<Statement> = config.statements.iter().map(|(s, _)| *s).collect();
    assert_eq!(reported, Statement::ALL);
    assert!(Statement::ALL.contains(&Statement::SaltedCoinReveal));
    for (statement, estimate) in config.statements {
        assert!(
            estimate.trace_height <= MAX_TRACE_HEIGHT,
            "{statement:?}: {} rows, over the budget of {MAX_TRACE_HEIGHT}",
            estimate.trace_height
        );
        assert!(
            estimate.trace_width <= MAX_TRACE_WIDTH,
            "{statement:?}: {} columns, over the budget of {MAX_TRACE_WIDTH}",
            estimate.trace_width
        );
        assert!(proof_length_bound(estimate.trace_height, estimate.trace_width) <= PROOF_FIELD_BYTES);
    }
}

/// The longest proof the encoding can produce for the budget trace fits the
/// proof field of version 1.
#[test]
fn proof_length_bound_fits_field() {
    assert_eq!(PROOF_FIELD_BYTES, 1_310_720);
    let bound = proof_length_bound(MAX_TRACE_HEIGHT, MAX_TRACE_WIDTH);
    assert!(bound <= PROOF_FIELD_BYTES, "the bound {bound} is over {PROOF_FIELD_BYTES}");
    // The figure spec 07, section 3 derives term by term for 3,808 columns,
    // and 212 bytes for each of the salt's 16 carried columns.
    assert_eq!(bound, 1_053_331 + 16 * 212);
    assert_eq!(bound, 1_056_723);
    // Any smaller trace has a smaller bound.
    for statement in Statement::ALL {
        let t = statement_trace(statement);
        assert!(proof_length_bound(t.trace_height, t.trace_width) <= bound, "{statement:?}");
    }
}

/// A real coin reveal proof fits the field and its trace's bound.
#[test]
fn coin_reveal_proof_fits_field() {
    let _one = one_at_a_time();
    let t = statement_trace(Statement::CoinReveal);
    let bound = proof_length_bound(t.trace_height, t.trace_width);
    for (coin, seed) in [(partial_reveal(), 60), (example_coin(ONE_GHOST, ONE_GHOST - FEE, 0, FEE), 61)] {
        let (_, proof) = valid_reveal(&coin, seed);
        let len = proof.as_bytes().len();
        assert!(len <= PROOF_FIELD_BYTES, "a coin reveal proof of {len} bytes");
        assert!(len <= bound, "a coin reveal proof of {len} bytes, over the bound {bound}");
    }
}

/// A real data reveal proof, reveal and revoke, fits the field and its
/// trace's bound.
#[cfg(feature = "unsettled-points-test")]
#[test]
fn data_reveal_proof_fits_field() {
    let _one = one_at_a_time();
    let t = statement_trace(Statement::DataReveal);
    let bound = proof_length_bound(t.trace_height, t.trace_width);
    let d = example_data();
    let opening = DataOpening {
        s: d.s,
        r: d.r,
        b: d.b,
        cf: d.cf,
        position: 0,
        path: d.path,
    };
    for (purpose, seed) in [(DataPurpose::Reveal, 62), (DataPurpose::Revoke, 63)] {
        let request = DataRevealRequest {
            purpose,
            root: d.root,
            party: [0x70; 32],
            fee: amount_word(FEE),
            rule: EMPTY_RULE,
        };
        let (tx, proof) = prove_data_reveal(&params(), &opening, &request, zk(seed)).expect("honest proof");
        assert_eq!(verify_data_reveal_unsettled(&params(), &tx, &proof), Ok(()));
        let len = proof.as_bytes().len();
        assert!(len <= PROOF_FIELD_BYTES, "a data reveal proof of {len} bytes");
        assert!(len <= bound, "a data reveal proof of {len} bytes, over the bound {bound}");
    }
}

/// Section 7: every binding layout field, offset and width, and the totals,
/// as the specification's tables state them.
#[test]
fn binding_layout_sizes_match_spec() {
    let cases = [
        ("### Coin reveal binding", Binding::CoinReveal),
        ("### Data reveal binding", Binding::DataReveal),
        ("### Hold binding", Binding::Hold),
    ];
    for (heading, binding) in cases {
        let section = SPEC_02.split(heading).nth(1).expect("the heading").split("\nTotal:").collect::<Vec<_>>();
        let rows: Vec<(usize, usize, String)> = section[0]
            .lines()
            .filter(|l| l.starts_with("| ") && l.contains('`'))
            .map(|l| {
                let cells: Vec<&str> = l.split('|').map(str::trim).collect();
                (
                    cells[1].parse().expect("offset"),
                    cells[2].parse().expect("width"),
                    cells[3].trim_matches('`').to_string(),
                )
            })
            .collect();
        let layout = binding.layout();
        assert_eq!(rows.len(), layout.len(), "{heading}");
        for ((offset, width, name), field) in rows.iter().zip(layout) {
            assert_eq!((field.name, field.offset, field.width), (name.as_str(), *offset, *width), "{heading}");
        }
        let total: Vec<usize> = section[1]
            .split('.')
            .next()
            .unwrap()
            .split(';')
            .map(|part| part.split_whitespace().next().unwrap().parse().unwrap())
            .collect();
        assert_eq!(
            total,
            vec![binding.fields_len(), binding.input_len(), binding.permutations()],
            "{heading}"
        );
    }
}

/// Section 10 and PS-11, PS-12: the word, the limbs and the validity of each
/// amount vector.
#[test]
fn amount_vectors_from_spec_agree() {
    let vectors = vector_blocks(SPEC_02, "amount-");
    assert!(vectors.len() >= 5, "the amount vectors were not found");
    for (name, v) in vectors {
        let word = decimal_word(&v["value"]);
        assert_eq!(to_hex(&word), v["word"], "{name}: word");
        let limbs: Vec<String> = amount_limbs(&word).iter().map(|l| format!("{l:04x}")).collect();
        assert_eq!(limbs.join(" "), v["limbs"], "{name}: limbs");
        assert_eq!(amount_is_valid(&word), yes(&v), "{name}: valid");
        match amount_value(&word) {
            Some(value) => {
                assert!(yes(&v), "{name}");
                assert_eq!(amount_word(value), word, "{name}");
                assert_eq!(value.to_string(), v["value"], "{name}");
            }
            None => assert!(!yes(&v), "{name}"),
        }
    }
}

/// Section 9 and PS-10: each conservation vector under the integer rule and
/// under the limb rule the proof uses.
#[test]
fn conservation_vectors_from_spec_agree() {
    let vectors = vector_blocks(SPEC_02, "conservation-");
    assert!(vectors.len() >= 9, "the conservation vectors were not found");
    for (name, c) in vectors {
        let words: Vec<[u8; 32]> = ["v", "out", "remainder", "fee"].iter().map(|k| decimal_word(&c[*k])).collect();
        let values: Vec<Option<u128>> = words.iter().map(amount_value).collect();
        let integer = match values[..] {
            [Some(v), Some(out), Some(rem), Some(fee)] => out + rem + fee == v,
            _ => false,
        };
        assert_eq!(integer, yes(&c), "{name}: integer rule");
        assert_eq!(conservation_holds(&words[0], &words[1], &words[2], &words[3]), yes(&c), "{name}: limb rule");
        if let Some(carries) = conservation_carries(&words[0], &words[1], &words[2], &words[3]) {
            assert!(carries.iter().all(|&carry| carry <= 2), "{name}");
        }
    }
}

/// The native hashes against spec 01 and spec 05, which the proofs below
/// rely on: the derivation reproduces the example key's secrets, and the
/// fingerprint, commitment, marker and tree vectors agree.
#[test]
fn commitment_vectors_from_spec_agree() {
    let d = vector(SPEC_01, "derivation-standard");
    let (s, r, b0, b1) = key_secrets(&d["key"]);
    assert_eq!((s, r, b0, b1), (hex32(&d["s"]), hex32(&d["r"]), hex32(&d["b0"]), hex32(&d["b1"])));
    for (name, b) in [("coin-commit", b0), ("coin-remainder", b1)] {
        let c = vector(SPEC_01, name);
        let v = amount_word(c["amount"].parse().unwrap());
        let f = coin_fingerprint(&s, &r, &b, &hex32(&c["rule"]));
        assert_eq!(f, hex32(&c["fingerprint"]), "{name}");
        assert_eq!(coin_commitment(&f, &v), hex32(&c["commitment"]), "{name}");
        assert_eq!(coin_marker(&r, &b), hex32(&c["marker"]), "{name}");
    }
    let data = vector(SPEC_01, "data-commit");
    let (ds, dr, db, _) = key_secrets(&data["key"]);
    let f = data_fingerprint(&ds, &dr, &db, &hex32(&data["content-fingerprint"]), &EMPTY_RULE);
    assert_eq!(f, hex32(&data["fingerprint"]));
    assert_eq!(data_marker(&dr, &db), hex32(&data["marker"]));
    assert_eq!(empty_leaf(), hex32(&vector(SPEC_01, "empty-leaf")["leaf"]));
    let node = vector(SPEC_01, "coin-tree-node");
    assert_eq!(tree_node(Tree::Coin, 0, &hex32(&node["left"]), &hex32(&node["right"])), hex32(&node["node"]));
    let two = vector(SPEC_05, "coin-tree-two-leaves");
    let leaves: Vec<[u8; 32]> = two["leaves"].split_whitespace().map(hex32).collect();
    let mut path = empty_subtrees(Tree::Coin);
    path[0] = leaves[1];
    assert_eq!(merkle_root(Tree::Coin, &leaves[0], 0, &path), hex32(&two["root"]));
    path[0] = leaves[0];
    assert_eq!(merkle_root(Tree::Coin, &leaves[1], 1, &path), hex32(&two["root"]));
    let z = empty_subtrees(Tree::Data);
    let empty = tree_node(Tree::Data, 31, &z[31], &z[31]);
    assert_eq!(empty, hex32(&vector(SPEC_05, "empty-data-tree")["root"]));
}

/// Spec 01, section 14: the salted (version 2) vectors agree with the v2
/// fingerprint, commitment and marker the salted reveal proves, and differ
/// from the version 1 values of the same secrets.
#[test]
fn salted_commitment_vectors_from_spec_agree() {
    let salt = |map: &BTreeMap<String, String>| -> [u8; SALT_BYTES] {
        hex(&map["salt"]).try_into().expect("16 bytes")
    };
    let coins = vector_blocks(SPEC_01, "coin-");
    let salted: Vec<_> = coins
        .iter()
        .filter(|(_, c)| c.get("kind").map(String::as_str) == Some("salted-coin-commitment"))
        .collect();
    assert_eq!(salted.len(), 4);
    for (name, c) in salted {
        assert_eq!((c["version"].as_str(), c["type-tag"].as_str()), ("2", "0201"), "{name}");
        let (s, r, b0, b1) = key_secrets(&c["key"]);
        let b = match c["index"].as_str() {
            "0" => b0,
            "1" => b1,
            other => panic!("{name}: index {other}"),
        };
        let v = amount_word(c["amount"].parse().unwrap());
        let rule = hex32(&c["rule"]);
        let f = coin_fingerprint_v2(&s, &r, &b, &salt(c), &rule);
        assert_eq!(f, hex32(&c["fingerprint"]), "{name}");
        assert_eq!(coin_commitment_v2(&f, &v), hex32(&c["commitment"]), "{name}");
        assert_eq!(coin_marker_v2(&r, &b, &salt(c)), hex32(&c["marker"]), "{name}");
        assert_ne!(f, coin_fingerprint(&s, &r, &b, &rule), "{name}");
        assert_ne!(coin_marker_v2(&r, &b, &salt(c)), coin_marker(&r, &b), "{name}");
    }
    let datas = vector_blocks(SPEC_01, "data-commit-salted");
    assert_eq!(datas.len(), 2);
    for (name, d) in datas {
        assert_eq!((d["kind"].as_str(), d["type-tag"].as_str()), ("salted-data-commitment", "0202"), "{name}");
        let (s, r, b, _) = key_secrets(&d["key"]);
        let f = data_fingerprint_v2(&s, &r, &b, &salt(&d), &hex32(&d["content-fingerprint"]), &hex32(&d["rule"]));
        assert_eq!(f, hex32(&d["fingerprint"]), "{name}");
        assert_eq!(data_commitment_v2(&f), hex32(&d["commitment"]), "{name}");
        assert_eq!(data_marker_v2(&r, &b, &salt(&d)), hex32(&d["marker"]), "{name}");
    }
}

// ---------------------------------------------------------------------------
// S1: the one-time reveal of a coin.

/// PS-1, PS-3, PS-13: an honest partial reveal verifies, publishes the
/// marker and remainder of spec 01, proves against the spec 05 root and
/// shares no value with its commit.
#[test]
fn reveal_honest_proof_verifies() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, _proof) = valid_reveal(&coin, 1);
    let commit = vector(SPEC_01, "coin-commit");
    assert_eq!(tx.root, hex32(&vector(SPEC_05, "coin-tree-two-leaves")["root"]));
    assert_eq!(tx.marker, hex32(&commit["marker"]));
    assert_eq!(tx.remainder, hex32(&vector(SPEC_01, "coin-remainder")["commitment"]));
    // Nothing the reveal publishes contains 16 bytes of the commit's F or C.
    let published = [
        &tx.root[..],
        &tx.marker,
        &tx.remainder,
        &tx.remainder_note,
        &tx.recipient,
        &tx.out,
        &tx.fee,
        &tx.rule,
        &coin_reveal_binding(&params(), &tx),
    ]
    .concat();
    let needles = [hex32(&commit["fingerprint"]), hex32(&commit["commitment"])];
    assert!(!shares_window(&published, &needles));
}

/// PS-10, PS-13: the full reveal, `v' = 0`, still creates its remainder.
#[test]
fn reveal_full_reveal_with_zero_remainder_verifies() {
    let _one = one_at_a_time();
    let coin = example_coin(ONE_GHOST, ONE_GHOST - FEE, 0, FEE);
    let (tx, _proof) = valid_reveal(&coin, 2);
    let (s, r, b1) = (coin.remainder.s, coin.remainder.r, coin.remainder.b);
    assert_eq!(tx.remainder, coin_commitment(&coin_fingerprint(&s, &r, &b1, &EMPTY_RULE), &amount_word(0)));
    assert_eq!(amount_value(&tx.out), Some(ONE_GHOST - FEE));
}

/// AV-7, PS-10: another `out` fails, and the prover cannot claim one.
#[test]
fn reveal_wrong_amount_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 3);
    for out in [add_one(&tx.out), sub_one(&tx.out), amount_word(0)] {
        assert!(rejected(&CoinReveal { out, ..tx.clone() }, &proof));
    }
    let mut request = coin.request.clone();
    request.out = add_one(&request.out);
    let refused = prove_coin_reveal(&params(), &coin.opening, &coin.remainder, &request, zk(4));
    assert_eq!(refused.unwrap_err(), ProofError::ConservationFails);
    // The lying prover makes a proof that verifies when its claim is true, so
    // its failures here and below come from the lie, not from the harness.
    let truthful = prove_coin_reveal_claiming(&params(), &coin.opening, &coin.remainder, &tx, zk(12)).unwrap();
    assert_eq!(verify_coin_reveal(&params(), &tx, &truthful), Ok(()));
    forged_fails(&coin, &CoinReveal { out: add_one(&tx.out), ..tx.clone() }, 5);
}

/// PS-3, AV-6: a marker other than the one of the opened commitment fails,
/// and a prover cannot prove one of its choosing.
#[test]
fn reveal_wrong_marker_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 6);
    let (r, b) = (coin.opening.r, coin.opening.b);
    let other_blinding = coin_marker(&r, &coin.remainder.b);
    for marker in [other_blinding, data_marker(&r, &b), [0; 32]] {
        assert!(rejected(&CoinReveal { marker, ..tx.clone() }, &proof));
    }
    forged_fails(&coin, &CoinReveal { marker: other_blinding, ..tx.clone() }, 7);
}

/// A remainder with the input's blinding is refused by the prover. The chain
/// cannot see the blinding; what it sees is that two reveals of one
/// commitment publish the same marker, so the second fails the marker check.
#[test]
fn reveal_reused_blinding_refused() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let reused = CoinRemainder {
        s: coin.remainder.s,
        r: coin.remainder.r,
        b: coin.opening.b,
        v: coin.remainder.v,
    };
    let refused = prove_coin_reveal(&params(), &coin.opening, &reused, &coin.request, zk(8));
    assert_eq!(refused.unwrap_err(), ProofError::ReusedBlinding);

    let (first, _) = valid_reveal(&coin, 9);
    let mut again = partial_reveal();
    again.request.recipient = [0x22; 20];
    let (second, _) = valid_reveal(&again, 10);
    assert_eq!(first.marker, second.marker);
    let mut spent: HashSet<[u8; 32]> = HashSet::new();
    assert!(spent.insert(first.marker), "the first reveal is applied");
    assert!(!spent.insert(second.marker), "the second reveal is rejected at the marker check");
}

/// AV-1: a substituted recipient fails.
#[test]
fn reveal_wrong_destination_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 11);
    for recipient in [[0x12; 20], [0; 20]] {
        assert!(rejected(&CoinReveal { recipient, ..tx.clone() }, &proof));
    }
    let mut last_byte = tx.recipient;
    last_byte[19] ^= 1;
    assert!(rejected(&CoinReveal { recipient: last_byte, ..tx.clone() }, &proof));
}

/// AV-2: a fee changed up or down fails.
#[test]
fn reveal_wrong_fee_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 13);
    for fee in [add_one(&tx.fee), sub_one(&tx.fee), amount_word(0)] {
        assert!(rejected(&CoinReveal { fee, ..tx.clone() }, &proof));
    }
    forged_fails(&coin, &CoinReveal { fee: sub_one(&tx.fee), ..tx.clone() }, 14);
}

/// AV-8, PS-24: a substituted remainder commitment fails.
#[test]
fn reveal_wrong_remainder_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 15);
    let (s, r) = (coin.remainder.s, coin.remainder.r);
    // A remainder of the same amount under another blinding, and one of
    // another type tag.
    let other = coin_commitment(&coin_fingerprint(&s, &r, &[0x99; 32], &EMPTY_RULE), &coin.remainder.v);
    let as_data = data_commitment(&data_fingerprint(&s, &r, &coin.remainder.b, &[0; 32], &EMPTY_RULE));
    for remainder in [other, as_data] {
        assert!(rejected(&CoinReveal { remainder, ..tx.clone() }, &proof));
    }
    forged_fails(&coin, &CoinReveal { remainder: other, ..tx.clone() }, 16);
}

/// AV-8, PS-24: a substituted remainder note of valid length fails.
#[test]
fn reveal_wrong_remainder_note_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 17);
    let mut flipped = tx.remainder_note;
    flipped[NOTE_BYTES - 1] ^= 0x80;
    for remainder_note in [[0x44; NOTE_BYTES], flipped] {
        assert!(rejected(&CoinReveal { remainder_note, ..tx.clone() }, &proof));
    }
}

/// AV-3, AV-4, PS-8: another chain identifier, protocol version or domain
/// fails.
#[test]
fn reveal_wrong_chain_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 19);
    let ours = params();
    let others = [
        ChainParams {
            chain_id: 1235u64.to_be_bytes(),
            ..ours.clone()
        },
        ChainParams {
            version: [0x00, 0x02],
            ..ours.clone()
        },
        ChainParams {
            domain: [0x48; 32],
            ..ours.clone()
        },
    ];
    for other in others {
        assert_eq!(verify_coin_reveal(&other, &tx, &proof), Err(ProofError::Rejected));
    }
}

/// PS-19, AV-5, AV-11: another root fails, a root the leaf is not under is
/// refused, and a prover cannot claim one.
#[test]
fn reveal_wrong_root_fails() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 20);
    let empty_coin = hex32(&vector(SPEC_05, "empty-coin-tree")["root"]);
    let data_root = hex32(&vector(SPEC_05, "data-tree-one-leaf")["root"]);
    for root in [empty_coin, data_root] {
        assert!(rejected(&CoinReveal { root, ..tx.clone() }, &proof));
    }
    let mut request = coin.request.clone();
    request.root = empty_coin;
    let refused = prove_coin_reveal(&params(), &coin.opening, &coin.remainder, &request, zk(21));
    assert_eq!(refused.unwrap_err(), ProofError::NotInTree);
    forged_fails(&coin, &CoinReveal { root: empty_coin, ..tx.clone() }, 22);
}

/// AV-7: a remainder that wraps the field is unprovable: the spec's 64-bit
/// example and its BabyBear analogue fail the integer rule, and a lying
/// prover's proof of the BabyBear one fails.
#[test]
fn reveal_field_wrap_unprovable() {
    let _one = one_at_a_time();
    let honest = partial_reveal();
    valid_reveal(&honest, 23);
    let spec = vector(SPEC_02, "conservation-field-wrap");
    let wrap_64: u128 = spec["remainder"].parse().unwrap();
    for (v, out, rem) in [(10, 20, wrap_64), (10, 20, BABY_BEAR_MODULUS - 10)] {
        let coin = example_coin(v, out, rem, 0);
        let refused = prove_coin_reveal(&params(), &coin.opening, &coin.remainder, &coin.request, zk(24));
        assert_eq!(refused.unwrap_err(), ProofError::ConservationFails);
    }
    let coin = example_coin(10, 20, BABY_BEAR_MODULUS - 10, 0);
    let claimed = CoinReveal {
        root: coin.request.root,
        marker: coin_marker(&coin.opening.r, &coin.opening.b),
        remainder: coin_commitment(
            &coin_fingerprint(&coin.remainder.s, &coin.remainder.r, &coin.remainder.b, &EMPTY_RULE),
            &coin.remainder.v,
        ),
        remainder_note: coin.request.remainder_note,
        recipient: coin.request.recipient,
        out: coin.request.out,
        fee: coin.request.fee,
        rule: EMPTY_RULE,
    };
    forged_fails(&coin, &claimed, 25);
}

/// AV-7, PS-11: a public amount word with a high byte set is rejected before
/// the proof; a private one is refused; a sum that wraps at `2^96` is
/// unprovable.
#[test]
fn reveal_overflow_amount_rejected() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 26);
    let two_to_96 = hex32(&vector(SPEC_02, "amount-two-to-96")["word"]);
    let top_bit = hex32(&vector(SPEC_02, "amount-top-bit")["word"]);
    for word in [two_to_96, top_bit] {
        let wrong_out = CoinReveal { out: word, ..tx.clone() };
        assert_eq!(verify_coin_reveal(&params(), &wrong_out, &proof), Err(ProofError::AmountOutOfRange));
        let wrong_fee = CoinReveal { fee: word, ..tx.clone() };
        assert_eq!(verify_coin_reveal(&params(), &wrong_fee, &proof), Err(ProofError::AmountOutOfRange));
        let mut request = coin.request.clone();
        request.out = word;
        let refused = prove_coin_reveal(&params(), &coin.opening, &coin.remainder, &request, zk(27));
        assert_eq!(refused.unwrap_err(), ProofError::AmountOutOfRange);
        let big_remainder = CoinRemainder {
            s: coin.remainder.s,
            r: coin.remainder.r,
            b: coin.remainder.b,
            v: word,
        };
        let refused = prove_coin_reveal(&params(), &coin.opening, &big_remainder, &coin.request, zk(27));
        assert_eq!(refused.unwrap_err(), ProofError::AmountOutOfRange);
    }
    let wrap = vector(SPEC_02, "conservation-wrap-at-two-to-96");
    let [v, out, rem]: [u128; 3] = ["v", "out", "remainder"].map(|k| wrap[k].parse().unwrap());
    let coin = example_coin(v, out, rem, 0);
    let refused = prove_coin_reveal(&params(), &coin.opening, &coin.remainder, &coin.request, zk(28));
    assert_eq!(refused.unwrap_err(), ProofError::ConservationFails);
    let claimed = CoinReveal {
        root: coin.request.root,
        marker: coin_marker(&coin.opening.r, &coin.opening.b),
        remainder: coin_commitment(
            &coin_fingerprint(&coin.remainder.s, &coin.remainder.r, &coin.remainder.b, &EMPTY_RULE),
            &coin.remainder.v,
        ),
        remainder_note: coin.request.remainder_note,
        recipient: coin.request.recipient,
        out: coin.request.out,
        fee: coin.request.fee,
        rule: EMPTY_RULE,
    };
    forged_fails(&coin, &claimed, 29);
}

/// PS-21: version 1 accepts only the empty rule.
#[test]
fn reveal_nonempty_rule_rejected() {
    let _one = one_at_a_time();
    let coin = partial_reveal();
    let (tx, proof) = valid_reveal(&coin, 30);
    let mut rule = EMPTY_RULE;
    rule[31] = 1;
    assert_eq!(
        verify_coin_reveal(&params(), &CoinReveal { rule, ..tx.clone() }, &proof),
        Err(ProofError::RuleNotEmpty)
    );
    let mut request = coin.request.clone();
    request.rule = rule;
    let refused = prove_coin_reveal(&params(), &coin.opening, &coin.remainder, &request, zk(31));
    assert_eq!(refused.unwrap_err(), ProofError::RuleNotEmpty);
}

// ---------------------------------------------------------------------------
// S2: the one-time reveal of data.

fn data_reveal_tx(d: &Data, purpose: DataPurpose) -> DataReveal {
    DataReveal {
        purpose,
        root: d.root,
        marker: data_marker(&d.r, &d.b),
        party: [0x70; 32],
        fee: amount_word(FEE),
        rule: EMPTY_RULE,
    }
}

/// PS-20: the shipped verifier rejects every data reveal at the fee step,
/// including one whose proof verifies; purpose codes other than reveal and
/// revoke are unknown.
#[test]
fn data_reveal_shipped_verifier_rejects_until_fee_settled() {
    let d = example_data();
    for purpose in [DataPurpose::Reveal, DataPurpose::Revoke] {
        for proof in [Proof::from_bytes(Vec::new()), Proof::from_bytes(vec![0xa5; 4096])] {
            let result = verify_data_reveal(&params(), &data_reveal_tx(&d, purpose), &proof);
            assert_eq!(result, Err(ProofError::DataFeeUnsettled));
        }
    }
    assert_eq!(DataPurpose::from_code(0x02), Ok(DataPurpose::Reveal));
    assert_eq!(DataPurpose::from_code(0x03), Ok(DataPurpose::Revoke));
    for code in [0x00, 0x01, 0x04, 0x05, 0xff] {
        assert_eq!(DataPurpose::from_code(code), Err(ProofError::UnknownPurpose));
    }
    #[cfg(feature = "unsettled-points-test")]
    {
        let _one = one_at_a_time();
        let request = DataRevealRequest {
            purpose: DataPurpose::Reveal,
            root: d.root,
            party: [0x70; 32],
            fee: amount_word(FEE),
            rule: EMPTY_RULE,
        };
        let opening = DataOpening {
            s: d.s,
            r: d.r,
            b: d.b,
            cf: d.cf,
            position: 0,
            path: d.path,
        };
        let (tx, proof) = prove_data_reveal(&params(), &opening, &request, zk(40)).expect("honest proof");
        assert_eq!(verify_data_reveal_unsettled(&params(), &tx, &proof), Ok(()));
        assert_eq!(verify_data_reveal(&params(), &tx, &proof), Err(ProofError::DataFeeUnsettled));
    }
}

/// PS-23, AV-9: a data reveal resubmitted as a revocation fails, and the
/// other way round.
#[cfg(feature = "unsettled-points-test")]
#[test]
fn data_reveal_as_revocation_fails() {
    let _one = one_at_a_time();
    let d = example_data();
    let opening = DataOpening {
        s: d.s,
        r: d.r,
        b: d.b,
        cf: d.cf,
        position: 0,
        path: d.path,
    };
    for (purpose, swapped, seed) in [
        (DataPurpose::Reveal, DataPurpose::Revoke, 41),
        (DataPurpose::Revoke, DataPurpose::Reveal, 42),
    ] {
        let request = DataRevealRequest {
            purpose,
            root: d.root,
            party: [0x70; 32],
            fee: amount_word(FEE),
            rule: EMPTY_RULE,
        };
        let (tx, proof) = prove_data_reveal(&params(), &opening, &request, zk(seed)).expect("honest proof");
        assert_eq!(tx.marker, hex32(&vector(SPEC_01, "data-commit")["marker"]));
        assert_eq!(verify_data_reveal_unsettled(&params(), &tx, &proof), Ok(()));
        let resubmitted = DataReveal { purpose: swapped, ..tx };
        assert_eq!(verify_data_reveal_unsettled(&params(), &resubmitted, &proof), Err(ProofError::Rejected));
    }
}

// ---------------------------------------------------------------------------
// S3: the proof of holding.

/// PS-20: the shipped verifier rejects every proof of holding, including one
/// that verifies as written.
#[test]
fn hold_shipped_verifier_rejects_every_proof() {
    let d = example_data();
    let mut coin_ctx = hold_context(&d, 1, [0x0c; 32]);
    coin_ctx.type_tag = COIN;
    for ctx in [hold_context(&d, 1, [0x0c; 32]), coin_ctx] {
        for proof in [Proof::from_bytes(Vec::new()), Proof::from_bytes(vec![0xa5; 4096])] {
            assert_eq!(verify_hold(&params(), &ctx, &proof), Err(ProofError::HoldUnsettled));
        }
    }
    #[cfg(feature = "unsettled-points-test")]
    {
        let _one = one_at_a_time();
        let ctx = hold_context(&d, 1, [0x0c; 32]);
        let proof = prove_hold(&params(), &hold_opening(&d), &ctx, zk(50)).expect("honest proof");
        assert_eq!(verify_hold_unsettled(&params(), &ctx, &proof), Ok(()));
        assert_eq!(verify_hold(&params(), &ctx, &proof), Err(ProofError::HoldUnsettled));
    }
}

/// PS-20: a proof of holding for `COIN` is rejected, by the public functions
/// and by the test-only path, while `DATA` passes the same check.
#[test]
fn hold_coin_rejected() {
    let d = example_data();
    let data_ctx = hold_context(&d, 1, [0x0c; 32]);
    assert_eq!(data_ctx.check(), Ok(()));
    assert!(hold_binding(&params(), &data_ctx).is_ok());
    // A salted data commitment's type passes the same check.
    let salted_ctx = HoldContext {
        type_tag: DATA_V2,
        ..data_ctx.clone()
    };
    assert_eq!(salted_ctx.check(), Ok(()));
    assert!(hold_binding(&params(), &salted_ctx).is_ok());
    let coin_ctx = HoldContext {
        type_tag: COIN,
        ..data_ctx.clone()
    };
    assert_eq!(coin_ctx.check(), Err(ProofError::HoldCoinUnsettled));
    assert_eq!(hold_binding(&params(), &coin_ctx), Err(ProofError::HoldCoinUnsettled));
    assert!(verify_hold(&params(), &coin_ctx, &Proof::from_bytes(Vec::new())).is_err());
    for unknown in [[0x01, 0x03], [0x02, 0x01], [0x00, 0x00]] {
        let ctx = HoldContext {
            type_tag: unknown,
            ..data_ctx.clone()
        };
        assert_eq!(ctx.check(), Err(ProofError::UnknownType));
    }
    #[cfg(feature = "unsettled-points-test")]
    {
        let _one = one_at_a_time();
        let opening = hold_opening(&d);
        assert_eq!(
            prove_hold(&params(), &opening, &coin_ctx, zk(51)).unwrap_err(),
            ProofError::HoldCoinUnsettled
        );
        let proof = prove_hold(&params(), &opening, &data_ctx, zk(52)).expect("honest proof");
        assert_eq!(verify_hold_unsettled(&params(), &data_ctx, &proof), Ok(()));
        assert_eq!(verify_hold_unsettled(&params(), &coin_ctx, &proof), Err(ProofError::HoldCoinUnsettled));
    }
}

/// PS-16, AV-10: a proof answering a challenge past its lifetime, or one the
/// verifier has replaced with a fresh one, fails.
#[cfg(feature = "unsettled-points-test")]
#[test]
fn hold_stale_challenge_fails() {
    let _one = one_at_a_time();
    let d = example_data();
    let mut book = ChallengeBook::new(300);
    let challenge = book.issue([0xc1; 32], 0).unwrap();
    let ctx = hold_context(&d, 1, challenge);
    let proof = prove_hold(&params(), &hold_opening(&d), &ctx, zk(53)).expect("honest proof");
    assert_eq!(verify_hold_unsettled(&params(), &ctx, &proof), Ok(()));
    assert_eq!(book.check(&challenge, 299), Ok(()));

    let late = verify_hold_unsettled_with_book(&params(), &mut book.clone(), &ctx, &proof, 300);
    assert_eq!(late, Err(ProofError::ChallengeExpired));
    let fresh = book.issue([0xc2; 32], 100).unwrap();
    let answered_old = HoldContext {
        challenge: fresh,
        ..ctx.clone()
    };
    let result = verify_hold_unsettled_with_book(&params(), &mut book, &answered_old, &proof, 101);
    assert_eq!(result, Err(ProofError::Rejected));
    assert_eq!(book.check(&fresh, 102), Ok(()), "a failed proof does not use the challenge up");
    book.prune(1000);
    assert_eq!(book.check(&challenge, 1000), Err(ProofError::ChallengeUnknown));
}

/// PS-16, AV-10: a verifier accepts each challenge it issued once, and
/// rejects a proof that answers a challenge it never issued.
#[cfg(feature = "unsettled-points-test")]
#[test]
fn hold_challenge_accepted_once() {
    let _one = one_at_a_time();
    let d = example_data();
    let mut book = ChallengeBook::new(300);
    let challenge = book.issue([0xc3; 32], 0).unwrap();
    assert_eq!(book.issue([0xc3; 32], 1), Err(ProofError::ChallengeAlreadyIssued));
    let ctx = hold_context(&d, 1, challenge);
    let proof = prove_hold(&params(), &hold_opening(&d), &ctx, zk(54)).expect("honest proof");
    assert_eq!(verify_hold_unsettled_with_book(&params(), &mut book, &ctx, &proof, 10), Ok(()));
    assert_eq!(
        verify_hold_unsettled_with_book(&params(), &mut book, &ctx, &proof, 11),
        Err(ProofError::ChallengeUsed)
    );

    let never_issued = hold_context(&d, 1, [0xc4; 32]);
    let proof = prove_hold(&params(), &hold_opening(&d), &never_issued, zk(55)).expect("honest proof");
    assert_eq!(verify_hold_unsettled(&params(), &never_issued, &proof), Ok(()));
    assert_eq!(
        verify_hold_unsettled_with_book(&params(), &mut book, &never_issued, &proof, 12),
        Err(ProofError::ChallengeUnknown)
    );
}

/// PS-16, AV-3, AV-10: a proof made for one verifier fails for another, and
/// on another chain.
#[cfg(feature = "unsettled-points-test")]
#[test]
fn hold_wrong_verifier_fails() {
    let _one = one_at_a_time();
    let d = example_data();
    let ctx = hold_context(&d, 0x0a, [0xc5; 32]);
    let proof = prove_hold(&params(), &hold_opening(&d), &ctx, zk(56)).expect("honest proof");
    assert_eq!(verify_hold_unsettled(&params(), &ctx, &proof), Ok(()));
    let other_verifier = HoldContext {
        verifier: [0x0b; 32],
        ..ctx.clone()
    };
    assert_eq!(verify_hold_unsettled(&params(), &other_verifier, &proof), Err(ProofError::Rejected));
    let other_chain = ChainParams {
        chain_id: 1235u64.to_be_bytes(),
        ..params()
    };
    assert_eq!(verify_hold_unsettled(&other_chain, &ctx, &proof), Err(ProofError::Rejected));
    let other_set = HoldContext {
        marker_set_root: [0x6e; 32],
        ..ctx.clone()
    };
    assert_eq!(verify_hold_unsettled(&params(), &other_set, &proof), Err(ProofError::Rejected));
}

/// PS-23, AV-9: a proof of holding submitted as a data reveal, or as a coin
/// reveal, fails.
#[cfg(feature = "unsettled-points-test")]
#[test]
fn hold_proof_submitted_as_reveal_fails() {
    let _one = one_at_a_time();
    let d = example_data();
    let ctx = hold_context(&d, 0x0a, [0xc6; 32]);
    let proof = prove_hold(&params(), &hold_opening(&d), &ctx, zk(57)).expect("honest proof");
    assert_eq!(verify_hold_unsettled(&params(), &ctx, &proof), Ok(()));
    for purpose in [DataPurpose::Reveal, DataPurpose::Revoke] {
        let as_data = DataReveal {
            party: ctx.verifier,
            ..data_reveal_tx(&d, purpose)
        };
        assert_eq!(verify_data_reveal_unsettled(&params(), &as_data, &proof), Err(ProofError::Rejected));
    }
    let as_coin = CoinReveal {
        root: d.root,
        marker: data_marker(&d.r, &d.b),
        remainder: [0; 32],
        remainder_note: [0; NOTE_BYTES],
        recipient: [0x0a; 20],
        out: amount_word(0),
        fee: amount_word(0),
        rule: EMPTY_RULE,
    };
    assert!(verify_coin_reveal(&params(), &as_coin, &proof).is_err());
}

/// PS-2, PS-15: ten proofs of holding of one commitment all verify; they
/// share no public value beyond the tree state, the chain constants and the
/// verifiers' choices, and none carries 16 bytes of the commitment, its
/// fingerprint or its marker.
#[cfg(feature = "unsettled-points-test")]
#[test]
fn hold_ten_proofs_verify_and_share_no_public_value() {
    let _one = one_at_a_time();
    let d = example_data();
    let commit = vector(SPEC_01, "data-commit");
    let needles = [
        hex32(&commit["commitment"]),
        hex32(&commit["fingerprint"]),
        hex32(&commit["marker"]),
    ];
    let mut book = ChallengeBook::new(1_000);
    let mut bindings = HashSet::new();
    let mut proofs: Vec<Proof> = Vec::new();
    for n in 0..10u8 {
        let challenge = book.issue([0xd0 + n; 32], 0).unwrap();
        let ctx = hold_context(&d, 0x0a + n % 2, challenge);
        let proof = prove_hold(&params(), &hold_opening(&d), &ctx, zk(60 + n)).expect("honest proof");
        assert_eq!(verify_hold_unsettled_with_book(&params(), &mut book, &ctx, &proof, 1), Ok(()));
        let binding = hold_binding(&params(), &ctx).unwrap();
        assert!(bindings.insert(binding), "two proofs share a binding digest");
        let public = [&ctx.root[..], &ctx.marker_set_root, &ctx.verifier, &ctx.challenge, &binding].concat();
        assert!(!shares_window(&public, &needles), "proof {n} publishes part of the commitment");
        assert!(!shares_window(proof.as_bytes(), &needles), "proof {n} carries part of the commitment");
        assert!(proofs.iter().all(|p| p != &proof), "two proofs are equal");
        proofs.push(proof);
    }
}

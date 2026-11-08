//! The C interface to the root proof verifiers, end to end at the test
//! shape: a bundle's shrink over a real coin reveal, and the public root over
//! real ML-DSA-44 signatures, each proven through the batch, root and shrink
//! layers, written as a root key, root inputs and a zero-padded proof field,
//! and given to the `extern "C"` functions as a node would.

use std::ptr;

use ghost_proofs::ffi::*;
use ghost_proofs::layers::{self, Claim, LayerShape};
use ghost_proofs::mldsa::{self, SignedTx};
use ghost_proofs::*;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

type F = BabyBear;

/// The reveal proofs' shape: blowup 2^3 and two queries.
const TEST: LayerShape = LayerShape {
    log_blowup: 3,
    num_queries: 2,
};

/// The layers' shape: blowup 2^2, enough for the tables' degree-3
/// constraints, and two queries, to bound proving memory.
const LEAN: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 2,
};

/// The chunk and its batch: blowup 2^2 and one query.
const SMALL: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 1,
};

/// The reveal proven on testnet2 that the layers tests keep.
const TESTNET2_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/foreign_chain_reveal_testnet2.txt");

/// The ML-DSA-44 known-answer vectors of the chunk tests.
const VECTORS: &str = include_str!("data/ml_dsa_44_vectors.txt");

/// A progress line with the process's peak memory, uncaptured, so a run
/// killed for memory shows where it was.
fn progress(what: &str) {
    use std::io::Write;
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let peak = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap_or("VmHWM: unknown");
    let _ = writeln!(std::io::stderr(), "PROGRESS {what}: {}", peak.trim());
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length");
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().unwrap()
}

/// The kept testnet2 reveal: its chain, transaction and proof.
fn load_testnet2() -> (ChainParams, CoinRevealV2, Proof) {
    let text = std::fs::read_to_string(TESTNET2_PATH).unwrap();
    let mut fields = std::collections::BTreeMap::new();
    let mut proof = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let (name, value) = line.split_once(' ').unwrap();
        if name == "proof" {
            proof.extend(unhex(value));
        } else {
            assert!(fields.insert(name, value).is_none(), "{name} twice");
        }
    }
    let take = |name: &str| fields[name];
    assert_eq!(take("num_queries"), TEST.num_queries.to_string());
    assert_eq!(take("digest_elems"), "9");
    let params = ChainParams {
        chain_id: array(take("chain_id")),
        version: array(take("version")),
        domain: array(take("domain")),
    };
    let tx = CoinRevealV2 {
        root: array(take("root")),
        marker: array(take("marker")),
        remainder: array(take("remainder")),
        remainder_note: array(take("remainder_note")),
        recipient: array(take("recipient")),
        out: array(take("out")),
        fee: array(take("fee")),
    };
    (params, tx, Proof::from_bytes(proof))
}

/// The four vectors that sign 32 bytes, a transaction hash's length, account
/// `i` the byte `i + 1` twenty times.
fn hash_vectors() -> Vec<SignedTx> {
    let mut out = Vec::new();
    let (mut pk, mut msg) = (None, None);
    for line in VECTORS.lines() {
        if let Some(h) = line.strip_prefix("pk ") {
            pk = Some(unhex(h));
        } else if let Some(h) = line.strip_prefix("msg ") {
            msg = Some(unhex(h));
        } else if let Some(h) = line.strip_prefix("sig ") {
            let account = [out.len() as u8 + 1; 20];
            out.push(SignedTx::new(account, pk.take().unwrap(), msg.take().unwrap(), unhex(h)));
        }
    }
    out.into_iter().filter(|t| t.message.len() == mldsa::TX_HASH_BYTES).collect()
}

/// A proof in the proof field: its bytes, then zeros.
fn field_of(proof: &[u8]) -> Vec<u8> {
    assert!(proof.len() <= PROOF_FIELD_BYTES, "a proof of {} bytes", proof.len());
    let mut field = proof.to_vec();
    field.resize(PROOF_FIELD_BYTES, 0);
    field
}

type RootFn = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32;

fn call(f: RootFn, key: &[u8], inputs: &[u8], proof: &[u8]) -> i32 {
    let status = unsafe { f(key.as_ptr(), key.len(), inputs.as_ptr(), inputs.len(), proof.as_ptr(), proof.len()) };
    assert_ne!(status, GHOST_PROOFS_PANICKED, "the verifier panicked");
    status
}

fn bundle(key: &[u8], inputs: &[u8], proof: &[u8]) -> i32 {
    call(ghost_verify_bundle_root, key, inputs, proof)
}

fn public(key: &[u8], inputs: &[u8], proof: &[u8]) -> i32 {
    call(ghost_verify_public_root, key, inputs, proof)
}

fn rejects(status: i32) -> bool {
    status == GHOST_PROOFS_REJECTED || status == GHOST_PROOFS_MALFORMED_INPUT
}

/// A field with one byte of the proof inside it changed, at several places:
/// none verifies.
fn assert_changed_bytes_refused(f: RootFn, key: &[u8], inputs: &[u8], proof_len: usize, field: &[u8]) {
    for at in [0, proof_len / 4, proof_len / 2, 3 * proof_len / 4, proof_len - 1] {
        let mut changed = field.to_vec();
        changed[at] ^= 1;
        let status = call(f, key, inputs, &changed);
        assert!(rejects(status), "a proof changed at byte {at} of {proof_len}: status {status}");
    }
    // A non-zero byte in the padding, a field one byte short or long.
    for at in [proof_len, PROOF_FIELD_BYTES - 1] {
        let mut padded = field.to_vec();
        padded[at] = 1;
        assert_eq!(call(f, key, inputs, &padded), GHOST_PROOFS_MALFORMED_INPUT, "padding byte {at}");
    }
    assert_eq!(call(f, key, inputs, &field[..PROOF_FIELD_BYTES - 1]), GHOST_PROOFS_MALFORMED_INPUT);
    let mut longer = field.to_vec();
    longer.push(0);
    assert_eq!(call(f, key, inputs, &longer), GHOST_PROOFS_MALFORMED_INPUT);
}

/// A key with one word changed: the commitment, the children's key digest,
/// a table's height, the queries. None verifies.
fn assert_changed_key_refused(f: RootFn, key: &[u8], inputs: &[u8], field: &[u8]) {
    let word = |key: &mut Vec<u8>, at: usize, value: u32| key[4 * at..4 * at + 4].copy_from_slice(&value.to_le_bytes());
    let read = |at: usize| u32::from_le_bytes(key[4 * at..4 * at + 4].try_into().unwrap());
    for (what, at, value) in [
        ("commitment", 13, read(13) ^ 2),
        ("children's key", 22, read(22) ^ 2),
        ("wire table height", 4, read(4) * 2),
        ("queries", 2, read(2) + 1),
    ] {
        let mut changed = key.to_vec();
        word(&mut changed, at, value);
        let status = call(f, &changed, inputs, field);
        assert_ne!(status, GHOST_PROOFS_ACCEPTED, "a key with a changed {what} accepts");
    }
}

/// A bundle of one real coin reveal proven on testnet2, through a batch, a
/// root and a shrink. Returns the shrink's proof field.
fn bundle_root_through_the_c_interface() -> Vec<u8> {
    let t = std::time::Instant::now();
    let (testnet2, tx, reveal) = load_testnet2();
    assert_eq!(testnet2.chain_id, *b"testnet2");
    let testnet1 = ChainParams {
        chain_id: *b"testnet1",
        ..testnet2.clone()
    };
    let shape = ScaleShape {
        num_queries: TEST.num_queries,
        digest_elems: 9,
    };
    verify_coin_reveal_v2_scale_shaped(&testnet2, &tx, &reveal, shape).unwrap();

    let child = layers::RevealChild::new(TEST.num_queries);
    let binding = layers::Binding::of(&testnet2);
    let start = layers::START_DIGEST;
    let item = coin_reveal_v2_public_values(&testnet2, &tx);
    assert_eq!(item.len(), REVEAL_PUBLIC_BYTES);
    let publics = layers::RevealChild::public_values(&testnet2, &tx);
    assert_eq!(publics, item.iter().map(|&b| F::from_u8(b)).collect::<Vec<_>>());
    let claim = Claim::of(&start, std::slice::from_ref(&publics));

    let batch_key = layers::batch_key(&child, TEST, child.log_height(), 1, LEAN).unwrap();
    progress(&format!("bundle: batch key, table heights {:?}", batch_key.table_heights()));
    let children = vec![(reveal.as_bytes().to_vec(), publics.clone())];
    let batch = layers::prove_batch(&batch_key, &child, &binding, 0, &start, &children, [31; 32]).unwrap();
    progress(&format!("bundle: batch proven, {} bytes after {:?}", batch.len(), t.elapsed()));
    let root_key = layers::root_key(&batch_key, 1, LEAN).unwrap();
    progress(&format!("bundle: root key, table heights {:?}", root_key.table_heights()));
    let root = layers::prove_layer(&root_key, &batch_key, &binding, 0, &[(batch, claim)], [32; 32]).unwrap();
    progress(&format!("bundle: root proven, {} bytes after {:?}", root.len(), t.elapsed()));
    drop(batch_key);
    let shrink_key = layers::shrink_key(&root_key, LEAN).unwrap();
    progress(&format!("bundle: shrink key, table heights {:?}", shrink_key.table_heights()));
    let shrink = layers::prove_layer(&shrink_key, &root_key, &binding, 0, &[(root.clone(), claim)], [33; 32]).unwrap();
    progress(&format!("bundle: shrink proven, {} bytes after {:?}", shrink.len(), t.elapsed()));
    layers::verify_layer(&shrink_key, &binding, 0, &claim, &shrink).unwrap();

    // The shrink through the C interface: accepted.
    let key = root_key_to_bytes(&shrink_key, RootPath::Bundle).unwrap();
    assert!(root_key_to_bytes(&root_key, RootPath::Bundle).is_err(), "only a shrink key is a root key");
    let inputs = root_inputs_to_bytes(&binding, std::slice::from_ref(&item));
    assert_eq!(inputs.len(), ROOT_BINDING_BYTES + REVEAL_PUBLIC_BYTES);
    assert_eq!(&inputs[..8], b"testnet2");
    let field = field_of(&shrink);
    assert_eq!(bundle(&key, &inputs, &field), GHOST_PROOFS_ACCEPTED);
    assert_eq!(verify_bundle_root_bytes(&key, &inputs, &field), GHOST_PROOFS_ACCEPTED);

    // A changed input: a field of the reveal (marker, recipient, fee, note,
    // binding digest), the binding (chain, protocol and statement version),
    // the reveal twice.
    for (what, at) in [
        ("marker", 79),
        ("recipient", 143),
        ("fee", 226),
        ("note", 400),
        ("digest", REVEAL_PUBLIC_BYTES - 1),
    ] {
        let mut changed = item.clone();
        changed[at] ^= 1;
        let changed = root_inputs_to_bytes(&binding, &[changed]);
        assert_eq!(bundle(&key, &changed, &field), GHOST_PROOFS_REJECTED, "a changed {what}");
    }
    for (what, at) in [("chain_id", 7), ("protocol_version", 9), ("statement_version", 10)] {
        let mut changed = inputs.clone();
        changed[at] ^= 1;
        assert_eq!(bundle(&key, &changed, &field), GHOST_PROOFS_REJECTED, "a changed {what}");
    }
    let twice = root_inputs_to_bytes(&binding, &[item.clone(), item.clone()]);
    assert_eq!(bundle(&key, &twice, &field), GHOST_PROOFS_REJECTED);

    // A changed proof byte, padding or field length.
    assert_changed_bytes_refused(ghost_verify_bundle_root, &key, &inputs, shrink.len(), &field);
    assert_changed_key_refused(ghost_verify_bundle_root, &key, &inputs, &field);

    // A proof for another chain: a node of testnet1 given the testnet2
    // bundle's honest shrink, with the reveal's public values on its own
    // chain, refuses it; and a shrink made for testnet1 over the testnet2
    // root (proven although its circuit fails) is refused under either chain.
    let binding1 = layers::Binding::of(&testnet1);
    let item1 = coin_reveal_v2_public_values(&testnet1, &tx);
    let inputs1 = root_inputs_to_bytes(&binding1, std::slice::from_ref(&item1));
    assert_eq!(bundle(&key, &inputs1, &field), GHOST_PROOFS_REJECTED);
    let foreign_inputs = root_inputs_to_bytes(&binding1, std::slice::from_ref(&item));
    assert_eq!(bundle(&key, &foreign_inputs, &field), GHOST_PROOFS_REJECTED);
    let tag1 = shrink_key.tag(&binding1, 0);
    let forged = layers::prove_layer_unchecked(&shrink_key, &root_key, &tag1, &[(root.clone(), claim)], [34; 32]).unwrap();
    progress(&format!("bundle: testnet1 shrink forged after {:?}", t.elapsed()));
    let forged = field_of(&forged);
    for inputs in [&foreign_inputs, &inputs1, &inputs] {
        assert_eq!(bundle(&key, inputs, &forged), GHOST_PROOFS_REJECTED);
    }

    // A reveal's proof, or the root's, in the root field.
    let reveal_bytes = reveal.as_bytes();
    let reveal_field = field_of(&reveal_bytes[..reveal_bytes.len().min(PROOF_FIELD_BYTES)]);
    let status = bundle(&key, &inputs, &reveal_field);
    assert!(rejects(status), "a reveal's proof in the root field: status {status}");
    let status = bundle(&key, &inputs, &field_of(&root));
    assert!(rejects(status), "the root's proof in the root field: status {status}");

    // The bundle's key is not a public root key.
    let public_inputs = root_inputs_to_bytes(&binding, &[vec![0; PUBLIC_TX_BYTES]]);
    assert_eq!(public(&key, &public_inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
    progress(&format!("bundle: every check done after {:?}", t.elapsed()));
    field
}

/// The public root over two real ML-DSA-44 signatures on testnet1: one chunk
/// of two, a batch over it, a root over the batch, the shrink. `bundle_field`
/// is a bundle's shrink, refused here.
fn public_root_through_the_c_interface(bundle_field: &[u8]) {
    let t = std::time::Instant::now();
    let binding = layers::Binding {
        chain_id: *b"testnet1",
        protocol_version: PROTOCOL_VERSION_2,
        statement_version: STATEMENT_VERSION_2,
    };
    let start = layers::START_DIGEST;
    let txs: Vec<SignedTx> = hash_vectors().into_iter().take(2).collect();
    assert_eq!(txs.len(), 2);
    let contents: Vec<Vec<F>> = txs.iter().map(SignedTx::public_values).collect();
    let items: Vec<Vec<u8>> =
        txs.iter().map(|tx| [&tx.account[..], &tx.key_id[..], &tx.message[..]].concat()).collect();
    for (item, values) in items.iter().zip(&contents) {
        assert_eq!(item.len(), PUBLIC_TX_BYTES);
        assert_eq!(*values, item.iter().map(|&b| F::from_u8(b)).collect::<Vec<_>>());
    }
    let claim = mldsa::claim_of(&start, &contents);

    let chunk = mldsa::chunk_key(2, mldsa::TX_HASH_BYTES, SMALL).unwrap();
    let chunk_proof = mldsa::prove_chunk(&chunk, &binding, 0, &start, &txs, [41; 32]).unwrap();
    progress(&format!("public: chunk proven, {} bytes after {:?}", chunk_proof.len(), t.elapsed()));
    let batch_key = mldsa::chunk_batch_key(&chunk, 1, SMALL).unwrap();
    let batch =
        layers::prove_layer(&batch_key, chunk.layer_key(), &binding, 0, &[(chunk_proof, claim)], [42; 32]).unwrap();
    progress(&format!("public: batch proven, {} bytes after {:?}", batch.len(), t.elapsed()));
    drop(chunk);
    let root_key = layers::root_key(&batch_key, 1, LEAN).unwrap();
    let root = layers::prove_layer(&root_key, &batch_key, &binding, 0, &[(batch, claim)], [43; 32]).unwrap();
    progress(&format!("public: root proven, {} bytes after {:?}", root.len(), t.elapsed()));
    drop(batch_key);
    let shrink_key = layers::shrink_key(&root_key, LEAN).unwrap();
    let shrink = layers::prove_layer(&shrink_key, &root_key, &binding, 0, &[(root.clone(), claim)], [44; 32]).unwrap();
    progress(&format!("public: shrink proven, {} bytes after {:?}", shrink.len(), t.elapsed()));
    layers::verify_layer(&shrink_key, &binding, 0, &claim, &shrink).unwrap();

    let key = root_key_to_bytes(&shrink_key, RootPath::Public).unwrap();
    let inputs = root_inputs_to_bytes(&binding, &items);
    let field = field_of(&shrink);
    assert_eq!(public(&key, &inputs, &field), GHOST_PROOFS_ACCEPTED);
    assert_eq!(verify_public_root_bytes(&key, &inputs, &field), GHOST_PROOFS_ACCEPTED);

    // A changed input: an account, a key identity, a transaction hash, the
    // order, a dropped or added transaction, the chain.
    for t in 0..2 {
        for (what, at) in [("account", 0), ("key identity", 20), ("transaction hash", 83)] {
            let mut changed = items.clone();
            changed[t][at] ^= 1;
            let changed = root_inputs_to_bytes(&binding, &changed);
            assert_eq!(public(&key, &changed, &field), GHOST_PROOFS_REJECTED, "a changed {what} of {t}");
        }
    }
    let swapped = root_inputs_to_bytes(&binding, &[items[1].clone(), items[0].clone()]);
    assert_eq!(public(&key, &swapped, &field), GHOST_PROOFS_REJECTED);
    let dropped = root_inputs_to_bytes(&binding, &items[..1]);
    assert_eq!(public(&key, &dropped, &field), GHOST_PROOFS_REJECTED);
    let added = root_inputs_to_bytes(&binding, &[items[0].clone(), items[1].clone(), items[0].clone()]);
    assert_eq!(public(&key, &added, &field), GHOST_PROOFS_REJECTED);
    let other_chain = layers::Binding {
        chain_id: *b"testnet2",
        ..binding
    };
    assert_eq!(public(&key, &root_inputs_to_bytes(&other_chain, &items), &field), GHOST_PROOFS_REJECTED);

    // A changed proof byte, padding or field length; a changed key.
    assert_changed_bytes_refused(ghost_verify_public_root, &key, &inputs, shrink.len(), &field);
    assert_changed_key_refused(ghost_verify_public_root, &key, &inputs, &field);

    // The root's proof, or a bundle's shrink, in the public root field.
    let status = public(&key, &inputs, &field_of(&root));
    assert!(rejects(status), "the root's proof in the public root field: status {status}");
    let status = public(&key, &inputs, bundle_field);
    assert!(rejects(status), "a bundle's shrink in the public root field: status {status}");

    // The public key is not a bundle root key.
    let bundle_inputs = root_inputs_to_bytes(&binding, &[vec![0; REVEAL_PUBLIC_BYTES]]);
    assert_eq!(bundle(&key, &bundle_inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
    progress(&format!("public: every check done after {:?}", t.elapsed()));
}

/// A real test-shape shrink of a bundle and a real test-shape public root
/// proof each verify through the C interface; a changed input, a changed
/// proof byte, a proof for another chain and a reveal's proof in the root
/// field are refused.
#[test]
fn a_real_shrink_and_root_proof_verify_through_the_c_interface() {
    let bundle_field = bundle_root_through_the_c_interface();
    public_root_through_the_c_interface(&bundle_field);
}

/// A root key's words, little endian: the path, blowup 2^2 and two queries,
/// one lane of 64 rows a table, a zero commitment and children's key.
fn plain_key(path: u32) -> Vec<u8> {
    let mut words = vec![path, 2, 2];
    for _ in 0..5 {
        words.extend([1, 64]);
    }
    words.extend([0; 18]);
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Null pointers, buffers of the wrong length and keys out of bounds are
/// refused before anything is verified; a key in bounds with a field that is
/// not its proof is refused by the verifier.
#[test]
fn bad_root_arguments_are_refused() {
    let key = plain_key(ROOT_KEY_BUNDLE);
    assert_eq!(key.len(), ROOT_KEY_BYTES);
    let binding = layers::Binding {
        chain_id: *b"testnet1",
        protocol_version: PROTOCOL_VERSION_2,
        statement_version: STATEMENT_VERSION_2,
    };
    let inputs = root_inputs_to_bytes(&binding, &[vec![7; REVEAL_PUBLIC_BYTES]]);
    let field = vec![0u8; PROOF_FIELD_BYTES];

    // In bounds: the field decodes to nothing that verifies.
    assert!(rejects(bundle(&key, &inputs, &field)));

    for k in 0..3 {
        let (a, b, c) = (
            if k == 0 { ptr::null() } else { key.as_ptr() },
            if k == 1 { ptr::null() } else { inputs.as_ptr() },
            if k == 2 { ptr::null() } else { field.as_ptr() },
        );
        let status = unsafe { ghost_verify_bundle_root(a, key.len(), b, inputs.len(), c, field.len()) };
        assert_eq!(status, GHOST_PROOFS_BAD_ARGUMENT, "null pointer {k}");
        let status = unsafe { ghost_verify_public_root(a, key.len(), b, inputs.len(), c, field.len()) };
        assert_eq!(status, GHOST_PROOFS_BAD_ARGUMENT, "null pointer {k}");
    }
    assert_eq!(bundle(&key[..ROOT_KEY_BYTES - 1], &inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(bundle(&[key.clone(), vec![0]].concat(), &inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(bundle(&key, &inputs[..ROOT_BINDING_BYTES], &field), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(bundle(&key, &inputs[..inputs.len() - 1], &field), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(bundle(&key, &[inputs.clone(), vec![0]].concat(), &field), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(verify_bundle_root_bytes(&key, &inputs[..5], &field), GHOST_PROOFS_BAD_ARGUMENT);
    assert_eq!(bundle(&key, &inputs, &field[..1000]), GHOST_PROOFS_MALFORMED_INPUT);
    assert_eq!(bundle(&key, &inputs, &[]), GHOST_PROOFS_MALFORMED_INPUT);

    // Keys out of bounds or of the other path.
    let word = |at: usize, value: u32| {
        let mut k = key.clone();
        k[4 * at..4 * at + 4].copy_from_slice(&value.to_le_bytes());
        k
    };
    for (what, bad) in [
        ("path 0", word(0, 0)),
        ("public path", word(0, ROOT_KEY_PUBLIC)),
        ("blowup 0", word(1, 0)),
        ("blowup 2^9", word(1, 9)),
        ("no queries", word(2, 0)),
        ("lanes 3", word(3, 3)),
        ("lanes 128", word(3, 128)),
        ("two permutation lanes", word(7, 2)),
        ("height 100", word(4, 100)),
        ("height 32", word(4, 32)),
        ("height 2^30", word(4, 1 << 30)),
        ("a commitment element of the order", word(13, 0x7800_0001)),
        ("a children's key element of the order", word(30, 0x7800_0001)),
    ] {
        assert_eq!(bundle(&bad, &inputs, &field), GHOST_PROOFS_BAD_ARGUMENT, "{what}");
    }
    let public_inputs = root_inputs_to_bytes(&binding, &[vec![7; PUBLIC_TX_BYTES]]);
    assert_eq!(public(&key, &public_inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
    assert!(rejects(public(&plain_key(ROOT_KEY_PUBLIC), &public_inputs, &field)));
    assert_eq!(public(&plain_key(ROOT_KEY_PUBLIC), &inputs, &field), GHOST_PROOFS_BAD_ARGUMENT);
}

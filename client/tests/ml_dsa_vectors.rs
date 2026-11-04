//! The ML-DSA-44 known-answer vectors the chunk proof of public signatures
//! is tested against (proofs/tests/data/ml_dsa_44_vectors.txt).
//!
//! The proofs crate has no ML-DSA implementation of its own to sign with, so
//! its vectors are text: a public key, a message and a signature per vector,
//! made here with the pinned RustCrypto `ml-dsa` (=0.1.1): the key from a
//! fixed 32-byte seed (`ML-DSA.KeyGen_internal`), the signature deterministic
//! (`ML-DSA.Sign` with no randomness) under the transaction context
//! `ghost/tx/v1`, over messages of several lengths. They come from that
//! implementation, not from NIST's own files.
//!
//! This test regenerates the file's text and fails if the file differs.
//! Running it once with `GHOST_WRITE_VECTORS=1` writes the file instead.

use ghost_client::account::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES, TX_CONTEXT};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa44, Signature, VerifyingKey};

/// The vectors: a key seed byte and a message length each. The first four
/// sign 32 bytes, the length of a transaction's signature hash.
const VECTORS: [(u8, usize); 6] = [(0x11, 32), (0x22, 32), (0x33, 32), (0x44, 32), (0x55, 0), (0x66, 77)];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Message `i` of `len` bytes: a fixed pattern of its seed.
fn message(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|j| (j as u8).wrapping_mul(29).wrapping_add(seed)).collect()
}

/// The text of the vectors file.
fn vectors_text() -> String {
    let mut out = String::new();
    out.push_str("# ML-DSA-44 known-answer vectors (FIPS 204), made with RustCrypto ml-dsa =0.1.1\n");
    out.push_str("# by client/tests/ml_dsa_vectors.rs: KeyGen_internal from a fixed seed, deterministic\n");
    out.push_str("# signing under the context \"ghost/tx/v1\". Not NIST's own files.\n");
    out.push_str("# Each vector: pk, msg and sig lines, lower-case hex.\n");
    for (seed, len) in VECTORS {
        let signing = ExpandedSigningKey::<MlDsa44>::from_seed(&[seed; 32].into());
        let pk: [u8; PUBLIC_KEY_BYTES] = signing.verifying_key().encode().into();
        let msg = message(seed, len);
        let sig: [u8; SIGNATURE_BYTES] =
            signing.sign_deterministic(&msg, TX_CONTEXT).expect("a short context").encode().into();
        // The pinned implementation verifies its own signature.
        let vk = VerifyingKey::<MlDsa44>::decode(&EncodedVerifyingKey::<MlDsa44>::try_from(&pk[..]).unwrap());
        let decoded = Signature::<MlDsa44>::decode(&EncodedSignature::<MlDsa44>::try_from(&sig[..]).unwrap()).unwrap();
        assert!(vk.verify_with_context(&msg, TX_CONTEXT, &decoded));
        out.push('\n');
        out.push_str(&format!("pk {}\n", hex(&pk)));
        out.push_str(&format!("msg {}\n", hex(&msg)));
        out.push_str(&format!("sig {}\n", hex(&sig)));
    }
    out
}

#[test]
fn the_vectors_file_is_what_the_pinned_implementation_makes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../proofs/tests/data/ml_dsa_44_vectors.txt");
    let text = vectors_text();
    if std::env::var("GHOST_WRITE_VECTORS").as_deref() == Ok("1") {
        let dir = std::path::Path::new(path).parent().expect("a directory");
        std::fs::create_dir_all(dir).expect("the data directory");
        std::fs::write(path, &text).expect("write the vectors file");
        return;
    }
    let on_disk = std::fs::read_to_string(path).expect("the vectors file");
    assert!(on_disk == text, "{path} differs from what the pinned ml-dsa makes; rerun with GHOST_WRITE_VECTORS=1");
}

/// A changed signature, message or context does not verify under the pinned
/// implementation: the vectors are not trivially accepted.
#[test]
fn a_changed_vector_does_not_verify() {
    let (seed, len) = VECTORS[0];
    let signing = ExpandedSigningKey::<MlDsa44>::from_seed(&[seed; 32].into());
    let vk = signing.verifying_key();
    let msg = message(seed, len);
    let sig = signing.sign_deterministic(&msg, TX_CONTEXT).unwrap();
    assert!(vk.verify_with_context(&msg, TX_CONTEXT, &sig));
    let mut other = msg.clone();
    other[0] ^= 1;
    assert!(!vk.verify_with_context(&other, TX_CONTEXT, &sig));
    assert!(!vk.verify_with_context(&msg, b"ghost/tx/v2", &sig));
    let mut bytes: [u8; SIGNATURE_BYTES] = sig.encode().into();
    bytes[100] ^= 1;
    let changed = Signature::<MlDsa44>::decode(&EncodedSignature::<MlDsa44>::try_from(&bytes[..]).unwrap());
    assert!(changed.is_none_or(|s| !vk.verify_with_context(&msg, TX_CONTEXT, &s)));
}

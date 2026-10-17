//! The browser entry point's library code, run natively: a session's proof
//! verifies after its public fields go through the byte encoding the worker
//! uses, a changed field is rejected, and the pinned revision matches
//! `proofs/Cargo.toml`.

use ghost_proofs::Proof;
use ghost_reveal_bench::{PLONKY3_REVISION, REVEAL_BYTES, Session, decode_reveal, encode_reveal, record_fields, verify};

#[test]
fn a_session_proof_verifies_through_the_byte_encoding() {
    for (seed, same_key) in [(7, true), (8, false)] {
        let session = Session::new(seed, same_key);
        let (tx, proof) = session.prove([seed as u8; 32]).expect("proves");
        let bytes = encode_reveal(&tx);
        assert_eq!(bytes.len(), REVEAL_BYTES);
        let back = decode_reveal(&bytes).expect("decodes");
        assert_eq!(back, tx);
        let carried = Proof::from_bytes(proof.as_bytes().to_vec());
        verify(&back, &carried).expect("verifies");

        // A changed public field (the recipient) is rejected.
        let mut changed = bytes.clone();
        changed[32 * 3 + ghost_proofs::NOTE_BYTES] ^= 1;
        assert!(verify(&decode_reveal(&changed).unwrap(), &carried).is_err());
    }
}

#[test]
fn wrong_lengths_do_not_decode() {
    assert!(decode_reveal(&[0; REVEAL_BYTES - 1]).is_none());
    assert!(decode_reveal(&[0; REVEAL_BYTES + 1]).is_none());
}

#[test]
fn record_fields_name_the_shipped_configuration() {
    let fields = record_fields(&Session::new(1, true)).expect("fields");
    assert!(fields.contains("\"zero_knowledge\":true"));
    assert!(fields.contains("keccak-256/hiding-fri/blowup-2^2/queries-57/grinding-q16-b16-o0/ext-5/zk"));
    assert!(fields.contains("\"conjectured_security_bits\":128,"));
}

#[test]
fn revision_matches_the_prover_crate() {
    let manifest = include_str!("../../../proofs/Cargo.toml");
    assert!(manifest.contains(&format!("rev = \"{PLONKY3_REVISION}\"")));
    assert!(!manifest.lines().any(|l| l.contains("rev = ") && !l.contains(PLONKY3_REVISION)));
}

#[test]
fn the_native_verifier_fails_on_a_file_without_proofs() {
    let dir = std::env::temp_dir().join(format!("ghost-reveal-verify-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let empty = dir.join("empty.proofs");
    std::fs::write(&empty, "\n  \n").unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_ghost-reveal-verify"))
        .arg(&empty)
        .output()
        .unwrap()
        .status;
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(status.code(), Some(1));
}

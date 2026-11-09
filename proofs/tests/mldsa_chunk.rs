//! Public signatures of the scale build: ML-DSA-44 verifications proven in
//! chunks (proofs/src/mldsa/) and folded by the batch, root and shrink layers
//! into one public root proof.

use std::sync::OnceLock;

use ghost_proofs::layers::{self, Claim, LayerShape};
use ghost_proofs::mldsa::{self, ChunkKey, SignedTx, native};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

type F = BabyBear;

/// The known-answer vectors: public key, message, signature, made with the
/// pinned RustCrypto ml-dsa by client/tests/ml_dsa_vectors.rs.
const VECTORS: &str = include_str!("data/ml_dsa_44_vectors.txt");

/// Proving runs one test at a time to bound memory.
static PROVING: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    PROVING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reset the process's peak resident memory (VmHWM) to its current
/// resident memory, so the next [`progress`] line gives one stage's peak.
fn reset_peak() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

/// A progress line with the process's peak memory, uncaptured.
fn progress(what: &str) {
    use std::io::Write;
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let peak = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap_or("VmHWM: unknown");
    let _ = writeln!(std::io::stderr(), "PROGRESS {what}: {}", peak.trim());
}

const BINDING: layers::Binding = layers::Binding {
    chain_id: *b"testnet1",
    protocol_version: [0, 2],
    statement_version: 2,
};

/// The chunk's shape in these tests: blowup 2^2, enough for the tables'
/// degree-3 constraints, and one query, to bound proving memory.
const SMALL: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 1,
};

/// The layers' shape over chunks: blowup 2^2 and two queries.
const LEAN: LayerShape = LayerShape {
    log_blowup: 2,
    num_queries: 2,
};

/// Verifications a chunk proves in the tests.
const SLOTS: usize = 2;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The vectors as transactions, account `i` the byte `i + 1` twenty times.
fn vectors() -> Vec<SignedTx> {
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
    out
}

/// The vectors that sign 32 bytes, a transaction hash's length.
fn hash_vectors() -> Vec<SignedTx> {
    vectors().into_iter().filter(|t| t.message.len() == mldsa::TX_HASH_BYTES).collect()
}

fn values(txs: &[SignedTx]) -> Vec<Vec<F>> {
    txs.iter().map(SignedTx::public_values).collect()
}

fn hash_key() -> &'static ChunkKey {
    static KEY: OnceLock<ChunkKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = mldsa::chunk_key(SLOTS, mldsa::TX_HASH_BYTES, SMALL).unwrap();
        progress(&format!("chunk key, table heights {:?}", key.table_heights()));
        key
    })
}

/// The two chunk proofs of the four 32-byte vectors, the second from where
/// the first ended. Each is the only child of its batch in the fold below,
/// so each is proven at index 0, its slot in that batch.
fn hash_chunks() -> &'static Vec<(Vec<u8>, Claim)> {
    static CHUNKS: OnceLock<Vec<(Vec<u8>, Claim)>> = OnceLock::new();
    CHUNKS.get_or_init(|| {
        let txs = hash_vectors();
        let mut start = layers::START_DIGEST;
        let mut out = Vec::new();
        for (i, part) in txs.chunks(SLOTS).enumerate() {
            reset_peak();
            let t = std::time::Instant::now();
            let proof = mldsa::prove_chunk(hash_key(), &BINDING, 0, &start, part, [i as u8 + 1; 32]).unwrap();
            let secs = t.elapsed().as_secs_f64();
            let claim = mldsa::claim_of(&start, &values(part));
            progress(&format!("chunk {i} of {SLOTS}: {} bytes in {secs:.2} s", proof.len()));
            start = claim.end;
            out.push((proof, claim));
        }
        out
    })
}

#[test]
fn the_vectors_verify_natively_and_name_their_keys() {
    let txs = vectors();
    assert!(txs.len() >= 6);
    let lens: std::collections::BTreeSet<usize> = txs.iter().map(|t| t.message.len()).collect();
    assert!(lens.len() >= 3, "several message lengths: {lens:?}");
    for tx in &txs {
        assert!(tx.verifies());
        let mut other = tx.clone();
        other.message.push(0);
        assert!(!other.verifies());
        let mut other = tx.clone();
        other.signature[10] ^= 1;
        assert!(!other.verifies());
    }
}

/// A chunk of valid signatures verifies; a changed signature, message, key
/// identity or account does not.
#[test]
fn a_chunk_verifies_valid_signatures_and_refuses_any_change() {
    let _guard = one_at_a_time();
    let key = hash_key();
    let txs = hash_vectors();
    let part = &txs[..SLOTS];
    let (proof, claim) = &hash_chunks()[0];
    let start = layers::START_DIGEST;
    mldsa::verify_chunk(key, &BINDING, 0, &start, &values(part), proof).unwrap();
    assert_eq!(*claim, mldsa::claim_of(&start, &values(part)));

    // Each public value of each transaction, changed: the account, the key
    // identity, the message.
    for t in 0..SLOTS {
        for (field, at) in [("account", 0), ("key identity", 20), ("message", 52)] {
            let mut vals = values(part);
            vals[t][at] += F::ONE;
            assert!(
                mldsa::verify_chunk(key, &BINDING, 0, &start, &vals, proof).is_err(),
                "a changed {field} of transaction {t} verifies"
            );
        }
    }
    // Another position, another chain.
    assert!(mldsa::verify_chunk(key, &BINDING, 1, &start, &values(part), proof).is_err());
    let other = layers::Binding {
        chain_id: *b"testnet2",
        ..BINDING
    };
    assert!(mldsa::verify_chunk(key, &other, 0, &start, &values(part), proof).is_err());

    // A changed signature, message, key identity or account in the
    // transaction itself: the prover refuses the signature's checks, and the
    // circuit proven anyway does not verify.
    let mut changed: Vec<(&str, Vec<SignedTx>)> = Vec::new();
    let mut sig = part.to_vec();
    sig[1].signature[5] ^= 1;
    changed.push(("signature", sig));
    let mut msg = part.to_vec();
    msg[0].message[3] ^= 1;
    changed.push(("message", msg));
    let mut id = part.to_vec();
    id[1].key_id[0] ^= 1;
    changed.push(("key identity", id));
    for (what, txs) in &changed {
        assert!(
            mldsa::prove_chunk(key, &BINDING, 0, &start, txs, [9; 32]).is_err(),
            "a changed {what} is proven"
        );
    }
    let forged = mldsa::prove_chunk_unchecked(key, &BINDING, 0, &start, &changed[0].1, [9; 32]).unwrap();
    progress("forged chunk proven");
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &values(&changed[0].1), &forged).is_err());
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &values(part), &forged).is_err());
    // An account is only a public value: proving under another one gives a
    // proof of that account, which the first account's values refuse.
    let mut acct = part.to_vec();
    acct[0].account[0] ^= 1;
    let moved = mldsa::prove_chunk(key, &BINDING, 0, &start, &acct, [10; 32]).unwrap();
    mldsa::verify_chunk(key, &BINDING, 0, &start, &values(&acct), &moved).unwrap();
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &values(part), &moved).is_err());
}

/// Reordered, added or dropped transactions do not verify.
#[test]
fn reordered_added_or_dropped_transactions_fail() {
    let _guard = one_at_a_time();
    let key = hash_key();
    let txs = hash_vectors();
    let part = &txs[..SLOTS];
    let (proof, _) = &hash_chunks()[0];
    let start = layers::START_DIGEST;
    let vals = values(part);
    mldsa::verify_chunk(key, &BINDING, 0, &start, &vals, proof).unwrap();
    let swapped = vec![vals[1].clone(), vals[0].clone()];
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &swapped, proof).is_err());
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &vals[..1], proof).is_err());
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &vals[1..], proof).is_err());
    let mut added = vals.clone();
    added.push(values(&txs[2..3])[0].clone());
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &added, proof).is_err());
    // A chunk of one transaction, its slot two padded: the proof is of one
    // transaction, not of two.
    let single = mldsa::prove_chunk(key, &BINDING, 0, &start, &part[..1], [11; 32]).unwrap();
    mldsa::verify_chunk(key, &BINDING, 0, &start, &vals[..1], &single).unwrap();
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &vals, &single).is_err());
    let doubled = vec![vals[0].clone(), vals[0].clone()];
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &doubled, &single).is_err());
    // More transactions than slots are refused.
    assert!(mldsa::prove_chunk(key, &BINDING, 0, &start, &txs[..SLOTS + 1], [12; 32]).is_err());
    // The second chunk from the first one's end, not from the start.
    let (proof1, claim1) = &hash_chunks()[1];
    let vals1 = values(&txs[SLOTS..2 * SLOTS]);
    mldsa::verify_chunk(key, &BINDING, 0, &claim1.start, &vals1, proof1).unwrap();
    assert!(mldsa::verify_chunk(key, &BINDING, 0, &start, &vals1, proof1).is_err());
}

/// Every known-answer vector passes inside a chunk proof: the 32-byte ones
/// in the two chunks of 2 above, the others in a chunk of 1 of their own
/// length (a chunk key is held beside the shared one while it proves, and a
/// chunk of 1 keeps the two within the acceptance run's memory).
#[test]
fn the_known_answer_vectors_pass_inside_the_chunk_proof() {
    let _guard = one_at_a_time();
    let all = vectors();
    let txs = hash_vectors();
    for (i, (proof, claim)) in hash_chunks().iter().enumerate() {
        let part = &txs[SLOTS * i..SLOTS * (i + 1)];
        mldsa::verify_chunk(hash_key(), &BINDING, 0, &claim.start, &values(part), proof).unwrap();
    }
    let others: Vec<&SignedTx> = all.iter().filter(|t| t.message.len() != mldsa::TX_HASH_BYTES).collect();
    assert!(!others.is_empty());
    for tx in others {
        let key = mldsa::chunk_key(1, tx.message.len(), SMALL).unwrap();
        let one = std::slice::from_ref(tx);
        let start = layers::START_DIGEST;
        reset_peak();
        let proof = mldsa::prove_chunk(&key, &BINDING, 0, &start, one, [13; 32]).unwrap();
        progress(&format!("vector of {} bytes proven", tx.message.len()));
        mldsa::verify_chunk(&key, &BINDING, 0, &start, &values(one), &proof).unwrap();
        let mut bad = tx.clone();
        bad.signature[2000] ^= 1;
        assert!(mldsa::prove_chunk(&key, &BINDING, 0, &start, &[bad], [13; 32]).is_err());
    }
}

/// What a verification costs, counted from the built tables, against the
/// native permutation count and the design's modeled figures.
#[test]
fn verification_cost_is_counted_from_the_tables() {
    let cost = mldsa::verification_cost(mldsa::TX_HASH_BYTES);
    // tr: ten SHAKE-256 blocks of the 1,312-byte key; mu: one; SampleInBall:
    // one; ExpandA: five SHAKE-128 blocks for each of sixteen entries; c~':
    // seven.
    assert_eq!(cost.permutations, 10 + 1 + 1 + 80 + 7);
    assert_eq!(cost.rows.len(), 15);
    for tx in hash_vectors() {
        let pk: [u8; native::PUBLIC_KEY_BYTES] = tx.public_key.as_slice().try_into().unwrap();
        let sig: [u8; native::SIGNATURE_BYTES] = tx.signature.as_slice().try_into().unwrap();
        let v = native::verify(&pk, &tx.message, &sig, mldsa::TX_CONTEXT).unwrap();
        assert!(v.permutations <= cost.permutations, "the circuit runs every permutation native verification does");
    }
    // Keccak rows: 24 a permutation.
    assert_eq!(cost.rows[5], 24 * cost.permutations);
    assert!(cost.cells > 0);
    progress(&format!("verification cost: {cost:?}"));
}

/// The batch and root of the fold over [`hash_chunks`]: one batch a chunk,
/// the root over both batches, each proof verified against its claim.
struct Folded {
    chunks: Vec<(Vec<u8>, Claim)>,
    whole: Claim,
    batch_key: layers::LayerKey,
    batches: Vec<(Vec<u8>, Claim)>,
    root_key: layers::LayerKey,
    root: Vec<u8>,
}

/// Prove the batches and the root of the fold. Both fold tests below prove
/// them, so each can run in its own CI job within the 10-minute limit.
fn fold_batches_and_root() -> Folded {
    let chunk = hash_key();
    let chunks = hash_chunks().clone();
    let txs = hash_vectors();
    let whole = Claim::joined(&chunks.iter().map(|(_, c)| *c).collect::<Vec<_>>()).unwrap();
    assert_eq!(whole, mldsa::claim_of(&layers::START_DIGEST, &values(&txs)));

    // One batch a chunk; the root folds both batches. The chunk's tables are
    // laid out so the batch circuit over one chunk proof fits tables of 2^18
    // wire rows and 2^17 arithmetic rows, which keeps the batch's prover
    // within the acceptance run's memory.
    let entries = mldsa::batch_entries(chunk, 1);
    progress(&format!("batch circuit over one chunk proof: entries {entries:?}"));
    assert!(entries[0] <= 1 << 18 && entries[1] <= 1 << 17, "the batch circuit grew: {entries:?}");
    reset_peak();
    let batch_key = mldsa::chunk_batch_key(chunk, 1, SMALL).unwrap();
    progress(&format!(
        "batch key, table heights {:?}, lanes {:?}, modeled prover bytes {}",
        batch_key.table_heights(),
        batch_key.table_lanes(),
        layers::modeled_prover_bytes(&batch_key)
    ));
    let mut batches = Vec::new();
    for (i, (proof, claim)) in chunks.iter().enumerate() {
        reset_peak();
        let t = std::time::Instant::now();
        let child = [(proof.clone(), *claim)];
        let batch = layers::prove_layer(&batch_key, chunk.layer_key(), &BINDING, i as u32, &child, [21; 32]).unwrap();
        progress(&format!("batch {i} proven: {} bytes in {:.2} s", batch.len(), t.elapsed().as_secs_f64()));
        let part = values(&txs[SLOTS * i..SLOTS * (i + 1)]);
        layers::verify_batch(&batch_key, &BINDING, i as u32, &claim.start, &part, &batch).unwrap();
        batches.push((batch, *claim));
    }

    reset_peak();
    let root_key = layers::root_key(&batch_key, 2, LEAN).unwrap();
    progress(&format!(
        "root key, table heights {:?}, lanes {:?}",
        root_key.table_heights(),
        root_key.table_lanes()
    ));
    reset_peak();
    let t = std::time::Instant::now();
    let root = layers::prove_layer(&root_key, &batch_key, &BINDING, 0, &batches, [23; 32]).unwrap();
    progress(&format!("root proven: {} bytes in {:.2} s", root.len(), t.elapsed().as_secs_f64()));
    layers::verify_layer(&root_key, &BINDING, 0, &whole, &root).unwrap();
    Folded {
        chunks,
        whole,
        batch_key,
        batches,
        root_key,
        root,
    }
}

/// The chunk proofs fold through a batch each and a root over both batches,
/// each layer's prover within the acceptance run's memory; reordered,
/// dropped or added transactions under a batch, and batches out of order
/// under the root, are refused.
#[test]
fn chunks_batch_and_root_fold_correctly() {
    let _guard = one_at_a_time();
    let txs = hash_vectors();
    let Folded {
        chunks,
        whole,
        batch_key,
        batches,
        root_key,
        root,
    } = fold_batches_and_root();
    for (i, ((batch, claim), (_, chunk_claim))) in batches.iter().zip(&chunks).enumerate() {
        assert_eq!(claim, chunk_claim);
        // fold_batches_and_root verified the batch against its own part.
        let part = values(&txs[SLOTS * i..SLOTS * (i + 1)]);
        // Reordered, dropped or added transactions under the batch.
        let swapped = vec![part[1].clone(), part[0].clone()];
        assert!(layers::verify_batch(&batch_key, &BINDING, i as u32, &claim.start, &swapped, batch).is_err());
        assert!(layers::verify_batch(&batch_key, &BINDING, i as u32, &claim.start, &part[..1], batch).is_err());
        let mut added = part.clone();
        added.push(part[0].clone());
        assert!(layers::verify_batch(&batch_key, &BINDING, i as u32, &claim.start, &added, batch).is_err());
    }
    // Batches out of order are refused by the root's prover.
    let reversed = vec![batches[1].clone(), batches[0].clone()];
    assert!(layers::prove_layer(&root_key, &batch_key, &BINDING, 0, &reversed, [22; 32]).is_err());
    // The root claims both chunks (verified in fold_batches_and_root), not
    // the first alone.
    assert_eq!(whole, Claim::joined(&[chunks[0].1, chunks[1].1]).unwrap());
    let short = Claim::joined(&[chunks[0].1]).unwrap();
    assert!(layers::verify_layer(&root_key, &BINDING, 0, &short, &root).is_err());
}

/// The root of the fold shrinks into one public root proof of at most
/// 859,736 bytes, the shrink's prover within the acceptance run's memory. It
/// proves the batches and root again (fold_batches_and_root) rather than
/// take them from chunks_batch_and_root_fold_correctly, so the two run in
/// separate CI jobs.
#[test]
fn chunks_shrink_folds_to_the_public_root_size() {
    let _guard = one_at_a_time();
    let Folded {
        chunks,
        whole,
        batch_key,
        batches,
        root_key,
        root,
    } = fold_batches_and_root();
    // Nothing below needs the batches or the batch key's prover data.
    drop(batches);
    drop(batch_key);

    reset_peak();
    let shrink_key = layers::shrink_key(&root_key, LEAN).unwrap();
    progress(&format!(
        "shrink key, table heights {:?}, lanes {:?}",
        shrink_key.table_heights(),
        shrink_key.table_lanes()
    ));
    reset_peak();
    let t = std::time::Instant::now();
    let shrink = layers::prove_layer(&shrink_key, &root_key, &BINDING, 0, &[(root, whole)], [24; 32]).unwrap();
    progress(&format!("shrink proven: {} bytes in {:.2} s", shrink.len(), t.elapsed().as_secs_f64()));
    layers::verify_layer(&shrink_key, &BINDING, 0, &whole, &shrink).unwrap();
    let short = Claim::joined(&[chunks[0].1]).unwrap();
    assert!(layers::verify_layer(&shrink_key, &BINDING, 0, &short, &shrink).is_err());

    // The size: the public root proof after the shrink is within the design's
    // 859,736 bytes, the proof field and its own computed bound.
    progress(&format!(
        "public root proof after the shrink: {} bytes, bound {}",
        shrink.len(),
        layers::proof_size_bound(&shrink_key)
    ));
    assert!(shrink.len() <= PUBLIC_ROOT_PROOF_BYTES, "a public root proof of {} bytes", shrink.len());
    assert!(shrink.len() <= layers::proof_size_bound(&shrink_key));
    assert!(shrink.len() <= layers::PROOF_FIELD_BYTES);
    assert_eq!(layers::PROOF_FIELD_BYTES, 1_310_720);
}

/// The design's public root proof after the shrink (stage 2 design, "Public
/// signature size").
const PUBLIC_ROOT_PROOF_BYTES: usize = 859_736;

/// The results page names the machine it was measured on and labels its
/// figures measured.
#[test]
fn the_results_page_names_the_machine_and_labels_its_figures() {
    let page = include_str!("../../docs/scale/mldsa-chunk-results.md");
    assert!(page.contains("Machine:"), "the page names its machine");
    assert!(page.contains("/proc/cpuinfo") && page.contains("/proc/meminfo"));
    assert!(page.contains("measured"));
    assert!(page.contains("not NIST's own files"));
    assert!(page.contains("859,736") && page.contains("1,310,720"));
}

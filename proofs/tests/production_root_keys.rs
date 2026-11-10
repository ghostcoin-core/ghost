//! The production root keys: the bundle root (shrink) key at the layers'
//! chosen shape (`layers::REVEALS_PER_BATCH` version 2 coin reveals a batch,
//! a root of `layers::BATCHES_PER_ROOT` batches) and the public root key over
//! chunks of `mldsa::DESIGN_CHUNK` ML-DSA-44 verifications folded by the same
//! layers, derived from the real-shape circuits and their preprocessed
//! commitments, never from a proof, and checked against the key bytes (hex
//! text) and SHA-256 digests committed in `proofs/keys/`.
//!
//! Each derivation's plan is printed stage by stage with its modeled peak
//! (`layers::KeyMemory`), which must be within the 6,144 MiB budget
//! (`layers::KEY_DERIVATION_BUDGET_BYTES`). Planning builds no key and runs
//! with the normal tests, as does the check of the committed key bytes
//! against their pinned digests. Every test that builds a key is
//! `#[ignore]`d, so the normal tests stay fast; run them with
//! `-- --ignored --nocapture` (`derive_production_bundle_root_key` and
//! `derive_production_public_root_key` derive one production key each). The
//! rust-proofs-root-key-* jobs of `.github/workflows/ci.yml` run them after
//! every merge.

use std::io::Write;
use std::time::Instant;

use ghost_proofs::ffi::{
    GHOST_PROOFS_ACCEPTED, GHOST_PROOFS_BAD_ARGUMENT, GHOST_PROOFS_REJECTED, ROOT_KEY_BUNDLE, ROOT_KEY_BYTES,
    ROOT_KEY_PUBLIC, RootPath, ghost_root_key_is_production, is_production_root_key, production_root_key,
    root_key_to_bytes, sha256, to_hex,
};
use ghost_proofs::layers::{self, KeyPlan};
use ghost_proofs::mldsa;

const GIB: f64 = (1u64 << 30) as f64;

fn say(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

fn gib(b: usize) -> f64 {
    b as f64 / GIB
}

/// The process's peak resident memory so far, from `/proc/self/status`.
fn vm_hwm() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024.0 / GIB)
}

fn report(name: &str, plan: &KeyPlan) {
    for stage in &plan.stages {
        let m = &stage.memory;
        say(&format!(
            "modeled: {name} key, {:?} stage: tables {:?} lanes {:?}; circuit {:.2} GiB, its rows {:.2} GiB, \
             preprocessed columns {:.2} GiB, block {:.2} GiB; peak {:.2} GiB",
            stage.layer,
            stage.heights,
            stage.lanes,
            gib(m.circuit),
            gib(m.rows),
            gib(m.columns),
            gib(m.block),
            gib(m.peak),
        ));
    }
    say(&format!(
        "modeled: {name} key derivation peak {:.2} GiB of the {:.2} GiB budget",
        gib(plan.peak()),
        layers::KEY_DERIVATION_BUDGET_BYTES as f64 / GIB
    ));
}

/// Every stage is planned, the derivation peaks at its largest stage, and
/// every stage fits the derivation budget.
fn check_plan(name: &str, plan: &KeyPlan, stages: usize) {
    report(name, plan);
    assert_eq!(plan.stages.len(), stages, "{name}");
    for stage in &plan.stages {
        let m = &stage.memory;
        assert!(m.columns > 0 && m.block > 0 && m.rows < m.circuit, "{name}: {stage:?}");
        assert_eq!(m.peak, m.circuit.max(m.rows + m.columns).max(m.columns + m.block), "{name}");
    }
    assert_eq!(plan.peak(), plan.stages.iter().map(|s| s.memory.peak).max().unwrap_or(0));
    for stage in &plan.stages {
        assert!(
            stage.memory.peak as u64 <= layers::KEY_DERIVATION_BUDGET_BYTES,
            "the {name} key's {:?} stage plans {:.2} GiB, above the {:.2} GiB budget",
            stage.layer,
            gib(stage.memory.peak),
            layers::KEY_DERIVATION_BUDGET_BYTES as f64 / GIB
        );
    }
}

/// The directory of the committed key files, `proofs/keys/`.
fn keys_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("keys")
}

/// The file under `proofs/keys/` holding `path`'s production key bytes as
/// lower-case hex text.
fn key_hex_file(path: RootPath) -> &'static str {
    match path {
        RootPath::Bundle => "bundle-root-key.hex",
        RootPath::Public => "public-root-key.hex",
    }
}

/// The file under `proofs/keys/` holding the SHA-256 digest of `path`'s
/// production key bytes as lower-case hex text.
fn key_digest_file(path: RootPath) -> &'static str {
    match path {
        RootPath::Bundle => "bundle-root-key.sha256",
        RootPath::Public => "public-root-key.sha256",
    }
}

fn read_key_file(file: &str) -> String {
    std::fs::read_to_string(keys_dir().join(file)).unwrap_or_else(|e| panic!("proofs/keys/{file}: {e}"))
}

/// `path`'s committed production key bytes: its hex file, exactly
/// `ROOT_KEY_BYTES` bytes in lower-case hexadecimal on one line, decoded.
fn committed_key_bytes(path: RootPath) -> [u8; ROOT_KEY_BYTES] {
    let file = key_hex_file(path);
    let text = read_key_file(file);
    let hex = text.strip_suffix('\n').unwrap_or(&text);
    assert_eq!(hex.len(), 2 * ROOT_KEY_BYTES, "proofs/keys/{file}: {ROOT_KEY_BYTES} bytes, one line");
    let digit = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("proofs/keys/{file}: {:?} is not a lower-case hex digit", c as char),
    };
    let mut bytes = [0u8; ROOT_KEY_BYTES];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    assert_eq!(to_hex(&bytes), hex, "proofs/keys/{file}");
    bytes
}

/// Derive `path`'s key as `plan` plans it, and check it against the
/// committed key: the derived bytes are the committed hex file's, their
/// SHA-256 is the pinned one, the key's tables are the plan's shrink, and a
/// key one byte off, or under the other path, is not the production key.
fn derive_and_check(name: &str, path: RootPath, plan: &KeyPlan) {
    let started = Instant::now();
    let key = production_root_key(path).expect("the production key derives");
    let seconds = started.elapsed().as_secs_f64();
    let shrink = plan.stages.last().expect("a shrink stage");
    assert_eq!(key.kind(), layers::LayerKind::Shrink, "{name}");
    assert_eq!(key.shape(), layers::LayerShape::SHRINK, "{name}");
    assert_eq!(key.table_heights(), shrink.heights, "{name}: the built shrink's tables are the plan's");
    assert_eq!(key.table_lanes(), shrink.lanes, "{name}: the built shrink's lanes are the plan's");
    let bytes = root_key_to_bytes(&key, path).expect("a shrink key has root key bytes");
    let digest = to_hex(&sha256(&bytes));
    say(&format!(
        "measured: {name} key derived in {seconds:.0} s, process peak so far {} GiB",
        vm_hwm().map_or_else(|| "unknown".into(), |g| format!("{g:.2}"))
    ));
    say(&format!("derived: {name} key bytes {}", to_hex(&bytes)));
    say(&format!("derived: {name} key sha256 {digest}"));
    assert_eq!(digest, path.production_key_sha256(), "{name}: the derived key is not the pinned one");
    assert_eq!(
        to_hex(&bytes),
        to_hex(&committed_key_bytes(path)),
        "{name}: the derived key is not the one committed in proofs/keys/{}",
        key_hex_file(path)
    );
    assert!(is_production_root_key(path, &bytes), "{name}");
    let code = path.code();
    // SAFETY: `bytes` is ROOT_KEY_BYTES long and readable.
    assert_eq!(unsafe { ghost_root_key_is_production(code, bytes.as_ptr(), bytes.len()) }, GHOST_PROOFS_ACCEPTED);
    for i in [0, 4, ROOT_KEY_BYTES / 2, ROOT_KEY_BYTES - 1] {
        let mut off = bytes;
        off[i] ^= 1;
        assert!(!is_production_root_key(path, &off), "{name}: byte {i} flipped");
        // SAFETY: as above.
        assert_eq!(unsafe { ghost_root_key_is_production(code, off.as_ptr(), off.len()) }, GHOST_PROOFS_REJECTED);
    }
    let other = if path == RootPath::Bundle { ROOT_KEY_PUBLIC } else { ROOT_KEY_BUNDLE };
    // SAFETY: as above.
    assert_eq!(unsafe { ghost_root_key_is_production(other, bytes.as_ptr(), bytes.len()) }, GHOST_PROOFS_REJECTED);
    // SAFETY: as above; the length check refuses before reading.
    assert_eq!(unsafe { ghost_root_key_is_production(code, bytes.as_ptr(), 3) }, GHOST_PROOFS_BAD_ARGUMENT);
    // SAFETY: as above.
    assert_eq!(unsafe { ghost_root_key_is_production(7, bytes.as_ptr(), bytes.len()) }, GHOST_PROOFS_BAD_ARGUMENT);
}

#[test]
fn sha256_matches_the_fips_180_4_examples() {
    assert_eq!(to_hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(to_hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        to_hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(
        to_hex(&sha256(&[b'a'; 1_000_000])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

/// The C header declares the two production key calls as `src/ffi.rs`
/// exports them.
#[test]
fn the_header_declares_the_production_key_calls() {
    const HEADER: &str = include_str!("../include/ghost_proofs.h");
    let check = "int32_t ghost_root_key_is_production(uint32_t path, const uint8_t *key, size_t key_len);";
    assert!(HEADER.contains(check));
    assert!(HEADER.contains("int32_t ghost_production_root_key(uint32_t path, uint8_t *out, size_t out_len);"));
    let _: unsafe extern "C" fn(u32, *const u8, usize) -> i32 = ghost_root_key_is_production;
    let _: unsafe extern "C" fn(u32, *mut u8, usize) -> i32 = ghost_proofs::ffi::ghost_production_root_key;
}

/// The build-side checks of `ghost_production_root_key` refuse before
/// anything is built.
#[test]
fn production_key_calls_refuse_bad_arguments_before_building() {
    let mut out = [0u8; ROOT_KEY_BYTES];
    let build = ghost_proofs::ffi::ghost_production_root_key;
    // SAFETY: `out` is ROOT_KEY_BYTES long and writable; every call is refused
    // before it is written.
    unsafe {
        assert_eq!(build(7, out.as_mut_ptr(), out.len()), GHOST_PROOFS_BAD_ARGUMENT);
        assert_eq!(build(ROOT_KEY_BUNDLE, out.as_mut_ptr(), ROOT_KEY_BYTES - 1), GHOST_PROOFS_BAD_ARGUMENT);
        assert_eq!(build(ROOT_KEY_BUNDLE, std::ptr::null_mut(), ROOT_KEY_BYTES), GHOST_PROOFS_BAD_ARGUMENT);
        let null = ghost_root_key_is_production(ROOT_KEY_BUNDLE, std::ptr::null(), ROOT_KEY_BYTES);
        assert_eq!(null, GHOST_PROOFS_BAD_ARGUMENT);
    }
    assert_eq!(out, [0u8; ROOT_KEY_BYTES]);
}

/// Both pinned digests are SHA-256 digests in lower-case hexadecimal.
#[test]
fn the_pinned_digests_are_sha256_hex() {
    for path in [RootPath::Bundle, RootPath::Public] {
        let pinned = path.production_key_sha256();
        assert_eq!(pinned.len(), 64, "{path:?}: {pinned}");
        assert!(pinned.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{path:?}: {pinned}");
    }
    assert_ne!(RootPath::Bundle.production_key_sha256(), RootPath::Public.production_key_sha256());
}

/// The digests are committed as hex text under `proofs/keys/`, and they are
/// the ones the library pins.
#[test]
fn the_digest_files_are_committed_and_pinned() {
    for path in [RootPath::Bundle, RootPath::Public] {
        let file = key_digest_file(path);
        assert_eq!(read_key_file(file).trim(), path.production_key_sha256(), "proofs/keys/{file}");
    }
}

/// Each production key's bytes are committed as lower-case hex text under
/// `proofs/keys/`, for the node to embed: the bytes' SHA-256 is the digest
/// in the key's `.sha256` file, the library accepts them as that path's
/// production key and no other, and they are a root key of the path, at
/// the shrink's shape and with the planned shrink's tables.
#[test]
fn the_committed_key_bytes_are_the_pinned_keys() {
    let plans = [
        (RootPath::Bundle, layers::bundle_root_key_plan().expect("the bundle root key plans")),
        (RootPath::Public, mldsa::public_root_key_plan().expect("the public root key plans")),
    ];
    for (path, plan) in &plans {
        let (path, hex, sha) = (*path, key_hex_file(*path), key_digest_file(*path));
        let bytes = committed_key_bytes(path);
        assert_eq!(
            to_hex(&sha256(&bytes)),
            read_key_file(sha).trim(),
            "the SHA-256 of proofs/keys/{hex} is not the digest in proofs/keys/{sha}"
        );
        assert!(is_production_root_key(path, &bytes), "proofs/keys/{hex}");
        let other = if path == RootPath::Bundle { RootPath::Public } else { RootPath::Bundle };
        assert!(!is_production_root_key(other, &bytes), "proofs/keys/{hex} is not the {other:?} key");
        // SAFETY: `bytes` is ROOT_KEY_BYTES long and readable.
        let accepted = unsafe { ghost_root_key_is_production(path.code(), bytes.as_ptr(), bytes.len()) };
        assert_eq!(accepted, GHOST_PROOFS_ACCEPTED, "proofs/keys/{hex}");

        // The words of the key: its path, the shrink's shape, then each
        // table's lanes and height as the plan's shrink stage has them.
        let words: Vec<u32> =
            bytes.chunks_exact(4).map(|w| u32::from_le_bytes(w.try_into().expect("four bytes"))).collect();
        let shrink = plan.stages.last().expect("a shrink stage");
        assert_eq!(shrink.layer, layers::LayerKind::Shrink, "{path:?}");
        let shape = layers::LayerShape::SHRINK;
        let mut header = vec![path.code(), shape.log_blowup as u32, shape.num_queries as u32];
        for (lanes, height) in shrink.lanes.iter().zip(&shrink.heights) {
            header.extend([*lanes as u32, *height as u32]);
        }
        assert_eq!(header.len(), 3 + 2 * 5, "{path:?}: five tables");
        assert_eq!(words[..header.len()], header[..], "proofs/keys/{hex}: path, shape and tables");
    }
    assert_ne!(committed_key_bytes(RootPath::Bundle), committed_key_bytes(RootPath::Public));
}

/// A key built for verifying alone, its circuit's wire values dropped and
/// its columns committed in place a block at a time, has the library's
/// preprocessed commitment and lookups, in one block and in many. It builds
/// keys, so it runs with `-- --ignored`.
#[test]
#[ignore = "builds keys; run with -- --ignored"]
fn the_verifier_key_commits_as_the_library_does() {
    let blocks = layers::verifier_key_check(&[usize::MAX, 1 << 14, 1]).expect("the verifier's key is the library's");
    // One block, then several, then as many as the smallest matrix has rows,
    // for both table layouts.
    assert_eq!(blocks.len(), 6, "{blocks:?}");
    for layout in blocks.chunks(3) {
        assert_eq!(layout[0], 1, "{blocks:?}");
        assert!(layout[1] > 1 && layout[2] > layout[1], "{blocks:?}");
    }
}

/// The public layers take the private layers' shape.
#[test]
fn the_public_root_takes_the_layers_shape() {
    assert_eq!(mldsa::DESIGN_CHUNKS_PER_BATCH, layers::REVEALS_PER_BATCH);
    assert_eq!(mldsa::DESIGN_BATCHES_PER_ROOT, layers::BATCHES_PER_ROOT);
}

/// Every stage of both production keys is planned within the derivation
/// budget, without building anything: the bundle root's batch, root and
/// shrink, and the public root's chunk, batch, root and shrink at
/// `mldsa::DESIGN_CHUNKS_PER_BATCH` chunks a batch and
/// `mldsa::DESIGN_BATCHES_PER_ROOT` batches a root.
#[test]
fn every_production_key_stage_plans_within_its_budget() {
    let bundle = layers::bundle_root_key_plan().expect("the bundle root key plans");
    check_plan("bundle root", &bundle, 3);
    let public = mldsa::public_root_key_plan().expect("the public root key plans");
    check_plan("public root", &public, 4);
    let at_design = mldsa::public_root_key_plan_of(mldsa::DESIGN_CHUNKS_PER_BATCH, mldsa::DESIGN_BATCHES_PER_ROOT)
        .expect("the public root plans at the design's shape");
    assert_eq!(public, at_design, "the public root key is planned at the design's batch and root");
    let one_batch = mldsa::public_root_key_plan_of(mldsa::DESIGN_CHUNKS_PER_BATCH, 1).expect("a one-batch root plans");
    assert_ne!(public.stages[2], one_batch.stages[2], "the public root's stage follows its batches a root");
}

/// The production bundle root key derived layer by layer and checked against
/// its committed bytes and pinned digest. Building it takes minutes and up
/// to the planned peak, so it runs with `-- --ignored`, after every merge in
/// the rust-proofs-root-key-bundle job of `.github/workflows/ci.yml`.
#[test]
#[ignore = "builds the production bundle root key; run with -- --ignored"]
fn derive_production_bundle_root_key() {
    let bundle = layers::bundle_root_key_plan().expect("the bundle root key plans");
    check_plan("bundle root", &bundle, 3);
    derive_and_check("bundle root", RootPath::Bundle, &bundle);
}

/// The production public root key derived layer by layer and checked
/// against its committed bytes and pinned digest. Building it takes minutes
/// and up to the planned peak, so it runs with `-- --ignored`, after every
/// merge in the rust-proofs-root-key-public job of
/// `.github/workflows/ci.yml`.
#[test]
#[ignore = "builds the production public root key; run with -- --ignored"]
fn derive_production_public_root_key() {
    let public = mldsa::public_root_key_plan().expect("the public root key plans");
    check_plan("public root", &public, 4);
    derive_and_check("public root", RootPath::Public, &public);
}
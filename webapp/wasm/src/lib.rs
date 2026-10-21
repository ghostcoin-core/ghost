//! The Ghost client library for the web app's background worker, as plain
//! WebAssembly exports (`../src/wasm.mjs` calls them; `../src/worker-core.mjs`
//! runs them in the worker).
//!
//! There is no bindings generator. The caller copies an input buffer into
//! linear memory through [`ghost_alloc`], calls one export with its pointer
//! and length, and reads the result from [`ghost_out_ptr`] and
//! [`ghost_out_len`]. Every export returns 0 on success and 1 otherwise;
//! [`ghost_error_ptr`] and [`ghost_error_len`] then give the message, which
//! never holds a digit of a key or a secret value. Integers in an input are
//! big-endian; a text is its length as 4 bytes, then its UTF-8 bytes.
//!
//! What it adds to the client library:
//!
//! - the coin tree over the leaves the wallet fetched in whole pages
//!   (spec 05, section 8): page roots, the tree root, the roots of every
//!   prefix of the leaves and the witness of one position, so no endpoint is
//!   ever asked for a path;
//! - the commit payload sent to the commit entry address;
//! - the private transaction envelope of spec 07, section 3, and its
//!   decoding and verification, which the test's stand-in node uses;
//! - the built-in wallet (spec 09, section 9): a new seed as 24 words, the
//!   account a seed derives, and the account transaction (type 0x52) signed
//!   with ML-DSA-44, plus its decoding and check for the stand-in node;
//! - the page's header chain, over the client library's `header_chain`: one
//!   chain held in the module's memory from a trusted start (genesis or a
//!   pinned header), to which the page adds every header the endpoint
//!   returns. Each header is adopted only once its difficulty (spec 06,
//!   section 4.3) and its RandomX seal (spec 08) check; the best chain is
//!   the one with the most work.
//!
//! # Secrets
//!
//! Nothing here is stored: a key or a wallet seed exists in memory only
//! during the call that received its digits or words, and the result buffer is overwritten with zeros
//! before it is replaced and when [`ghost_clear`] is called. Random bytes
//! come from the caller (`crypto.getRandomValues` in the worker), as a seed
//! for the generator the proofs crate already uses; its state is not wiped.
//!
//! The header chain is the only state kept between calls. It holds public
//! headers only, never a key or a seed, and lives as long as the module.
//!
//! A WebAssembly module runs on one thread, so the `static mut` state below
//! is never touched concurrently.

#![allow(static_mut_refs)]

use ghost_client::account::{AccountTx, WalletSeed, verify_envelope};
use ghost_client::header_chain::{
    Added, ChainError, ChainParams as ChainConstants, HeaderChain, PinnedStart, U256,
};
use ghost_client::seal::header_fields;
use ghost_client::reveal::{ChainParams, CoinReveal, Proof, TREE_DEPTH};
use ghost_client::{
    Amount, Commitment, HeaderRoot, KeyFormat, Marker, NOTE_BYTES, NoteContents, OwnedCoin, PhantomKey,
    RevealTerms, Rule, TreeLeaf, TreeStateChoice, choose_tree_state, claim_to_new_key, encrypt_note,
    partial_reveal, restore_coins,
};
use ghost_proofs::{PROTOCOL_VERSION_1, Tree, empty_leaf, keccak256, tree_node, verify_coin_reveal};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// EIP-2718 type of the private transaction (spec 07, section 2).
pub const TYPE_BYTE: u8 = 0x50;
/// The only transaction version (spec 07, section 2).
pub const TX_VERSION: [u8; 2] = [0x00, 0x01];
/// Width of the proof field of the envelope: 1.25 MiB, the settled width of
/// version 1 for every reveal kind (spec 07, section 3, "Proof field").
pub const PROOF_FIELD_BYTES: usize = 1_310_720;
const _: () = assert!(PROOF_FIELD_BYTES == ghost_proofs::PROOF_FIELD_BYTES);
/// The payload fields before the proof: version, chain identifier, marker,
/// root, remainder, recipient, amount out and fee.
const HEAD_BYTES: usize = 2 + 8 + 32 + 32 + 32 + 20 + 32 + 32;
/// Length of the envelope: the type byte and the payload.
pub const ENVELOPE_BYTES: usize = 1 + HEAD_BYTES + PROOF_FIELD_BYTES + NOTE_BYTES;

/// Commit format version, the first two bytes of a commit payload: the
/// transaction version (spec 07, section 2).
pub const COMMIT_FORMAT_VERSION: [u8; 2] = TX_VERSION;
/// A commit payload: the version, the fingerprint `F` and the note, 190
/// bytes (spec 07; the node's `ghostpriv.CommitData`).
pub const COMMIT_PAYLOAD_BYTES: usize = COMMIT_FORMAT_VERSION.len() + 32 + NOTE_BYTES;
const _: () = assert!(COMMIT_PAYLOAD_BYTES == 190);

/// Leaves per page of wallet tree data (spec 05, section 8).
const PAGE_LEAVES: usize = 4096;
/// Levels below a page root: a page is a subtree of height 12.
const PAGE_LEVELS: usize = 12;
/// One leaf with its note, as a page carries it.
const LEAF_RECORD_BYTES: usize = 32 + NOTE_BYTES;

static mut OUT: Vec<u8> = Vec::new();
static mut ERROR: String = String::new();
/// The page's header chain, from [`ghost_chain_start`] on.
static mut CHAIN: Option<HeaderChain> = None;

/// Reads the fields of one input buffer in order.
struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Input<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.bytes.len() - self.at < n {
            return Err(String::from("the input is too short"));
        }
        let part = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(part)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, String> {
        Ok(self.u32()? as usize)
    }

    fn text(&mut self) -> Result<&'a str, String> {
        let n = self.count()?;
        core::str::from_utf8(self.take(n)?).map_err(|_| String::from("the text is not UTF-8"))
    }

    fn rest(&mut self) -> &'a [u8] {
        let part = &self.bytes[self.at..];
        self.at = self.bytes.len();
        part
    }

    fn records<const N: usize>(&mut self) -> Result<Vec<[u8; N]>, String> {
        let n = self.count()?;
        let n_bytes = n.checked_mul(N).ok_or_else(|| String::from("the input is too long"))?;
        Ok(self
            .take(n_bytes)?
            .chunks_exact(N)
            .map(|chunk| chunk.try_into().expect("N bytes"))
            .collect())
    }

    fn end(&self) -> Result<(), String> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(String::from("the input has bytes left over"))
        }
    }
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned reference.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

fn run(ptr: *const u8, len: usize, call: impl FnOnce(&mut Input) -> Result<Vec<u8>, String>) -> u32 {
    // SAFETY: the caller passes a buffer from `ghost_alloc` of at least `len`
    // bytes.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let mut input = Input { bytes, at: 0 };
    let result = call(&mut input).and_then(|out| input.end().map(|()| out));
    match result {
        Ok(out) => unsafe {
            wipe(&mut OUT);
            OUT = out;
            0
        },
        Err(message) => unsafe {
            ERROR = message;
            1
        },
    }
}

fn params(chain_id: u64, domain: [u8; 32]) -> ChainParams {
    ChainParams {
        chain_id: chain_id.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain,
    }
}

fn amount(word: [u8; 32]) -> Result<Amount, String> {
    if word[..16].iter().any(|&byte| byte != 0) {
        return Err(String::from("an amount is above 2^96 - 1 wei"));
    }
    Amount::new(u128::from_be_bytes(word[16..].try_into().expect("16 bytes"))).map_err(|e| e.to_string())
}

fn key(text: &str) -> Result<PhantomKey, String> {
    PhantomKey::parse(text).map_err(|e| format!("not a valid Phantom Key: {e}"))
}

fn rng(seed: [u8; 32]) -> StdRng {
    StdRng::from_seed(seed)
}

/// `Z_0` to `Z_32`: the empty subtree of each height in the coin tree.
fn zeros() -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut z = [[0u8; 32]; TREE_DEPTH + 1];
    z[0] = empty_leaf();
    for level in 0..TREE_DEPTH {
        z[level + 1] = tree_node(Tree::Coin, level as u8, &z[level], &z[level]);
    }
    z
}

/// The nodes of height `to` above `nodes` of height `from`, filled to the
/// right with empty subtrees.
fn climb(mut nodes: Vec<[u8; 32]>, from: usize, to: usize, z: &[[u8; 32]]) -> Vec<[u8; 32]> {
    for level in from..to {
        nodes = nodes
            .chunks(2)
            .map(|pair| tree_node(Tree::Coin, level as u8, &pair[0], pair.get(1).unwrap_or(&z[level])))
            .collect();
    }
    nodes
}

/// The root of the coin tree holding exactly `leaves` from position 0.
fn tree_root(leaves: &[[u8; 32]], z: &[[u8; 32]]) -> [u8; 32] {
    climb(leaves.to_vec(), 0, TREE_DEPTH, z).first().copied().unwrap_or(z[TREE_DEPTH])
}

/// The 32 siblings of `position` in the tree holding exactly `leaves`.
fn witness(leaves: &[[u8; 32]], position: usize, z: &[[u8; 32]]) -> [[u8; 32]; TREE_DEPTH] {
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut nodes = leaves.to_vec();
    let mut index = position;
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = *nodes.get(index ^ 1).unwrap_or(&z[level]);
        nodes = climb(nodes, level, level + 1, z);
        index >>= 1;
    }
    path
}

/// The roots of the tree after each number of leaves from `from` to `to`,
/// with an incremental frontier.
fn prefix_roots(leaves: &[[u8; 32]], from: usize, to: usize, z: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut branch = [[0u8; 32]; TREE_DEPTH];
    let mut roots = Vec::with_capacity(to.saturating_sub(from) + 1);
    for count in 0..=to {
        if count >= from {
            let mut node = z[0];
            let mut size = count;
            for (level, left) in branch.iter().enumerate() {
                node = if size & 1 == 1 {
                    tree_node(Tree::Coin, level as u8, left, &node)
                } else {
                    tree_node(Tree::Coin, level as u8, &node, &z[level])
                };
                size >>= 1;
            }
            roots.push(node);
        }
        if count == to {
            break;
        }
        let mut node = leaves[count];
        let mut size = count + 1;
        for (level, left) in branch.iter_mut().enumerate() {
            if size & 1 == 1 {
                *left = node;
                break;
            }
            node = tree_node(Tree::Coin, level as u8, left, &node);
            size >>= 1;
        }
    }
    roots
}

/// The envelope of spec 07, section 3, with the proof field of
/// [`PROOF_FIELD_BYTES`].
fn encode_envelope(chain_id: u64, tx: &CoinReveal, proof: &Proof) -> Result<Vec<u8>, String> {
    let bytes = proof.as_bytes();
    if bytes.len() > PROOF_FIELD_BYTES {
        return Err(format!(
            "the proof has {} bytes, more than the {PROOF_FIELD_BYTES} the transaction carries; prove again",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(ENVELOPE_BYTES);
    out.push(TYPE_BYTE);
    out.extend_from_slice(&TX_VERSION);
    out.extend_from_slice(&chain_id.to_be_bytes());
    for field in [&tx.marker[..], &tx.root, &tx.remainder, &tx.recipient, &tx.out, &tx.fee] {
        out.extend_from_slice(field);
    }
    out.extend_from_slice(bytes);
    out.resize(1 + HEAD_BYTES + PROOF_FIELD_BYTES, 0);
    out.extend_from_slice(&tx.remainder_note);
    debug_assert_eq!(out.len(), ENVELOPE_BYTES);
    Ok(out)
}

/// Allocate `len` bytes the caller may write into; freed with
/// [`ghost_free`].
#[unsafe(no_mangle)]
pub extern "C" fn ghost_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Free a buffer from [`ghost_alloc`].
///
/// # Safety
/// `ptr` and `len` must come from one [`ghost_alloc`] call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_free(ptr: *mut u8, len: usize) {
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_out_ptr() -> *const u8 {
    unsafe { OUT.as_ptr() }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_out_len() -> usize {
    unsafe { OUT.len() }
}

/// Overwrite the last result with zeros and drop it.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_clear() {
    unsafe {
        wipe(&mut OUT);
        OUT = Vec::new();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_error_ptr() -> *const u8 {
    unsafe { ERROR.as_ptr() }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_error_len() -> usize {
    unsafe { ERROR.len() }
}

/// A new standard key. Input: a 32-byte seed. Output: the key as twelve
/// groups of four digits separated by spaces.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_new_key(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let mut rng = rng(input.array()?);
        let key = PhantomKey::generate(KeyFormat::Standard, &mut rng);
        Ok(key.format_groups().as_str().as_bytes().to_vec())
    })
}

/// Checks typed digits. Input: the text. Output: the number of groups (12
/// or 24) as one byte.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_check_key(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let text = core::str::from_utf8(input.rest()).map_err(|_| String::from("the text is not UTF-8"))?;
        Ok(vec![key(text)?.key_format().groups() as u8])
    })
}

/// The commit of a key's first coin. Input: chain identifier (8), amount word
/// (32), seed (32), key text. Output: `C` (32), marker (32), then the commit
/// payload: format version (2), `F` and the note of number 0.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_commit(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let chain_id = input.u64()?;
        let value = amount(input.array()?)?;
        let mut rng = rng(input.array()?);
        let key = key(input.text()?)?;
        if value.wei() == 0 {
            return Err(String::from("a commit holds at least 1 wei"));
        }
        let commit = key.coin_commit(0, value, Rule::EMPTY).map_err(|e| e.to_string())?;
        let note = encrypt_note(
            &key.note_key(),
            chain_id,
            &commit.commitment,
            &NoteContents::coin(0, value, Rule::EMPTY),
            &mut rng,
        );
        let mut out = Vec::with_capacity(64 + COMMIT_PAYLOAD_BYTES);
        out.extend_from_slice(commit.commitment.as_bytes());
        out.extend_from_slice(commit.marker.as_bytes());
        out.extend_from_slice(&COMMIT_FORMAT_VERSION);
        out.extend_from_slice(commit.fingerprint.as_bytes());
        out.extend_from_slice(&note);
        Ok(out)
    })
}

/// Restores a key's coins. Input: chain identifier (8), key text, leaf count
/// (4) and that many leaves with their notes (32 + 156 each, from position
/// 0), marker count (4) and that many spent markers (32 each). Output: the
/// number found (4), then per coin: number (8), amount word (32), position
/// (4), `C` (32), marker (32), spent (1).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_restore(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let chain_id = input.u64()?;
        let key = key(input.text()?)?;
        let leaves: Vec<TreeLeaf> = input
            .records::<LEAF_RECORD_BYTES>()?
            .iter()
            .map(|record| TreeLeaf {
                commitment: Commitment::from_bytes(record[..32].try_into().expect("32 bytes")),
                note: record[32..].try_into().expect("note bytes"),
            })
            .collect();
        let spent: Vec<Marker> = input.records::<32>()?.into_iter().map(Marker::from_bytes).collect();
        let restored = restore_coins(&key, chain_id, &leaves, &spent);
        let mut out = Vec::new();
        out.extend_from_slice(&(restored.found.len() as u32).to_be_bytes());
        for coin in &restored.found {
            out.extend_from_slice(&coin.number.to_be_bytes());
            out.extend_from_slice(&coin.amount.to_bytes());
            out.extend_from_slice(&coin.position.to_be_bytes());
            out.extend_from_slice(coin.commitment.as_bytes());
            out.extend_from_slice(coin.marker.as_bytes());
            out.push(u8::from(spent.contains(&coin.marker)));
        }
        Ok(out)
    })
}

/// Checks fetched tree data against a header root (spec 05, section 8,
/// items 1 and 2). Input: the page-root list (count, 32 each), the leaves
/// (count, 32 each, from position 0), the header's coin root (32). Output:
/// nothing.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_tree_check(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let page_roots = input.records::<32>()?;
        let leaves = input.records::<32>()?;
        let header_root: [u8; 32] = input.array()?;
        let z = zeros();
        if leaves.len().div_ceil(PAGE_LEAVES) != page_roots.len() {
            return Err(format!(
                "{} leaves do not fill the {} pages of the page-root list",
                leaves.len(),
                page_roots.len()
            ));
        }
        let computed = climb(leaves, 0, PAGE_LEVELS, &z);
        if let Some(page) = computed.iter().zip(&page_roots).position(|(a, b)| a != b) {
            return Err(format!("page {page} does not match its page root"));
        }
        let root = climb(page_roots, PAGE_LEVELS, TREE_DEPTH, &z).first().copied().unwrap_or(z[TREE_DEPTH]);
        if root != header_root {
            return Err(String::from("the page-root list does not give the header's coin root"));
        }
        Ok(Vec::new())
    })
}

/// The tree root and the page roots of some leaves. Input: the leaves
/// (count, 32 each, from position 0). Output: the root (32), then each page
/// root (32).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_tree_roots(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let leaves = input.records::<32>()?;
        let z = zeros();
        let mut out = tree_root(&leaves, &z).to_vec();
        for page in climb(leaves, 0, PAGE_LEVELS, &z) {
            out.extend_from_slice(&page);
        }
        Ok(out)
    })
}

/// The root after each number of leaves from `from` to `to`. Input: from
/// (4), to (4), the leaves (count, 32 each). Output: `to - from + 1` roots.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_prefix_roots(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let from = input.count()?;
        let to = input.count()?;
        let leaves = input.records::<32>()?;
        if from > to || to > leaves.len() {
            return Err(String::from("the prefix range is outside the leaves"));
        }
        Ok(prefix_roots(&leaves, from, to, &zeros()).concat())
    })
}

/// Whether the tree-state rule of spec 02, section 8 picks the candidate: a
/// root at least SETTLE_DEPTH below the tip, above the leaf's block, and not
/// that block's root. Input: tip (8), the leaf's block height (8) and coin
/// root (32), the candidate's height (8) and coin root (32). Output: 1 if it
/// is a root to prove against, 0 to wait.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_choose_tree_state(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let tip = input.u64()?;
        let leaf_block = HeaderRoot { height: input.u64()?, root: input.array()? };
        let candidate = HeaderRoot { height: input.u64()?, root: input.array()? };
        let chosen = matches!(
            choose_tree_state(&[candidate], tip, &leaf_block, None),
            TreeStateChoice::Settled(header) if header == candidate
        );
        Ok(vec![u8::from(chosen)])
    })
}

/// Builds, proves and checks a partial reveal or a claim to a new key.
///
/// Input: chain identifier (8), domain (32), kind (1: 0 partial, 1 claim,
/// 2 decoy partial, 3 decoy claim), root (32), recipient (20), amount out
/// (32), fee (32), the coin's number (8), amount word (32) and position (4),
/// the leaves of the tree under the root (count, 32 each), seed (32),
/// zero-knowledge randomness (32), the key text, then for a claim the new
/// key's text.
///
/// A decoy does the same work for a key and a new key made from the seed:
/// its coin replaces the leaf at the position (the last one, from the
/// caller), the root is that tree's, and the given root and key texts are
/// not used. The app proves a decoy when it has no coin to prove, so the
/// time before its next request does not depend on whether it found one.
/// A real reveal refused before its proof (its coin not under the root, a
/// key that does not parse, amounts that do not balance) proves a decoy too
/// before it returns the refusal, so neither does it depend on whether the
/// proof could be made.
///
/// Output: transaction hash (32), the spent marker (32), the remainder's `C`
/// (32), number (8) and amount word (32), then the envelope.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_prove(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let chain_id = input.u64()?;
        let params = params(chain_id, input.array()?);
        let (claim, decoy) = match input.u8()? {
            kind @ 0..=3 => (kind & 1 == 1, kind & 2 == 2),
            _ => return Err(String::from("unknown reveal kind")),
        };
        let root = input.array()?;
        let recipient = input.array()?;
        let out = amount(input.array()?)?;
        let mut terms = RevealTerms { root, recipient, fee: amount(input.array()?)? };
        let number = input.u64()?;
        let value = amount(input.array()?)?;
        let position = input.u32()?;
        let mut leaves = input.records::<32>()?;
        let mut rng = rng(input.array()?);
        let zk: [u8; 32] = input.array()?;
        let key_text = input.text()?;
        let new_key_text = if claim { Some(input.text()?) } else { None };

        let z = zeros();
        // A real reveal refused before its proof is made is not refused at
        // once: a decoy is proved, checked and encoded in its place and only
        // then is the refusal returned, so the time this call takes does not
        // depend on whether the reveal could be made.
        let mut refused = None;
        let mut built = None;
        if !decoy {
            match real_coin(key_text, new_key_text, number, value, position, &leaves, &terms, &z) {
                Ok((key, new_key, coin)) => match prove_coin(&params, &key, &coin, new_key.as_ref(), &terms, out, &mut rng, zk) {
                    Ok(made) => built = Some(made),
                    Err(e) => refused = Some(e),
                },
                Err(e) => refused = Some(e),
            }
        }
        let built = match built {
            Some(made) => made,
            None => {
                // In place of a refused reveal, the coin the app gives a
                // decoy: the fee plus 1 wei, and 1 wei out for a partial.
                let (number, value, out) = match refused {
                    Some(_) => {
                        let spare = if claim { 1 } else { 2 };
                        (0, terms.fee.wei().saturating_add(spare), spare - 1)
                    }
                    None => (number, value.wei(), out.wei()),
                };
                let made = Amount::new(value).and_then(|value| Ok((value, Amount::new(out)?))).map_err(|e| e.to_string()).and_then(
                    |(value, out)| {
                        let (key, new_key, coin) =
                            decoy_coin(claim, number, value, position, &mut leaves, &mut terms, &mut rng, &z)?;
                        prove_coin(&params, &key, &coin, new_key.as_ref(), &terms, out, &mut rng, zk)
                    },
                );
                if let Some(refusal) = refused {
                    if let Ok(made) = made {
                        let _ = verify_coin_reveal(&params, &made.reveal, &made.proof);
                        let _ = encode_envelope(chain_id, &made.reveal, &made.proof);
                    }
                    return Err(refusal);
                }
                made?
            }
        };
        verify_coin_reveal(&params, &built.reveal, &built.proof)
            .map_err(|e| format!("the proof did not verify in the worker: {e}"))?;
        let envelope = encode_envelope(chain_id, &built.reveal, &built.proof)?;

        let mut result = Vec::with_capacity(136 + envelope.len());
        result.extend_from_slice(&keccak256(&envelope));
        result.extend_from_slice(&built.reveal.marker);
        result.extend_from_slice(built.remainder.commitment.as_bytes());
        result.extend_from_slice(&built.remainder.number.to_be_bytes());
        result.extend_from_slice(&built.remainder.amount.to_bytes());
        result.extend_from_slice(&envelope);
        Ok(result)
    })
}

/// The key, the new key of a claim and the coin of a real reveal, if the
/// coin is the leaf at `position` of the tree under `terms.root`.
#[allow(clippy::too_many_arguments)]
fn real_coin(
    key_text: &str,
    new_key_text: Option<&str>,
    number: u64,
    value: Amount,
    position: u32,
    leaves: &[[u8; 32]],
    terms: &RevealTerms,
    z: &[[u8; 32]],
) -> Result<(PhantomKey, Option<PhantomKey>, OwnedCoin), String> {
    let key = key(key_text)?;
    let new_key = new_key_text.map(key_for_claim).transpose()?;
    let index = position as usize;
    if index >= leaves.len() {
        return Err(String::from("the coin is not in the tree under the chosen root"));
    }
    let commit = key.coin_commit(number, value, Rule::EMPTY).map_err(|e| e.to_string())?;
    if &leaves[index] != commit.commitment.as_bytes() || tree_root(leaves, z) != terms.root {
        return Err(String::from("the coin is not in the tree under the chosen root"));
    }
    let coin = OwnedCoin { number, amount: value, rule: Rule::EMPTY, position, path: witness(leaves, index, z) };
    Ok((key, new_key, coin))
}

/// A decoy's throwaway key (and new key for a claim) and coin: the coin
/// replaces the leaf at `position` (or the last), and `terms.root` becomes
/// that tree's root.
#[allow(clippy::too_many_arguments)]
fn decoy_coin(
    claim: bool,
    number: u64,
    value: Amount,
    position: u32,
    leaves: &mut Vec<[u8; 32]>,
    terms: &mut RevealTerms,
    rng: &mut StdRng,
    z: &[[u8; 32]],
) -> Result<(PhantomKey, Option<PhantomKey>, OwnedCoin), String> {
    if leaves.is_empty() {
        leaves.push(z[0]);
    }
    let key = PhantomKey::generate(KeyFormat::Standard, rng);
    let new_key = claim.then(|| PhantomKey::generate(KeyFormat::Standard, rng));
    let index = (position as usize).min(leaves.len() - 1);
    let commit = key.coin_commit(number, value, Rule::EMPTY).map_err(|e| e.to_string())?;
    leaves[index] = *commit.commitment.as_bytes();
    terms.root = tree_root(leaves, z);
    let position = index as u32;
    let coin = OwnedCoin { number, amount: value, rule: Rule::EMPTY, position, path: witness(leaves, index, z) };
    Ok((key, new_key, coin))
}

/// A partial reveal of `coin`, or with `new_key` a claim to it.
#[allow(clippy::too_many_arguments)]
fn prove_coin(
    params: &ChainParams,
    key: &PhantomKey,
    coin: &OwnedCoin,
    new_key: Option<&PhantomKey>,
    terms: &RevealTerms,
    out: Amount,
    rng: &mut StdRng,
    zk: [u8; 32],
) -> Result<ghost_client::BuiltReveal, String> {
    match new_key {
        None => partial_reveal(params, key, coin, terms, out, rng, zk),
        Some(new_key) => claim_to_new_key(params, key, coin, new_key, terms, out, rng, zk),
    }
    .map_err(|e| e.to_string())
}

fn key_for_claim(text: &str) -> Result<PhantomKey, String> {
    PhantomKey::parse(text).map_err(|e| format!("the new key is not valid: {e}"))
}

/// Decodes a private transaction envelope and verifies its proof, as a node
/// would at decoding (spec 07, section 3) and step 9 of admission. Input:
/// chain identifier (8), domain (32), the envelope. Output: transaction hash
/// (32), marker (32), root (32), remainder (32), recipient (20), amount out
/// (32), fee (32), note (156).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_decode_envelope(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let chain_id = input.u64()?;
        let params = params(chain_id, input.array()?);
        let envelope = input.rest();
        if envelope.len() != ENVELOPE_BYTES || envelope[0] != TYPE_BYTE {
            return Err(String::from("not a private transaction of the expected size"));
        }
        let mut tx = Input { bytes: &envelope[1..], at: 0 };
        if tx.array::<2>()? != TX_VERSION {
            return Err(String::from("unknown transaction version"));
        }
        if tx.u64()? != chain_id {
            return Err(String::from("wrong chain identifier"));
        }
        let marker = tx.array()?;
        let root = tx.array()?;
        let remainder = tx.array()?;
        let recipient = tx.array()?;
        let out: [u8; 32] = tx.array()?;
        let fee: [u8; 32] = tx.array()?;
        amount(out)?;
        amount(fee)?;
        let proof = Proof::from_bytes(tx.take(PROOF_FIELD_BYTES)?.to_vec());
        let remainder_note = tx.array()?;
        tx.end()?;
        let reveal = CoinReveal { root, marker, remainder, remainder_note, recipient, out, fee, rule: [0; 32] };
        verify_coin_reveal(&params, &reveal, &proof).map_err(|e| format!("the proof does not verify: {e}"))?;
        let mut result = keccak256(envelope).to_vec();
        for field in [&marker[..], &root, &remainder, &recipient, &out, &fee, &remainder_note] {
            result.extend_from_slice(field);
        }
        Ok(result)
    })
}

/// The commitment the node computes from a commit: `C = K(tag, COIN, F, v)`.
/// Input: `F` (32), amount word (32). Output: `C` (32).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_coin_commitment(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let fingerprint = input.array()?;
        let value = amount(input.array()?)?;
        Ok(ghost_proofs::coin_commitment(&fingerprint, &value.to_bytes()).to_vec())
    })
}

/// Keccak-256 of the input, for transaction hashes.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_keccak256(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| Ok(keccak256(input.rest()).to_vec()))
}

/// Constants the JavaScript side checks it agrees with: the envelope length
/// (4) and the commit payload length (4).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_constants(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |_| {
        let mut out = (ENVELOPE_BYTES as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&(COMMIT_PAYLOAD_BYTES as u32).to_be_bytes());
        Ok(out)
    })
}

/// A 256-bit word as a `u128`, refused above 2^128 - 1 (fees and values of an
/// account transaction).
fn wide(word: [u8; 32]) -> Result<u128, String> {
    if word[..16].iter().any(|&byte| byte != 0) {
        return Err(String::from("a fee or value is above 2^128 - 1 wei"));
    }
    Ok(u128::from_be_bytes(word[16..].try_into().expect("16 bytes")))
}

fn word_of(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

fn wallet_seed(text: &str) -> Result<WalletSeed, String> {
    WalletSeed::from_words(text).map_err(|e| format!("not a valid wallet seed: {e}"))
}

/// A new wallet seed (spec 09, section 9). Input: 32 random bytes, used as
/// the seed itself. Output: its 24 words separated by spaces.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_wallet_new(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let mut bytes = input.array::<32>()?;
        let seed = WalletSeed::from_bytes(bytes);
        wipe(&mut bytes);
        Ok(seed.to_words().as_str().as_bytes().to_vec())
    })
}

/// An account of a wallet seed. Input: the words (text), the account index
/// (4). Output: the address (20), then the ML-DSA-44 public key (1,312).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_wallet_account(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let seed = wallet_seed(input.text()?)?;
        let account = seed.account(input.u32()?);
        let mut out = account.address().to_vec();
        out.extend_from_slice(account.public_key());
        Ok(out)
    })
}

/// Signs an account transaction (type 0x52) with account `index` of a wallet
/// seed, hedged. Input: the words (text), index (4), chain identifier (8),
/// genesis hash (32), nonce (8), max priority fee word (32), max fee word
/// (32), gas limit (8), destination kind (1: 1 for an address, 0 for a
/// contract creation) and the address (20, present only for kind 1), value
/// word (32), data (4-byte length and bytes), 32 random bytes. Output: the
/// transaction hash (32), the sender (20), then the envelope.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_wallet_sign(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let seed = wallet_seed(input.text()?)?;
        let account = seed.account(input.u32()?);
        drop(seed);
        let chain_id = input.u64()?;
        let genesis = input.array::<32>()?;
        let nonce = input.u64()?;
        let max_priority_fee_per_gas = wide(input.array()?)?;
        let max_fee_per_gas = wide(input.array()?)?;
        let gas_limit = input.u64()?;
        let to = match input.u8()? {
            0 => None,
            1 => Some(input.array::<20>()?),
            _ => return Err(String::from("unknown destination kind")),
        };
        let value = wide(input.array()?)?;
        let n = input.count()?;
        let data = input.take(n)?.to_vec();
        let mut rng = rng(input.array()?);
        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(String::from("the priority fee is above the fee cap"));
        }
        let tx = AccountTx {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list: Vec::new(),
        };
        let signed = account.sign(&tx, &genesis, &mut rng);
        let mut out = Vec::with_capacity(52 + signed.envelope.len());
        out.extend_from_slice(&signed.hash);
        out.extend_from_slice(&signed.sender);
        out.extend_from_slice(&signed.envelope);
        Ok(out)
    })
}

/// Decodes and checks an account transaction as the node's signer does
/// (for the test's stand-in node). Input: chain identifier (8), genesis hash
/// (32), the envelope. Output: hash (32), sender (20), nonce (8), gas limit
/// (8), max priority fee word (32), max fee word (32), destination kind (1)
/// and address (20, zeros for a creation), value word (32), then the data.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_account_tx_verify(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let chain_id = input.u64()?;
        let genesis = input.array::<32>()?;
        let checked = verify_envelope(input.rest(), chain_id, &genesis).map_err(|e| e.to_string())?;
        let tx = &checked.tx;
        let mut out = Vec::new();
        out.extend_from_slice(&checked.hash);
        out.extend_from_slice(&checked.sender);
        out.extend_from_slice(&tx.nonce.to_be_bytes());
        out.extend_from_slice(&tx.gas_limit.to_be_bytes());
        out.extend_from_slice(&word_of(tx.max_priority_fee_per_gas));
        out.extend_from_slice(&word_of(tx.max_fee_per_gas));
        out.push(u8::from(tx.to.is_some()));
        out.extend_from_slice(&tx.to.unwrap_or([0; 20]));
        out.extend_from_slice(&word_of(tx.value));
        out.extend_from_slice(&tx.data);
        Ok(out)
    })
}

/// Why [`ghost_chain_add`] stopped at a header: its RLP does not hash to the
/// hash the endpoint returned with it.
const REFUSED_HASH: u8 = 1;
/// The header passes every check but is more than the future drift ahead of
/// the page's clock.
const REFUSED_AHEAD: u8 = 2;
/// The header fails the chain's check: it does not decode, its parent is not
/// held, its number or timestamp is wrong, it does not carry the required
/// difficulty, or its seal is not valid.
const REFUSED_CHECK: u8 = 3;

fn chain() -> Result<&'static mut HeaderChain, String> {
    // SAFETY: one thread; see the module documentation.
    unsafe { CHAIN.as_mut() }.ok_or_else(|| String::from("the page holds no header chain yet"))
}

/// The best chain's tip: height (8), hash (32), total work (32).
fn best_of(chain: &HeaderChain, out: &mut Vec<u8>) {
    out.extend_from_slice(&chain.best_height().to_be_bytes());
    out.extend_from_slice(&chain.best_hash());
    out.extend_from_slice(&chain.best_total_work().to_be_bytes());
}

/// Starts the page's header chain, replacing any chain held before. Input:
/// the chain constants (block time, half-life, start difficulty, minimum
/// difficulty, future drift; 8 each), the start's kind (1: 0 genesis, 1 a
/// pinned header), then for genesis the genesis header's RLP; for a pinned
/// header its height (8), the total work up to it (32), the genesis
/// timestamp (8), the key blocks below it (count, then height (8) and hash
/// (32) each) and its RLP. Output: the start's hash (32).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_chain_start(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let params = ChainConstants {
            block_time: input.u64()?,
            half_life: input.u64()?,
            start_difficulty: input.u64()?,
            min_difficulty: input.u64()?,
            future_drift: input.u64()?,
        };
        let started = match input.u8()? {
            0 => HeaderChain::from_genesis(input.rest(), params),
            1 => {
                let height = input.u64()?;
                let total_work = U256::from_be_bytes(&input.array::<32>()?).expect("32 bytes fit");
                let genesis_timestamp = input.u64()?;
                let key_blocks = input
                    .records::<40>()?
                    .into_iter()
                    .map(|record| {
                        let height = u64::from_be_bytes(record[..8].try_into().expect("8 bytes"));
                        (height, record[8..].try_into().expect("32 bytes"))
                    })
                    .collect();
                let header = input.rest().to_vec();
                HeaderChain::from_pinned(PinnedStart { header, height, total_work, genesis_timestamp, key_blocks }, params)
            }
            _ => return Err(String::from("unknown kind of start")),
        };
        let chain = started.map_err(|e| format!("the start header is refused: {e}"))?;
        let hash = chain.start_hash().to_vec();
        // SAFETY: one thread; see the module documentation.
        unsafe { CHAIN = Some(chain) };
        Ok(hash)
    })
}

/// Adds headers to the page's chain, in order, stopping at the first one
/// refused. Input: the page's clock in Unix seconds (8), the number of
/// headers (4), then per header the hash the endpoint returned with it (32)
/// and its RLP (4-byte length and bytes). Output: how many were adopted
/// (4), then 0, or 1 and the refused header's number (8, 0 if it does not
/// decode), why (1: [`REFUSED_HASH`], [`REFUSED_AHEAD`] or
/// [`REFUSED_CHECK`]) and the reason (text); then the best chain's tip
/// (height, hash, total work) and how many headers left the best chain in
/// reorganisations (8).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_chain_add(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let now = input.u64()?;
        let count = input.count()?;
        let chain = chain()?;
        let mut adopted = 0u32;
        let mut refused = None;
        let mut removed = 0u64;
        for _ in 0..count {
            let claimed = input.array::<32>()?;
            let n = input.count()?;
            let header = input.take(n)?;
            let fields = match header_fields(header) {
                Ok(fields) => fields,
                Err(e) => {
                    refused = Some((0, REFUSED_CHECK, ChainError::Header(e).to_string()));
                    break;
                }
            };
            if fields.hash != claimed {
                refused = Some((fields.number, REFUSED_HASH, String::from("the header does not hash to the block hash returned")));
                break;
            }
            match chain.add_header(header, now) {
                Ok(added) => {
                    if let Added::Reorganised { removed: gone, .. } = added {
                        removed += gone;
                    }
                    adopted += 1;
                }
                Err(ChainError::TooFarAhead) => {
                    refused = Some((fields.number, REFUSED_AHEAD, ChainError::TooFarAhead.to_string()));
                    break;
                }
                Err(e) => {
                    refused = Some((fields.number, REFUSED_CHECK, e.to_string()));
                    break;
                }
            }
        }
        if refused.is_some() {
            // The headers after the refused one are not read.
            input.rest();
        }
        let mut out = adopted.to_be_bytes().to_vec();
        match refused {
            None => out.push(0),
            Some((number, why, reason)) => {
                out.push(1);
                out.extend_from_slice(&number.to_be_bytes());
                out.push(why);
                out.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                out.extend_from_slice(reason.as_bytes());
            }
        }
        best_of(chain, &mut out);
        out.extend_from_slice(&removed.to_be_bytes());
        Ok(out)
    })
}

/// The page's chain as seen from one header. Input: a header hash (32), and
/// a height range `from` (8) to `to` (8). Output: the best chain's tip
/// (height, hash, total work), whether the header is held (1), its total
/// work (32, zero if not held), its confirmations on the best chain (8, 0
/// when it is not on it), then the best chain's hash at each height from
/// `from` to `to` (none when `from > to`). Refused when the best chain holds
/// no header at one of those heights.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_chain_view(ptr: *const u8, len: usize) -> u32 {
    run(ptr, len, |input| {
        let hash = input.array::<32>()?;
        let from = input.u64()?;
        let to = input.u64()?;
        let chain = chain()?;
        let mut out = Vec::new();
        best_of(chain, &mut out);
        out.push(u8::from(chain.contains(&hash)));
        out.extend_from_slice(&chain.total_work(&hash).unwrap_or(U256::ZERO).to_be_bytes());
        out.extend_from_slice(&chain.confirmations(&hash).unwrap_or(0).to_be_bytes());
        if from <= to {
            let missing = |height: u64| format!("the best chain holds no header at height {height}");
            chain.best_hash_at(from).ok_or_else(|| missing(from))?;
            // One walk down from `to` by parent hashes, rather than one walk
            // from the tip per height; every header from `from` up is held.
            let mut hashes = vec![chain.best_hash_at(to).ok_or_else(|| missing(to))?];
            for _ in from..to {
                let held = chain.header(hashes.last().expect("one hash")).expect("held");
                hashes.push(header_fields(held).expect("a held header decodes").parent_hash);
            }
            for hash in hashes.iter().rev() {
                out.extend_from_slice(hash);
            }
        }
        Ok(out)
    })
}

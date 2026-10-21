//! The encrypted note, the reveal builders, restore from the digits and the
//! choice of tree state, checked against the proofs crate's own verifier and
//! the vectors of spec 01, section 14 and RFC 8439.
//!
//! Proving is slow, so one test chain is built once and shared: a commit and
//! three partial reveals among other keys' commits, with a small coin tree
//! built by hand (each path is 32 siblings, empty subtrees are zero hashes).

use std::sync::OnceLock;

use ghost_client::note::{
    chacha20poly1305_open, chacha20poly1305_seal, note_associated_data, NOTE_PLAINTEXT_BYTES,
};
use ghost_client::reveal::{ChainParams, CoinReveal, Proof, ProofError, TREE_DEPTH};
use ghost_client::tree_state::SETTLE_DEPTH;
use ghost_client::{
    choose_tree_state, decrypt_note, encrypt_note, full_reveal, partial_reveal,
    restore_coins, Amount, Commitment, ContentFingerprint, Current, DiscardReason, HeaderRoot,
    KeyFormat, Marker, NoteContents, NoteError, OwnedCoin, PhantomKey, RevealError, RevealTerms,
    Rule, TreeLeaf, TreeStateChoice, DATA, NOTE_BYTES,
};
use ghost_proofs::{empty_leaf, tree_node, verify_coin_reveal, Tree, PROTOCOL_VERSION_1};
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};

const SPEC: &str = include_str!("../../docs/spec/01-commitments-and-keys.md");

/// The standard example key of spec 01, section 14. Example only.
const DIGITS: &str = "1111 2222 3333 4444 5555 6666 7777 8888 9999 0000 1234 0417";
/// The example chain identifier of spec 01, section 14.
const CHAIN_ID: u64 = 1234;
const COMMITTED: u128 = 1_000_000_000;
const PAID: u128 = 100_000_000;
const FEE: u128 = 21_000;

fn params() -> ChainParams {
    ChainParams {
        chain_id: CHAIN_ID.to_be_bytes(),
        version: PROTOCOL_VERSION_1,
        domain: [7; 32],
    }
}

fn key() -> PhantomKey {
    PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("the example key parses"))
}

fn amount(wei: u128) -> Amount {
    Amount::new(wei).unwrap()
}

fn zk(rng: &mut StdRng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// The root over `leaves` (position order, the rest empty) and the path of
/// the leaf at `position`.
fn root_and_path(leaves: &[TreeLeaf], position: u32) -> ([u8; 32], [[u8; 32]; TREE_DEPTH]) {
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.commitment.as_bytes()).collect();
    let mut zero = empty_leaf();
    let mut path = [[0u8; 32]; TREE_DEPTH];
    let mut index = position as usize;
    for (depth, sibling) in path.iter_mut().enumerate() {
        *sibling = level.get(index ^ 1).copied().unwrap_or(zero);
        level = level
            .chunks(2)
            .map(|pair| tree_node(Tree::Coin, depth as u8, &pair[0], pair.get(1).unwrap_or(&zero)))
            .collect();
        zero = tree_node(Tree::Coin, depth as u8, &zero, &zero);
        index >>= 1;
    }
    (level[0], path)
}

/// The coin tree and the spent markers as the chain holds them.
#[derive(Clone)]
struct Chain {
    leaves: Vec<TreeLeaf>,
    spent: Vec<Marker>,
}

impl Chain {
    /// Appends a commit of `key`'s number 0 holding `wei`, with its note.
    fn commit(&mut self, key: &PhantomKey, wei: u128, rng: &mut StdRng) -> u32 {
        let commit = key.coin_commit(0, amount(wei), Rule::EMPTY).unwrap();
        let note = encrypt_note(
            &key.note_key(),
            CHAIN_ID,
            &commit.commitment,
            &NoteContents::coin(0, amount(wei), Rule::EMPTY),
            rng,
        );
        self.push(commit.commitment, note)
    }

    fn push(&mut self, commitment: Commitment, note: [u8; NOTE_BYTES]) -> u32 {
        self.leaves.push(TreeLeaf { commitment, note });
        (self.leaves.len() - 1) as u32
    }

    /// Includes a reveal: its marker is spent, its remainder appended.
    fn include(&mut self, reveal: &CoinReveal) -> u32 {
        self.spent.push(Marker::from_bytes(reveal.marker));
        self.push(Commitment::from_bytes(reveal.remainder), reveal.remainder_note)
    }

    fn owned(&self, number: u64, wei: u128, position: u32) -> (OwnedCoin, [u8; 32]) {
        let (root, path) = root_and_path(&self.leaves, position);
        let coin = OwnedCoin {
            number,
            amount: amount(wei),
            rule: Rule::EMPTY,
            position,
            path,
        };
        (coin, root)
    }
}

fn terms(root: [u8; 32]) -> RevealTerms {
    RevealTerms {
        root,
        recipient: [5; 20],
        fee: amount(FEE),
    }
}

/// The shared test chain after a commit and three partial reveals.
struct Scenario {
    chain: Chain,
    /// The first partial reveal, of number 0, with its proof.
    first: (CoinReveal, Proof),
    /// Where each of the key's commitments 0 to 3 sits.
    positions: [u32; 4],
    /// The amount of each of the key's commitments 0 to 3.
    amounts: [u128; 4],
    /// Another key with a commit on the chain.
    other_digits: String,
    other_position: u32,
}

fn scenario() -> &'static Scenario {
    static SCENARIO: OnceLock<Scenario> = OnceLock::new();
    SCENARIO.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x5eed);
        let key = key();
        let others: Vec<PhantomKey> = (0..4)
            .map(|_| PhantomKey::generate(KeyFormat::Standard, &mut rng))
            .collect();
        let mut chain = Chain {
            leaves: Vec::new(),
            spent: Vec::new(),
        };
        let other_position = chain.commit(&others[0], 5_000, &mut rng);
        let mut positions = [0u32; 4];
        let mut amounts = [0u128; 4];
        positions[0] = chain.commit(&key, COMMITTED, &mut rng);
        amounts[0] = COMMITTED;
        let mut first = None;
        for number in 0..3u64 {
            chain.commit(&others[number as usize + 1], 7_000 + u128::from(number), &mut rng);
            let i = number as usize;
            let (coin, root) = chain.owned(number, amounts[i], positions[i]);
            let zk_randomness = zk(&mut rng);
            let built = partial_reveal(
                &params(),
                &key,
                &coin,
                &terms(root),
                amount(PAID),
                &mut rng,
                zk_randomness,
            )
            .unwrap();
            assert_eq!(built.remainder.number, number + 1);
            amounts[i + 1] = amounts[i] - PAID - FEE;
            assert_eq!(built.remainder.amount.wei(), amounts[i + 1]);
            positions[i + 1] = chain.include(&built.reveal);
            if first.is_none() {
                first = Some((built.reveal, built.proof));
            }
        }
        Scenario {
            chain,
            first: first.unwrap(),
            positions,
            amounts,
            other_digits: others[0].format_groups().as_str().to_owned(),
            other_position,
        }
    })
}

#[test]
fn partial_reveal_proof_verifies_with_proofs_verifier() {
    let s = scenario();
    let key = key();
    let (reveal, proof) = &s.first;
    assert_eq!(verify_coin_reveal(&params(), reveal, proof), Ok(()));

    // It spends number 0 and creates number 1 under the same key.
    let spent = key.coin_commit(0, amount(COMMITTED), Rule::EMPTY).unwrap();
    let remainder = key.coin_commit(1, amount(s.amounts[1]), Rule::EMPTY).unwrap();
    assert_eq!(&reveal.marker, spent.marker.as_bytes());
    assert_eq!(&reveal.remainder, remainder.commitment.as_bytes());
    assert_ne!(remainder.marker, spent.marker, "a fresh blinding for the remainder");
    assert_eq!(reveal.out, amount(PAID).to_bytes());
    assert_eq!(reveal.fee, amount(FEE).to_bytes());

    // Its note is the remainder's, under the same key, for the new leaf.
    let note = decrypt_note(&key.note_key(), CHAIN_ID, &remainder.commitment, &reveal.remainder_note)
        .unwrap();
    assert_eq!(note.number, 1);
    assert_eq!(note.amount.wei(), s.amounts[1]);

    // The verifier rejects any changed public field or other chain constants.
    let mut changed = reveal.clone();
    changed.out = amount(PAID + 1).to_bytes();
    assert!(verify_coin_reveal(&params(), &changed, proof).is_err());
    let mut changed = reveal.clone();
    changed.remainder_note[0] ^= 1;
    assert!(verify_coin_reveal(&params(), &changed, proof).is_err());
    let mut other_chain = params();
    other_chain.chain_id = (CHAIN_ID + 1).to_be_bytes();
    assert!(verify_coin_reveal(&other_chain, reveal, proof).is_err());

    // What the proofs crate refuses, the builder refuses, before proving.
    let (coin, root) = s.chain.owned(3, s.amounts[3], s.positions[3]);
    let mut rng = StdRng::seed_from_u64(1);
    let too_much = partial_reveal(&params(), &key, &coin, &terms(root), amount(s.amounts[3]), &mut rng, [0; 32]);
    assert_eq!(too_much.err(), Some(RevealError::Proof(ProofError::ConservationFails)));
    let wrong_root = partial_reveal(&params(), &key, &coin, &terms([9; 32]), amount(PAID), &mut rng, [0; 32]);
    assert_eq!(wrong_root.err(), Some(RevealError::Proof(ProofError::NotInTree)));
    let wrong_number = OwnedCoin { number: 2, ..coin };
    let refused = partial_reveal(&params(), &key, &wrong_number, &terms(root), amount(PAID), &mut rng, [0; 32]);
    assert_eq!(refused.err(), Some(RevealError::Proof(ProofError::NotInTree)));
    let (coin, root) = s.chain.owned(3, s.amounts[3], s.positions[3]);
    let ruled = OwnedCoin { rule: Rule::from_bytes([1; 32]), ..coin };
    let refused = partial_reveal(&params(), &key, &ruled, &terms(root), amount(PAID), &mut rng, [0; 32]);
    assert_eq!(refused.err(), Some(RevealError::Proof(ProofError::RuleNotEmpty)));
}

#[test]
fn full_reveal_proof_verifies() {
    let s = scenario();
    let key = key();
    let mut chain = s.chain.clone();
    let (coin, root) = chain.owned(3, s.amounts[3], s.positions[3]);
    let mut rng = StdRng::seed_from_u64(2);
    let zk_randomness = zk(&mut rng);
    let built = full_reveal(&params(), &key, &coin, &terms(root), &mut rng, zk_randomness).unwrap();
    assert_eq!(verify_coin_reveal(&params(), &built.reveal, &built.proof), Ok(()));
    assert_eq!(built.reveal.out, amount(s.amounts[3] - FEE).to_bytes());

    // Still a remainder commitment, of amount zero, number 4, with its note.
    let zero = key.coin_commit(4, amount(0), Rule::EMPTY).unwrap();
    assert_eq!(built.remainder.number, 4);
    assert_eq!(built.remainder.amount.wei(), 0);
    assert_eq!(&built.reveal.remainder, zero.commitment.as_bytes());
    let note = decrypt_note(&key.note_key(), CHAIN_ID, &zero.commitment, &built.reveal.remainder_note)
        .unwrap();
    assert_eq!((note.number, note.amount.wei()), (4, 0));

    // Restore then finds the zero remainder as the current coin.
    let position = chain.include(&built.reveal);
    let restored = restore_coins(&key, CHAIN_ID, &chain.leaves, &chain.spent);
    let Current::One(current) = restored.current else {
        panic!("one unspent commitment after a full reveal");
    };
    assert_eq!((current.number, current.amount.wei(), current.position), (4, 0, position));

    // A fee above the amount is refused before proving.
    let (coin, root) = s.chain.owned(3, s.amounts[3], s.positions[3]);
    let terms = RevealTerms { fee: amount(s.amounts[3] + 1), ..terms(root) };
    let refused = full_reveal(&params(), &key, &coin, &terms, &mut rng, [0; 32]);
    assert_eq!(refused.err(), Some(RevealError::Proof(ProofError::ConservationFails)));
}

#[test]
fn claim_to_new_key() {
    let s = scenario();
    let key = key();
    let mut rng = StdRng::seed_from_u64(3);
    let new_key = PhantomKey::generate(KeyFormat::Standard, &mut rng);
    let mut chain = s.chain.clone();
    let (coin, root) = chain.owned(3, s.amounts[3], s.positions[3]);
    let zk_randomness = zk(&mut rng);
    let built = ghost_client::claim_to_new_key(
        &params(),
        &key,
        &coin,
        &new_key,
        &terms(root),
        amount(0),
        &mut rng,
        zk_randomness,
    )
    .unwrap();
    assert_eq!(verify_coin_reveal(&params(), &built.reveal, &built.proof), Ok(()));

    // The remainder is number 0 of the new key, holding everything but the fee.
    let left = s.amounts[3] - FEE;
    let expected = new_key.coin_commit(0, amount(left), Rule::EMPTY).unwrap();
    assert_eq!(built.remainder.number, 0);
    assert_eq!(built.remainder.amount.wei(), left);
    assert_eq!(&built.reveal.remainder, expected.commitment.as_bytes());
    assert_eq!(&built.reveal.marker, key.coin_commit(3, amount(s.amounts[3]), Rule::EMPTY).unwrap().marker.as_bytes());

    // Its note decrypts under the new key only.
    let leaf = expected.commitment;
    let note = decrypt_note(&new_key.note_key(), CHAIN_ID, &leaf, &built.reveal.remainder_note).unwrap();
    assert_eq!((note.number, note.amount.wei()), (0, left));
    assert_eq!(
        decrypt_note(&key.note_key(), CHAIN_ID, &leaf, &built.reveal.remainder_note).err(),
        Some(NoteError::Unauthentic)
    );

    // Once included, the old key has nothing unspent and the new key has it.
    let position = chain.include(&built.reveal);
    assert!(matches!(restore_coins(&key, CHAIN_ID, &chain.leaves, &chain.spent).current, Current::None));
    let fresh = PhantomKey::parse(new_key.format_groups().as_str()).unwrap_or_else(|_| panic!("parses"));
    let Current::One(found) = restore_coins(&fresh, CHAIN_ID, &chain.leaves, &chain.spent).current else {
        panic!("the new key holds the claimed coin");
    };
    assert_eq!((found.number, found.amount.wei(), found.position), (0, left, position));
    assert_eq!(found.next_number(), Some(1));

    // A claim to the key that holds the coin is refused.
    let same = PhantomKey::parse(DIGITS).unwrap_or_else(|_| panic!("parses"));
    let (coin, root) = s.chain.owned(3, s.amounts[3], s.positions[3]);
    let refused = ghost_client::claim_to_new_key(&params(), &key, &coin, &same, &terms(root), amount(0), &mut rng, [0; 32]);
    assert_eq!(refused.err(), Some(RevealError::ClaimToSameKey));
}

#[test]
fn restore_from_digits_after_three_partial_reveals_finds_current_remainder() {
    let s = scenario();
    // A fresh instance: only the digits, as the user types them, and the
    // chain's data, all of it.
    let typed = DIGITS.replace(' ', "-");
    let key = PhantomKey::parse(&typed).unwrap_or_else(|_| panic!("the typed key parses"));
    let restored = restore_coins(&key, CHAIN_ID, &s.chain.leaves, &s.chain.spent);

    let Current::One(current) = restored.current else {
        panic!("exactly one unspent commitment");
    };
    assert_eq!(current.number, 3);
    assert_eq!(current.amount.wei(), COMMITTED - 3 * (PAID + FEE));
    assert_eq!(current.position, s.positions[3]);
    assert_eq!(&current.commitment, &s.chain.leaves[s.positions[3] as usize].commitment);
    assert_eq!(current.next_number(), Some(4));

    // Every commitment of the key was found, at its own position.
    let found: Vec<(u64, u128, u32)> = restored
        .found
        .iter()
        .map(|coin| (coin.number, coin.amount.wei(), coin.position))
        .collect();
    let expected: Vec<(u64, u128, u32)> = (0..4).map(|i| (i as u64, s.amounts[i], s.positions[i])).collect();
    assert_eq!(found, expected);
    assert!(restored.discarded.is_empty());

    // The found coin is what a reveal takes, with the wallet's own path.
    let (_, path) = root_and_path(&s.chain.leaves, current.position);
    let owned = current.owned(path);
    assert_eq!((owned.number, owned.amount.wei(), owned.position), (3, s.amounts[3], s.positions[3]));

    // Without spent markers every commitment looks unspent; with only some,
    // so do the rest.
    let Current::Several(all) = restore_coins(&key, CHAIN_ID, &s.chain.leaves, &[]).current else {
        panic!("all four look unspent without markers");
    };
    assert_eq!(all.len(), 4);
    let Current::Several(two) = restore_coins(&key, CHAIN_ID, &s.chain.leaves, &s.chain.spent[..2]).current
    else {
        panic!("numbers 2 and 3 look unspent");
    };
    assert_eq!(two.iter().map(|coin| coin.number).collect::<Vec<_>>(), vec![2, 3]);

    // A wrong chain identifier finds nothing.
    let other_chain = restore_coins(&key, CHAIN_ID + 1, &s.chain.leaves, &s.chain.spent);
    assert!(other_chain.found.is_empty());
    assert!(matches!(other_chain.current, Current::None));
}

#[test]
fn restore_ignores_notes_for_other_keys() {
    let s = scenario();
    let key = key();

    // The other keys' notes are passed over without a report.
    let restored = restore_coins(&key, CHAIN_ID, &s.chain.leaves, &s.chain.spent);
    assert_eq!(restored.found.len(), 4);
    assert!(restored.found.iter().all(|coin| s.positions.contains(&coin.position)));
    assert!(restored.discarded.is_empty());

    // Another key finds its own commit and none of ours.
    let other = PhantomKey::parse(&s.other_digits).unwrap_or_else(|_| panic!("parses"));
    let theirs = restore_coins(&other, CHAIN_ID, &s.chain.leaves, &s.chain.spent);
    let Current::One(coin) = theirs.current else {
        panic!("the other key has its commit");
    };
    assert_eq!((coin.number, coin.amount.wei(), coin.position), (0, 5_000, s.other_position));
    assert_eq!(theirs.found.len(), 1);

    // Our current note's bytes copied to another leaf do not decrypt there:
    // passed over, and the real one is still found.
    let current = s.positions[3] as usize;
    let elsewhere = s.other_position as usize;
    let mut copied = s.chain.leaves.clone();
    copied[elsewhere].note = copied[current].note;
    let restored = restore_coins(&key, CHAIN_ID, &copied, &s.chain.spent);
    assert!(restored.discarded.is_empty());
    assert!(matches!(restored.current, Current::One(coin) if coin.position == s.positions[3]));

    // Our current note's contents sealed for another leaf, as a writer that
    // holds the key could do: it decrypts there, but the commitment it opens
    // is not that leaf, so it is reported and discarded.
    let mut moved = s.chain.leaves.clone();
    let mut rng = StdRng::seed_from_u64(4);
    let contents = NoteContents::coin(3, amount(s.amounts[3]), Rule::EMPTY);
    moved[elsewhere].note = encrypt_note(&key.note_key(), CHAIN_ID, &moved[elsewhere].commitment, &contents, &mut rng);
    let restored = restore_coins(&key, CHAIN_ID, &moved, &s.chain.spent);
    assert_eq!(restored.discarded.len(), 1);
    assert_eq!(restored.discarded[0].position, s.other_position);
    assert_eq!(restored.discarded[0].reason, DiscardReason::LeafMismatch);
    assert_eq!(restored.found.len(), 4);
    let Current::One(coin) = restored.current else {
        panic!("the moved note is not a second coin");
    };
    assert_eq!((coin.number, coin.position), (3, s.positions[3]));

    // A note of the key with a data type tag in the coin tree is reported too.
    let mut data = s.chain.leaves.clone();
    let contents = NoteContents { type_tag: DATA, ..contents };
    data[elsewhere].note = encrypt_note(&key.note_key(), CHAIN_ID, &data[elsewhere].commitment, &contents, &mut rng);
    let restored = restore_coins(&key, CHAIN_ID, &data, &s.chain.spent);
    assert_eq!(restored.discarded.len(), 1);
    assert_eq!(restored.discarded[0].reason, DiscardReason::NotACoin);
}

#[test]
fn tree_state_choice_never_picks_wallets_own_commit_block() {
    let root = |byte: u8| [byte; 32];
    let leaf_block = HeaderRoot { height: 100, root: root(0xaa) };
    // Heights 101 and 102 carry the leaf block's root: no coin leaf was added
    // in between. 64 and 96 are before the leaf.
    let candidates = [
        HeaderRoot { height: 64, root: root(1) },
        HeaderRoot { height: 96, root: root(2) },
        HeaderRoot { height: 100, root: root(0xaa) },
        HeaderRoot { height: 101, root: root(0xaa) },
        HeaderRoot { height: 102, root: root(0xaa) },
        HeaderRoot { height: 103, root: root(3) },
        HeaderRoot { height: 150, root: root(4) },
    ];
    let pick = |tip: u64| choose_tree_state(&candidates, tip, &leaf_block, None);

    // Only the leaf block's root is settled: wait.
    assert_eq!(pick(100), TreeStateChoice::Wait);
    assert_eq!(pick(104), TreeStateChoice::Wait);
    // 103 is settled at tip 105; 150 is not until tip 152.
    assert_eq!(pick(105), TreeStateChoice::Settled(candidates[5]));
    assert_eq!(pick(151), TreeStateChoice::Settled(candidates[5]));
    assert_eq!(pick(152), TreeStateChoice::Settled(candidates[6]));
    assert_eq!(pick(1), TreeStateChoice::Wait);

    // A later height that carries the leaf's root is never used, however deep.
    assert_eq!(choose_tree_state(&candidates[..5], 1_000, &leaf_block, None), TreeStateChoice::Wait);

    // Over many chains, the choice is never the leaf block's root, always a
    // settled later root, and always the newest one.
    let eligible = |h: &HeaderRoot, leaf: &HeaderRoot, tip: u64| {
        h.height > leaf.height && h.height + SETTLE_DEPTH <= tip && h.root != leaf.root
    };
    let mut rng = StdRng::seed_from_u64(6);
    for _ in 0..2_000 {
        let h_leaf = rng.random_range(0..400u64);
        let leaf_root = root(rng.random_range(0..4u8));
        let leaf = HeaderRoot { height: h_leaf, root: leaf_root };
        let headers: Vec<HeaderRoot> = (0..500u64)
            .filter_map(|height| {
                let kept = rng.random_range(0..3u8) != 0;
                let header = HeaderRoot { height, root: root(rng.random_range(0..4u8)) };
                kept.then_some(header)
            })
            .collect();
        let tip = rng.random_range(0..520u64);
        match choose_tree_state(&headers, tip, &leaf, None) {
            TreeStateChoice::Settled(chosen) => {
                assert_ne!(chosen.root, leaf.root);
                assert!(eligible(&chosen, &leaf, tip));
                assert!(!headers.iter().any(|h| h.height > chosen.height && eligible(h, &leaf, tip)));
            }
            TreeStateChoice::Wait => assert!(!headers.iter().any(|h| eligible(h, &leaf, tip))),
            TreeStateChoice::FinalRoot(_) => panic!("no final root was given"),
        }
    }

    // The full-tree exception is used only when given, and only once settled.
    let final_root = HeaderRoot { height: 100, root: root(0xaa) };
    assert_eq!(
        choose_tree_state(&candidates, 300, &leaf_block, Some(&final_root)),
        TreeStateChoice::FinalRoot(final_root)
    );
    assert_eq!(
        choose_tree_state(&candidates, 102, &leaf_block, Some(&final_root)),
        TreeStateChoice::FinalRoot(final_root)
    );
    assert_eq!(choose_tree_state(&candidates, 101, &leaf_block, Some(&final_root)), TreeStateChoice::Wait);
    let earlier_tree = HeaderRoot { height: 99, root: root(1) };
    assert_eq!(choose_tree_state(&candidates, 300, &leaf_block, Some(&earlier_tree)), TreeStateChoice::Wait);
}

/// The coin roots of blocks 0 to `tip` of a chain on which block `n` holds
/// `count(n)` leaves; a tree of `c` leaves has a root of bytes all `c`.
fn chain_roots(tip: u64, count: impl Fn(u64) -> u8) -> Vec<HeaderRoot> {
    (0..=tip).map(|height| HeaderRoot { height, root: [count(height); 32] }).collect()
}

#[test]
fn early_reveal_two_blocks_after_a_later_commit() {
    assert_eq!(SETTLE_DEPTH, 2);
    // The wallet's coin is leaf 2, added at block 50; a stranger commits
    // leaf 3 at block 51.
    let count = |n: u64| -> u8 {
        if n >= 51 {
            4
        } else if n >= 50 {
            3
        } else {
            2
        }
    };
    let leaf_block = HeaderRoot { height: 50, root: [3; 32] };
    // Block 51 is not settled until tip 53.
    for tip in 50..53 {
        let headers = chain_roots(tip, count);
        assert_eq!(choose_tree_state(&headers, tip, &leaf_block, None), TreeStateChoice::Wait, "tip {tip}");
    }
    // At tip 53 the coin can be revealed against block 51's root, two blocks
    // after the later commit: no epoch block, no 12-block depth.
    let headers = chain_roots(53, count);
    assert_eq!(
        choose_tree_state(&headers, 53, &leaf_block, None),
        TreeStateChoice::Settled(HeaderRoot { height: 51, root: [4; 32] })
    );
    // Later, always the newest settled root.
    let headers = chain_roots(80, count);
    assert_eq!(
        choose_tree_state(&headers, 80, &leaf_block, None),
        TreeStateChoice::Settled(HeaderRoot { height: 78, root: [4; 32] })
    );
}

#[test]
fn early_reveal_waits_without_a_later_leaf_and_never_picks_its_own_block_root() {
    // The wallet's coin is the last leaf, added at block 50 after an earlier
    // leaf of the same block; nobody commits after it.
    let count = |n: u64| -> u8 { if n >= 50 { 3 } else { 1 } };
    let leaf_block = HeaderRoot { height: 50, root: [3; 32] };
    for tip in [50, 52, 53, 100, 1_000] {
        let headers = chain_roots(tip, count);
        assert_eq!(choose_tree_state(&headers, tip, &leaf_block, None), TreeStateChoice::Wait, "tip {tip}");
    }
    // The leaf block itself, offered as a candidate, is never taken either.
    assert_eq!(choose_tree_state(&[leaf_block], 1_000, &leaf_block, None), TreeStateChoice::Wait);
    // A stranger's commit at block 200 opens it two blocks later.
    let later = |n: u64| -> u8 { if n >= 200 { 4 } else { count(n) } };
    assert_eq!(choose_tree_state(&chain_roots(201, later), 201, &leaf_block, None), TreeStateChoice::Wait);
    match choose_tree_state(&chain_roots(202, later), 202, &leaf_block, None) {
        TreeStateChoice::Settled(chosen) => {
            assert_eq!(chosen.height, 200);
            assert_ne!(chosen.root, leaf_block.root);
        }
        other => panic!("expected a settled root, got {other:?}"),
    }
}

#[test]
fn wrong_note_key_rejected() {
    let mut rng = StdRng::seed_from_u64(7);
    let key = key();
    let other = PhantomKey::generate(KeyFormat::Standard, &mut rng);
    let commit = key.coin_commit(2, amount(700), Rule::EMPTY).unwrap();
    let leaf = commit.commitment;
    let contents = NoteContents::coin(2, amount(700), Rule::EMPTY);
    let note = encrypt_note(&key.note_key(), CHAIN_ID, &leaf, &contents, &mut rng);

    let read = decrypt_note(&key.note_key(), CHAIN_ID, &leaf, &note).unwrap();
    assert!(read == contents);
    assert_eq!(decrypt_note(&other.note_key(), CHAIN_ID, &leaf, &note).err(), Some(NoteError::Unauthentic));
    assert_eq!(decrypt_note(&key.note_key(), CHAIN_ID + 1, &leaf, &note).err(), Some(NoteError::Unauthentic));
    let other_leaf = Commitment::from_bytes([3; 32]);
    assert_eq!(decrypt_note(&key.note_key(), CHAIN_ID, &other_leaf, &note).err(), Some(NoteError::Unauthentic));
    for byte in [0, 11, 12, 100, NOTE_BYTES - 1] {
        let mut changed = note;
        changed[byte] ^= 0x01;
        assert_eq!(decrypt_note(&key.note_key(), CHAIN_ID, &leaf, &changed).err(), Some(NoteError::Unauthentic));
    }

    // Two notes of the same contents differ: a fresh nonce each time.
    assert_ne!(note, encrypt_note(&key.note_key(), CHAIN_ID, &leaf, &contents, &mut rng));

    // A note that authenticates but is not one version 1 reads is rejected.
    let seal = |plaintext: [u8; NOTE_PLAINTEXT_BYTES]| {
        let mut note = [0u8; NOTE_BYTES];
        note[..12].copy_from_slice(&[1; 12]);
        note[12..140].copy_from_slice(&plaintext);
        let tag = chacha20poly1305_seal(
            key.note_key().as_bytes(),
            &[1; 12],
            &note_associated_data(CHAIN_ID, &leaf),
            &mut note[12..140],
        );
        note[140..].copy_from_slice(&tag);
        decrypt_note(&key.note_key(), CHAIN_ID, &leaf, &note).err()
    };
    let good = contents.to_plaintext();
    assert_eq!(seal(good), None);
    // Byte 0 or 2 set to 0x02 makes a version 2 note with a version 1 type
    // tag, or the other way round: the two must agree.
    let cases: [(usize, u8, NoteError); 8] = [
        (0, 0x03, NoteError::UnknownVersion),
        (0, 0x02, NoteError::VersionMismatch),
        (1, 0x02, NoteError::UnknownScheme),
        (2, 0x02, NoteError::VersionMismatch),
        (2, 0x03, NoteError::UnknownType),
        (3, 0x03, NoteError::UnknownType),
        (12, 0x01, NoteError::AmountTooLarge),
        (127, 0x01, NoteError::NonZeroPadding),
    ];
    for (offset, value, error) in cases {
        let mut bad = good;
        bad[offset] = value;
        assert_eq!(seal(bad), Some(error), "byte {offset}");
    }
    let mut padded = good;
    padded[116] = 0x80;
    assert_eq!(seal(padded), Some(NoteError::NonZeroPadding));
}

/// One `field = value` line of a `[name]` block of spec 01, section 14.
fn spec_field(block: &str, field: &str) -> String {
    let (_, rest) = SPEC.split_once(&format!("[{block}]\n")).expect("the block exists");
    rest.lines()
        .take_while(|line| !line.is_empty() && !line.starts_with("```"))
        .find_map(|line| line.strip_prefix(&format!("{field} = ")))
        .unwrap_or_else(|| panic!("{block} has {field}"))
        .to_owned()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn note_plaintext_matches_spec_vectors() {
    let leaf = Commitment::from_bytes(hex(&spec_field("note-coin-remainder", "leaf")).try_into().unwrap());
    let coin = NoteContents::coin(1, amount(700_000_000_000_000_000), Rule::EMPTY);
    assert_eq!(coin.to_plaintext().to_vec(), hex(&spec_field("note-coin-remainder", "plaintext")));
    assert_eq!(
        note_associated_data(CHAIN_ID, &leaf).to_vec(),
        hex(&spec_field("note-coin-remainder", "associated-data"))
    );
    // The vector's leaf is the commitment of [coin-remainder].
    assert_eq!(key().coin_commit(1, amount(700_000_000_000_000_000), Rule::EMPTY).unwrap().commitment, leaf);

    let data_leaf = Commitment::from_bytes(hex(&spec_field("note-data-commit", "leaf")).try_into().unwrap());
    let data = NoteContents {
        type_tag: DATA,
        number: 0,
        amount: amount(0),
        content_fingerprint: ContentFingerprint::from_bytes(
            hex(&spec_field("note-data-commit", "content-fingerprint")).try_into().unwrap(),
        ),
        content_length: 18,
        rule: Rule::EMPTY,
        salt: None,
    };
    let plaintext = data.to_plaintext();
    assert_eq!(plaintext.to_vec(), hex(&spec_field("note-data-commit", "plaintext")));
    assert_eq!(
        note_associated_data(CHAIN_ID, &data_leaf).to_vec(),
        hex(&spec_field("note-data-commit", "associated-data"))
    );
    assert!(NoteContents::from_plaintext(&plaintext).unwrap() == data);
}

#[test]
fn aead_matches_rfc8439_vector() {
    // RFC 8439, section 2.8.2.
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let associated_data = hex("50515253c0c1c2c3c4c5c6c7");
    let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
    let ciphertext = hex(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2",
        "a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b",
        "1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58",
        "fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b",
        "6116",
    ));
    let tag: [u8; 16] = hex("1ae10b594f09e26a7e902ecbd0600691").try_into().unwrap();

    let mut buffer = plaintext.to_vec();
    let sealed = chacha20poly1305_seal(&key, &nonce, &associated_data, &mut buffer);
    assert_eq!(buffer, ciphertext);
    assert_eq!(sealed, tag);

    assert_eq!(chacha20poly1305_open(&key, &nonce, &associated_data, &mut buffer, &tag), Ok(()));
    assert_eq!(buffer, plaintext.to_vec());

    let mut changed = ciphertext.clone();
    changed[0] ^= 1;
    assert_eq!(
        chacha20poly1305_open(&key, &nonce, &associated_data, &mut changed, &tag),
        Err(NoteError::Unauthentic)
    );
    let mut buffer = ciphertext.clone();
    assert_eq!(
        chacha20poly1305_open(&key, &nonce, &associated_data[1..], &mut buffer, &tag),
        Err(NoteError::Unauthentic)
    );
}

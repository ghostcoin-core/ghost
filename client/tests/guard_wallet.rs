//! Ghost Guard in the wallet (spec 10, sections 3.1, 12 and 13): commit,
//! normal spend with the override, transfer, words-only spend, cancel,
//! release and restore, each checked against the proofs crate's own
//! verifiers, and the refusals and warnings around them.
//!
//! Proving is slow, so one test chain is built once and shared: an owner's
//! Guard commit, a normal spend that rotates the remainder's rule, a transfer
//! to a receiver's own Guard rule, the receiver's words-only spend, and a
//! cancel by the receiver's stop card to a new key. The coin tree is small
//! and built by hand (each path is 32 siblings, empty subtrees are zero
//! hashes). The Guard address and code hash are test values: the real ones
//! are not final.

use std::convert::Infallible;
use std::sync::OnceLock;

use ghost_client::guard::{
    action_cost, guard_params_hash, hand_over_warning, instr_for, slot_cost_warning, ACTION_PAYLOAD_BYTES,
    ACTION_TX_TYPE, CANCEL_CALLDATA_BYTES, G_ACTION, RELEASE_CALLDATA_BYTES, SLOT_WORDS,
};
use ghost_client::reveal::{SaltedCoinOpening, TREE_DEPTH};
use ghost_client::{
    guard_cancel, guard_commit, guard_release, guard_spend, guard_transfer, partial_reveal, restore_coins,
    restore_guard_coins, words_only_spend, Amount, BuiltCancel, CancelTerms, ChainHead, Commitment, Current,
    EscrowSlot, GuardChain, GuardError, GuardPolicy, GuardRule, GuardSecret, GuardWarning, KeyFormat, Marker,
    NoteContents, OwnedCoin, PhantomKey, RemainderRule, RevealTerms, Rule, Salt, StopRoot, TreeLeaf, TreeRoom,
    WalletSeed, HOLD_BLOCKS, HOLD_SECONDS, NOTE_BYTES,
};
use ghost_client::guard::{CoinRevealV2, KnowAction, PolicyReveal};
use ghost_client::reveal::Proof;
use ghost_client::{encrypt_note, Capsule};
use ghost_proofs::{
    action_calldata_hash, coin_commitment_v2, empty_leaf, policy_action_tag, prove_coin_reveal_v2, tree_node,
    verify_coin_reveal_v2, verify_know_action, verify_policy_reveal, CoinRevealV2Request, InputRule, ProofError,
    SaltedCoinRemainder, Tree,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const CHAIN_ID: u64 = 1234;
const DOMAIN: [u8; 32] = [7; 32];
/// Test values for the Guard address and code hash.
const GUARD_TEST_ADDRESS: [u8; 20] = [0x47; 20];
const GUARD_TEST_CODEHASH: [u8; 32] = [0x5a; 32];
const CANCEL_SELECTOR: [u8; 4] = [0xca, 0x11, 0xce, 0x1d];
const RELEASE_SELECTOR: [u8; 4] = [0x7e, 0x1e, 0xa5, 0xe0];
const COMMITTED: u128 = 1_000_000_000_000;
const PAID: u128 = 100_000_000;
const FEE: u128 = 21_000;
/// The base fee of the test chain and the action cost at it.
const BASE_FEE: u128 = 3;
const SLOT_HEIGHT: u64 = 5_000;
const SLOT_TIME: u64 = 1_700_000_000;
const ROOM: TreeRoom = TreeRoom {
    filled_leaves: 100,
    leaves_per_block: 64,
};

fn guard_chain() -> GuardChain {
    GuardChain {
        chain_id: CHAIN_ID,
        domain: DOMAIN,
    }
}

fn policy() -> GuardPolicy {
    GuardPolicy::new(GUARD_TEST_ADDRESS, GUARD_TEST_CODEHASH).unwrap()
}

fn amount(wei: u128) -> Amount {
    Amount::new(wei).unwrap()
}

fn zk(rng: &mut StdRng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn parse(text: &str) -> PhantomKey {
    PhantomKey::parse(text).unwrap_or_else(|_| panic!("a test key parses"))
}

fn seed(byte: u8) -> WalletSeed {
    WalletSeed::from_bytes([byte; 32])
}

fn cost() -> u128 {
    action_cost(BASE_FEE).unwrap()
}

/// A random source that gives the same byte forever: a broken generator.
struct StuckRng(u8);

impl rand_core::TryRng for StuckRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_ne_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_ne_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(self.0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for StuckRng {}

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
#[derive(Clone, Default)]
struct Chain {
    leaves: Vec<TreeLeaf>,
    spent: Vec<Marker>,
}

impl Chain {
    fn push(&mut self, commitment: Commitment, note: [u8; NOTE_BYTES], salt: Option<Salt>) -> u32 {
        self.leaves.push(TreeLeaf { commitment, note, salt });
        (self.leaves.len() - 1) as u32
    }

    /// A plain commit of another key, so the Guard coins are not alone.
    fn filler(&mut self, rng: &mut StdRng) {
        let key = PhantomKey::generate(KeyFormat::Words, rng);
        let commit = key.salted_coin_commit(0, amount(5_000), Rule::EMPTY, rng).unwrap();
        let contents = NoteContents::salted_coin(0, amount(5_000), Rule::EMPTY, commit.salt);
        let note = encrypt_note(&key.note_key(), CHAIN_ID, &commit.commitment, &contents, &Capsule::empty(), rng);
        self.push(commit.commitment, note, Some(commit.salt));
    }

    /// Includes an ordinary reveal as the node does: marker spent, remainder
    /// appended with its 380-byte note and no salt beside it.
    fn include_v2(&mut self, reveal: &CoinRevealV2) -> u32 {
        self.spent.push(Marker::from_bytes(reveal.marker));
        self.push(Commitment::from_bytes(reveal.remainder), reveal.remainder_note, None)
    }

    /// Includes a policy reveal as the node does.
    fn include_policy(&mut self, reveal: &PolicyReveal) -> u32 {
        self.spent.push(Marker::from_bytes(reveal.marker));
        self.push(Commitment::from_bytes(reveal.remainder), reveal.remainder_note, None)
    }

    /// Guard's `recommit` as the escrow native does it, read from the
    /// cancel's calldata alone: `C = K(coin-commitment, COIN_V2, F_new, a)`,
    /// the note appended, the salt stored beside `F`.
    fn recommit(&mut self, calldata: &[u8; CANCEL_CALLDATA_BYTES], settled: Amount) -> u32 {
        let f: [u8; 32] = calldata[4..36].try_into().unwrap();
        let salt: [u8; 16] = calldata[36..52].try_into().unwrap();
        let note: [u8; NOTE_BYTES] = calldata[52..].try_into().unwrap();
        let leaf = coin_commitment_v2(&f, &settled.to_bytes());
        self.push(Commitment::from_bytes(leaf), note, Some(Salt::from_bytes(salt)))
    }

    fn owned(&self, number: u64, wei: u128, rule: Rule, salt: Salt, position: u32) -> (OwnedCoin, [u8; 32]) {
        let (root, path) = root_and_path(&self.leaves, position);
        let coin = OwnedCoin {
            number,
            amount: amount(wei),
            rule,
            salt,
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

/// The fifteen words of `slot()` for a slot a policy reveal opened.
fn slot_words(reveal: &PolicyReveal) -> [[u8; 32]; SLOT_WORDS] {
    let mut words = [[0u8; 32]; SLOT_WORDS];
    words[0][12..].copy_from_slice(&reveal.policy_address);
    words[1][31] = 1;
    words[2] = reveal.out;
    words[3] = reveal.out;
    words[9][24..].copy_from_slice(&SLOT_HEIGHT.to_be_bytes());
    words[10][24..].copy_from_slice(&SLOT_TIME.to_be_bytes());
    words[11] = reveal.params_hash;
    words[12] = reveal.action_tag;
    words[13] = reveal.action_salt;
    words[14] = reveal.instr;
    words
}

struct Scenario {
    chain: Chain,
    owner: String,
    receiver: String,
    rescue: String,
    /// The owner's committed rule and its rotated rule.
    committed_rule: GuardRule,
    rotated_rule: GuardRule,
    receiver_rule: GuardRule,
    /// Position of the commit, the owner's remainder and the receiver's coin.
    positions: [u32; 3],
    /// The owner's normal spend.
    spend: (CoinRevealV2, Proof),
    /// The transfer.
    transfer: (CoinRevealV2, Proof),
    /// The receiver's coin before the words-only spend, with its root.
    receiver_coin: (OwnedCoin, [u8; 32]),
    /// The words-only spend.
    words_only: (PolicyReveal, Proof),
    /// The slot it opened.
    slot: EscrowSlot,
    /// The cancel.
    cancel: BuiltCancel,
    cancel_position: u32,
}

const RECEIVER_SEED: u8 = 0xb0;
const OWNER_SEED: u8 = 0xa0;
const RECIPIENT: [u8; 20] = [0x99; 20];

fn owner_stop() -> StopRoot {
    StopRoot::from_bytes([0xa5; 32]).unwrap()
}

fn receiver_stop() -> StopRoot {
    StopRoot::from_bytes([0xb5; 32]).unwrap()
}

fn cancel_terms() -> CancelTerms {
    CancelTerms {
        debit: amount(2 * cost()),
        expiry: SLOT_HEIGHT + 100,
        action_cost: cost(),
        head_height: SLOT_HEIGHT + 10,
        selector: CANCEL_SELECTOR,
    }
}

fn scenario() -> &'static Scenario {
    static SCENARIO: OnceLock<Scenario> = OnceLock::new();
    SCENARIO.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x6a4d);
        let mut zk_rng = StdRng::seed_from_u64(0x2c);
        let policy = policy();
        let owner = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let receiver = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let rescue = PhantomKey::generate(KeyFormat::Words, &mut rng);
        let owner_secret = GuardSecret::from_seed(&seed(OWNER_SEED), 0);
        let receiver_secret = GuardSecret::from_seed(&seed(RECEIVER_SEED), 0);
        let mut chain = Chain::default();
        chain.filler(&mut rng);

        // Commit.
        let committed_rule = GuardRule::new(&policy, &owner_secret, &owner_stop(), &mut rng).unwrap();
        let commit = guard_commit(&owner, CHAIN_ID, amount(COMMITTED), &committed_rule, &ROOM, &mut rng).unwrap();
        let p0 = chain.push(commit.commit.commitment, commit.note, Some(commit.commit.salt));
        chain.filler(&mut rng);

        // Normal spend with the override, rotating the remainder's rule.
        let found = restore_guard_coins(&owner, CHAIN_ID, 0, &chain.leaves, &chain.spent, &policy).unwrap();
        assert_eq!(found.guard.len(), 1);
        let coin0 = found.guard[0];
        let (owned, root) = chain.owned(0, COMMITTED, coin0.coin.rule, coin0.coin.salt, coin0.coin.position);
        let rotated_rule = GuardRule::new(&policy, &owner_secret, &owner_stop(), &mut rng).unwrap();
        let built = guard_spend(
            &guard_chain(),
            &owner,
            &owned,
            &coin0.rule,
            &owner_secret,
            &terms(root),
            amount(PAID),
            RemainderRule::Guard { rule: rotated_rule, room: ROOM },
            &mut rng,
            zk(&mut zk_rng),
        )
        .unwrap();
        assert_eq!(built.remainder.number, 1);
        let p1 = chain.include_v2(&built.reveal);
        let spend = (built.reveal, built.proof);
        chain.filler(&mut rng);

        // Transfer to the receiver's own Guard rule, handed over as a capsule.
        let made_by_receiver = GuardRule::new(&policy, &receiver_secret, &receiver_stop(), &mut rng).unwrap();
        let receiver_rule = GuardRule::from_capsule(&policy, &made_by_receiver.capsule()).unwrap();
        let left1 = COMMITTED - PAID - FEE;
        let found = restore_guard_coins(&owner, CHAIN_ID, 0, &chain.leaves, &chain.spent, &policy).unwrap();
        let coin1 = found.guard.iter().find(|g| g.unspent).unwrap();
        assert_eq!((coin1.coin.number, coin1.coin.position, coin1.coin.amount.wei()), (1, p1, left1));
        let (owned1, root1) = chain.owned(1, left1, coin1.coin.rule, coin1.coin.salt, p1);
        let built = guard_transfer(
            &guard_chain(),
            &owner,
            &owned1,
            &coin1.rule,
            &owner_secret,
            &receiver,
            &terms(root1),
            amount(PAID),
            RemainderRule::Guard { rule: receiver_rule, room: ROOM },
            &mut rng,
            zk(&mut zk_rng),
        )
        .unwrap();
        assert_eq!(built.remainder.number, 0);
        let p2 = chain.include_v2(&built.reveal);
        let transfer = (built.reveal, built.proof);
        chain.filler(&mut rng);

        // The receiver's words-only spend, from the words and the chain alone.
        let restored = restore_guard_coins(&receiver, CHAIN_ID, 0, &chain.leaves, &chain.spent, &policy).unwrap();
        assert_eq!(restored.guard.len(), 1);
        let found = restored.guard[0];
        let left2 = left1 - PAID - FEE;
        assert_eq!(found.coin.amount.wei(), left2);
        let (owned2, root2) = chain.owned(0, left2, found.coin.rule, found.coin.salt, found.coin.position);
        let receiver_coin = chain.owned(0, left2, found.coin.rule, found.coin.salt, found.coin.position);
        let built = words_only_spend(
            &guard_chain(),
            &receiver,
            &owned2,
            &found.rule,
            root2,
            amount(FEE),
            &RECIPIENT,
            &mut rng,
            zk(&mut zk_rng),
        )
        .unwrap();
        assert_eq!(built.remainder.amount.wei(), 0);
        chain.include_policy(&built.reveal);
        let slot = EscrowSlot::from_words(&slot_words(&built.reveal)).unwrap();
        let words_only = (built.reveal, built.proof);

        // The stop card cancels to a new key.
        let marker = Marker::from_bytes(words_only.0.marker);
        let cancel = guard_cancel(
            &guard_chain(),
            &policy,
            &marker,
            &slot,
            &receiver_stop(),
            &receiver_secret,
            &rescue,
            &cancel_terms(),
            &mut rng,
            zk(&mut zk_rng),
        )
        .unwrap();
        let settled = amount(slot.remaining.wei() - cancel_terms().debit.wei());
        let cancel_position = chain.recommit(&cancel.calldata, settled);

        Scenario {
            chain,
            owner: owner.format_groups().as_str().to_owned(),
            receiver: receiver.format_groups().as_str().to_owned(),
            rescue: rescue.format_groups().as_str().to_owned(),
            committed_rule,
            rotated_rule,
            receiver_rule,
            positions: [p0, p1, p2],
            spend,
            transfer,
            receiver_coin,
            words_only,
            slot,
            cancel,
            cancel_position,
        }
    })
}

#[test]
fn a_guard_commit_holds_the_rule_and_its_capsule() {
    let s = scenario();
    let policy = policy();
    let owner = parse(&s.owner);
    let leaf = &s.chain.leaves[s.positions[0] as usize];
    // The note opens with the owner's note key and carries the rule's capsule.
    let (contents, capsule) =
        ghost_client::decrypt_note_with_capsule(&owner.note_key(), CHAIN_ID, &leaf.commitment, &leaf.note).unwrap();
    assert_eq!(contents.number, 0);
    assert_eq!(contents.amount.wei(), COMMITTED);
    assert_eq!(contents.rule, s.committed_rule.rule());
    assert!(capsule == s.committed_rule.capsule());
    // The rule has Guard's six fields: the policy, empty parameters, the
    // override hash of the guard secret, the action tag of the stop root.
    let secret = GuardSecret::from_seed(&seed(OWNER_SEED), 0);
    assert_eq!(capsule.policy_address(), &GUARD_TEST_ADDRESS);
    assert_eq!(capsule.policy_codehash(), &GUARD_TEST_CODEHASH);
    assert!(capsule.params().is_empty());
    assert_eq!(capsule.params_hash(), guard_params_hash());
    assert_eq!(capsule.override_hash(), &secret.override_hash());
    assert_eq!(
        capsule.action_tag(),
        &policy_action_tag(owner_stop().as_bytes(), capsule.action_salt())
    );
    assert_ne!(capsule.action_salt(), &[0; 32]);
    let rule = GuardRule::from_capsule(&policy, &capsule).unwrap();
    assert!(rule == s.committed_rule);
    // The commit's data carries the fingerprint, the salt and the note.
    let mut rng = StdRng::seed_from_u64(1);
    let again = guard_commit(&owner, CHAIN_ID, amount(COMMITTED), &s.committed_rule, &ROOM, &mut rng).unwrap();
    assert_eq!(&again.data[2..34], again.commit.fingerprint.as_bytes());
    assert_eq!(&again.data[34..50], again.commit.salt.as_bytes());
    assert_eq!(&again.data[50..], &again.note[..]);
    assert_eq!(
        again.commit.commitment,
        owner.coin_commit_with_rule(0, amount(COMMITTED), rule.rule(), again.commit.salt).commitment
    );
}

#[test]
fn the_normal_spend_verifies_and_its_remainder_carries_the_chosen_rule() {
    let s = scenario();
    let policy = policy();
    let (reveal, proof) = &s.spend;
    verify_coin_reveal_v2(&guard_chain().ordinary_params(), reveal, proof).unwrap();
    // It is not a policy-class reveal and binds no rule: the ordinary shape.
    assert_eq!(reveal.remainder_note.len(), NOTE_BYTES);
    assert_eq!(reveal.recipient, [5; 20]);
    assert_eq!(reveal.out, amount(PAID).to_bytes());

    // Restore from the owner's words finds the spent commit and the
    // remainder, which carries the rotated rule and a matching capsule.
    let owner = parse(&s.owner);
    let restored = restore_guard_coins(&owner, CHAIN_ID, 0, &s.chain.leaves, &s.chain.spent, &policy).unwrap();
    assert_eq!(restored.guard.len(), 2);
    let remainder = restored.guard.iter().find(|g| g.coin.number == 1).unwrap();
    assert_eq!(remainder.coin.position, s.positions[1]);
    assert_eq!(remainder.coin.amount.wei(), COMMITTED - PAID - FEE);
    assert_eq!(remainder.coin.rule, s.rotated_rule.rule());
    assert!(remainder.coin.capsule == s.rotated_rule.capsule());
    assert!(remainder.rule == s.rotated_rule);
    assert_ne!(remainder.coin.rule, s.committed_rule.rule());
    assert!(restored.guard.iter().all(|g| !g.unspent), "both were spent by the end");
}

#[test]
fn the_transfer_hands_the_coin_to_the_receivers_rule() {
    let s = scenario();
    let policy = policy();
    let (reveal, proof) = &s.transfer;
    verify_coin_reveal_v2(&guard_chain().ordinary_params(), reveal, proof).unwrap();
    let receiver = parse(&s.receiver);
    let restored = restore_guard_coins(&receiver, CHAIN_ID, 0, &s.chain.leaves, &s.chain.spent, &policy).unwrap();
    assert_eq!(restored.guard.len(), 1);
    let coin = restored.guard[0];
    assert_eq!(coin.coin.number, 0);
    assert_eq!(coin.coin.position, s.positions[2]);
    assert!(coin.rule == s.receiver_rule);
    // The receiver's rule opens with the receiver's secret and stop root, not
    // the giver's.
    assert!(coin.rule.opened_by(&GuardSecret::from_seed(&seed(RECEIVER_SEED), 0)));
    assert!(!coin.rule.opened_by(&GuardSecret::from_seed(&seed(OWNER_SEED), 0)));
    assert_eq!(
        coin.rule.action_tag(),
        &receiver_stop().action_tag(coin.rule.action_salt())
    );
    assert_ne!(coin.rule.action_tag(), &owner_stop().action_tag(coin.rule.action_salt()));
    // The giver's words find nothing unspent.
    let owner = parse(&s.owner);
    let theirs = restore_coins(&owner, CHAIN_ID, 0, &s.chain.leaves, &s.chain.spent).unwrap();
    assert!(matches!(theirs.current, Current::None));
}

#[test]
fn the_words_only_spend_is_a_policy_reveal_with_the_recipient_in_instr() {
    let s = scenario();
    let (reveal, proof) = &s.words_only;
    verify_policy_reveal(&guard_chain().policy_params(), reveal, proof).unwrap();
    assert_eq!(reveal.policy_address, GUARD_TEST_ADDRESS);
    assert_eq!(reveal.policy_codehash, GUARD_TEST_CODEHASH);
    assert_eq!(reveal.params_hash, guard_params_hash());
    assert_eq!(reveal.action_tag, *s.receiver_rule.action_tag());
    assert_eq!(reveal.action_salt, *s.receiver_rule.action_salt().as_bytes());
    let mut instr = [0u8; 32];
    instr[12..].copy_from_slice(&RECIPIENT);
    assert_eq!(reveal.instr, instr);
    assert_eq!(instr_for(&RECIPIENT), instr);
    // A full sweep: everything but the fee goes to the slot.
    let value = s.receiver_coin.0.amount.wei();
    assert_eq!(reveal.out, amount(value - FEE).to_bytes());
    assert_eq!(reveal.fee, amount(FEE).to_bytes());
    assert_eq!(s.slot.remaining.wei(), value - FEE);
}

#[test]
fn the_cancel_signs_the_exact_new_coin_and_restore_finds_it() {
    let s = scenario();
    let policy = policy();
    let cancel = &s.cancel;
    let terms = cancel_terms();
    let marker = Marker::from_bytes(s.words_only.0.marker);

    // The action statement is the slot's, as the node sets it.
    let statement = KnowAction {
        policy_address: GUARD_TEST_ADDRESS,
        marker: *marker.as_bytes(),
        action_nonce: 0,
        action_tag: s.slot.action_tag,
        action_salt: s.slot.action_salt,
        expected_remaining: s.slot.remaining.to_bytes(),
        debit: terms.debit.to_bytes(),
        expiry: terms.expiry,
        calldata_hash: action_calldata_hash(&cancel.calldata).unwrap(),
    };
    assert_eq!(cancel.statement, statement);
    verify_know_action(&guard_chain().action_params(), &statement, &cancel.proof).unwrap();

    // The calldata: the selector, F_new, salt_new, note_new; 432 bytes.
    assert_eq!(cancel.calldata.len(), 432);
    assert_eq!(&cancel.calldata[..4], &CANCEL_SELECTOR);
    let settled = amount(s.slot.remaining.wei() - terms.debit.wei());
    let rescue = parse(&s.rescue);
    let expected = rescue.coin_commit_with_rule(0, settled, cancel.new_rule.rule(), cancel.new_coin.salt);
    assert_eq!(&cancel.calldata[4..36], expected.fingerprint.as_bytes());
    assert_eq!(&cancel.calldata[36..52], cancel.new_coin.salt.as_bytes());
    assert_eq!(&cancel.calldata[52..], &cancel.new_coin.note[..]);
    assert_eq!(cancel.new_coin.commitment, expected.commitment);
    assert_eq!(cancel.new_coin.amount, settled);

    // The new coin is a Guard coin under a fresh action salt.
    assert_ne!(cancel.new_rule.action_salt().as_bytes(), &s.slot.action_salt);

    // A words-only restore of the new key finds what Guard re-committed.
    let restored = restore_guard_coins(&rescue, CHAIN_ID, 0, &s.chain.leaves, &s.chain.spent, &policy).unwrap();
    assert_eq!(restored.guard.len(), 1);
    let found = restored.guard[0];
    assert!(found.unspent);
    assert_eq!(found.coin.position, s.cancel_position);
    assert_eq!(found.coin.amount, settled);
    assert!(found.rule == cancel.new_rule);

    // The action envelope of spec 10, section 8.1.
    let envelope = cancel.envelope();
    assert_eq!(envelope.len(), 1 + ACTION_PAYLOAD_BYTES);
    assert_eq!(envelope[0], ACTION_TX_TYPE);
    let p = &envelope[1..];
    assert_eq!(&p[0..2], &[0, 1]);
    assert_eq!(&p[2..10], &CHAIN_ID.to_be_bytes());
    assert_eq!(&p[10..42], marker.as_bytes());
    assert_eq!(&p[42..50], &0u64.to_be_bytes());
    assert_eq!(&p[50..82], &s.slot.remaining.to_bytes());
    assert_eq!(&p[82..114], &terms.debit.to_bytes());
    assert_eq!(&p[114..122], &terms.expiry.to_be_bytes());
    assert_eq!(&p[122..124], &432u16.to_be_bytes());
    assert_eq!(&p[124..556], &cancel.calldata[..]);
    assert!(p[556..1148].iter().all(|&b| b == 0));
    let proof = cancel.proof.as_bytes();
    assert_eq!(&p[1148..1148 + proof.len()], proof);
    assert!(p[1148 + proof.len()..].iter().all(|&b| b == 0));
}

#[test]
fn every_guard_coin_has_its_own_action_salt() {
    let s = scenario();
    let salts = [
        *s.committed_rule.action_salt().as_bytes(),
        *s.rotated_rule.action_salt().as_bytes(),
        *s.receiver_rule.action_salt().as_bytes(),
        *s.cancel.new_rule.action_salt().as_bytes(),
    ];
    for (i, a) in salts.iter().enumerate() {
        assert_ne!(a, &[0; 32]);
        for b in &salts[i + 1..] {
            assert_ne!(a, b);
        }
    }

    // Many rules of one secret and one stop root: never the same salt or tag.
    let mut rng = StdRng::seed_from_u64(0x5a17);
    let secret = GuardSecret::from_seed(&seed(OWNER_SEED), 0);
    let rules: Vec<GuardRule> =
        (0..64).map(|_| GuardRule::new(&policy(), &secret, &owner_stop(), &mut rng).unwrap()).collect();
    for (i, a) in rules.iter().enumerate() {
        for b in &rules[i + 1..] {
            assert_ne!(a.action_salt().as_bytes(), b.action_salt().as_bytes());
            assert_ne!(a.action_tag(), b.action_tag());
            assert_ne!(a.rule(), b.rule());
        }
    }

    // A generator stuck at zero gives no salt and no stop root.
    let mut zero = StuckRng(0);
    assert_eq!(
        GuardRule::new(&policy(), &secret, &owner_stop(), &mut zero).err(),
        Some(GuardError::ZeroRandom)
    );
    assert_eq!(StopRoot::generate(&mut zero).err(), Some(GuardError::ZeroRandom));
    assert_eq!(StopRoot::from_bytes([0; 32]).err(), Some(GuardError::ZeroRandom));
}

#[test]
fn a_cancel_never_recommits_under_the_slots_own_salt() {
    let s = scenario();
    // A slot whose salt is what a stuck generator draws next: the cancel's
    // new coin would reuse it, and the cancel is refused.
    let stuck_salt = [0x11; 32];
    let slot = EscrowSlot {
        action_salt: stuck_salt,
        action_tag: policy_action_tag(receiver_stop().as_bytes(), &stuck_salt),
        ..s.slot
    };
    let secret = GuardSecret::from_seed(&seed(RECEIVER_SEED), 0);
    let rescue = parse(&s.rescue);
    let result = guard_cancel(
        &guard_chain(),
        &policy(),
        &Marker::from_bytes([3; 32]),
        &slot,
        &receiver_stop(),
        &secret,
        &rescue,
        &cancel_terms(),
        &mut StuckRng(0x11),
        [0; 32],
    );
    assert_eq!(result.err(), Some(GuardError::SaltReused));
}

#[test]
fn a_spend_never_keeps_the_inputs_action_salt() {
    let s = scenario();
    let policy = policy();
    let receiver = parse(&s.receiver);
    let secret = GuardSecret::from_seed(&seed(RECEIVER_SEED), 0);
    let (coin, root) = &s.receiver_coin;
    let mut rng = StdRng::seed_from_u64(9);
    // The input's own rule, read back from its capsule, as the remainder's.
    let same = GuardRule::from_capsule(&policy, &s.receiver_rule.capsule()).unwrap();
    let kept = guard_spend(
        &guard_chain(),
        &receiver,
        coin,
        &s.receiver_rule,
        &secret,
        &terms(*root),
        amount(PAID),
        RemainderRule::Guard { rule: same, room: ROOM },
        &mut rng,
        [0; 32],
    );
    assert_eq!(kept.err(), Some(GuardError::SaltReused));
    // So does a transfer whose receiver rule reuses it.
    let rescue = parse(&s.rescue);
    let moved = guard_transfer(
        &guard_chain(),
        &receiver,
        coin,
        &s.receiver_rule,
        &secret,
        &rescue,
        &terms(*root),
        amount(PAID),
        RemainderRule::Guard { rule: same, room: ROOM },
        &mut rng,
        [0; 32],
    );
    assert_eq!(moved.err(), Some(GuardError::SaltReused));
    // A transfer to the key that holds the coin is not a transfer.
    let to_self = guard_transfer(
        &guard_chain(),
        &receiver,
        coin,
        &s.receiver_rule,
        &secret,
        &parse(&s.receiver),
        &terms(*root),
        amount(PAID),
        RemainderRule::Empty,
        &mut rng,
        [0; 32],
    );
    assert_eq!(to_self.err(), Some(GuardError::TransferToSameKey));
    // A Guard remainder near a full tree is refused like a commit.
    let fresh = GuardRule::new(&policy, &secret, &receiver_stop(), &mut rng).unwrap();
    let full = TreeRoom {
        filled_leaves: (1u64 << 32) - HOLD_BLOCKS,
        leaves_per_block: 1,
    };
    let near_full = guard_spend(
        &guard_chain(),
        &receiver,
        coin,
        &s.receiver_rule,
        &secret,
        &terms(*root),
        amount(PAID),
        RemainderRule::Guard { rule: fresh, room: full },
        &mut rng,
        [0; 32],
    );
    assert_eq!(near_full.err(), Some(GuardError::TreeNearlyFull));
}

/// RP-27: with only the words, the wallet makes a policy-class spend and
/// nothing else, and no cancel.
#[test]
fn the_words_alone_make_a_policy_spend_and_nothing_else() {
    let s = scenario();
    let policy = policy();
    let receiver = parse(&s.receiver);
    let (coin, root) = &s.receiver_coin;
    let mut rng = StdRng::seed_from_u64(27);

    // The words-only spend of the scenario was built from the words and the
    // chain alone, and verifies.
    verify_policy_reveal(&guard_chain().policy_params(), &s.words_only.0, &s.words_only.1).unwrap();

    // The words are not a wallet seed, so they give no guard secret.
    let words = receiver.format_words().unwrap();
    assert!(WalletSeed::from_words(words.as_str()).is_err());

    // A guard secret that is not the coin's cannot make the normal spend.
    for wrong in [GuardSecret::from_seed(&seed(OWNER_SEED), 0), GuardSecret::from_seed(&seed(RECEIVER_SEED), 1)] {
        let spent = guard_spend(
            &guard_chain(),
            &receiver,
            coin,
            &s.receiver_rule,
            &wrong,
            &terms(*root),
            amount(PAID),
            RemainderRule::Empty,
            &mut rng,
            [0; 32],
        );
        assert_eq!(spent.err(), Some(GuardError::WrongGuardSecret));
    }

    // Nor can the prover itself: the plain case does not open a coin with a
    // rule, and the override case needs the secret.
    let key_bytes = receiver.key_bytes();
    let opening = SaltedCoinOpening {
        s: *key_bytes.secret().as_bytes(),
        r: *key_bytes.reveal_secret().as_bytes(),
        b: *key_bytes.blinding(0).as_bytes(),
        salt: *coin.salt.as_bytes(),
        v: coin.amount.to_bytes(),
        position: coin.position,
        path: coin.path,
    };
    let remainder = SaltedCoinRemainder {
        s: *key_bytes.secret().as_bytes(),
        r: *key_bytes.reveal_secret().as_bytes(),
        b: *key_bytes.blinding(1).as_bytes(),
        salt: [4; 16],
        v: amount(coin.amount.wei() - PAID - FEE).to_bytes(),
    };
    let request = CoinRevealV2Request {
        root: *root,
        recipient: [5; 20],
        out: amount(PAID).to_bytes(),
        fee: amount(FEE).to_bytes(),
        remainder_note: [0; NOTE_BYTES],
    };
    let params = guard_chain().ordinary_params();
    let plain = prove_coin_reveal_v2(&params, &opening, &InputRule::plain(), &remainder, &[0; 32], &request, [0; 32]);
    assert_eq!(plain.err(), Some(ProofError::NotInTree));
    let guessed = InputRule::with_override(
        ghost_proofs::PolicyRule {
            policy_address: GUARD_TEST_ADDRESS,
            policy_codehash: GUARD_TEST_CODEHASH,
            params_hash: guard_params_hash(),
            override_hash: *s.receiver_rule.override_hash(),
            action_tag: *s.receiver_rule.action_tag(),
            action_salt: *s.receiver_rule.action_salt().as_bytes(),
        },
        *key_bytes.secret().as_bytes(),
    );
    let with_words = prove_coin_reveal_v2(&params, &opening, &guessed, &remainder, &[0; 32], &request, [0; 32]);
    assert_eq!(with_words.err(), Some(ProofError::WrongOverrideSecret));

    // The version 1 reveal refuses a coin with a rule.
    let v1_params = ghost_client::reveal::ChainParams {
        chain_id: CHAIN_ID.to_be_bytes(),
        version: ghost_proofs::PROTOCOL_VERSION_1,
        domain: DOMAIN,
    };
    let v1 = partial_reveal(&v1_params, &receiver, coin, &terms(*root), amount(PAID), &mut rng, [0; 32]);
    assert!(v1.is_err());

    // No cancel: a stop root that is not the card's does not open the slot,
    // whether random or made from the words' own derived bytes.
    let marker = Marker::from_bytes(s.words_only.0.marker);
    let secret = GuardSecret::from_seed(&seed(RECEIVER_SEED), 0);
    let random_root = StopRoot::generate(&mut rng).unwrap();
    let words_root = StopRoot::from_bytes(*key_bytes.secret().as_bytes()).unwrap();
    for wrong in [&random_root, &words_root, &owner_stop()] {
        let cancelled = guard_cancel(
            &guard_chain(),
            &policy,
            &marker,
            &s.slot,
            wrong,
            &secret,
            &parse(&s.rescue),
            &cancel_terms(),
            &mut rng,
            [0; 32],
        );
        assert_eq!(cancelled.err(), Some(GuardError::NotTheStopRoot));
    }
}

#[test]
fn cancel_refuses_what_guard_or_the_node_would() {
    let s = scenario();
    let policy = policy();
    let secret = GuardSecret::from_seed(&seed(RECEIVER_SEED), 0);
    let rescue = parse(&s.rescue);
    let marker = Marker::from_bytes(s.words_only.0.marker);
    let mut rng = StdRng::seed_from_u64(26);
    let mut cancel = |slot: &EscrowSlot, terms: &CancelTerms| {
        guard_cancel(
            &guard_chain(),
            &policy,
            &marker,
            slot,
            &receiver_stop(),
            &secret,
            &rescue,
            terms,
            &mut rng,
            [0; 32],
        )
        .err()
    };
    let good = cancel_terms();
    let remaining = s.slot.remaining.wei();

    let other_policy = EscrowSlot { policy_address: [0x48; 20], ..s.slot };
    assert_eq!(cancel(&other_policy, &good), Some(GuardError::SlotNotGuard));
    let closed = EscrowSlot { open: false, ..s.slot };
    assert_eq!(cancel(&closed, &good), Some(GuardError::SlotClosed));
    let no_actions = EscrowSlot { action_tag: [0; 32], ..s.slot };
    assert_eq!(cancel(&no_actions, &good), Some(GuardError::SlotHasNoActions));

    // remaining <= debit: the cancel cannot run.
    let all = CancelTerms { debit: s.slot.remaining, ..good };
    assert_eq!(cancel(&s.slot, &all), Some(GuardError::SlotTooSmall));
    let more = CancelTerms { debit: amount(remaining + 1), ..good };
    assert_eq!(cancel(&s.slot, &more), Some(GuardError::SlotTooSmall));
    let small = EscrowSlot { remaining: amount(cost()), out: amount(cost()), ..s.slot };
    let at_cost = CancelTerms { debit: amount(cost()), ..good };
    assert_eq!(cancel(&small, &at_cost), Some(GuardError::SlotTooSmall));

    let cheap = CancelTerms { debit: amount(cost() - 1), ..good };
    assert_eq!(cancel(&s.slot, &cheap), Some(GuardError::DebitBelowActionCost));
    let unknown = CancelTerms { action_cost: 0, ..good };
    assert_eq!(cancel(&s.slot, &unknown), Some(GuardError::ActionCostUnknown));
    let expired = CancelTerms { expiry: good.head_height, ..good };
    assert_eq!(cancel(&s.slot, &expired), Some(GuardError::Expired));
    let overflow = CancelTerms { head_height: u64::MAX, expiry: u64::MAX, ..good };
    assert_eq!(cancel(&s.slot, &overflow), Some(GuardError::Expired));
}

#[test]
fn release_waits_for_both_holds_and_pays_the_address_in_instr() {
    let s = scenario();
    let policy = policy();
    let marker = Marker::from_bytes(s.words_only.0.marker);
    let release = |slot: &EscrowSlot, height: u64, timestamp: u64| {
        guard_release(&policy, &marker, slot, &ChainHead { height, timestamp }, RELEASE_SELECTOR)
    };
    let end_height = SLOT_HEIGHT + HOLD_BLOCKS;
    let end_time = SLOT_TIME + HOLD_SECONDS;
    assert_eq!(HOLD_BLOCKS, 8_640);
    assert_eq!(HOLD_SECONDS, 259_200);

    assert_eq!(release(&s.slot, end_height - 1, end_time).err(), Some(GuardError::HoldNotOver));
    assert_eq!(release(&s.slot, end_height, end_time - 1).err(), Some(GuardError::HoldNotOver));
    let call = release(&s.slot, end_height, end_time).unwrap();
    assert_eq!(call.to, GUARD_TEST_ADDRESS);
    assert_eq!(call.data.len(), RELEASE_CALLDATA_BYTES);
    assert_eq!(&call.data[..4], &RELEASE_SELECTOR);
    assert_eq!(&call.data[4..], marker.as_bytes());
    let tx = call.account_tx(CHAIN_ID, 7, 1, 10, 200_000);
    assert_eq!(tx.to, Some(GUARD_TEST_ADDRESS));
    assert_eq!(tx.value, 0);
    assert_eq!(tx.data, call.data.to_vec());

    let late = EscrowSlot { height: u64::MAX - 1, ..s.slot };
    assert_eq!(release(&late, u64::MAX, u64::MAX).err(), Some(GuardError::HoldNotOver));
    let mut instr = s.slot.instr;
    instr[0] = 1;
    let bad_instr = EscrowSlot { instr, ..s.slot };
    assert_eq!(release(&bad_instr, end_height, end_time).err(), Some(GuardError::InstrNotAnAddress));
    let closed = EscrowSlot { open: false, ..s.slot };
    assert_eq!(release(&closed, end_height, end_time).err(), Some(GuardError::SlotClosed));
    let other = EscrowSlot { policy_address: [0x48; 20], ..s.slot };
    assert_eq!(release(&other, end_height, end_time).err(), Some(GuardError::SlotNotGuard));
    let other_params = EscrowSlot { params_hash: [1; 32], ..s.slot };
    assert_eq!(release(&other_params, end_height, end_time).err(), Some(GuardError::SlotNotGuard));
}

#[test]
fn the_slot_words_are_read_strictly() {
    let s = scenario();
    let words = slot_words(&s.words_only.0);
    let slot = EscrowSlot::from_words(&words).unwrap();
    assert_eq!(slot.policy_address, GUARD_TEST_ADDRESS);
    assert!(slot.open);
    assert_eq!((slot.height, slot.timestamp, slot.action_nonce), (SLOT_HEIGHT, SLOT_TIME, 0));

    let refuse = |change: &dyn Fn(&mut [[u8; 32]; SLOT_WORDS])| {
        let mut bad = words;
        change(&mut bad);
        assert_eq!(EscrowSlot::from_words(&bad).err(), Some(GuardError::MalformedSlot));
    };
    refuse(&|w| w[0][0] = 1);
    refuse(&|w| w[1][31] = 2);
    refuse(&|w| w[2][11] = 1);
    refuse(&|w| w[8][0] = 1);
    // The accounting identity: out = remaining + paid + ... + forfeited.
    refuse(&|w| w[4][31] = 1);
    refuse(&|w| w[3][31] ^= 1);
}

#[test]
fn a_guard_commit_is_refused_near_a_full_tree() {
    let mut rng = StdRng::seed_from_u64(0x7ee);
    let key = PhantomKey::generate(KeyFormat::Words, &mut rng);
    let secret = GuardSecret::from_seed(&seed(OWNER_SEED), 0);
    let rule = GuardRule::new(&policy(), &secret, &owner_stop(), &mut rng).unwrap();
    let max = 1u64 << 32;
    let mut commit = |filled_leaves: u64, leaves_per_block: u64| {
        let room = TreeRoom { filled_leaves, leaves_per_block };
        guard_commit(&key, CHAIN_ID, amount(COMMITTED), &rule, &room, &mut rng).err()
    };
    // Free leaves at most HOLD_BLOCKS times the leaves a block can add.
    assert_eq!(commit(max - HOLD_BLOCKS, 1), Some(GuardError::TreeNearlyFull));
    assert_eq!(commit(max - HOLD_BLOCKS - 1, 1), None);
    assert_eq!(commit(max - 5 * HOLD_BLOCKS, 5), Some(GuardError::TreeNearlyFull));
    assert_eq!(commit(max - 5 * HOLD_BLOCKS - 1, 5), None);
    assert_eq!(commit(max, 1), Some(GuardError::TreeNearlyFull));
    assert_eq!(commit(0, 1), None);
    // What cannot be checked is refused.
    assert_eq!(commit(0, 0), Some(GuardError::TreeRoomUnknown));
    assert_eq!(commit(max + 1, 1), Some(GuardError::TreeRoomUnknown));
    assert_eq!(commit(0, u64::MAX), Some(GuardError::TreeRoomUnknown));
    assert_eq!(commit(0, max), Some(GuardError::TreeNearlyFull));
}

#[test]
fn warnings_for_words_handover_and_a_small_slot() {
    let s = scenario();
    // A Guard coin handed over as words stays under the giver's stop key.
    let receiver = parse(&s.receiver);
    let restored = restore_coins(&receiver, CHAIN_ID, 0, &s.chain.leaves, &s.chain.spent).unwrap();
    let guard_coin = restored.found.iter().find(|c| c.number == 0).unwrap();
    assert_eq!(hand_over_warning(guard_coin), Some(GuardWarning::HandedOverAsWords));
    // The zero-value remainder of the words-only spend has the empty rule.
    let plain = restored.found.iter().find(|c| c.number == 1).unwrap();
    assert!(plain.rule.is_empty());
    assert_eq!(hand_over_warning(plain), None);

    // The slot is not above the action cost.
    assert_eq!(G_ACTION, 15_585_968);
    assert_eq!(action_cost(1_000_000_000), Some(15_585_968_000_000_000));
    assert_eq!(action_cost(u128::MAX), None);
    let c = cost();
    assert_eq!(slot_cost_warning(amount(c), c), Some(GuardWarning::SlotNotAboveActionCost));
    assert_eq!(slot_cost_warning(amount(c - 1), c), Some(GuardWarning::SlotNotAboveActionCost));
    assert_eq!(slot_cost_warning(amount(0), c), Some(GuardWarning::SlotNotAboveActionCost));
    assert_eq!(slot_cost_warning(amount(c + 1), c), None);
    assert_eq!(slot_cost_warning(amount(c + 1), 0), Some(GuardWarning::ActionCostUnknown));
    assert!(GuardWarning::HandedOverAsWords.to_string().contains("stop key"));
}

#[test]
fn the_guard_policy_is_a_parameter_and_never_a_reserved_address() {
    assert!(GuardPolicy::new(GUARD_TEST_ADDRESS, GUARD_TEST_CODEHASH).is_ok());
    let mut low = [0u8; 20];
    low[18] = 0xff;
    low[19] = 0xff;
    assert_eq!(GuardPolicy::new(low, GUARD_TEST_CODEHASH).err(), Some(GuardError::PolicyNotUsable));
    low[17] = 1;
    low[18] = 0;
    low[19] = 0;
    assert!(GuardPolicy::new(low, GUARD_TEST_CODEHASH).is_ok());
    let mut native = [0u8; 20];
    native[..5].copy_from_slice(b"ghost");
    for last in 1..=0x0a {
        native[19] = last;
        assert_eq!(GuardPolicy::new(native, GUARD_TEST_CODEHASH).err(), Some(GuardError::PolicyNotUsable));
    }
    native[19] = 0x0b;
    assert!(GuardPolicy::new(native, GUARD_TEST_CODEHASH).is_ok());
    assert_eq!(GuardPolicy::new(GUARD_TEST_ADDRESS, [0; 32]).err(), Some(GuardError::PolicyNotUsable));

    // A capsule of another policy, other parameters or no override is not a
    // Guard coin of this one.
    let mut rng = StdRng::seed_from_u64(4);
    let secret = GuardSecret::from_seed(&seed(OWNER_SEED), 0);
    let rule = GuardRule::new(&policy(), &secret, &owner_stop(), &mut rng).unwrap();
    let other = GuardPolicy::new([0x48; 20], GUARD_TEST_CODEHASH).unwrap();
    assert_eq!(GuardRule::from_capsule(&other, &rule.capsule()).err(), Some(GuardError::NotAGuardCoin));
    let other_code = GuardPolicy::new(GUARD_TEST_ADDRESS, [0x5b; 32]).unwrap();
    assert_eq!(GuardRule::from_capsule(&other_code, &rule.capsule()).err(), Some(GuardError::NotAGuardCoin));
    let c = rule.capsule();
    let capsule = |params: &[u8], override_hash: [u8; 32], tag: [u8; 32], salt: [u8; 32]| {
        Capsule::policy(GUARD_TEST_ADDRESS, GUARD_TEST_CODEHASH, params, override_hash, tag, salt).unwrap()
    };
    let with_params = capsule(&[1], *c.override_hash(), *c.action_tag(), *c.action_salt());
    assert_eq!(GuardRule::from_capsule(&policy(), &with_params).err(), Some(GuardError::NotAGuardCoin));
    let no_override = capsule(&[], [0; 32], *c.action_tag(), *c.action_salt());
    assert_eq!(GuardRule::from_capsule(&policy(), &no_override).err(), Some(GuardError::NotAGuardCoin));
    let no_actions = capsule(&[], *c.override_hash(), [0; 32], [0; 32]);
    assert_eq!(GuardRule::from_capsule(&policy(), &no_actions).err(), Some(GuardError::NotAGuardCoin));
    // The same fields with empty parameters are the rule itself.
    let same = capsule(&[], *c.override_hash(), *c.action_tag(), *c.action_salt());
    assert!(GuardRule::from_capsule(&policy(), &same).unwrap() == rule);
    assert_eq!(GuardRule::from_capsule(&policy(), &Capsule::empty()).err(), Some(GuardError::NotAGuardCoin));
    assert_eq!(CANCEL_CALLDATA_BYTES, 432);
}

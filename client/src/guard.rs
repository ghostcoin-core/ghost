//! Ghost Guard in the wallet (spec 10, sections 3.1, 12 and 13): the Guard
//! rule, the commit, the normal spend, the words-only spend, release, cancel,
//! transfer, restore and the warnings a wallet shows.
//!
//! ```text
//! rule          = K("ghost/reveal-policy/v2", Guard address (left-padded to 32),
//!                   Guard code hash, params_hash, override_hash, action_tag, action_salt)
//! params_hash   = K("ghost/policy-params/v1")                    Guard has empty parameters
//! override_hash = K("ghost/policy-override/v1", guard secret)
//! action_tag    = K("ghost/policy-action/v1", stop root, action_salt)
//! action_salt   = 32 fresh random bytes for every new Guard coin
//! guard secret  = X("ghost/wallet-guard-secret/v1", 32, wallet seed, index as 4 bytes)
//! ```
//!
//! # The two secrets
//!
//! A Guard coin has two secrets besides its Phantom Key, and neither comes
//! from the Phantom Key (spec 10, section 3.1; property RP-28):
//!
//! - the [`GuardSecret`], held by the app. It is derived from the wallet seed
//!   of spec 09, section 9 under its own tag `ghost/wallet-guard-secret/v1`
//!   (one of the `ghost/wallet-*` tags, disjoint from the digit tags of spec
//!   01) and an index. It opens the override: the normal spend.
//! - the [`StopRoot`], held by the stop card. The library never makes one
//!   from anything but the caller's random source or the bytes the card gives
//!   it. It proves a policy action: the cancel.
//!
//! The two are different types, so one cannot be passed where the other is
//! asked for:
//!
//! ```compile_fail
//! use ghost_client::guard::{GuardSecret, StopRoot};
//! fn needs_stop_root(_: &StopRoot) {}
//! let seed = ghost_client::WalletSeed::from_bytes([7; 32]);
//! needs_stop_root(&GuardSecret::from_seed(&seed, 0));
//! ```
//!
//! ```compile_fail
//! use ghost_client::guard::{GuardSecret, StopRoot};
//! fn needs_guard_secret(_: &GuardSecret) {}
//! needs_guard_secret(&StopRoot::from_bytes([7; 32]).unwrap());
//! ```
//!
//! With the words alone (the Phantom Key, no guard secret and no stop root) a
//! wallet can restore a Guard coin and spend it in the policy class
//! ([`words_only_spend`]), which puts the value in a public escrow slot for
//! the hold. It cannot make an ordinary spend ([`guard_spend`] and
//! [`guard_transfer`] need the guard secret, and the plain case cannot open a
//! coin with a rule) and it cannot cancel ([`guard_cancel`] needs the stop
//! root that opens the slot's action tag): property RP-27.
//!
//! # The Guard address and code hash
//!
//! They are not final (spec 10, section 15, item 4), so this module defines
//! no Guard address: every function takes them as a [`GuardPolicy`]. The same
//! holds for the 4-byte selectors of Guard's `cancel` and `release` entry
//! points, which the Guard contract fixes: the caller passes them.
//!
//! # Action salts
//!
//! Every new Guard coin draws a fresh 32-byte action salt from the caller's
//! random source inside this module; no builder takes a salt to reuse. A salt
//! of 32 zero bytes (it would mean "no actions") is refused, and so is a new
//! coin's salt equal to the salt of the coin or slot it comes from: the
//! remainder of a spend that keeps Guard, a transfer's remainder and the coin
//! a cancel re-commits (spec 10, section 3.1).
//!
//! # Fail closed
//!
//! Where a figure the wallet needs is missing or cannot be checked (the
//! leaves a block can add, the action cost, a slot word out of range, an
//! addition that overflows), the function refuses rather than guess.
//!
//! The chain data (the slot, the head, the tree's leaf count, the base fee)
//! is read by the caller: this module has no network code.

use core::fmt;

pub use ghost_proofs::{CoinRevealV2, KnowAction, PolicyReveal};
use ghost_proofs::{
    action_calldata_hash, policy_action_tag, policy_override_hash, prove_coin_reveal_v2, prove_know_action,
    prove_policy_reveal, CoinRevealV2Request, InputRule, PolicyRevealRequest, PolicyRule, ACTION_CALLDATA_MAX,
    ACTION_PROOF_BYTES, PROTOCOL_VERSION_1, PROTOCOL_VERSION_2,
};
use rand_core::CryptoRng;

use crate::account::{AccountTx, WalletSeed};
use crate::commit::{salted_commit_data, Amount, CoinCommit, Commitment, Marker, Rule, Salt, SALTED_COMMIT_DATA_BYTES};
use crate::hash;
use crate::key::PhantomKey;
use crate::note::{encrypt_note, Capsule, NoteContents, NOTE_BYTES, POLICY_ADDRESS_BYTES, TAG_POLICY_PARAMS};
use crate::restore::{restore_coins, FoundCoin, RestoreError, Restored, TreeLeaf, MAX_TREE_LEAVES};
use crate::reveal::{OwnedCoin, Proof, ProofError, RevealTerms, SaltedCoinOpening, SaltedCoinRemainder};
use crate::wipe::wipe;

/// Tag of the guard secret's derivation from the wallet seed (SHAKE256).
pub const TAG_GUARD_SECRET: &str = "ghost/wallet-guard-secret/v1";
/// Guard's hold in blocks before a release (spec 10, section 12).
pub const HOLD_BLOCKS: u64 = 8_640;
/// Guard's hold in seconds before a release: 72 hours (spec 10, section 12).
pub const HOLD_SECONDS: u64 = 259_200;
/// The gas of a policy action, `G_ACTION` (spec 10, section 10.3). The action
/// cost at a base fee is `G_ACTION * baseFee` ([`action_cost`]).
pub const G_ACTION: u64 = 15_585_968;
/// Length of an action salt.
pub const ACTION_SALT_BYTES: usize = 32;
/// Length of an entry point selector of the Guard contract.
pub const SELECTOR_BYTES: usize = 4;
/// Length of the cancel calldata: selector (4), `F_new` (32), `salt_new`
/// (16), `note_new` (380).
pub const CANCEL_CALLDATA_BYTES: usize = SELECTOR_BYTES + 32 + crate::commit::SALT_BYTES + NOTE_BYTES;
/// Length of the release calldata: selector (4), the slot's marker (32).
pub const RELEASE_CALLDATA_BYTES: usize = SELECTOR_BYTES + 32;
/// The type byte of a policy action (spec 10, section 8.1).
pub const ACTION_TX_TYPE: u8 = 0x54;
/// The version of a policy action, `0x0001`.
pub const ACTION_VERSION: [u8; 2] = [0x00, 0x01];
/// The length of a policy action's payload (spec 10, section 8.1).
pub const ACTION_PAYLOAD_BYTES: usize = 2 + 8 + 32 + 8 + 32 + 32 + 8 + 2 + ACTION_CALLDATA_MAX + ACTION_PROOF_BYTES;
/// The number of 32-byte words `slot(marker)` and `ghost_escrowSlot` return
/// (spec 10, sections 7.2 and 11).
pub const SLOT_WORDS: usize = 15;

const _: () = assert!(CANCEL_CALLDATA_BYTES == 432);
const _: () = assert!(CANCEL_CALLDATA_BYTES <= ACTION_CALLDATA_MAX);
const _: () = assert!(ACTION_PAYLOAD_BYTES == 949_372);

/// Why a Guard operation was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardError {
    /// The Guard address is a reserved address (spec 10, section 6.5) or the
    /// code hash is zero: no frozen policy can be there.
    PolicyNotUsable,
    /// The caller's random source gave 32 zero bytes, which is no salt or
    /// stop root at all.
    ZeroRandom,
    /// A new Guard coin's action salt equals the salt of the coin or slot it
    /// comes from.
    SaltReused,
    /// The coin tree is within [`HOLD_BLOCKS`] blocks of full at the caller's
    /// leaves per block: a cancel's re-commit could find it full.
    TreeNearlyFull,
    /// The tree room cannot be checked: zero leaves per block, more leaves
    /// than a tree holds, or an overflow.
    TreeRoomUnknown,
    /// The coin or capsule is not a Guard coin of this policy, or the rule
    /// given is not the coin's.
    NotAGuardCoin,
    /// The guard secret does not open the rule's override hash.
    WrongGuardSecret,
    /// The stop root does not open the slot's action tag.
    NotTheStopRoot,
    /// The slot belongs to another policy or has other parameters.
    SlotNotGuard,
    /// The slot is closed.
    SlotClosed,
    /// The slot has no action tag: nothing can cancel it.
    SlotHasNoActions,
    /// `remaining <= debit`: the cancel cannot run (spec 10, section 12).
    SlotTooSmall,
    /// The debit is below the action cost, or zero.
    DebitBelowActionCost,
    /// The action cost is zero: it cannot be checked.
    ActionCostUnknown,
    /// The expiry is before the next block.
    Expired,
    /// The hold in blocks or in seconds is not over, or cannot be computed.
    HoldNotOver,
    /// The slot's `instr` has a non-zero byte in its top 12: release fails.
    InstrNotAnAddress,
    /// A slot word that is not what `slot()` writes, or a slot whose amounts
    /// do not add up.
    MalformedSlot,
    /// A transfer to the key that already holds the coin.
    TransferToSameKey,
    /// The coin's number is the last a key has.
    NumbersExhausted,
    /// The proofs crate refused the spend or failed to prove it. Too little
    /// value for `out + fee` is [`ProofError::ConservationFails`].
    Proof(ProofError),
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyNotUsable => f.write_str("the Guard address is reserved or its code hash is zero"),
            Self::ZeroRandom => f.write_str("the random source gave only zero bytes"),
            Self::SaltReused => f.write_str("a new Guard coin would reuse an action salt"),
            Self::TreeNearlyFull => f.write_str("the coin tree is within the hold period of full"),
            Self::TreeRoomUnknown => f.write_str("the coin tree's room cannot be checked"),
            Self::NotAGuardCoin => f.write_str("not a Guard coin of this policy"),
            Self::WrongGuardSecret => f.write_str("the guard secret does not open this coin's override"),
            Self::NotTheStopRoot => f.write_str("the stop root does not open this slot"),
            Self::SlotNotGuard => f.write_str("the slot is not a Guard slot"),
            Self::SlotClosed => f.write_str("the slot is closed"),
            Self::SlotHasNoActions => f.write_str("the slot has no action tag"),
            Self::SlotTooSmall => f.write_str("the slot is not larger than the debit: a cancel cannot run"),
            Self::DebitBelowActionCost => f.write_str("the debit is below the action cost"),
            Self::ActionCostUnknown => f.write_str("the action cost is unknown"),
            Self::Expired => f.write_str("the expiry is before the next block"),
            Self::HoldNotOver => f.write_str("the hold is not over"),
            Self::InstrNotAnAddress => f.write_str("the slot's payout instruction is not an address"),
            Self::MalformedSlot => f.write_str("the slot words are malformed"),
            Self::TransferToSameKey => f.write_str("a transfer must go to a new key"),
            Self::NumbersExhausted => f.write_str("the key has no commitment number left"),
            Self::Proof(error) => write!(f, "the spend was refused: {error}"),
        }
    }
}

impl std::error::Error for GuardError {}

impl From<ProofError> for GuardError {
    fn from(error: ProofError) -> Self {
        Self::Proof(error)
    }
}

/// The chain a Guard transaction is for. Each class binds its own protocol
/// version (spec 10, sections 4.2, 5.1 and 8.2), so the module sets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardChain {
    /// The chain identifier.
    pub chain_id: u64,
    /// The genesis block hash.
    pub domain: [u8; 32],
}

impl GuardChain {
    fn params(&self, version: [u8; 2]) -> ghost_proofs::ChainParams {
        ghost_proofs::ChainParams {
            chain_id: self.chain_id.to_be_bytes(),
            version,
            domain: self.domain,
        }
    }

    /// The parameters of the ordinary class, version `0x0002`.
    pub fn ordinary_params(&self) -> ghost_proofs::ChainParams {
        self.params(PROTOCOL_VERSION_2)
    }

    /// The parameters of the policy class, version `0x0001`.
    pub fn policy_params(&self) -> ghost_proofs::ChainParams {
        self.params(PROTOCOL_VERSION_1)
    }

    /// The parameters of a policy action, version `0x0001`.
    pub fn action_params(&self) -> ghost_proofs::ChainParams {
        self.params(ACTION_VERSION)
    }
}

/// The Guard policy: its address and code hash, which the caller supplies
/// until the Guard code is final (spec 10, section 15, item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardPolicy {
    address: [u8; POLICY_ADDRESS_BYTES],
    codehash: [u8; 32],
}

/// The prefix of the native accounts `0x6768...01` to `...0a`.
const NATIVE_ACCOUNT_PREFIX: [u8; 5] = *b"ghost";

impl GuardPolicy {
    /// The policy at `address` with `codehash`. A reserved address (below
    /// `0x10000`, or a native account `0x6768...01` to `...0a`, spec 10,
    /// section 6.5) or a zero code hash is [`GuardError::PolicyNotUsable`].
    pub fn new(address: [u8; POLICY_ADDRESS_BYTES], codehash: [u8; 32]) -> Result<Self, GuardError> {
        let low = address[..POLICY_ADDRESS_BYTES - 2].iter().all(|&byte| byte == 0);
        let native = address[..5] == NATIVE_ACCOUNT_PREFIX
            && address[5..POLICY_ADDRESS_BYTES - 1].iter().all(|&byte| byte == 0)
            && (0x01..=0x0a).contains(&address[POLICY_ADDRESS_BYTES - 1]);
        if low || native || codehash == [0; 32] {
            return Err(GuardError::PolicyNotUsable);
        }
        Ok(Self { address, codehash })
    }

    /// The policy address.
    pub const fn address(&self) -> &[u8; POLICY_ADDRESS_BYTES] {
        &self.address
    }

    /// The policy code hash.
    pub const fn codehash(&self) -> &[u8; 32] {
        &self.codehash
    }
}

/// `params_hash` of Guard's empty parameters: `K("ghost/policy-params/v1")`.
pub fn guard_params_hash() -> [u8; 32] {
    hash::k(TAG_POLICY_PARAMS, &[])
}

/// The guard secret: the override secret of a Guard coin, held by the app.
/// It has no `Debug`, `Display`, `Clone` or serialisation, and is wiped when
/// dropped.
pub struct GuardSecret([u8; 32]);

impl GuardSecret {
    /// The guard secret number `index` of a wallet seed:
    /// `X("ghost/wallet-guard-secret/v1", 32, seed, index as 4 bytes)`. The
    /// wallet seed never derives a Phantom Key, nor a key a seed (spec 09,
    /// section 9), and this is the only way the module makes one.
    pub fn from_seed(seed: &WalletSeed, index: u32) -> Self {
        Self(hash::x::<32>(TAG_GUARD_SECRET, &[seed.as_bytes(), &index.to_be_bytes()]))
    }

    /// The 32 secret bytes. Pass them on; never store or log them.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `override_hash = K("ghost/policy-override/v1", secret)`.
    pub fn override_hash(&self) -> [u8; 32] {
        policy_override_hash(&self.0)
    }
}

impl Drop for GuardSecret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// The stop root: the `action_root` of a Guard coin, held by the stop card.
/// It has no `Debug`, `Display`, `Clone` or serialisation, and is wiped when
/// dropped.
pub struct StopRoot([u8; 32]);

impl StopRoot {
    /// A new stop root: 32 bytes from the caller's secure random source. All
    /// zero bytes are [`GuardError::ZeroRandom`].
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, GuardError> {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let root = Self::from_bytes(bytes);
        wipe(&mut bytes);
        root
    }

    /// The stop root the card holds, from its 32 bytes. The caller wipes its
    /// copy. All zero bytes are [`GuardError::ZeroRandom`].
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, GuardError> {
        if bytes == [0; 32] {
            return Err(GuardError::ZeroRandom);
        }
        Ok(Self(bytes))
    }

    /// The 32 secret bytes. Pass them on; never store or log them.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `action_tag = K("ghost/policy-action/v1", stop root, action_salt)`.
    pub fn action_tag(&self, salt: &ActionSalt) -> [u8; 32] {
        policy_action_tag(&self.0, &salt.0)
    }
}

impl Drop for StopRoot {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// The action salt of a Guard coin: 32 fresh random bytes per coin. It is
/// private in the capsule until a words-only spend publishes it, so it has no
/// `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActionSalt([u8; ACTION_SALT_BYTES]);

impl ActionSalt {
    /// A fresh salt from the caller's secure random source. All zero bytes
    /// are [`GuardError::ZeroRandom`]: they mean "no actions".
    fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, GuardError> {
        let mut bytes = [0u8; ACTION_SALT_BYTES];
        rng.fill_bytes(&mut bytes);
        if bytes == [0; ACTION_SALT_BYTES] {
            return Err(GuardError::ZeroRandom);
        }
        Ok(Self(bytes))
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; ACTION_SALT_BYTES] {
        &self.0
    }
}

/// A Guard rule: the six fields of spec 10, section 3.1 with Guard's policy,
/// empty parameters, the override hash of a guard secret and the action tag
/// of a stop root under a fresh action salt.
///
/// It holds the private rule fields, so it has no `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GuardRule {
    policy: GuardPolicy,
    override_hash: [u8; 32],
    action_tag: [u8; 32],
    action_salt: ActionSalt,
}

impl GuardRule {
    /// A new Guard rule for a new coin, under a fresh action salt drawn from
    /// the caller's secure random source.
    pub fn new<R: CryptoRng + ?Sized>(
        policy: &GuardPolicy,
        secret: &GuardSecret,
        stop: &StopRoot,
        rng: &mut R,
    ) -> Result<Self, GuardError> {
        let action_salt = ActionSalt::random(rng)?;
        Ok(Self {
            policy: *policy,
            override_hash: secret.override_hash(),
            action_tag: stop.action_tag(&action_salt),
            action_salt,
        })
    }

    /// The Guard rule a capsule opens: a version 1 capsule with this
    /// policy's address and code hash, empty parameters, and a non-zero
    /// override hash, action tag and action salt. Anything else is
    /// [`GuardError::NotAGuardCoin`]. This is how a receiver hands over the
    /// rule a transfer's remainder takes, and how restore recognises a Guard
    /// coin.
    pub fn from_capsule(policy: &GuardPolicy, capsule: &Capsule) -> Result<Self, GuardError> {
        let is_guard = !capsule.is_empty()
            && capsule.policy_address() == &policy.address
            && capsule.policy_codehash() == &policy.codehash
            && capsule.params().is_empty()
            && capsule.override_hash() != &[0; 32]
            && capsule.action_tag() != &[0; 32]
            && capsule.action_salt() != &[0; 32];
        if !is_guard {
            return Err(GuardError::NotAGuardCoin);
        }
        Ok(Self {
            policy: *policy,
            override_hash: *capsule.override_hash(),
            action_tag: *capsule.action_tag(),
            action_salt: ActionSalt(*capsule.action_salt()),
        })
    }

    /// The Guard rule of a coin restore found: its capsule's, checked against
    /// the coin's rule.
    pub fn of_coin(policy: &GuardPolicy, coin: &FoundCoin) -> Result<Self, GuardError> {
        let rule = Self::from_capsule(policy, &coin.capsule)?;
        if rule.rule() != coin.rule {
            return Err(GuardError::NotAGuardCoin);
        }
        Ok(rule)
    }

    /// The policy.
    pub const fn policy(&self) -> &GuardPolicy {
        &self.policy
    }

    /// The override hash.
    pub const fn override_hash(&self) -> &[u8; 32] {
        &self.override_hash
    }

    /// The action tag.
    pub const fn action_tag(&self) -> &[u8; 32] {
        &self.action_tag
    }

    /// The action salt.
    pub const fn action_salt(&self) -> &ActionSalt {
        &self.action_salt
    }

    /// The six fields as the proofs crate takes them.
    fn policy_rule(&self) -> PolicyRule {
        PolicyRule {
            policy_address: self.policy.address,
            policy_codehash: self.policy.codehash,
            params_hash: guard_params_hash(),
            override_hash: self.override_hash,
            action_tag: self.action_tag,
            action_salt: self.action_salt.0,
        }
    }

    /// The 32-byte rule the coin's fingerprint holds.
    pub fn rule(&self) -> Rule {
        Rule::from_bytes(self.policy_rule().rule())
    }

    /// The version 1 capsule that opens this rule (spec 10, section 3.2).
    pub fn capsule(&self) -> Capsule {
        Capsule::policy(
            self.policy.address,
            self.policy.codehash,
            &[],
            self.override_hash,
            self.action_tag,
            self.action_salt.0,
        )
        .expect("empty parameters fit a capsule")
    }

    /// Whether the guard secret opens this rule's override.
    pub fn opened_by(&self, secret: &GuardSecret) -> bool {
        secret.override_hash() == self.override_hash
    }
}

/// The coin tree's room, as the caller read it from the chain: the leaves it
/// holds and the most leaves one block can add.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeRoom {
    /// The leaves the coin tree holds now.
    pub filled_leaves: u64,
    /// The most leaves one block can add to the coin tree.
    pub leaves_per_block: u64,
}

impl TreeRoom {
    /// Refuses a Guard commit when the tree's free leaves are at most
    /// [`HOLD_BLOCKS`] times the leaves a block can add: within the hold the
    /// tree could fill, and a cancel's re-commit would fail (spec 10,
    /// section 15, item 5). Zero leaves per block, more leaves than a tree
    /// holds and an overflow are [`GuardError::TreeRoomUnknown`].
    pub fn check(&self) -> Result<(), GuardError> {
        if self.leaves_per_block == 0 {
            return Err(GuardError::TreeRoomUnknown);
        }
        let free = MAX_TREE_LEAVES
            .checked_sub(self.filled_leaves)
            .ok_or(GuardError::TreeRoomUnknown)?;
        let need = HOLD_BLOCKS
            .checked_mul(self.leaves_per_block)
            .ok_or(GuardError::TreeRoomUnknown)?;
        if free <= need {
            return Err(GuardError::TreeNearlyFull);
        }
        Ok(())
    }
}

/// A Guard commit: what the commit carries and what the wallet tracks.
pub struct GuardCommit {
    /// The coin commitment, number 0 of the key.
    pub commit: CoinCommit,
    /// The amount.
    pub amount: Amount,
    /// The coin's Guard rule.
    pub rule: GuardRule,
    /// The 380-byte note with the rule's capsule.
    pub note: [u8; NOTE_BYTES],
    /// The commit's data: format version, `F`, salt and note.
    pub data: [u8; SALTED_COMMIT_DATA_BYTES],
}

/// Commits `amount` to a new Guard coin, number 0 of `key`, whose
/// fingerprint holds `rule` and whose note holds its capsule (spec 10,
/// section 12, "Commit"). Refuses when the coin tree is within the hold
/// period of full ([`TreeRoom::check`]).
pub fn guard_commit<R: CryptoRng + ?Sized>(
    key: &PhantomKey,
    chain_id: u64,
    amount: Amount,
    rule: &GuardRule,
    room: &TreeRoom,
    rng: &mut R,
) -> Result<GuardCommit, GuardError> {
    room.check()?;
    let salt = Salt::random(rng);
    let commit = key.coin_commit_with_rule(0, amount, rule.rule(), salt);
    let contents = NoteContents::salted_coin(0, amount, rule.rule(), salt);
    let note = encrypt_note(&key.note_key(), chain_id, &commit.commitment, &contents, &rule.capsule(), rng);
    Ok(GuardCommit {
        commit,
        amount,
        rule: *rule,
        data: salted_commit_data(&commit.fingerprint, &salt, &note),
        note,
    })
}

/// The rule a spend's remainder takes: the owner's choice (spec 10, section
/// 4.3, O6).
#[derive(Clone, Copy)]
pub enum RemainderRule {
    /// The empty rule: the remainder is a plain coin.
    Empty,
    /// A Guard rule with a fresh action salt: the owner's own new rule, or a
    /// receiver's ([`GuardRule::from_capsule`]). A new Guard coin, so the
    /// tree's room is checked as for a commit.
    Guard {
        /// The remainder's rule.
        rule: GuardRule,
        /// The coin tree's room.
        room: TreeRoom,
    },
}

/// A coin a Guard operation creates: a spend's remainder or a cancel's new
/// coin. It holds the number and amount, so it has no `Debug`.
#[derive(Clone, Copy)]
pub struct GuardRemainder {
    /// Its number under the key that holds it.
    pub number: u64,
    /// Its amount.
    pub amount: Amount,
    /// Its rule.
    pub rule: Rule,
    /// The capsule its note carries.
    pub capsule: Capsule,
    /// Its commitment salt.
    pub salt: Salt,
    /// The leaf `C`.
    pub commitment: Commitment,
    /// Its marker.
    pub marker: Marker,
    /// Its 380-byte note.
    pub note: [u8; NOTE_BYTES],
}

/// A built normal spend or transfer: an ordinary class reveal (type `0x50`,
/// version `0x0002`) with the override.
pub struct BuiltGuardSpend {
    /// The public fields the transaction carries.
    pub reveal: CoinRevealV2,
    /// The proof.
    pub proof: Proof,
    /// The remainder.
    pub remainder: GuardRemainder,
}

/// The normal spend of a Guard coin (spec 10, section 12): the ordinary class
/// with `use_override = 1`. Pays `out` to the recipient and keeps
/// `v - out - fee` under the same key as number `i + 1`, with the rule the
/// owner chose and a note with its capsule. Needs the guard secret.
#[allow(clippy::too_many_arguments)]
pub fn guard_spend<R: CryptoRng + ?Sized>(
    chain: &GuardChain,
    key: &PhantomKey,
    coin: &OwnedCoin,
    rule: &GuardRule,
    secret: &GuardSecret,
    terms: &RevealTerms,
    out: Amount,
    remainder_rule: RemainderRule,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltGuardSpend, GuardError> {
    let number = coin.number.checked_add(1).ok_or(GuardError::NumbersExhausted)?;
    override_spend(chain, key, coin, rule, secret, terms, out, key, number, remainder_rule, rng, zk_randomness)
}

/// A transfer of a Guard coin (spec 10, section 12): the ordinary class with
/// the override, the remainder `v - out - fee` going to `new_key` as its
/// number 0, with the receiver's own Guard rule (a fresh capsule) or the
/// empty rule. The giver's stop key has no hold on it after. Needs the guard
/// secret.
#[allow(clippy::too_many_arguments)]
pub fn guard_transfer<R: CryptoRng + ?Sized>(
    chain: &GuardChain,
    key: &PhantomKey,
    coin: &OwnedCoin,
    rule: &GuardRule,
    secret: &GuardSecret,
    new_key: &PhantomKey,
    terms: &RevealTerms,
    out: Amount,
    receiver_rule: RemainderRule,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltGuardSpend, GuardError> {
    if key.key_bytes().as_bytes() == new_key.key_bytes().as_bytes() {
        return Err(GuardError::TransferToSameKey);
    }
    override_spend(chain, key, coin, rule, secret, terms, out, new_key, 0, receiver_rule, rng, zk_randomness)
}

/// Checks that `rule` is the coin's.
fn check_coin_rule(coin: &OwnedCoin, rule: &GuardRule) -> Result<(), GuardError> {
    if coin.rule != rule.rule() {
        return Err(GuardError::NotAGuardCoin);
    }
    Ok(())
}

/// The opening of a key's coin, as the provers take it. The caller wipes it.
fn opening(key: &PhantomKey, coin: &OwnedCoin) -> SaltedCoinOpening {
    let input = key.key_bytes();
    SaltedCoinOpening {
        s: *input.secret().as_bytes(),
        r: *input.reveal_secret().as_bytes(),
        b: *input.blinding(coin.number).as_bytes(),
        salt: *coin.salt.as_bytes(),
        v: coin.amount.to_bytes(),
        position: coin.position,
        path: coin.path,
    }
}

/// A new coin of `holder`, number `number`, holding `amount` under `rule`
/// with a fresh commitment salt, its note under the holder's note key, and
/// the remainder witness the provers take (the caller wipes it).
#[allow(clippy::too_many_arguments)]
fn new_coin<R: CryptoRng + ?Sized>(
    holder: &PhantomKey,
    chain_id: u64,
    number: u64,
    amount: Amount,
    rule: Rule,
    capsule: Capsule,
    rng: &mut R,
) -> (GuardRemainder, SaltedCoinRemainder) {
    let salt = Salt::random(rng);
    let commit = holder.coin_commit_with_rule(number, amount, rule, salt);
    let contents = NoteContents::salted_coin(number, amount, rule, salt);
    let note = encrypt_note(&holder.note_key(), chain_id, &commit.commitment, &contents, &capsule, rng);
    let output = holder.key_bytes();
    let witness = SaltedCoinRemainder {
        s: *output.secret().as_bytes(),
        r: *output.reveal_secret().as_bytes(),
        b: *output.blinding(number).as_bytes(),
        salt: *salt.as_bytes(),
        v: amount.to_bytes(),
    };
    let remainder = GuardRemainder {
        number,
        amount,
        rule,
        capsule,
        salt,
        commitment: commit.commitment,
        marker: commit.marker,
        note,
    };
    (remainder, witness)
}

fn wipe_witnesses(opening: &mut SaltedCoinOpening, remainder: &mut SaltedCoinRemainder) {
    for secret in [&mut opening.s, &mut opening.r, &mut opening.b, &mut opening.v] {
        wipe(secret);
    }
    for secret in [&mut remainder.s, &mut remainder.r, &mut remainder.b, &mut remainder.v] {
        wipe(secret);
    }
}

#[allow(clippy::too_many_arguments)]
fn override_spend<R: CryptoRng + ?Sized>(
    chain: &GuardChain,
    key: &PhantomKey,
    coin: &OwnedCoin,
    rule: &GuardRule,
    secret: &GuardSecret,
    terms: &RevealTerms,
    out: Amount,
    holder: &PhantomKey,
    number: u64,
    remainder_rule: RemainderRule,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltGuardSpend, GuardError> {
    check_coin_rule(coin, rule)?;
    if !rule.opened_by(secret) {
        return Err(GuardError::WrongGuardSecret);
    }
    let left = coin
        .amount
        .wei()
        .checked_sub(out.wei())
        .and_then(|wei| wei.checked_sub(terms.fee.wei()))
        .and_then(|wei| Amount::new(wei).ok())
        .ok_or(GuardError::Proof(ProofError::ConservationFails))?;
    let (out_rule, capsule) = match remainder_rule {
        RemainderRule::Empty => (Rule::EMPTY, Capsule::empty()),
        RemainderRule::Guard { rule: new_rule, room } => {
            if new_rule.action_salt == rule.action_salt {
                return Err(GuardError::SaltReused);
            }
            room.check()?;
            (new_rule.rule(), new_rule.capsule())
        }
    };
    let (remainder, mut witness) = new_coin(holder, chain.chain_id, number, left, out_rule, capsule, rng);
    let mut opened = opening(key, coin);
    let mut input = InputRule::with_override(rule.policy_rule(), *secret.as_bytes());
    let request = CoinRevealV2Request {
        root: terms.root,
        recipient: terms.recipient,
        out: out.to_bytes(),
        fee: terms.fee.to_bytes(),
        remainder_note: remainder.note,
    };
    let proved = prove_coin_reveal_v2(
        &chain.ordinary_params(),
        &opened,
        &input,
        &witness,
        out_rule.as_bytes(),
        &request,
        zk_randomness,
    );
    wipe(&mut input.override_secret);
    wipe_witnesses(&mut opened, &mut witness);
    let (reveal, proof) = proved?;
    debug_assert_eq!(&reveal.remainder, remainder.commitment.as_bytes());
    Ok(BuiltGuardSpend {
        reveal,
        proof,
        remainder,
    })
}

/// A built words-only spend: a policy class reveal (type `0x53`).
pub struct BuiltWordsOnlySpend {
    /// The public fields the transaction carries.
    pub reveal: PolicyReveal,
    /// The proof.
    pub proof: Proof,
    /// The zero-value remainder, number `i + 1` of the key, empty rule.
    pub remainder: GuardRemainder,
}

/// The payout instruction of a words-only spend: 12 zero bytes, then the
/// recipient's address (spec 10, section 12).
pub fn instr_for(recipient: &[u8; 20]) -> [u8; 32] {
    let mut instr = [0u8; 32];
    instr[12..].copy_from_slice(recipient);
    instr
}

/// The words-only spend of a Guard coin (spec 10, section 12): the policy
/// class, a full sweep of `v - fee` into Guard's escrow slot, `instr` naming
/// the recipient. It needs only the words and the coin's capsule, which
/// restore reads from the note: no guard secret and no stop root. The stop
/// card can cancel it during the hold.
#[allow(clippy::too_many_arguments)]
pub fn words_only_spend<R: CryptoRng + ?Sized>(
    chain: &GuardChain,
    key: &PhantomKey,
    coin: &OwnedCoin,
    rule: &GuardRule,
    root: [u8; 32],
    fee: Amount,
    recipient: &[u8; 20],
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltWordsOnlySpend, GuardError> {
    check_coin_rule(coin, rule)?;
    let number = coin.number.checked_add(1).ok_or(GuardError::NumbersExhausted)?;
    let out = coin
        .amount
        .wei()
        .checked_sub(fee.wei())
        .and_then(|wei| Amount::new(wei).ok())
        .ok_or(GuardError::Proof(ProofError::ConservationFails))?;
    let zero = Amount::new(0).expect("zero is an amount");
    let (remainder, mut witness) = new_coin(key, chain.chain_id, number, zero, Rule::EMPTY, Capsule::empty(), rng);
    let mut opened = opening(key, coin);
    let request = PolicyRevealRequest {
        root,
        out: out.to_bytes(),
        fee: fee.to_bytes(),
        instr: instr_for(recipient),
        remainder_note: remainder.note,
    };
    let proved = prove_policy_reveal(
        &chain.policy_params(),
        &opened,
        &rule.policy_rule(),
        &witness,
        &request,
        zk_randomness,
    );
    wipe_witnesses(&mut opened, &mut witness);
    let (reveal, proof) = proved?;
    debug_assert_eq!(&reveal.remainder, remainder.commitment.as_bytes());
    Ok(BuiltWordsOnlySpend {
        reveal,
        proof,
        remainder,
    })
}

/// An escrow slot as `slot(marker)` and `ghost_escrowSlot` return it (spec
/// 10, sections 7.1, 7.2 and 11). Public chain data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowSlot {
    /// The slot's policy.
    pub policy_address: [u8; POLICY_ADDRESS_BYTES],
    /// Whether the slot is open.
    pub open: bool,
    /// The value left in the slot.
    pub remaining: Amount,
    /// The value the slot opened with.
    pub out: Amount,
    /// The value paid out.
    pub paid: Amount,
    /// The value re-committed.
    pub recommitted: Amount,
    /// The value spent on actions.
    pub action_debits: Amount,
    /// The value forfeited by a close.
    pub forfeited: Amount,
    /// The nonce the next action must carry.
    pub action_nonce: u64,
    /// The opening block's height.
    pub height: u64,
    /// The opening block's timestamp.
    pub timestamp: u64,
    /// The rule's `params_hash`.
    pub params_hash: [u8; 32],
    /// The rule's `action_tag`.
    pub action_tag: [u8; 32],
    /// The rule's `action_salt`.
    pub action_salt: [u8; 32],
    /// The payout instruction.
    pub instr: [u8; 32],
}

fn word_address(word: &[u8; 32]) -> Result<[u8; POLICY_ADDRESS_BYTES], GuardError> {
    if word[..32 - POLICY_ADDRESS_BYTES].iter().any(|&byte| byte != 0) {
        return Err(GuardError::MalformedSlot);
    }
    let mut out = [0u8; POLICY_ADDRESS_BYTES];
    out.copy_from_slice(&word[32 - POLICY_ADDRESS_BYTES..]);
    Ok(out)
}

fn word_amount(word: &[u8; 32]) -> Result<Amount, GuardError> {
    // An amount word: the top 20 bytes zero, so the value is below 2^96.
    if word[..20].iter().any(|&byte| byte != 0) {
        return Err(GuardError::MalformedSlot);
    }
    let mut low = [0u8; 16];
    low.copy_from_slice(&word[16..]);
    Amount::new(u128::from_be_bytes(low)).map_err(|_| GuardError::MalformedSlot)
}

fn word_u64(word: &[u8; 32]) -> Result<u64, GuardError> {
    if word[..24].iter().any(|&byte| byte != 0) {
        return Err(GuardError::MalformedSlot);
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(low))
}

impl EscrowSlot {
    /// The slot from the fifteen 32-byte words of `slot(marker)`, in the
    /// order of spec 10, section 7.2: `policy_address`, `open`, `remaining`,
    /// `out`, `paid`, `recommitted`, `action_debits`, `forfeited`,
    /// `action_nonce`, `height`, `timestamp`, `params_hash`, `action_tag`,
    /// `action_salt`, `instr`. Refuses as [`GuardError::MalformedSlot`] an
    /// address word with a high byte set, an `open` word other than 0 or 1,
    /// an amount word at or above `2^96`, a number word above `2^64 - 1`, and
    /// amounts that break `out = remaining + paid + recommitted +
    /// action_debits + forfeited` (spec 10, section 7.3).
    pub fn from_words(words: &[[u8; 32]; SLOT_WORDS]) -> Result<Self, GuardError> {
        let open = match word_u64(&words[1])? {
            0 => false,
            1 => true,
            _ => return Err(GuardError::MalformedSlot),
        };
        let slot = Self {
            policy_address: word_address(&words[0])?,
            open,
            remaining: word_amount(&words[2])?,
            out: word_amount(&words[3])?,
            paid: word_amount(&words[4])?,
            recommitted: word_amount(&words[5])?,
            action_debits: word_amount(&words[6])?,
            forfeited: word_amount(&words[7])?,
            action_nonce: word_u64(&words[8])?,
            height: word_u64(&words[9])?,
            timestamp: word_u64(&words[10])?,
            params_hash: words[11],
            action_tag: words[12],
            action_salt: words[13],
            instr: words[14],
        };
        let total = [slot.paid, slot.recommitted, slot.action_debits, slot.forfeited]
            .iter()
            .try_fold(slot.remaining.wei(), |sum, amount| sum.checked_add(amount.wei()));
        if total != Some(slot.out.wei()) {
            return Err(GuardError::MalformedSlot);
        }
        Ok(slot)
    }

    /// Whether this is an open slot of the Guard policy, with Guard's empty
    /// parameters.
    fn check_guard(&self, policy: &GuardPolicy) -> Result<(), GuardError> {
        if self.policy_address != policy.address || self.params_hash != guard_params_hash() {
            return Err(GuardError::SlotNotGuard);
        }
        if !self.open || self.remaining.wei() == 0 {
            return Err(GuardError::SlotClosed);
        }
        Ok(())
    }
}

/// The chain's head as the caller read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    /// The head block's height.
    pub height: u64,
    /// The head block's timestamp.
    pub timestamp: u64,
}

/// A release call: an ordinary account transaction to Guard that anyone may
/// send and that pays its own gas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseCall {
    /// The Guard address.
    pub to: [u8; POLICY_ADDRESS_BYTES],
    /// The calldata: the release selector, then the slot's marker.
    pub data: [u8; RELEASE_CALLDATA_BYTES],
}

impl ReleaseCall {
    /// The account transaction that carries the call, with value zero and
    /// the sender's own nonce, fees and gas limit, to be signed by the
    /// sender's account key.
    pub fn account_tx(
        &self,
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
    ) -> AccountTx {
        AccountTx {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: Some(self.to),
            value: 0,
            data: self.data.to_vec(),
            access_list: Vec::new(),
        }
    }
}

/// The release of a Guard slot after the hold (spec 10, section 12,
/// "Release"): `Guard.release(marker)` pays all of `remaining` to the address
/// in `instr`. Refuses, as Guard would: a slot of another policy or a closed
/// one, an `instr` whose top 12 bytes are not zero, and a head that is not
/// at least [`HOLD_BLOCKS`] blocks and [`HOLD_SECONDS`] seconds past the
/// slot's opening block ([`GuardError::HoldNotOver`], also when the sum
/// overflows). `selector` is the release entry point's selector.
pub fn guard_release(
    policy: &GuardPolicy,
    marker: &Marker,
    slot: &EscrowSlot,
    head: &ChainHead,
    selector: [u8; SELECTOR_BYTES],
) -> Result<ReleaseCall, GuardError> {
    slot.check_guard(policy)?;
    if slot.instr[..12].iter().any(|&byte| byte != 0) {
        return Err(GuardError::InstrNotAnAddress);
    }
    let blocks_over = slot.height.checked_add(HOLD_BLOCKS).is_some_and(|end| head.height >= end);
    let seconds_over = slot.timestamp.checked_add(HOLD_SECONDS).is_some_and(|end| head.timestamp >= end);
    if !(blocks_over && seconds_over) {
        return Err(GuardError::HoldNotOver);
    }
    let mut data = [0u8; RELEASE_CALLDATA_BYTES];
    data[..SELECTOR_BYTES].copy_from_slice(&selector);
    data[SELECTOR_BYTES..].copy_from_slice(marker.as_bytes());
    Ok(ReleaseCall {
        to: policy.address,
        data,
    })
}

/// The choices of a cancel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelTerms {
    /// The amount the action takes from the slot. At least the action cost;
    /// what is above it is the tip.
    pub debit: Amount,
    /// The last block height at which the action is valid.
    pub expiry: u64,
    /// The action cost, `G_ACTION` times the base fee ([`action_cost`]).
    pub action_cost: u128,
    /// The head's height: the action can land from the next block.
    pub head_height: u64,
    /// The selector of Guard's cancel entry point.
    pub selector: [u8; SELECTOR_BYTES],
}

/// A built cancel: a policy action (type `0x54`) on the slot.
pub struct BuiltCancel {
    /// The slot's marker.
    pub marker: Marker,
    /// The chain identifier.
    pub chain_id: u64,
    /// The calldata: the cancel selector, `F_new`, `salt_new`, `note_new`.
    pub calldata: [u8; CANCEL_CALLDATA_BYTES],
    /// The public inputs of `KNOW_ACTION_v1`, as the node sets them.
    pub statement: KnowAction,
    /// The proof of the stop root.
    pub proof: Proof,
    /// The coin Guard re-commits: number 0 of the new key, holding
    /// `remaining - debit`.
    pub new_coin: GuardRemainder,
    /// The new coin's Guard rule, under a fresh action salt.
    pub new_rule: GuardRule,
}

impl BuiltCancel {
    /// The action's payload (spec 10, section 8.1): version, `chain_id`,
    /// marker, `action_nonce`, `expected_remaining`, `debit`, `expiry`,
    /// `calldata_len`, calldata zero-padded to 1,024 bytes, proof zero-padded
    /// to `ACTION_PROOF_BYTES`.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACTION_PAYLOAD_BYTES);
        out.extend_from_slice(&ACTION_VERSION);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(self.marker.as_bytes());
        out.extend_from_slice(&self.statement.action_nonce.to_be_bytes());
        out.extend_from_slice(&self.statement.expected_remaining);
        out.extend_from_slice(&self.statement.debit);
        out.extend_from_slice(&self.statement.expiry.to_be_bytes());
        out.extend_from_slice(&(CANCEL_CALLDATA_BYTES as u16).to_be_bytes());
        out.extend_from_slice(&self.calldata);
        out.resize(ACTION_PAYLOAD_BYTES - ACTION_PROOF_BYTES, 0);
        out.extend_from_slice(self.proof.as_bytes());
        out.resize(ACTION_PAYLOAD_BYTES, 0);
        out
    }

    /// The envelope: the type byte `0x54`, then the payload.
    pub fn envelope(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ACTION_PAYLOAD_BYTES);
        out.push(ACTION_TX_TYPE);
        out.extend_from_slice(&self.payload());
        out
    }
}

/// The cancel of a words-only spend (spec 10, section 12, "Cancel"): from
/// the slot the caller read, the debit and expiry chosen, it builds the new
/// key's coin for exactly `remaining - debit` under a new Guard rule with a
/// fresh action salt, the calldata `selector || F_new || salt_new ||
/// note_new`, and the action's proof of the stop root.
///
/// Refuses: a slot of another policy, a closed one, one with no action tag;
/// a stop root that does not open the slot's action tag; a zero action cost;
/// a debit below the action cost; `remaining <= debit` (the cancel cannot
/// run); an expiry before the next block; and a new action salt equal to the
/// slot's.
///
/// The new coin is a Guard coin of `secret` and `stop`. `new_key` must be a
/// new key: the old one's words are what the cancel defends against. The
/// tree's room is not checked here: a cancel is never held back, and a full
/// tree makes Guard's re-commit fail on the chain (spec 10, section 12).
#[allow(clippy::too_many_arguments)]
pub fn guard_cancel<R: CryptoRng + ?Sized>(
    chain: &GuardChain,
    policy: &GuardPolicy,
    marker: &Marker,
    slot: &EscrowSlot,
    stop: &StopRoot,
    secret: &GuardSecret,
    new_key: &PhantomKey,
    terms: &CancelTerms,
    rng: &mut R,
    zk_randomness: [u8; 32],
) -> Result<BuiltCancel, GuardError> {
    slot.check_guard(policy)?;
    if slot.action_tag == [0; 32] {
        return Err(GuardError::SlotHasNoActions);
    }
    if policy_action_tag(stop.as_bytes(), &slot.action_salt) != slot.action_tag {
        return Err(GuardError::NotTheStopRoot);
    }
    if terms.action_cost == 0 {
        return Err(GuardError::ActionCostUnknown);
    }
    if terms.debit.wei() == 0 || terms.debit.wei() < terms.action_cost {
        return Err(GuardError::DebitBelowActionCost);
    }
    if slot.remaining.wei() <= terms.debit.wei() {
        return Err(GuardError::SlotTooSmall);
    }
    let settled = Amount::new(slot.remaining.wei() - terms.debit.wei()).expect("below the remaining amount");
    if !terms.head_height.checked_add(1).is_some_and(|next| terms.expiry >= next) {
        return Err(GuardError::Expired);
    }

    let new_rule = GuardRule::new(policy, secret, stop, rng)?;
    if new_rule.action_salt.0 == slot.action_salt {
        return Err(GuardError::SaltReused);
    }
    let (new_coin, mut witness) = new_coin(
        new_key,
        chain.chain_id,
        0,
        settled,
        new_rule.rule(),
        new_rule.capsule(),
        rng,
    );
    for secret_bytes in [&mut witness.s, &mut witness.r, &mut witness.b, &mut witness.v] {
        wipe(secret_bytes);
    }
    let fingerprint = new_key.coin_commit_with_rule(0, settled, new_coin.rule, new_coin.salt).fingerprint;

    let mut calldata = [0u8; CANCEL_CALLDATA_BYTES];
    let (selector, rest) = calldata.split_at_mut(SELECTOR_BYTES);
    selector.copy_from_slice(&terms.selector);
    let (f, rest) = rest.split_at_mut(32);
    f.copy_from_slice(fingerprint.as_bytes());
    let (salt, note) = rest.split_at_mut(crate::commit::SALT_BYTES);
    salt.copy_from_slice(new_coin.salt.as_bytes());
    note.copy_from_slice(&new_coin.note);

    let statement = KnowAction {
        policy_address: slot.policy_address,
        marker: *marker.as_bytes(),
        action_nonce: slot.action_nonce,
        action_tag: slot.action_tag,
        action_salt: slot.action_salt,
        expected_remaining: slot.remaining.to_bytes(),
        debit: terms.debit.to_bytes(),
        expiry: terms.expiry,
        calldata_hash: action_calldata_hash(&calldata)?,
    };
    let proof = prove_know_action(&chain.action_params(), &statement, stop.as_bytes(), zk_randomness)?;
    Ok(BuiltCancel {
        marker: *marker,
        chain_id: chain.chain_id,
        calldata,
        statement,
        proof,
        new_coin,
        new_rule,
    })
}

/// A Guard coin restore found.
#[derive(Clone, Copy)]
pub struct GuardFound {
    /// The coin.
    pub coin: FoundCoin,
    /// Its Guard rule, from its capsule.
    pub rule: GuardRule,
    /// Whether its marker is unspent.
    pub unspent: bool,
}

/// What a Guard restore found.
pub struct GuardRestored {
    /// Every coin of the key, as [`restore_coins`] found it.
    pub restored: Restored,
    /// The key's coins whose capsule opens a Guard rule of the policy.
    pub guard: Vec<GuardFound>,
}

/// Restores the key's coins from the words, as [`restore_coins`] does, and
/// picks out the Guard coins of `policy` by their capsules: a committed Guard
/// coin, a spend's Guard remainder and the coin a cancel re-committed to a
/// new key all come back with their rule.
pub fn restore_guard_coins(
    key: &PhantomKey,
    chain_id: u64,
    tree_index: u32,
    leaves: &[TreeLeaf],
    spent: &[Marker],
    policy: &GuardPolicy,
) -> Result<GuardRestored, RestoreError> {
    let restored = restore_coins(key, chain_id, tree_index, leaves, spent)?;
    let guard = restored
        .found
        .iter()
        .filter_map(|coin| {
            GuardRule::of_coin(policy, coin).ok().map(|rule| GuardFound {
                coin: *coin,
                rule,
                unspent: !spent.contains(&coin.marker),
            })
        })
        .collect();
    Ok(GuardRestored { restored, guard })
}

/// What a wallet must say before an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardWarning {
    /// The coin has a policy rule: handed over as words alone, it stays under
    /// the giver's stop key, who can cancel the receiver's words-only spend.
    /// Transfer it with [`guard_transfer`] instead.
    HandedOverAsWords,
    /// The coin's value is not above the action cost: a cancel of its slot
    /// cannot run at this base fee (spec 10, section 12).
    SlotNotAboveActionCost,
    /// The action cost is zero or unknown, so the slot size cannot be
    /// checked.
    ActionCostUnknown,
}

impl fmt::Display for GuardWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HandedOverAsWords => {
                "a Guard coin handed over as words alone stays under the giver's stop key"
            }
            Self::SlotNotAboveActionCost => "the coin is not larger than the cost of a cancel",
            Self::ActionCostUnknown => "the cost of a cancel is unknown",
        })
    }
}

/// The warning to show before handing a coin over as its words alone: any
/// coin with a policy rule stays under the giver's stop key.
pub fn hand_over_warning(coin: &FoundCoin) -> Option<GuardWarning> {
    (!coin.rule.is_empty()).then_some(GuardWarning::HandedOverAsWords)
}

/// The warning for a Guard coin of `value` at the caller's action cost
/// (`G_ACTION` times the base fee): [`GuardWarning::SlotNotAboveActionCost`]
/// when the value is not above it, [`GuardWarning::ActionCostUnknown`] when
/// the cost is zero.
pub fn slot_cost_warning(value: Amount, action_cost: u128) -> Option<GuardWarning> {
    if action_cost == 0 {
        Some(GuardWarning::ActionCostUnknown)
    } else if value.wei() <= action_cost {
        Some(GuardWarning::SlotNotAboveActionCost)
    } else {
        None
    }
}

/// The action cost at a base fee: `G_ACTION * base_fee`, `None` on overflow.
pub fn action_cost(base_fee: u128) -> Option<u128> {
    u128::from(G_ACTION).checked_mul(base_fee)
}

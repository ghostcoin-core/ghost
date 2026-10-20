//! Quantum-safe accounts (spec 09, sections 5, 6 and 9): the wallet seed and
//! its words, the account keys it derives, the account address, and the
//! account transaction signed with ML-DSA-44.
//!
//! The node takes the account transaction as type `0x52` (ghost-node
//! `docs/account-transactions.md`; spec 09 proposes `0x51`, which is the data
//! reveal in the node). Everything here matches the node byte for byte:
//!
//! ```text
//! key_seed(scheme, i) = X("ghost/wallet-account/v1", 32, seed, scheme, i as 4 bytes)
//! (sk, pk)            = ML-DSA-44.KeyGen_internal(key_seed)
//! sender              = first 20 bytes of K("ghost/account-address/v1", scheme, pk)
//! unsigned            = rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//!                            gas_limit, to, value, data, access_list, scheme, pk])
//! sighash             = K("ghost/account-tx/v1", 0x52, genesis_hash, keccak256(unsigned))
//! signature           = ML-DSA-44.Sign(sk, sighash, ctx = "ghost/tx/v1"), hedged
//! envelope            = 0x52 || rlp([... the eleven fields ..., signature])
//! ```
//!
//! A wallet seed and a Phantom Key never derive each other (spec 09,
//! section 9): the seed is 32 random bytes shown as 24 words, and the only
//! tag it is hashed under is `ghost/wallet-account/v1`. Words are refused in
//! a Phantom Key field and digits in a seed field.
//!
//! # Secrets
//!
//! [`WalletSeed`], [`SeedWords`] and [`AccountKey`] have no `Debug`,
//! `Display`, `Clone` or serialisation, and overwrite their bytes with zeros
//! when dropped (the ML-DSA key through the `zeroize` feature of `ml-dsa`).
//! Signing is hedged: 32 fresh bytes from the caller's generator are mixed
//! with the key, as FIPS 204 makes the default.

use core::fmt;

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa44, Signature, VerifyingKey};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};

use crate::hash::{k, x};
use crate::wipe::wipe;
use crate::wordlist::{WORD_COUNT, WORDLIST};

/// EIP-2718 type byte of the account transaction in the node.
pub const ACCOUNT_TX_TYPE: u8 = 0x52;
/// Scheme ID of ML-DSA-44 (FIPS 204), pure mode: the wallet's only scheme.
pub const SCHEME_ML_DSA_44: u16 = 0x0001;
/// ML-DSA-44 public key length.
pub const PUBLIC_KEY_BYTES: usize = 1312;
/// ML-DSA-44 signature length.
pub const SIGNATURE_BYTES: usize = 2420;
/// The ML-DSA context string of a transaction signature.
pub const TX_CONTEXT: &[u8] = b"ghost/tx/v1";
/// Hash tag of the account address (Keccak-256).
pub const TAG_ACCOUNT_ADDRESS: &str = "ghost/account-address/v1";
/// Hash tag of the signature hash (Keccak-256).
pub const TAG_ACCOUNT_TX: &str = "ghost/account-tx/v1";
/// Hash tag of an account key's seed (SHAKE256).
pub const TAG_WALLET_ACCOUNT: &str = "ghost/wallet-account/v1";
/// Bytes of a wallet seed.
pub const SEED_BYTES: usize = 32;
/// Words of a wallet seed: 256 bits and an 8-bit checksum, 11 bits a word.
pub const SEED_WORDS: usize = 24;
/// Gas of each byte of the scheme ID, public key and signature, and of one
/// ML-DSA-44 verification (ghost-node `params/ghost/accounttx.go`).
pub const SIG_BYTE_GAS: u64 = 16;
/// `VERIFY_GAS[0x0001]` (ghost-node `params/ghost/accounttx.go`).
pub const VERIFY_GAS_ML_DSA_44: u64 = 3_000;
/// The gas an account transaction adds to a type `0x02` transaction's
/// intrinsic gas: `16 * (2 + 1312 + 2420) + 3000` = 62,744.
pub const ACCOUNT_EXTRA_GAS: u64 =
    SIG_BYTE_GAS * (2 + PUBLIC_KEY_BYTES as u64 + SIGNATURE_BYTES as u64) + VERIFY_GAS_ML_DSA_44;

/// The two bytes of a scheme ID, big-endian.
pub const fn scheme_bytes(scheme: u16) -> [u8; 2] {
    scheme.to_be_bytes()
}

/// The account address of a scheme and a public key: the first 20 bytes of
/// `K("ghost/account-address/v1", scheme, public_key)`. It checks nothing.
pub fn account_address(scheme: u16, public_key: &[u8]) -> [u8; 20] {
    let h = k(TAG_ACCOUNT_ADDRESS, &[&scheme_bytes(scheme), public_key]);
    h[..20].try_into().expect("20 bytes")
}

/// `K("ghost/account-tx/v1", 0x52, genesis_hash, unsigned_hash)`.
pub fn signature_hash(genesis: &[u8; 32], unsigned_hash: &[u8; 32]) -> [u8; 32] {
    k(TAG_ACCOUNT_TX, &[&[ACCOUNT_TX_TYPE], genesis, unsigned_hash])
}

/// Why words were not accepted as a wallet seed. The messages never repeat
/// a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedError {
    /// The text holds digits: a Phantom Key goes in the key field, not here.
    Digits,
    /// Not 24 words.
    WordCount(usize),
    /// The word at this position (1-based) is not in the word list.
    UnknownWord(usize),
    /// The words are in the list but their checksum does not match.
    Checksum,
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digits => write!(
                f,
                "a wallet seed is 24 words, not digits; a Phantom Key's digits never open a wallet"
            ),
            Self::WordCount(n) => write!(f, "a wallet seed is {SEED_WORDS} words, not {n}"),
            Self::UnknownWord(i) => write!(f, "word {i} is not in the word list"),
            Self::Checksum => write!(f, "the words' checksum does not match: a word is wrong or out of order"),
        }
    }
}

impl core::error::Error for SeedError {}

/// A wallet seed: 32 bytes from a secure random source (spec 09, section 9).
pub struct WalletSeed([u8; SEED_BYTES]);

impl WalletSeed {
    /// A new seed from the caller's secure generator.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; SEED_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The seed of these bytes. The caller should wipe its copy.
    pub fn from_bytes(bytes: [u8; SEED_BYTES]) -> Self {
        Self(bytes)
    }

    /// The seed's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; SEED_BYTES] {
        &self.0
    }

    /// The seed as 24 words of the BIP-39 English list: the 256 bits, then
    /// the first 8 bits of SHA-256 of the seed as the checksum, 11 bits a
    /// word, separated by single spaces.
    pub fn to_words(&self) -> SeedWords {
        let mut bits = [0u8; SEED_BYTES + 1];
        bits[..SEED_BYTES].copy_from_slice(&self.0);
        bits[SEED_BYTES] = checksum(&self.0);
        let mut text = String::with_capacity(SEED_WORDS * 9);
        for i in 0..SEED_WORDS {
            if i > 0 {
                text.push(' ');
            }
            text.push_str(WORDLIST[word_index(&bits, i)]);
        }
        wipe(&mut bits);
        SeedWords(text)
    }

    /// The seed of 24 words. Words are separated by any whitespace and
    /// compared in lower case; each must be in the list and the checksum must
    /// match. Digits are refused outright.
    pub fn from_words(text: &str) -> Result<Self, SeedError> {
        if text.chars().any(|c| c.is_ascii_digit()) {
            return Err(SeedError::Digits);
        }
        let count = text.split_whitespace().count();
        if count != SEED_WORDS {
            return Err(SeedError::WordCount(count));
        }
        let mut bits = [0u8; SEED_BYTES + 1];
        let mut lower = String::new();
        for (i, word) in text.split_whitespace().enumerate() {
            wipe_string(&mut lower);
            lower.extend(word.chars().map(|c| c.to_ascii_lowercase()));
            let Ok(index) = WORDLIST.binary_search(&lower.as_str()) else {
                wipe_string(&mut lower);
                wipe(&mut bits);
                return Err(SeedError::UnknownWord(i + 1));
            };
            for b in 0..11 {
                if index >> (10 - b) & 1 == 1 {
                    let at = i * 11 + b;
                    bits[at / 8] |= 0x80 >> (at % 8);
                }
            }
        }
        wipe_string(&mut lower);
        let mut seed = [0u8; SEED_BYTES];
        seed.copy_from_slice(&bits[..SEED_BYTES]);
        let ok = checksum(&seed) == bits[SEED_BYTES];
        wipe(&mut bits);
        if !ok {
            wipe(&mut seed);
            return Err(SeedError::Checksum);
        }
        Ok(Self(seed))
    }

    /// Account `index`'s ML-DSA-44 key (scheme `0x0001`).
    pub fn account(&self, index: u32) -> AccountKey {
        let mut key_seed = account_key_seed(&self.0, SCHEME_ML_DSA_44, index);
        let signing = ExpandedSigningKey::<MlDsa44>::from_seed(&key_seed.into());
        wipe(&mut key_seed);
        let public_key: [u8; PUBLIC_KEY_BYTES] = signing.verifying_key().encode().into();
        AccountKey {
            index,
            address: account_address(SCHEME_ML_DSA_44, &public_key),
            public_key,
            signing,
        }
    }
}

impl Drop for WalletSeed {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// `key_seed(scheme, i) = X("ghost/wallet-account/v1", 32, seed, scheme, i)`
/// for ML-DSA-44, the 32-byte seed of `ML-DSA.KeyGen_internal` (FIPS 204,
/// algorithm 6). It is a secret: the caller wipes it.
pub fn account_key_seed(seed: &[u8; SEED_BYTES], scheme: u16, index: u32) -> [u8; 32] {
    x::<32>(TAG_WALLET_ACCOUNT, &[seed, &scheme_bytes(scheme), &index.to_be_bytes()])
}

fn checksum(seed: &[u8; SEED_BYTES]) -> u8 {
    Sha256::digest(seed)[0]
}

/// The 11-bit word index at word position `i` of `bits`.
fn word_index(bits: &[u8], i: usize) -> usize {
    let mut index = 0usize;
    for b in 0..11 {
        let at = i * 11 + b;
        index = index << 1 | usize::from(bits[at / 8] >> (7 - at % 8) & 1);
    }
    debug_assert!(index < WORD_COUNT);
    index
}

fn wipe_string(text: &mut String) {
    // SAFETY: zero bytes are valid UTF-8.
    wipe(unsafe { text.as_bytes_mut() });
    text.clear();
}

/// A wallet seed's 24 words, wiped on drop.
pub struct SeedWords(String);

impl SeedWords {
    /// The words, separated by single spaces.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SeedWords {
    fn drop(&mut self) {
        wipe_string(&mut self.0);
    }
}

/// One account of a wallet: its ML-DSA-44 key, public key and address.
pub struct AccountKey {
    index: u32,
    address: [u8; 20],
    public_key: [u8; PUBLIC_KEY_BYTES],
    signing: ExpandedSigningKey<MlDsa44>,
}

impl AccountKey {
    /// The account index the key was derived at.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The account address (spec 09, section 6, "Sender").
    pub fn address(&self) -> &[u8; 20] {
        &self.address
    }

    /// The FIPS 204 encoding of the public key, 1,312 bytes.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    /// Signs `tx` for the chain of `genesis` with hedged ML-DSA-44 and the
    /// context `ghost/tx/v1`. The scheme and public key fields are this
    /// key's.
    pub fn sign<R: CryptoRng + ?Sized>(&self, tx: &AccountTx, genesis: &[u8; 32], rng: &mut R) -> SignedAccountTx {
        let sighash = signature_hash(genesis, &tx.unsigned_hash(SCHEME_ML_DSA_44, &self.public_key));
        let signature = self
            .signing
            .sign_randomized(&sighash, TX_CONTEXT, rng)
            .expect("the context is shorter than 256 bytes and the generator cannot fail");
        self.finish(tx, sighash, signature)
    }

    fn finish(&self, tx: &AccountTx, sighash: [u8; 32], signature: Signature<MlDsa44>) -> SignedAccountTx {
        let signature: [u8; SIGNATURE_BYTES] = signature.encode().into();
        let envelope = tx.envelope(SCHEME_ML_DSA_44, &self.public_key, &signature);
        SignedAccountTx {
            hash: crate::hash::keccak256(&envelope),
            sighash,
            sender: self.address,
            envelope,
        }
    }

    /// The deterministic variant of ML-DSA.Sign, for the cross-check against
    /// the node's signer only: wallets sign hedged.
    #[cfg(test)]
    fn sign_deterministic(&self, tx: &AccountTx, genesis: &[u8; 32]) -> SignedAccountTx {
        let sighash = signature_hash(genesis, &tx.unsigned_hash(SCHEME_ML_DSA_44, &self.public_key));
        let signature = self.signing.sign_deterministic(&sighash, TX_CONTEXT).expect("short context");
        self.finish(tx, sighash, signature)
    }
}

/// One entry of an EIP-2930 access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListEntry {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// The fields of an account transaction that the sender chooses: all but
/// the scheme, the public key and the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// `None` is a contract creation.
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListEntry>,
}

impl AccountTx {
    fn fields(&self, out: &mut Vec<u8>) {
        rlp::uint(out, u128::from(self.chain_id));
        rlp::uint(out, u128::from(self.nonce));
        rlp::uint(out, self.max_priority_fee_per_gas);
        rlp::uint(out, self.max_fee_per_gas);
        rlp::uint(out, u128::from(self.gas_limit));
        rlp::bytes(out, self.to.as_ref().map_or(&[][..], |to| &to[..]));
        rlp::uint(out, self.value);
        rlp::bytes(out, &self.data);
        let mut list = Vec::new();
        for entry in &self.access_list {
            let mut item = Vec::new();
            rlp::bytes(&mut item, &entry.address);
            let mut keys = Vec::new();
            for key in &entry.storage_keys {
                rlp::bytes(&mut keys, key);
            }
            rlp::list(&mut item, &keys);
            rlp::list(&mut list, &item);
        }
        rlp::list(out, &list);
    }

    /// `rlp([chain_id, ..., access_list, scheme, public_key])`.
    pub fn unsigned_rlp(&self, scheme: u16, public_key: &[u8]) -> Vec<u8> {
        let mut items = Vec::new();
        self.fields(&mut items);
        rlp::bytes(&mut items, &scheme_bytes(scheme));
        rlp::bytes(&mut items, public_key);
        let mut out = Vec::with_capacity(items.len() + 4);
        rlp::list(&mut out, &items);
        out
    }

    /// `keccak256(unsigned)`.
    pub fn unsigned_hash(&self, scheme: u16, public_key: &[u8]) -> [u8; 32] {
        crate::hash::keccak256(&self.unsigned_rlp(scheme, public_key))
    }

    /// `0x52 || rlp([... twelve fields ...])`.
    pub fn envelope(&self, scheme: u16, public_key: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut items = Vec::new();
        self.fields(&mut items);
        rlp::bytes(&mut items, &scheme_bytes(scheme));
        rlp::bytes(&mut items, public_key);
        rlp::bytes(&mut items, signature);
        let mut out = Vec::with_capacity(items.len() + 5);
        out.push(ACCOUNT_TX_TYPE);
        rlp::list(&mut out, &items);
        out
    }
}

/// A signed account transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAccountTx {
    /// The transaction hash, `keccak256(envelope)`.
    pub hash: [u8; 32],
    /// The signature hash the signature covers.
    pub sighash: [u8; 32],
    /// The sender's address.
    pub sender: [u8; 20],
    /// The envelope sent with `eth_sendRawTransaction`.
    pub envelope: Vec<u8>,
}

/// Why an envelope was refused by [`verify_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountTxError {
    /// Not type `0x52`.
    Type,
    /// The RLP is not the canonical twelve-item list.
    Encoding(&'static str),
    /// A scheme other than ML-DSA-44.
    Scheme(u16),
    /// A key or signature of the wrong length.
    Length,
    /// The chain identifier is not the expected one.
    ChainId,
    /// The signature does not verify.
    Signature,
}

impl fmt::Display for AccountTxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type => write!(f, "not an account transaction (type 0x52)"),
            Self::Encoding(why) => write!(f, "account transaction encoding: {why}"),
            Self::Scheme(s) => write!(f, "account transaction scheme {s:#06x} not accepted"),
            Self::Length => write!(f, "account transaction key or signature has the wrong length"),
            Self::ChainId => write!(f, "account transaction is for another chain"),
            Self::Signature => write!(f, "account transaction signature does not verify"),
        }
    }
}

impl core::error::Error for AccountTxError {}

/// An account transaction checked by [`verify_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccountTx {
    pub tx: AccountTx,
    pub scheme: u16,
    pub sender: [u8; 20],
    pub hash: [u8; 32],
}

/// Decodes an envelope strictly and checks it as the node's signer does, in
/// its order: the type, the canonical twelve-item list, the scheme and the
/// lengths, the chain identifier, the sender, and the signature last. For
/// the web app's stand-in node and the tests; integers wider than this
/// type's fields are refused.
pub fn verify_envelope(envelope: &[u8], chain_id: u64, genesis: &[u8; 32]) -> Result<VerifiedAccountTx, AccountTxError> {
    use AccountTxError::Encoding;
    let (&ty, body) = envelope.split_first().ok_or(AccountTxError::Type)?;
    if ty != ACCOUNT_TX_TYPE {
        return Err(AccountTxError::Type);
    }
    let mut outer = rlp::Reader::new(body);
    let items = outer.list().map_err(Encoding)?;
    outer.end().map_err(Encoding)?;
    let mut r = rlp::Reader::new(items);
    let tx_chain_id = r.uint_u64().map_err(Encoding)?;
    let nonce = r.uint_u64().map_err(Encoding)?;
    let max_priority_fee_per_gas = r.uint_u128().map_err(Encoding)?;
    let max_fee_per_gas = r.uint_u128().map_err(Encoding)?;
    let gas_limit = r.uint_u64().map_err(Encoding)?;
    let to = match r.bytes().map_err(Encoding)? {
        [] => None,
        to if to.len() == 20 => Some(to.try_into().expect("20 bytes")),
        _ => return Err(Encoding("`to` is neither 20 bytes nor empty")),
    };
    let value = r.uint_u128().map_err(Encoding)?;
    let data = r.bytes().map_err(Encoding)?.to_vec();
    let mut access_list = Vec::new();
    let mut entries = rlp::Reader::new(r.list().map_err(Encoding)?);
    while !entries.is_empty() {
        let mut entry = rlp::Reader::new(entries.list().map_err(Encoding)?);
        let address: [u8; 20] = entry
            .bytes()
            .map_err(Encoding)?
            .try_into()
            .map_err(|_| Encoding("access list address is not 20 bytes"))?;
        let mut keys = rlp::Reader::new(entry.list().map_err(Encoding)?);
        entry.end().map_err(Encoding)?;
        let mut storage_keys = Vec::new();
        while !keys.is_empty() {
            storage_keys.push(
                keys.bytes()
                    .map_err(Encoding)?
                    .try_into()
                    .map_err(|_| Encoding("storage key is not 32 bytes"))?,
            );
        }
        access_list.push(AccessListEntry { address, storage_keys });
    }
    let scheme: [u8; 2] = r
        .bytes()
        .map_err(Encoding)?
        .try_into()
        .map_err(|_| Encoding("scheme is not 2 bytes"))?;
    let public_key = r.bytes().map_err(Encoding)?;
    let signature = r.bytes().map_err(Encoding)?;
    r.end().map_err(|_| Encoding("the list does not have exactly twelve items"))?;

    let scheme = u16::from_be_bytes(scheme);
    if scheme != SCHEME_ML_DSA_44 {
        return Err(AccountTxError::Scheme(scheme));
    }
    if public_key.len() != PUBLIC_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
        return Err(AccountTxError::Length);
    }
    if tx_chain_id != chain_id {
        return Err(AccountTxError::ChainId);
    }
    let tx = AccountTx {
        chain_id: tx_chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
        access_list,
    };
    let sender = account_address(scheme, public_key);
    let pk = VerifyingKey::<MlDsa44>::decode(&EncodedVerifyingKey::<MlDsa44>::try_from(public_key).expect("length checked"));
    let sig = Signature::<MlDsa44>::decode(&EncodedSignature::<MlDsa44>::try_from(signature).expect("length checked"))
        .ok_or(AccountTxError::Signature)?;
    let sighash = signature_hash(genesis, &tx.unsigned_hash(scheme, public_key));
    if !pk.verify_with_context(&sighash, TX_CONTEXT, &sig) {
        return Err(AccountTxError::Signature);
    }
    // The envelope re-encodes to itself: one transaction, one encoding.
    if tx.envelope(scheme, public_key, signature) != envelope {
        return Err(Encoding("not the canonical encoding"));
    }
    Ok(VerifiedAccountTx { tx, scheme, sender, hash: crate::hash::keccak256(envelope) })
}

/// The few RLP rules the account transaction needs: byte strings, unsigned
/// integers without leading zeros and lists, encoded and read strictly.
mod rlp {
    fn length(out: &mut Vec<u8>, len: usize, short: u8) {
        if len < 56 {
            out.push(short + len as u8);
        } else {
            let be = (len as u64).to_be_bytes();
            let skip = be.iter().take_while(|&&b| b == 0).count();
            out.push(short + 55 + (8 - skip) as u8);
            out.extend_from_slice(&be[skip..]);
        }
    }

    pub fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        if b.len() == 1 && b[0] < 0x80 {
            out.push(b[0]);
        } else {
            length(out, b.len(), 0x80);
            out.extend_from_slice(b);
        }
    }

    pub fn uint(out: &mut Vec<u8>, v: u128) {
        let be = v.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        bytes(out, &be[skip..]);
    }

    pub fn list(out: &mut Vec<u8>, payload: &[u8]) {
        length(out, payload.len(), 0xc0);
        out.extend_from_slice(payload);
    }

    pub struct Reader<'a> {
        rest: &'a [u8],
    }

    type R<T> = Result<T, &'static str>;

    impl<'a> Reader<'a> {
        pub fn new(rest: &'a [u8]) -> Self {
            Self { rest }
        }

        pub fn is_empty(&self) -> bool {
            self.rest.is_empty()
        }

        pub fn end(&self) -> R<()> {
            if self.rest.is_empty() { Ok(()) } else { Err("bytes after the item") }
        }

        fn take(&mut self, n: usize) -> R<&'a [u8]> {
            if self.rest.len() < n {
                return Err("an item runs past the end");
            }
            let (part, rest) = self.rest.split_at(n);
            self.rest = rest;
            Ok(part)
        }

        /// The payload of the next item and whether it is a list.
        fn item(&mut self) -> R<(&'a [u8], bool)> {
            let prefix = *self.rest.first().ok_or("an item runs past the end")?;
            if prefix < 0x80 {
                return Ok((self.take(1)?, false));
            }
            self.take(1)?;
            match prefix {
                0x80..=0xb7 => {
                    let n = usize::from(prefix - 0x80);
                    let payload = self.take(n)?;
                    if n == 1 && payload[0] < 0x80 {
                        return Err("a single byte below 0x80 is wrapped");
                    }
                    Ok((payload, false))
                }
                0xb8..=0xbf => Ok((self.long(prefix - 0xb7)?, false)),
                0xc0..=0xf7 => Ok((self.take(usize::from(prefix - 0xc0))?, true)),
                _ => Ok((self.long(prefix - 0xf7)?, true)),
            }
        }

        fn long(&mut self, size_bytes: u8) -> R<&'a [u8]> {
            let size = self.take(usize::from(size_bytes))?;
            if size[0] == 0 {
                return Err("a length has a leading zero");
            }
            if size.len() > 4 {
                return Err("a length is too large");
            }
            let n = size.iter().fold(0usize, |n, &b| n << 8 | usize::from(b));
            if n < 56 {
                return Err("a long length is used for a short item");
            }
            self.take(n)
        }

        pub fn bytes(&mut self) -> R<&'a [u8]> {
            match self.item()? {
                (payload, false) => Ok(payload),
                _ => Err("a list where a byte string belongs"),
            }
        }

        pub fn list(&mut self) -> R<&'a [u8]> {
            match self.item()? {
                (payload, true) => Ok(payload),
                _ => Err("a byte string where a list belongs"),
            }
        }

        pub fn uint_u128(&mut self) -> R<u128> {
            let b = self.bytes()?;
            if b.first() == Some(&0) {
                return Err("an integer has a leading zero");
            }
            if b.len() > 16 {
                return Err("an integer is too large");
            }
            Ok(b.iter().fold(0u128, |n, &x| n << 8 | u128::from(x)))
        }

        pub fn uint_u64(&mut self) -> R<u64> {
            u64::try_from(self.uint_u128()?).map_err(|_| "an integer is too large")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test transaction of ghost-node's `core/types/tx_ghost_account_test.go`
    /// (`ghostTestTxData`), to `0x…bb`.
    fn node_test_tx() -> AccountTx {
        let mut aa = [0u8; 20];
        aa[19] = 0xaa;
        let mut bb = [0u8; 20];
        bb[19] = 0xbb;
        let mut key = [0u8; 32];
        key[31] = 1;
        AccountTx {
            chain_id: 1337,
            nonce: 7,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 200_000,
            to: Some(bb),
            value: 123_456_789,
            data: vec![0xde, 0xad, 0xbe, 0xef],
            access_list: vec![AccessListEntry { address: aa, storage_keys: vec![key] }],
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The node's `ghostTestKey(1)`: the ML-DSA-44 key of 32 bytes of 0x01,
    /// as an [`AccountKey`].
    fn node_test_key() -> AccountKey {
        let signing = ExpandedSigningKey::<MlDsa44>::from_seed(&[1u8; 32].into());
        let public_key: [u8; PUBLIC_KEY_BYTES] = signing.verifying_key().encode().into();
        AccountKey { index: 0, address: account_address(SCHEME_ML_DSA_44, &public_key), public_key, signing }
    }

    // Values computed by ghost-node's own code (circl v1.6.1 and
    // core/types/tx_ghost_account.go at the commit in
    // webapp/test/e2e/NODE_COMMIT): mldsa44.NewKeyFromSeed of 32 bytes of 0x01,
    // GhostAccountAddressOf, the signer's Hash of ghostTestTxData with that
    // key and the test genesis, and keccak256 of the envelope that
    // SignTo(key, sighash, "ghost/tx/v1", randomized = false) gives.
    const NODE_KEY1_PUBLIC_KEY_KECCAK: &str = "30a5061cd97b50902a5d41219d8c86d8e1bb518443973199b47d9b36d0da3f2f";
    const NODE_KEY1_ADDRESS: &str = "235aa37be460a35641b68c6433ad0e4ca25938b9";
    const NODE_KEY1_SIGHASH: &str = "be96f5a62ebe0d4d6700d5e392d53febaa7360e46f0f973ace45e933801534ed";
    const NODE_KEY1_TX_HASH: &str = "526384882187ed00fbd1d617bf245e0eb53e3f1e57e9c9e20e85494e40f38b94";

    fn node_genesis() -> [u8; 32] {
        let h = "9a0c3e5d7f1b2a4c6e8f0a1b3c5d7e9f1a2b3c4d5e6f708192a3b4c5d6e7f809";
        core::array::from_fn(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn deterministic_signature_matches_the_node_signer() {
        let key = node_test_key();
        assert_eq!(hex(&crate::hash::keccak256(key.public_key())), NODE_KEY1_PUBLIC_KEY_KECCAK.trim());
        assert_eq!(hex(key.address()), NODE_KEY1_ADDRESS.trim());
        let signed = key.sign_deterministic(&node_test_tx(), &node_genesis());
        assert_eq!(hex(&signed.sighash), NODE_KEY1_SIGHASH.trim());
        assert_eq!(hex(&signed.hash), NODE_KEY1_TX_HASH.trim());
        let checked = verify_envelope(&signed.envelope, 1337, &node_genesis()).unwrap();
        assert_eq!(checked.tx, node_test_tx());
        assert_eq!(checked.sender, *key.address());
    }

    #[test]
    fn rlp_reader_is_strict() {
        let mut r = rlp::Reader::new(&[0x81, 0x05]);
        assert!(r.bytes().is_err(), "a wrapped single byte");
        let mut r = rlp::Reader::new(&[0x82, 0x00, 0x05]);
        assert!(r.uint_u128().is_err(), "a leading zero");
        let mut r = rlp::Reader::new(&[0xb8, 0x01, 0xff]);
        assert!(r.bytes().is_err(), "a long length for a short string");
        let mut r = rlp::Reader::new(&[0x05]);
        assert_eq!(r.bytes().unwrap(), &[0x05]);
        let mut r = rlp::Reader::new(&[0x80]);
        assert_eq!(r.uint_u128().unwrap(), 0);
    }
}

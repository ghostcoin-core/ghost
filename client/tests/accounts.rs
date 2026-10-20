//! Quantum-safe accounts (spec 09, sections 5, 6 and 9): the wallet seed's
//! words, the derivation of account keys, the account address and signing
//! the account transaction (type 0x52).
//!
//! Every expected value comes from an implementation other than this crate:
//!
//! - the words: the 256-bit vectors published with BIP-39 (the Trezor
//!   reference vectors), recomputed with Python's `hashlib.sha256`;
//! - the key seeds: Python's `hashlib.shake_256` over
//!   `tagbytes("ghost/wallet-account/v1") || seed || scheme || index`;
//! - the addresses and public key hashes: ghost-node's own code (circl
//!   v1.6.1 `mldsa44.NewKeyFromSeed` and `GhostAccountAddressOf` in
//!   `core/types/tx_ghost_account.go`, at the commit in
//!   `webapp/test/e2e/NODE_COMMIT`) given those key seeds.

use ghost_client::account::{
    ACCOUNT_EXTRA_GAS, ACCOUNT_TX_TYPE, AccountTx, AccountTxError, PUBLIC_KEY_BYTES, SCHEME_ML_DSA_44,
    SEED_WORDS, SIGNATURE_BYTES, SeedError, WalletSeed, account_address, account_key_seed, verify_envelope,
};
use ghost_client::hash::keccak256;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex<const N: usize>(h: &str) -> [u8; N] {
    core::array::from_fn(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
}

const COUNTING: [u8; 32] = {
    let mut s = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        s[i] = i as u8;
        i += 1;
    }
    s
};

#[test]
fn words_match_the_bip39_vectors() {
    let vectors = [
        ("00".repeat(32), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
        ("7f".repeat(32), "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
        ("80".repeat(32), "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
        ("ff".repeat(32), "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
        ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c".to_string(), "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"),
    ];
    for (entropy, words) in vectors {
        let seed = WalletSeed::from_bytes(unhex(&entropy));
        assert_eq!(seed.to_words().as_str(), words);
        let back = WalletSeed::from_words(words).unwrap();
        assert_eq!(hex(back.as_bytes()), entropy);
    }
}

#[test]
fn words_are_read_leniently_but_checked_strictly() {
    let words = WalletSeed::from_bytes(COUNTING).to_words();
    let text = words.as_str();
    assert_eq!(text.split(' ').count(), SEED_WORDS);

    // Case and whitespace do not matter.
    let loose = format!("  {}\n", text.to_uppercase().replace(' ', "\t "));
    assert_eq!(WalletSeed::from_words(&loose).unwrap().as_bytes(), &COUNTING);

    // A Phantom Key's digits are refused as a seed.
    let digits = "1234 5678 9012 3456 7890 1234 5678 9012 3456 7890 1234 5678";
    assert_eq!(WalletSeed::from_words(digits).err(), Some(SeedError::Digits));

    let list: Vec<&str> = text.split(' ').collect();
    assert_eq!(WalletSeed::from_words(&list[..23].join(" ")).err(), Some(SeedError::WordCount(23)));
    let mut unknown = list.clone();
    unknown[4] = "ghostly";
    assert_eq!(WalletSeed::from_words(&unknown.join(" ")).err(), Some(SeedError::UnknownWord(5)));
    // Two different words swapped: every word is valid, the checksum is not.
    let mut swapped = list.clone();
    let (a, b) = (1, (2..SEED_WORDS).find(|&j| list[j] != list[1]).unwrap());
    swapped.swap(a, b);
    assert_eq!(WalletSeed::from_words(&swapped.join(" ")).err(), Some(SeedError::Checksum));
}

#[test]
fn account_keys_derive_by_the_spec_and_match_the_node() {
    // (seed, index, key_seed by SHAKE256, address and keccak256(public key)
    // by ghost-node).
    let vectors = [
        (
            COUNTING,
            0u32,
            "8c900507ff0dbb4112705e4dadd15f923923c650eec1480b91b8b4c14832d497",
            "80992a5c983fc01cd9a0c16c4dfc47b9a750d022",
            "d4fd3744c756d20de20684e66d6cbc8a99b6d7dbbbe640da2840b2dbfe68157d",
        ),
        (
            COUNTING,
            1,
            "3515df14f16f7ccbdf5cff3676468ebaef7f4bc5546ed3823ff3d9067860ce21",
            "089bf63fb2681964eae8e04df95e26fda71ed2cb",
            "7219c8bb7aa417d5b81b96eb49e06861072f8d2b84e5b3214b9f7870e7999efa",
        ),
        (
            [0xff; 32],
            0,
            "4a1b8d08747efa15e33af72df527ab7d4051db8e78690846a0cede9730b52064",
            "b4b218840ca3723f470ab81db7cf81e4289e96c8",
            "b6bab7c7b89b6c6e358bf8d588d22f42903dd8b2df7cc9812f5445fc508c77bc",
        ),
    ];
    for (seed_bytes, index, key_seed, address, pk_hash) in vectors {
        assert_eq!(hex(&account_key_seed(&seed_bytes, SCHEME_ML_DSA_44, index)), key_seed);
        let account = WalletSeed::from_bytes(seed_bytes).account(index);
        assert_eq!(account.index(), index);
        assert_eq!(hex(account.address()), address);
        assert_eq!(hex(&keccak256(account.public_key())), pk_hash);
        assert_eq!(account.public_key().len(), PUBLIC_KEY_BYTES);
        assert_eq!(account_address(SCHEME_ML_DSA_44, account.public_key()), *account.address());
    }
    // Index 7 of the counting seed, by SHAKE256 only.
    assert_eq!(
        hex(&account_key_seed(&COUNTING, SCHEME_ML_DSA_44, 7)),
        "0941f40487b4fc2290a235cee66c5c06d0836c4813944e2248b67ac6fe2edbf5"
    );
    // The scheme is in the hash: another scheme ID gives another key seed.
    assert_ne!(account_key_seed(&COUNTING, 0x0002, 0), account_key_seed(&COUNTING, SCHEME_ML_DSA_44, 0));
}

fn commit_tx() -> AccountTx {
    AccountTx {
        chain_id: 6_777_971,
        nonce: 3,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: 200_000,
        to: Some(unhex("67686f7374000000000000000000000000000005")),
        value: 10u128.pow(18),
        data: vec![0x00, 0x01, 0xab, 0xcd],
        access_list: vec![],
    }
}

#[test]
fn hedged_signatures_verify_and_bind_the_chain() {
    let genesis: [u8; 32] = [0x42; 32];
    let account = WalletSeed::from_bytes(COUNTING).account(0);
    let mut rng = StdRng::from_seed([9; 32]);
    let tx = commit_tx();
    let a = account.sign(&tx, &genesis, &mut rng);
    let b = account.sign(&tx, &genesis, &mut rng);
    assert_eq!(a.envelope[0], ACCOUNT_TX_TYPE);
    assert_eq!(a.sighash, b.sighash, "one transaction, one signature hash");
    assert_ne!(a.envelope, b.envelope, "hedged: fresh randomness in every signature");
    assert_eq!(a.hash, keccak256(&a.envelope));
    assert_eq!(a.sender, *account.address());
    // The envelope ends with the signature as a long string.
    let sig_len = (SIGNATURE_BYTES as u16).to_be_bytes();
    let tail = &a.envelope[a.envelope.len() - SIGNATURE_BYTES - 3..a.envelope.len() - SIGNATURE_BYTES];
    assert_eq!(tail, [0xb9, sig_len[0], sig_len[1]]);

    for signed in [&a, &b] {
        let checked = verify_envelope(&signed.envelope, tx.chain_id, &genesis).unwrap();
        assert_eq!(checked.tx, tx);
        assert_eq!(checked.sender, *account.address());
        assert_eq!(checked.hash, signed.hash);
    }

    // Another genesis or chain: refused.
    assert_eq!(verify_envelope(&a.envelope, tx.chain_id, &[0x43; 32]).err(), Some(AccountTxError::Signature));
    assert_eq!(verify_envelope(&a.envelope, 1, &genesis).err(), Some(AccountTxError::ChainId));
    // One bit of the signature, or of the value, changed: refused.
    let mut bad = a.envelope.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(verify_envelope(&bad, tx.chain_id, &genesis).is_err());
    let mut other = tx.clone();
    other.value += 1;
    let forged = other.envelope(SCHEME_ML_DSA_44, account.public_key(), &a.envelope[a.envelope.len() - SIGNATURE_BYTES..]);
    assert_eq!(verify_envelope(&forged, tx.chain_id, &genesis).err(), Some(AccountTxError::Signature));
    // Another key's signature over the same fields: refused.
    let stranger = WalletSeed::from_bytes([0xff; 32]).account(0);
    let theirs = stranger.sign(&tx, &genesis, &mut rng);
    let mixed = tx.envelope(
        SCHEME_ML_DSA_44,
        account.public_key(),
        &theirs.envelope[theirs.envelope.len() - SIGNATURE_BYTES..],
    );
    assert_eq!(verify_envelope(&mixed, tx.chain_id, &genesis).err(), Some(AccountTxError::Signature));
    // Wrong type byte, another scheme, trailing bytes: refused before any
    // signature check.
    let mut typed = a.envelope.clone();
    typed[0] = 0x02;
    assert_eq!(verify_envelope(&typed, tx.chain_id, &genesis).err(), Some(AccountTxError::Type));
    let scheme2 = tx.envelope(0x0002, account.public_key(), &a.envelope[a.envelope.len() - SIGNATURE_BYTES..]);
    assert_eq!(verify_envelope(&scheme2, tx.chain_id, &genesis).err(), Some(AccountTxError::Scheme(2)));
    let mut long = a.envelope.clone();
    long.push(0);
    assert!(matches!(verify_envelope(&long, tx.chain_id, &genesis), Err(AccountTxError::Encoding(_))));
}

#[test]
fn contract_creation_and_access_lists_round_trip() {
    let genesis = [7u8; 32];
    let account = WalletSeed::from_bytes(COUNTING).account(1);
    let mut rng = StdRng::from_seed([1; 32]);
    let mut tx = commit_tx();
    tx.to = None;
    tx.value = 0;
    tx.nonce = 0;
    tx.data = vec![0x60; 300];
    tx.access_list = vec![ghost_client::account::AccessListEntry {
        address: [0xaa; 20],
        storage_keys: vec![[1; 32], [2; 32]],
    }];
    let signed = account.sign(&tx, &genesis, &mut rng);
    assert_eq!(verify_envelope(&signed.envelope, tx.chain_id, &genesis).unwrap().tx, tx);
}

#[test]
fn extra_intrinsic_gas_is_the_nodes() {
    // ghost-node docs/account-transactions.md: 16 * 3,734 + 3,000.
    assert_eq!(ACCOUNT_EXTRA_GAS, 62_744);
}

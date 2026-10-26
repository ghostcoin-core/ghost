//! Rescue-key accounts (spec 09, sections 5.1, 5.2, 6 and 9): the 80-byte
//! derivation, the ML-DSA-44 and SLH-DSA-SHAKE-128s halves of the key, the
//! address, and the account transaction signed in both modes (`0x0003` with
//! ML-DSA-44, `0x0004` the rescue with SLH-DSA).
//!
//! Every expected value comes from an implementation other than this crate:
//! Cloudflare CIRCL v1.6.5 (`sign/slhdsa` with SLH-DSA-SHAKE-128s and
//! `sign/mldsa/mldsa44`) with `golang.org/x/crypto/sha3`, in Go. Given the
//! seed and the index it computes
//!
//! - `out80 = SHAKE256(tagbytes("ghost/wallet-account/v1") || seed || 0x0003 || i as 4 bytes)`, 80 bytes;
//! - the ML-DSA-44 key of `out80[0..32]` (keccak256 of its 1,312 bytes);
//! - the SLH-DSA key of `SK.seed = out80[32..48]`, `SK.prf = out80[48..64]`,
//!   `PK.seed = out80[64..80]`, encoded `PK.seed || PK.root`;
//! - the address, the first 20 bytes of keccak256 of
//!   `tagbytes("ghost/account-address/v1") || 0x0003 || mldsa_pk || slhdsa_pk`,
//!   and the `0x0001` address of the ML-DSA key alone;
//! - the deterministic SLH-DSA signature (`opt_rand = PK.seed`) of the 32
//!   bytes 00..1f with the context `ghost/tx/v1`, given by its SHA-256 and
//!   SHA3-256.
//!
//! An SLH-DSA-SHAKE-128s signature takes about a second, so each test makes
//! only a few.

use core::convert::Infallible;

use ghost_client::account::{
    AccountTx, AccountTxError, PUBLIC_KEY_BYTES, RESCUE_PUBLIC_KEY_BYTES, SCHEME_ML_DSA_44, SCHEME_RESCUE,
    SCHEME_RESCUE_KEY, SIGNATURE_BYTES, SLH_DSA_SIGNATURE_BYTES, WalletSeed, account_address, account_key_seed,
    rescue_account_key_seed, rescue_signature_verifies, verify_envelope,
};
use ghost_client::hash::keccak256;
use ghost_client::slh_dsa;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Sha3};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex<const N: usize>(h: &str) -> [u8; N] {
    assert_eq!(h.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
}

fn sha3_256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha3::v256();
    h.update(b);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
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

struct Vector {
    seed: [u8; 32],
    index: u32,
    out80: &'static str,
    mldsa_pk_keccak256: &'static str,
    slhdsa_pk: &'static str,
    address: &'static str,
    address_0x0001_of_mldsa_pk_alone: &'static str,
    sig_sha256: &'static str,
    sig_sha3_256: &'static str,
}

/// CIRCL v1.6.5 (see the file comment).
const VECTORS: [Vector; 3] = [
    Vector {
        seed: COUNTING,
        index: 0,
        out80: "21a0fb741e7c2aa8c7427ebbc12372870e4bfa5adb02b1b728b125f0f3c50d57a98fac9598fb219191231f18fdad940a91985477e37e1ddb9e82ce5dc0322e8c1fe1f8b250b35d2c15c14f58d2e6f3af",
        mldsa_pk_keccak256: "2420f8e16289fc0f855c40ca36e73e59b5623278bee2db757e74764eebd37f46",
        slhdsa_pk: "1fe1f8b250b35d2c15c14f58d2e6f3af8a4f5764636428f7a109e83d82d0bc62",
        address: "e5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd",
        address_0x0001_of_mldsa_pk_alone: "4c475039e338e0abdc8d27023c5e335e57067638",
        sig_sha256: "3169dd6a3009ef4c854a484d60e72dde2f902dab3a3d213ac745ecc23f02e242",
        sig_sha3_256: "4c3906c469ac98f4c86145e03e747ee72d1f31052c87f2b32f2136bde384d58d",
    },
    Vector {
        seed: COUNTING,
        index: 1,
        out80: "b5acddf9908bbf260fe125ba9dc15d8da7304ab1c95173fa457cf6201f4388fdfd706b892700b19d211e86b216d79ecca709e40bc8d115aa560a19d54b54b262449eb91b376c7ffc1221779a39b5253f",
        mldsa_pk_keccak256: "d18e33ab565c802a1946ec20180dad37edbf33af4789df86153b233eb93d9e69",
        slhdsa_pk: "449eb91b376c7ffc1221779a39b5253f18a51aaba6133954d4379985e1c6a1ff",
        address: "60ff4b78b1b623515382096c546a94726de6bc0e",
        address_0x0001_of_mldsa_pk_alone: "ceee0d310ed3287561b9fab473092262b8802868",
        sig_sha256: "fa09394caac6cfaae8c78e0c341283936745c2ea030f2838eabc28545027bf6e",
        sig_sha3_256: "12cd7cacd22f5b73fcaa2cb4d49e6d1db2d97b8dba6def726ad4a222020ad8c3",
    },
    Vector {
        seed: [0xff; 32],
        index: 0,
        out80: "b96992c9535e18ef59a312b0603fd9690bb2bf872e5010eed329297fc3e29c4d05bd4bba785733e1fe64cd32573e7cb4f7373d2e76b53c20ab7cf85c67d470de2736c9c95420c3da6c7a870ac6d7eed5",
        mldsa_pk_keccak256: "ee98ad4d8b2ed896327320dfcdf9a090e7c4b2f5b7b7f63fe3530b1311f26d7f",
        slhdsa_pk: "2736c9c95420c3da6c7a870ac6d7eed59b2da4bb4ece330f34575ce54f430b24",
        address: "ba555b04c55f4c39900456dc9867552fa568cfee",
        address_0x0001_of_mldsa_pk_alone: "2aed3c44ec977e0b417f37a03d169d008bbba7fe",
        sig_sha256: "4284d75c18ab1bb087a2143fa238dc28bab50f24f7e4c98c3b50c8ed6a623817",
        sig_sha3_256: "1b14ffbbe0820457e2719c2bee5f21eaebca24b2353627d88507d8dbe9e5fa3f",
    },
];

const CONTEXT: &[u8] = b"ghost/tx/v1";

/// A generator that gives the same 16 bytes on every request. Given
/// `PK.seed` it makes the hedged signer's `opt_rand` equal `PK.seed`, which
/// is FIPS 205's deterministic variant: the one the vectors use.
struct Fixed([u8; 16]);

impl rand_core::TryRng for Fixed {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes(self.0[..4].try_into().unwrap()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes(self.0[..8].try_into().unwrap()))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for (i, b) in dst.iter_mut().enumerate() {
            *b = self.0[i % 16];
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Fixed {}

fn transfer() -> AccountTx {
    AccountTx {
        chain_id: 6_777_971,
        nonce: 5,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 3_000_000_000,
        gas_limit: 200_000,
        to: Some([0x5a; 20]),
        value: 7 * 10u128.pow(18),
        data: vec![0x01, 0x02],
        access_list: vec![],
    }
}

const GENESIS: [u8; 32] = [0x42; 32];

/// The signature at the end of an envelope.
fn signature_of(envelope: &[u8], len: usize) -> &[u8] {
    &envelope[envelope.len() - len..]
}

#[test]
fn slh_dsa_matches_the_independent_vectors() {
    let message: [u8; 32] = core::array::from_fn(|i| i as u8);
    for v in &VECTORS {
        let out: [u8; 80] = unhex(v.out80);
        let pk_seed: [u8; 16] = out[64..].try_into().unwrap();
        let key = slh_dsa::SigningKey::from_seeds(
            out[32..48].try_into().unwrap(),
            out[48..64].try_into().unwrap(),
            &pk_seed,
        );
        let pk = key.public_key();
        assert_eq!(hex(&pk), v.slhdsa_pk);
        assert_eq!(pk[..16], pk_seed, "the public key starts with PK.seed");

        let sig = key.sign(&message, CONTEXT, &mut Fixed(pk_seed)).unwrap();
        assert_eq!(sig.len(), slh_dsa::SIGNATURE_BYTES);
        assert_eq!(sig.len(), 7_856);
        assert_eq!(hex(&Sha256::digest(&sig[..])), v.sig_sha256);
        assert_eq!(hex(&sha3_256(&sig[..])), v.sig_sha3_256);
        assert!(slh_dsa::verify(&pk, &message, CONTEXT, &sig[..]));

        // Another context, message or key, or one bit of the signature:
        // not valid.
        assert!(!slh_dsa::verify(&pk, &message, b"ghost/tx/v2", &sig[..]));
        assert!(!slh_dsa::verify(&pk, &message[1..], CONTEXT, &sig[..]));
        let mut other_pk = pk;
        other_pk[31] ^= 1;
        assert!(!slh_dsa::verify(&other_pk, &message, CONTEXT, &sig[..]));
        let mut bad = sig.clone();
        bad[7_000] ^= 0x10;
        assert!(!slh_dsa::verify(&pk, &message, CONTEXT, &bad[..]));
        assert!(!slh_dsa::verify(&pk, &message, CONTEXT, &sig[..7_855]));
    }

    // Hedged: other randomness gives another signature, which verifies too.
    let out: [u8; 80] = unhex(VECTORS[0].out80);
    let key = slh_dsa::SigningKey::from_seeds(
        out[32..48].try_into().unwrap(),
        out[48..64].try_into().unwrap(),
        out[64..80].try_into().unwrap(),
    );
    let hedged = key.sign(&message, CONTEXT, &mut StdRng::from_seed([3; 32])).unwrap();
    assert_ne!(hex(&Sha256::digest(&hedged[..])), VECTORS[0].sig_sha256);
    assert!(slh_dsa::verify(&key.public_key(), &message, CONTEXT, &hedged[..]));
}

#[test]
fn rescue_key_derives_by_the_spec_and_matches_the_vectors() {
    for v in &VECTORS {
        let out = rescue_account_key_seed(&v.seed, v.index);
        assert_eq!(hex(&out), v.out80);
        // One SHAKE256 output: its first 32 bytes are the 32-byte output
        // under the same input, scheme 0x0003.
        assert_eq!(out[..32], account_key_seed(&v.seed, SCHEME_RESCUE_KEY, v.index));

        let account = WalletSeed::from_bytes(v.seed).rescue_account(v.index);
        assert_eq!(account.index(), v.index);
        let pk = account.public_key();
        assert_eq!(pk.len(), RESCUE_PUBLIC_KEY_BYTES);
        assert_eq!(pk.len(), 1_344);
        assert_eq!(hex(&keccak256(&pk[..PUBLIC_KEY_BYTES])), v.mldsa_pk_keccak256);
        assert_eq!(hex(&pk[PUBLIC_KEY_BYTES..]), v.slhdsa_pk);
        assert_eq!(&pk[..PUBLIC_KEY_BYTES], account.ml_dsa_public_key());
        assert_eq!(&pk[PUBLIC_KEY_BYTES..], account.slh_dsa_public_key());
        // PK.seed is the last 16 bytes of the output.
        assert_eq!(pk[PUBLIC_KEY_BYTES..PUBLIC_KEY_BYTES + 16], out[64..]);
        assert_eq!(hex(account.address()), v.address);
        assert_eq!(account_address(SCHEME_RESCUE_KEY, pk), *account.address());
    }
}

#[test]
fn rescue_transaction_verifies_with_the_ml_dsa_half_removed() {
    let seed = WalletSeed::from_bytes(COUNTING);
    let account = seed.rescue_account(0);
    let mut rng = StdRng::from_seed([7; 32]);
    let tx = transfer();
    let rescue = account.sign_rescue(&tx, &GENESIS, &mut rng);
    assert_eq!(rescue.sender, *account.address());
    assert_eq!(rescue.hash, keccak256(&rescue.envelope));

    let checked = verify_envelope(&rescue.envelope, tx.chain_id, &GENESIS).unwrap();
    assert_eq!(checked.scheme, SCHEME_RESCUE);
    assert_eq!(checked.tx, tx);
    assert_eq!(checked.sender, *account.address());
    assert_eq!(checked.hash, rescue.hash);

    // The signature is SLH-DSA's and checks against the last 32 bytes alone:
    // a copy of the key with the ML-DSA half zeroed still verifies it.
    let signature = signature_of(&rescue.envelope, SLH_DSA_SIGNATURE_BYTES);
    let mut slh_only = *account.public_key();
    slh_only[..PUBLIC_KEY_BYTES].fill(0);
    assert!(rescue_signature_verifies(&slh_only, &rescue.sighash, signature));
    let slhdsa_pk: [u8; 32] = slh_only[PUBLIC_KEY_BYTES..].try_into().unwrap();
    assert!(slh_dsa::verify(&slhdsa_pk, &rescue.sighash, CONTEXT, signature));
    // ... and only under the account's SLH-DSA half.
    let mut wrong_half = *account.public_key();
    wrong_half[RESCUE_PUBLIC_KEY_BYTES - 1] ^= 1;
    assert!(!rescue_signature_verifies(&wrong_half, &rescue.sighash, signature));

    // QS-13: another account's SLH-DSA signature over the same fields is
    // refused.
    let stranger = seed.rescue_account(1);
    let theirs = stranger.sign_rescue(&tx, &GENESIS, &mut rng);
    assert!(verify_envelope(&theirs.envelope, tx.chain_id, &GENESIS).is_ok());
    let mixed = tx.envelope(SCHEME_RESCUE, account.public_key(), signature_of(&theirs.envelope, SLH_DSA_SIGNATURE_BYTES));
    assert_eq!(verify_envelope(&mixed, tx.chain_id, &GENESIS).err(), Some(AccountTxError::Signature));

    // QS-13: any one field changed is refused.
    let mut changes = Vec::new();
    let mut t = tx.clone();
    t.nonce += 1;
    changes.push(t);
    let mut t = tx.clone();
    t.to = Some([0x5b; 20]);
    changes.push(t);
    let mut t = tx.clone();
    t.value += 1;
    changes.push(t);
    let mut t = tx.clone();
    t.data.push(0);
    changes.push(t);
    let mut t = tx.clone();
    t.max_fee_per_gas += 1;
    changes.push(t);
    for changed in changes {
        let forged = changed.envelope(SCHEME_RESCUE, account.public_key(), signature);
        assert_eq!(verify_envelope(&forged, tx.chain_id, &GENESIS).err(), Some(AccountTxError::Signature));
    }
    // The ML-DSA half is inside the signed message: swapping it is refused.
    let swapped = tx.envelope(SCHEME_RESCUE, &slh_only, signature);
    assert_eq!(verify_envelope(&swapped, tx.chain_id, &GENESIS).err(), Some(AccountTxError::Signature));
}

#[test]
fn rescue_account_is_not_the_plain_account() {
    let seed = WalletSeed::from_bytes(COUNTING);
    for v in &VECTORS[..2] {
        let rescue = seed.rescue_account(v.index);
        let plain = seed.account(v.index);
        assert_ne!(rescue.address(), plain.address());
        assert_ne!(rescue.ml_dsa_public_key(), plain.public_key());
        let alone = account_address(SCHEME_ML_DSA_44, rescue.ml_dsa_public_key());
        assert_eq!(hex(&alone), v.address_0x0001_of_mldsa_pk_alone);
        assert_ne!(alone, *rescue.address());
    }

    // QS-15: a 0x0003 and a 0x0004 transaction of one key have one sender.
    let account = seed.rescue_account(0);
    let mut rng = StdRng::from_seed([5; 32]);
    let tx = transfer();
    let normal = account.sign(&tx, &GENESIS, &mut rng);
    let rescue = account.sign_rescue(&tx, &GENESIS, &mut rng);
    assert_ne!(normal.sighash, rescue.sighash, "the scheme ID is in the signed message");
    let a = verify_envelope(&normal.envelope, tx.chain_id, &GENESIS).unwrap();
    let b = verify_envelope(&rescue.envelope, tx.chain_id, &GENESIS).unwrap();
    assert_eq!((a.scheme, b.scheme), (SCHEME_RESCUE_KEY, SCHEME_RESCUE));
    assert_eq!(a.sender, *account.address());
    assert_eq!(b.sender, *account.address());
    assert_eq!(normal.sender, rescue.sender);
    assert_eq!(account_address(SCHEME_RESCUE, account.public_key()), *account.address());
}

#[test]
fn restore_on_a_second_device_gives_the_same_address_and_a_valid_rescue() {
    let mut rng = StdRng::from_seed([11; 32]);
    let first = WalletSeed::generate(&mut rng);
    let words = first.to_words();
    let second = WalletSeed::from_words(words.as_str()).unwrap();
    let device_one = first.rescue_account(2);
    let device_two = second.rescue_account(2);
    assert_eq!(device_one.address(), device_two.address());
    assert_eq!(device_one.public_key(), device_two.public_key());

    let tx = transfer();
    let from_two = device_two.sign_rescue(&tx, &GENESIS, &mut rng);
    let checked = verify_envelope(&from_two.envelope, tx.chain_id, &GENESIS).unwrap();
    assert_eq!(checked.sender, *device_one.address());

    let from_one = device_one.sign_rescue(&tx, &GENESIS, &mut rng);
    assert_eq!(from_one.sighash, from_two.sighash);
    assert!(rescue_signature_verifies(
        device_two.public_key(),
        &from_one.sighash,
        signature_of(&from_one.envelope, SLH_DSA_SIGNATURE_BYTES)
    ));
    let on_two = tx.envelope(SCHEME_RESCUE, device_two.public_key(), signature_of(&from_one.envelope, SLH_DSA_SIGNATURE_BYTES));
    assert_eq!(verify_envelope(&on_two, tx.chain_id, &GENESIS).unwrap().sender, *device_two.address());
}

#[test]
fn cross_scheme_signatures_are_refused() {
    let seed = WalletSeed::from_bytes([0xff; 32]);
    let account = seed.rescue_account(0);
    let plain = seed.account(0);
    let mut rng = StdRng::from_seed([13; 32]);
    let tx = transfer();
    let ml = account.sign(&tx, &GENESIS, &mut rng);
    let slh = account.sign_rescue(&tx, &GENESIS, &mut rng);
    let plain_signed = plain.sign(&tx, &GENESIS, &mut rng);
    assert!(verify_envelope(&ml.envelope, tx.chain_id, &GENESIS).is_ok());
    assert!(verify_envelope(&slh.envelope, tx.chain_id, &GENESIS).is_ok());
    assert!(verify_envelope(&plain_signed.envelope, tx.chain_id, &GENESIS).is_ok());
    let ml_sig = signature_of(&ml.envelope, SIGNATURE_BYTES);
    let slh_sig = signature_of(&slh.envelope, SLH_DSA_SIGNATURE_BYTES);
    let plain_sig = signature_of(&plain_signed.envelope, SIGNATURE_BYTES);
    let pk = account.public_key();
    let refused = |envelope: Vec<u8>| {
        let err = verify_envelope(&envelope, tx.chain_id, &GENESIS).err();
        assert!(
            matches!(err, Some(AccountTxError::Signature | AccountTxError::Length)),
            "expected Signature or Length, got {err:?}"
        );
    };

    // A 0x0003 signature in a 0x0004 envelope, and the other way round.
    refused(tx.envelope(SCHEME_RESCUE, pk, ml_sig));
    refused(tx.envelope(SCHEME_RESCUE_KEY, pk, slh_sig));
    assert!(!rescue_signature_verifies(pk, &slh.sighash, ml_sig));
    // A 0x0001 signature in a 0x0003 envelope: with the plain account's key
    // in front of a rescue half, and with the rescue account's key.
    let mut grafted = [0u8; RESCUE_PUBLIC_KEY_BYTES];
    grafted[..PUBLIC_KEY_BYTES].copy_from_slice(plain.public_key());
    grafted[PUBLIC_KEY_BYTES..].copy_from_slice(account.slh_dsa_public_key());
    refused(tx.envelope(SCHEME_RESCUE_KEY, &grafted, plain_sig));
    refused(tx.envelope(SCHEME_RESCUE_KEY, pk, plain_sig));
    // A 0x0003 signature presented as 0x0001 over the ML-DSA half alone.
    refused(tx.envelope(SCHEME_ML_DSA_44, account.ml_dsa_public_key(), ml_sig));
    // A 0x0004 signature as 0x0002: the stand-in node accepts no 0x0002.
    assert_eq!(
        verify_envelope(&tx.envelope(0x0002, account.slh_dsa_public_key(), slh_sig), tx.chain_id, &GENESIS).err(),
        Some(AccountTxError::Scheme(2))
    );

    // Wrong lengths: the 1,312-byte key under 0x0003 or 0x0004, a key one
    // byte short, a signature one byte short or long.
    for scheme in [SCHEME_RESCUE_KEY, SCHEME_RESCUE] {
        let sig = if scheme == SCHEME_RESCUE { slh_sig } else { ml_sig };
        let e = tx.envelope(scheme, account.ml_dsa_public_key(), sig);
        assert_eq!(verify_envelope(&e, tx.chain_id, &GENESIS).err(), Some(AccountTxError::Length));
        let e = tx.envelope(scheme, &pk[..RESCUE_PUBLIC_KEY_BYTES - 1], sig);
        assert_eq!(verify_envelope(&e, tx.chain_id, &GENESIS).err(), Some(AccountTxError::Length));
        let e = tx.envelope(scheme, pk, &sig[..sig.len() - 1]);
        assert_eq!(verify_envelope(&e, tx.chain_id, &GENESIS).err(), Some(AccountTxError::Length));
        let mut long = sig.to_vec();
        long.push(0);
        let e = tx.envelope(scheme, pk, &long);
        assert_eq!(verify_envelope(&e, tx.chain_id, &GENESIS).err(), Some(AccountTxError::Length));
    }
    assert!(!rescue_signature_verifies(&pk[..PUBLIC_KEY_BYTES], &slh.sighash, slh_sig));
    assert!(!rescue_signature_verifies(pk, &slh.sighash, &slh_sig[1..]));
}

//! Тесты для `family.rs`.

use p256::ecdsa::SigningKey;
use uu_i2p::{
    IdentHash,
    family::{Families, FamilyKey, MAX_FAMILY_NAME_LEN, create_family_signature},
};

/// Детерминированный seed для тестов.
const SEED: [u8; 32] = [0x42u8; 32];

/// Публичный ключ, соответствующий `SEED`.
fn family_key() -> FamilyKey {
    let sk = SigningKey::from_slice(&SEED).expect("valid seed");
    let sec1 = sk.verifying_key().to_sec1_point(false);
    FamilyKey::from_sec1(sec1.as_bytes()).expect("valid public key")
}
const fn ident(seed: u8) -> IdentHash {
    IdentHash::from_array([seed; 32])
}

///////////////////////////////////////////
// --- FamilyKey -----------------------------------------------------------

#[test]
fn family_key_accepts_uncompressed() {
    let sk = SigningKey::from_slice(&SEED).unwrap();
    let uncompressed = sk.verifying_key().to_sec1_point(false);
    assert!(FamilyKey::from_sec1(uncompressed.as_bytes()).is_ok());
}

#[test]
fn family_key_accepts_compressed() {
    let sk = SigningKey::from_slice(&SEED).unwrap();
    let compressed = sk.verifying_key().to_sec1_point(true);
    assert!(FamilyKey::from_sec1(compressed.as_bytes()).is_ok());
}

#[test]
fn family_key_rejects_empty() {
    assert!(FamilyKey::from_sec1(&[]).is_err());
}

#[test]
fn family_key_rejects_wrong_length() {
    // 64 байта без префикса 0x04 — не SEC1.
    let bytes = [0u8; 64];
    assert!(FamilyKey::from_sec1(&bytes).is_err());
}

#[test]
fn family_key_roundtrips_bytes() {
    let sk = SigningKey::from_slice(&SEED).unwrap();
    let sec1 = sk.verifying_key().to_sec1_point(false);
    let fk = FamilyKey::from_sec1(sec1.as_bytes()).unwrap();
    assert_eq!(fk.as_sec1(), sec1.as_bytes());
}

// --- Families: регистрация ----------------------------------------------

#[test]
fn families_new_is_empty() {
    let fams = Families::new();
    assert!(fams.is_empty());
    assert_eq!(fams.len(), 0);
}

#[test]
fn families_insert_returns_id_starting_at_one() {
    let mut fams = Families::new();
    let id = fams.insert("alpha", family_key()).unwrap();
    assert_eq!(id, 1);
    assert_eq!(fams.get_id("alpha"), 1);

    let id2 = fams.insert("beta", family_key()).unwrap();
    assert_eq!(id2, 2);
}

#[test]
fn families_insert_lowercases_name() {
    let mut fams = Families::new();
    fams.insert("MyFamily", family_key()).unwrap();
    assert_eq!(fams.get_id("myfamily"), 1);
    assert_eq!(fams.get_id("MYFAMILY"), 1);
}

#[test]
fn families_insert_rejects_duplicate() {
    let mut fams = Families::new();
    fams.insert("alpha", family_key()).unwrap();
    assert!(fams.insert("alpha", family_key()).is_err());
    // Регистр не важен — дубликат и так и так.
    assert!(fams.insert("ALPHA", family_key()).is_err());
}

#[test]
fn families_insert_rejects_empty_name() {
    let mut fams = Families::new();
    assert!(fams.insert("", family_key()).is_err());
}

#[test]
fn families_insert_rejects_too_long_name() {
    let mut fams = Families::new();
    let long = "x".repeat(MAX_FAMILY_NAME_LEN + 1);
    assert!(fams.insert(&long, family_key()).is_err());

    // На границе — должно пройти.
    let mut fams = Families::new();
    let exact = "x".repeat(MAX_FAMILY_NAME_LEN);
    assert!(fams.insert(&exact, family_key()).is_ok());
}

#[test]
fn families_get_id_unknown_is_zero() {
    let fams = Families::new();
    assert_eq!(fams.get_id("nope"), 0);
}

// --- Families: verify ---------------------------------------------------

#[test]
fn verify_succeeds_with_matching_signature() {
    let mut fams = Families::new();
    fams.insert("alpha", family_key()).unwrap();

    let id = ident(0x11);
    let sig_b64 = create_family_signature("alpha", &id, &SEED).unwrap();
    let sig = uu_i2p::base64::decode(&sig_b64).unwrap();

    assert!(fams.verify("alpha", &id, &sig));
}

#[test]
fn verify_case_insensitive() {
    let mut fams = Families::new();
    fams.insert("MyFamily", family_key()).unwrap();

    let id = ident(0x11);
    let sig_b64 = create_family_signature("myfamily", &id, &SEED).unwrap();
    let sig = uu_i2p::base64::decode(&sig_b64).unwrap();

    assert!(fams.verify("MYFAMILY", &id, &sig));
    assert!(fams.verify("myfamily", &id, &sig));
    assert!(fams.verify("MyFamily", &id, &sig));
}

#[test]
fn verify_fails_for_unknown_family() {
    let fams = Families::new();
    let id = ident(0x11);
    let sig = [0u8; 64];
    assert!(!fams.verify("ghost", &id, &sig));
}

#[test]
fn verify_fails_for_wrong_ident() {
    let mut fams = Families::new();
    fams.insert("alpha", family_key()).unwrap();

    let signed_id = ident(0x11);
    let other_id = ident(0x22);
    let sig_b64 = create_family_signature("alpha", &signed_id, &SEED).unwrap();
    let sig = uu_i2p::base64::decode(&sig_b64).unwrap();

    assert!(fams.verify("alpha", &signed_id, &sig));
    assert!(!fams.verify("alpha", &other_id, &sig));
}

#[test]
fn verify_fails_for_wrong_family_name() {
    let mut fams = Families::new();
    fams.insert("alpha", family_key()).unwrap();
    fams.insert("beta", family_key()).unwrap();

    let id = ident(0x11);
    let sig_b64 = create_family_signature("alpha", &id, &SEED).unwrap();
    let sig = uu_i2p::base64::decode(&sig_b64).unwrap();

    // Подпись валидна как подпись «alpha», но ключ «beta» её не примет.
    assert!(fams.verify("alpha", &id, &sig));
    assert!(!fams.verify("beta", &id, &sig));
}

#[test]
fn verify_fails_for_wrong_key() {
    // Семейство с одним ключом, подпись другим ключом.
    let mut fams = Families::new();
    let wrong_key = {
        let sk = SigningKey::from_slice(&[0xABu8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_sec1_point(false);
        FamilyKey::from_sec1(sec1.as_bytes()).unwrap()
    };
    fams.insert("alpha", wrong_key).unwrap();

    let id = ident(0x11);
    let sig_b64 = create_family_signature("alpha", &id, &SEED).unwrap();
    let sig = uu_i2p::base64::decode(&sig_b64).unwrap();

    assert!(!fams.verify("alpha", &id, &sig));
}

#[test]
fn verify_fails_for_bad_signature_length() {
    let mut fams = Families::new();
    fams.insert("alpha", family_key()).unwrap();
    // 63 байта вместо 64.
    assert!(!fams.verify("alpha", &ident(0x11), &[0u8; 63]));
    // Пусто.
    assert!(!fams.verify("alpha", &ident(0x11), &[]));
}

#[test]
fn verify_fails_for_tampered_signature() {
    let mut fams = Families::new();
    fams.insert("alpha", family_key()).unwrap();

    let id = ident(0x11);
    let sig_b64 = create_family_signature("alpha", &id, &SEED).unwrap();
    let mut sig = uu_i2p::base64::decode(&sig_b64).unwrap();
    // Портим r.
    sig[0] ^= 0xFF;

    assert!(!fams.verify("alpha", &id, &sig));
}

// --- create_family_signature --------------------------------------------

#[test]
fn signature_is_64_bytes_base64_encoded() {
    let id = ident(0x11);
    let b64 = create_family_signature("alpha", &id, &SEED).unwrap();
    let raw = uu_i2p::base64::decode(&b64).unwrap();
    assert_eq!(raw.len(), 64);
}

#[test]
fn signature_is_deterministic() {
    // ECDSA P-256 через `p256` использует RFC 6979 (deterministic
    // nonce) при подписи. Значит с одним и тем же ключом и одним
    // и тем же сообщением подпись всегда одна и та же.
    let id = ident(0x11);
    let a = create_family_signature("alpha", &id, &SEED).unwrap();
    let b = create_family_signature("alpha", &id, &SEED).unwrap();
    assert_eq!(a, b);
}

#[test]
fn signature_differs_by_ident() {
    let a = create_family_signature("alpha", &ident(0x11), &SEED).unwrap();
    let b = create_family_signature("alpha", &ident(0x22), &SEED).unwrap();
    assert_ne!(a, b);
}

#[test]
fn signature_differs_by_family_name() {
    let id = ident(0x11);
    let a = create_family_signature("alpha", &id, &SEED).unwrap();
    let b = create_family_signature("beta", &id, &SEED).unwrap();
    assert_ne!(a, b);
}

#[test]
fn signature_rejects_empty_name() {
    assert!(create_family_signature("", &ident(0x11), &SEED).is_err());
}

#[test]
fn signature_rejects_too_long_name() {
    // Порог в i2pd: len(name) + 32 <= 100 ⇒ len(name) <= 68.
    // 69 символов — уже не влезает.
    let long = "x".repeat(69);
    assert!(create_family_signature(&long, &ident(0x11), &SEED).is_err());

    // 68 — на границе, должно пройти.
    let exact = "x".repeat(68);
    assert!(create_family_signature(&exact, &ident(0x11), &SEED).is_ok());
}

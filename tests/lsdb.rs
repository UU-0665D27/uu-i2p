//! Тесты [`Lsdb`] — хранилища `LeaseSet`'ов флудфилла.
//!
//! Правила взяты из i2pd `NetDb::AddLeaseSet`/`AddLeaseSet2`/
//! `ManageLeaseSets`, поэтому проверяем не только «сохранил/отдал»,
//! но и порядок версий, `unpublished`, истечение и типы.

use std::time::{SystemTime, UNIX_EPOCH};

use uu_i2p::{
    ENCRYPTION_KEY_SIZE, I2PError, I2PTag, IdentHash, LEASE_ENDDATE_THRESHOLD_MS, Lease, LeaseSet,
    LeaseSet2, Lsdb, LsdbOutcome, MAX_LS_BUFFER_SIZE, StoreType, private_keys::I2PPrivateKeys,
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis()
        .try_into()
        .expect("millis fit u64")
}

fn now_secs() -> u32 {
    u32::try_from(now_ms() / 1000).expect("seconds fit u32")
}

fn lease(n: u8, end_date_ms: u64) -> Lease {
    Lease::new(IdentHash::from_array([n; 32]), u32::from(n), end_date_ms)
}

/// Подписанный `LeaseSet2` (тип 3) и его ключ (= `ident_hash`
/// destination'а).
fn signed_lease_set2(published: u32, expires: u16, lease_end_ms: u64) -> (IdentHash, Vec<u8>) {
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let ls = LeaseSet2::from_keys(&keys, published, expires, vec![lease(1, lease_end_ms)])
        .expect("build ls2");
    let key = *keys.public().ident_hash();
    (key, ls.to_buffer().expect("serialize ls2"))
}

/// Подписанный `LeaseSet` (тип 1).
///
/// Формат: identity | `encryption_key`[256] | `signing_key` | num | leases
/// | signature (i2pd `LeaseSet::ReadFromBuffer`).
fn signed_lease_set1(keys: &I2PPrivateKeys, leases: &[Lease]) -> Vec<u8> {
    let identity = keys.public();
    let mut out = vec![0u8; identity.full_len()];
    identity.to_buffer(&mut out).expect("identity to buffer");
    out.extend(std::iter::repeat_n(0xEE_u8, ENCRYPTION_KEY_SIZE));
    out.extend_from_slice(&identity.signing_public_key().expect("signing key"));
    out.push(u8::try_from(leases.len()).expect("lease count"));
    for lease in leases {
        out.extend_from_slice(&lease.to_buffer_ls1());
    }
    let signature = keys.sign(&out).expect("sign ls1");
    out.extend_from_slice(&signature);
    out
}

#[test]
fn empty_store() {
    let db = Lsdb::new();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
    assert_eq!(db.total_bytes(), 0);
    assert!(db.get(&I2PTag::from_array([1; 32]), now_ms()).is_none());
}

#[test]
fn insert_lease_set2_and_get() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let (key, bytes) = signed_lease_set2(now_secs(), 600, now + 600_000);

    let outcome = db
        .insert(key, StoreType::LeaseSet2, bytes.clone(), now)
        .expect("insert");
    assert_eq!(outcome, LsdbOutcome::Inserted);
    assert_eq!(db.len(), 1);
    assert_eq!(db.total_bytes(), bytes.len());

    let entry = db.get(&key, now).expect("entry");
    assert_eq!(entry.store_type(), StoreType::LeaseSet2);
    assert_eq!(entry.bytes(), bytes.as_slice());
    assert_eq!(entry.expires_ms(), u64::from(now_secs() + 600) * 1000);
    assert!(db.contains(&key, now));
}

#[test]
fn newer_lease_set2_replaces_older() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let key = *keys.public().ident_hash();
    let older = LeaseSet2::from_keys(&keys, now_secs() - 100, 600, vec![lease(2, now + 600_000)])
        .expect("older")
        .to_buffer()
        .expect("older bytes");
    let newer = LeaseSet2::from_keys(&keys, now_secs(), 900, vec![lease(2, now + 900_000)])
        .expect("newer")
        .to_buffer()
        .expect("newer bytes");

    db.insert(key, StoreType::LeaseSet2, older.clone(), now)
        .expect("insert older");
    assert_eq!(
        db.insert(key, StoreType::LeaseSet2, newer.clone(), now)
            .expect("insert newer"),
        LsdbOutcome::Updated
    );
    assert_eq!(db.get(&key, now).expect("entry").bytes(), newer.as_slice());
    assert_eq!(db.total_bytes(), newer.len());

    // Обратный порядок — Stale, байты не меняются.
    assert_eq!(
        db.insert(key, StoreType::LeaseSet2, older, now)
            .expect("insert older again"),
        LsdbOutcome::Stale
    );
    assert_eq!(db.get(&key, now).expect("entry").bytes(), newer.as_slice());
}

#[test]
fn unpublished_lease_set2_is_rejected_and_removes_old() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let key = *keys.public().ident_hash();

    let public = LeaseSet2::from_keys(&keys, now_secs(), 600, vec![lease(3, now + 600_000)])
        .expect("public")
        .to_buffer()
        .expect("public bytes");
    db.insert(key, StoreType::LeaseSet2, public, now)
        .expect("insert");
    assert_eq!(db.len(), 1);

    let unpublished = LeaseSet2::builder()
        .published_timestamp(now_secs() + 1)
        .expires(600)
        .unpublished()
        .add_lease(lease(3, now + 600_000))
        .build(&keys)
        .expect("unpublished")
        .to_buffer()
        .expect("unpublished bytes");

    assert_eq!(
        db.insert(key, StoreType::LeaseSet2, unpublished, now)
            .expect("insert unpublished"),
        LsdbOutcome::Rejected
    );
    // i2pd `AddLeaseSet2`: erase.
    assert_eq!(db.len(), 0);
}

#[test]
fn expired_lease_set2_is_rejected() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let (key, bytes) = signed_lease_set2(now_secs() - 100, 10, now - 60_000);

    assert_eq!(
        db.insert(key, StoreType::LeaseSet2, bytes, now)
            .expect("insert"),
        LsdbOutcome::Rejected
    );
    assert!(db.is_empty());
}

#[test]
fn get_hides_expired_entry() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let (key, bytes) = signed_lease_set2(now_secs(), 1, now + 1_000);
    db.insert(key, StoreType::LeaseSet2, bytes, now)
        .expect("insert");

    assert!(db.get(&key, now).is_some());
    let expires = u64::from(now_secs() + 1) * 1000;
    assert!(
        db.get(&key, expires + 1).is_none(),
        "по истечении запись не отдаётся"
    );
}

#[test]
fn expire_removes_before_formal_deadline() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let (key, bytes) = signed_lease_set2(now_secs(), 60, now + 60_000);
    db.insert(key, StoreType::LeaseSet2, bytes, now)
        .expect("insert");

    let expires = u64::from(now_secs() + 60) * 1000;
    // i2pd `ManageLeaseSets`: ts > expiration - LEASE_ENDDATE_THRESHOLD.
    assert_eq!(db.expire(expires - LEASE_ENDDATE_THRESHOLD_MS), 0);
    assert_eq!(db.expire(expires - LEASE_ENDDATE_THRESHOLD_MS + 1), 1);
    assert!(db.is_empty());
    assert_eq!(db.total_bytes(), 0);
}

#[test]
fn remove_updates_total_bytes() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let (key, bytes) = signed_lease_set2(now_secs(), 600, now + 600_000);
    let len = bytes.len();
    db.insert(key, StoreType::LeaseSet2, bytes, now)
        .expect("insert");
    assert_eq!(db.total_bytes(), len);

    let removed = db.remove(&key).expect("removed");
    assert_eq!(removed.bytes().len(), len);
    assert_eq!(db.total_bytes(), 0);
    assert!(db.remove(&key).is_none());
}

#[test]
fn too_long_is_rejected() {
    let mut db = Lsdb::new();
    let r = db.insert(
        I2PTag::from_array([1; 32]),
        StoreType::LeaseSet2,
        vec![0u8; MAX_LS_BUFFER_SIZE + 1],
        now_ms(),
    );
    assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
}

#[test]
fn router_info_type_is_rejected() {
    let mut db = Lsdb::new();
    let r = db.insert(
        I2PTag::from_array([1; 32]),
        StoreType::RouterInfo,
        vec![0u8; 10],
        now_ms(),
    );
    assert!(matches!(r, Err(I2PError::Malformed(_))));
}

#[test]
fn encrypted_and_meta_are_unsupported() {
    for store_type in [
        StoreType::EncryptedLeaseSet2,
        StoreType::MetaLeaseSet2,
        StoreType::Unknown(9),
    ] {
        let mut db = Lsdb::new();
        let r = db.insert(
            I2PTag::from_array([1; 32]),
            store_type,
            vec![0u8; 10],
            now_ms(),
        );
        assert!(
            matches!(r, Err(I2PError::Unsupported(_) | I2PError::Malformed(_))),
            "{store_type:?}: {r:?}"
        );
    }
}

#[test]
fn tampered_lease_set2_signature_is_rejected() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let (key, mut bytes) = signed_lease_set2(now_secs(), 600, now + 600_000);
    // Портим подпись (последний байт).
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    let r = db.insert(key, StoreType::LeaseSet2, bytes, now);
    assert!(matches!(r, Err(I2PError::Malformed(_))), "{r:?}");
    assert!(db.is_empty());
}

#[test]
fn lease_set1_insert_and_expiry() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let key = *keys.public().ident_hash();
    let end_date = now + 600_000;
    let bytes = signed_lease_set1(&keys, &[lease(4, end_date)]);

    // Разбор/подпись — как в i2pd.
    LeaseSet::from_buffer(&bytes)
        .expect("parse ls1")
        .verify(&bytes)
        .expect("verify ls1");

    assert_eq!(
        db.insert(key, StoreType::LeaseSet, bytes, now)
            .expect("insert"),
        LsdbOutcome::Inserted
    );
    let entry = db.get(&key, now).expect("entry");
    assert_eq!(entry.store_type(), StoreType::LeaseSet);
    // i2pd добавляет LEASE_ENDDATE_THRESHOLD к сроку LS1.
    assert_eq!(entry.expires_ms(), end_date + LEASE_ENDDATE_THRESHOLD_MS);
    assert_eq!(entry.published_ms(), 0);
}

#[test]
fn expired_lease_set1_is_rejected() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let key = *keys.public().ident_hash();
    let bytes = signed_lease_set1(&keys, &[lease(5, now - 60_000)]);

    assert_eq!(
        db.insert(key, StoreType::LeaseSet, bytes, now)
            .expect("insert"),
        LsdbOutcome::Rejected
    );
    assert!(db.is_empty());
}

#[test]
fn lease_set1_does_not_replace_lease_set2() {
    let mut db = Lsdb::new();
    let now = now_ms();
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let key = *keys.public().ident_hash();

    let ls2 = LeaseSet2::from_keys(&keys, now_secs(), 600, vec![lease(6, now + 600_000)])
        .expect("ls2")
        .to_buffer()
        .expect("ls2 bytes");
    db.insert(key, StoreType::LeaseSet2, ls2.clone(), now)
        .expect("insert ls2");

    let ls1 = signed_lease_set1(&keys, &[lease(6, now + 600_000)]);
    assert_eq!(
        db.insert(key, StoreType::LeaseSet, ls1, now)
            .expect("insert ls1"),
        LsdbOutcome::Stale
    );
    assert_eq!(
        db.get(&key, now).expect("entry").store_type(),
        StoreType::LeaseSet2
    );
    assert_eq!(db.get(&key, now).expect("entry").bytes(), ls2.as_slice());
}

#[test]
fn invalid_lease_set1_is_rejected() {
    let mut db = Lsdb::new();
    let keys = I2PPrivateKeys::generate_default().expect("keys");
    let key = *keys.public().ident_hash();
    let mut bytes = signed_lease_set1(&keys, &[lease(7, now_ms() + 600_000)]);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    let r = db.insert(key, StoreType::LeaseSet, bytes, now_ms());
    assert!(matches!(r, Err(I2PError::Malformed(_))), "{r:?}");
    assert!(db.is_empty());
}

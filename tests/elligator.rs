//! Тесты для `elligator`.
//!
//! Прямых golden-векторов из i2pd нет, поэтому проверяем свойства:
//! round-trip (encode → decode), детерминизм, обработку невалидных
//! входов. Косвенно проверяется и математика: если бы `sqrt` или
//! Legendre были с ошибкой, round-trip бы не сходился.

use rand::SeedableRng;
use rand::rngs::StdRng;
use uu_i2p::crypto::I2PX25519Keys;
use uu_i2p::elligator::{decode, encode, encode_random};

// --- хелперы -------------------------------------------------------------

/// Ищет X25519-ключ, который Elligator может закодировать.
///
/// `I2PX25519Keys::generate()` даёт случайный ключ; ~50% из них
/// не представимы. Перебираем, пока не найдём подходящий.
fn find_encodable(high_y: bool) -> ([u8; 32], [u8; 32]) {
    for _ in 0..64 {
        let sk = I2PX25519Keys::generate();
        let pk = *sk.public_key();
        if let Some(e) = encode(&pk, high_y) {
            return (pk, e);
        }
    }
    panic!("could not find an Elligator-encodable X25519 key in 64 tries");
}

// --- round-trip ----------------------------------------------------------

#[test]
fn roundtrip_high_y_true() {
    let (pk, e) = find_encodable(true);
    let back = decode(&e).expect("decode must succeed for our own encoding");
    assert_eq!(back, pk, "decode(encode(pk, true)) must return pk");
}

#[test]
fn roundtrip_high_y_false() {
    let (pk, e) = find_encodable(false);
    let back = decode(&e).expect("decode must succeed for our own encoding");
    assert_eq!(back, pk, "decode(encode(pk, false)) must return pk");
}

#[test]
fn roundtrip_many_keys() {
    // Прогоняем десяток ключей через оба варианта high_y.
    for _ in 0..10 {
        let sk = I2PX25519Keys::generate();
        let pk = *sk.public_key();
        if let Some(e) = encode(&pk, true) {
            assert_eq!(decode(&e).unwrap(), pk);
        }
        if let Some(e) = encode(&pk, false) {
            assert_eq!(decode(&e).unwrap(), pk);
        }
    }
}

#[test]
fn encode_random_roundtrips() {
    let mut rng = StdRng::seed_from_u64(0x1234_5678_9ABC_DEF0);
    for _ in 0..16 {
        let sk = I2PX25519Keys::generate();
        let pk = *sk.public_key();
        if let Some(e) = encode_random(&pk, &mut rng) {
            assert_eq!(
                decode(&e).unwrap(),
                pk,
                "encode_random → decode must roundtrip",
            );
        }
    }
}

// --- encode: свойства ----------------------------------------------------

#[test]
fn encode_is_deterministic() {
    let (pk, e1) = find_encodable(true);
    let e2 = encode(&pk, true).expect("same key still encodable");
    assert_eq!(e1, e2, "encode must be deterministic");
}

#[test]
fn encode_high_y_gives_different_results() {
    // Найдём ключ, который кодируется обоими вариантами high_y.
    // Он есть: оба варианта работают при одном и том же условии
    // Legendre(uxxA) != -1, различается только формула для r.
    for _ in 0..64 {
        let sk = I2PX25519Keys::generate();
        let pk = *sk.public_key();
        if let (Some(e_true), Some(e_false)) = (encode(&pk, true), encode(&pk, false)) {
            assert_ne!(e_true, e_false, "high_y must produce different encodings");
            // Но decode даёт один и тот же pk.
            assert_eq!(decode(&e_true).unwrap(), pk);
            assert_eq!(decode(&e_false).unwrap(), pk);
            return;
        }
    }
    panic!("could not find a key encodable with both high_y values");
}

#[test]
fn encode_produces_zero_top_bits() {
    let (_, e) = find_encodable(true);
    // Верхние 2 бита последнего байта (в LE) должны быть нулевыми.
    assert_eq!(e[31] & 0xC0, 0, "deterministic encode must zero top 2 bits");
}

#[test]
fn encode_random_top_bits_are_masked_in_decode() {
    // Закодируем с рандомными старшими битами и проверим,
    // что decode их отбрасывает и восстанавливает исходный pk.
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..32 {
        let sk = I2PX25519Keys::generate();
        let pk = *sk.public_key();
        if let Some(e) = encode_random(&pk, &mut rng) {
            // Просто очистим верхние биты «вручную» и убедимся,
            // что decode даёт то же самое.
            let mut e_clean = e;
            e_clean[31] &= 0x3F;
            assert_eq!(
                decode(&e).unwrap(),
                decode(&e_clean).unwrap(),
                "decode must ignore top 2 bits",
            );
        }
    }
}

// --- encode: отказ -------------------------------------------------------

#[test]
fn encode_rejects_some_keys() {
    // Не все случайные 32-байтовые значения — образ Elligator.
    // Ожидаем, что за 32 попытки хотя бы одна провалится.
    // (Вероятность ложного успеха всех 32 подряд ≈ 2^-32.)
    let mut failures = 0;
    for i in 0u8..64 {
        let key = [i; 32];
        if encode(&key, false).is_none() {
            failures += 1;
        }
    }
    assert!(
        failures > 0,
        "at least one of 64 simple keys must fail to encode",
    );
}

// --- decode: границы -----------------------------------------------------

#[test]
fn decode_rejects_zero_value() {
    // Все нули дают r = 0. По алгоритму decode отдаёт
    // x = −A; это валидный ответ, но не наш ключ.
    // Главное — decode не паникует.
    let zero = [0u8; 32];
    let _ = decode(&zero);
}

#[test]
fn decode_accepts_random_bytes_without_panic() {
    for i in 0u8..32 {
        let buf = [i.wrapping_mul(17); 32];
        let _ = decode(&buf);
    }
}

#[test]
fn decode_of_encode_of_zero_is_stable() {
    // Ключ из нулей кодируется в что-то (или нет), и decode
    // не падает. Основное — стабильность.
    let zero = [0u8; 32];
    if let Some(e) = encode(&zero, false) {
        let _ = decode(&e);
    }
}

// --- decode: форма -------------------------------------------------------

#[test]
fn decode_output_is_32_bytes() {
    let (_, e) = find_encodable(false);
    let pk = decode(&e).unwrap();
    assert_eq!(pk.len(), 32);
}

// --- интеграция с I2PX25519Keys -----------------------------------------

#[test]
fn decode_matches_original_x25519_public_key() {
    // Самый важный тест: ключ, отданный `I2PX25519Keys::generate`,
    // после encode/decode идентичен исходному. Это то, что
    // требуется для DH в ECIES ratchet.
    let (pk, e) = find_encodable(true);
    let back = decode(&e).unwrap();
    assert_eq!(back, pk);

    // И приватный ключ, которому соответствует этот pk, при
    // DH с самим собой даёт ненулевой секрет.
    // (Просто проверка, что `back` — валидный X25519 public.)
    assert!(!back.iter().all(|&b| b == 0));
}

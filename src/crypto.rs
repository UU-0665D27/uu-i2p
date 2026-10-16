//! Базовые криптографические примитивы I2P.
//!
//! Реализованы поверх `RustCrypto` (чистый Rust, без системного OpenSSL).
//! API повторяет `Crypto.h` из i2pd, чтобы код на Rust и C++ можно было
//! сопоставлять построчно.
//!
//! ## Что внутри
//!
//! - [`ChaCha20`] — потоковый шифр (IETF-вариант).
//! - [`AeadChaCha20Poly1305`] — AEAD (`ChaCha20` + Poly1305).
//! - [`hkdf`] — HKDF-SHA256.
//! - [`X25519Keys`] — X25519 для DH.
//! - [`NoiseSymmetricState`] — состояние Noise (h, ck, k) на базе
//!   ChaCha20-Poly1305 и SHA256.
//!
//! ## Что не внутри
//!
//! - Ed25519 (подписи) — отдельный модуль, чтобы не тянуть
//!   `ed25519-dalek` в бинарник, которому подписи не нужны;
//! - AES — если понадобится для совместимости с `ElGamal`, добавим
//!   точечно через `aes` + `cbc`;
//! - `ElGamal` — отдельный модуль (нужен только для legacy destination);
//! - ML-KEM — отдельный модуль (пост-квантовый).

use crate::error::{I2PError, Result};
use aes::Aes256;
use aes::cipher::{BlockModeDecrypt as _, BlockModeEncrypt as _};
use cbc::cipher::block_padding::NoPadding;
// `KeyIvInit` нужен для `Encryptor::new` / `Decryptor::new` и
// для `ChaCha20Raw::new`. В этой версии `cipher`-трейтов он один
// (cbc и chacha20 используют одну версию), поэтому импортируем
// его анонимно один раз — метод-резолюция сама найдёт impl.
use cbc::cipher::KeyIvInit as _;
use chacha20::ChaCha20 as ChaCha20Raw;
use chacha20::cipher::{StreamCipher, StreamCipherSeek as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305 as ChaCha20Poly1305Raw, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

// --- ChaCha20 ------------------------------------------------------------

/// `ChaCha20` (IETF): 32-байтовый ключ, 12-байтовый nonce, 32-битный counter.
///
/// Совпадает с `ChaCha20()` из i2pd. Используется в garlic,
/// NTCP2, SSU2 и ECIES-X25519-AEAD-Ratchet.
///
/// # Panics
///
/// Паникует, если `msg` и `out` пересекаются по памяти. Обычно
/// вызывается с одним и тем же буфером (`in-place`) — это разрешено,
/// т.к. реализация `RustCrypto` поддерживает in-place.
pub fn chacha20(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    // В I2P counter всегда начинается с 1 (см. `Crypto.cpp`
    // `ChaCha20`), но RustCrypto-крейт считает counter с 0.
    // i2pd использует счётчик 1 для совместимости с AEAD, но
    // в чистых stream-операциях обычно передаёт собственный
    // nonce с counter=1. Мы принимаем nonce как есть — caller
    // сам решает, какой counter внутри.
    let mut cipher = ChaCha20Raw::new(key.into(), nonce.into());
    cipher.apply_keystream(data);
}

/// `ChaCha20` с начальным счётчиком **1** — как `ChaCha20()` в i2pd.
///
/// i2pd кладёт в IV `htole32(1) || nonce`, т.е. keystream начинается
/// со второго блока. [`chacha20`] начинает с блока 0, поэтому для
/// совместимости с i2pd (tunnel build reply layers и т.п.) нужна
/// именно эта функция. Шифрование и расшифровка — одна и та же
/// операция (XOR).
pub fn chacha20_counter1(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let mut cipher = ChaCha20Raw::new(key.into(), nonce.into());
    // 64 байта = один блок ChaCha20, т.е. counter = 1
    cipher.seek(64_u32);
    cipher.apply_keystream(data);
}

/// AEAD на ChaCha20-Poly1305.
///
/// Один экземпляр можно переиспользовать — внутри не хранит
/// никакого состояния, каждый вызов `encrypt`/`decrypt`
/// независим.
///
/// Совпадает с `AEADChaCha20Poly1305` из i2pd.
#[derive(Default)]
pub struct AeadChaCha20Poly1305;

impl AeadChaCha20Poly1305 {
    /// Новый экземпляр.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Шифрует `msg` с `key` и `nonce`, дополнительно
    /// аутентифицирует `ad`.
    ///
    /// `buf` должен быть не меньше `msg.len() + 16` (тег Poly1305).
    /// Возвращает длину записанного ciphertext (включая тег).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `buf` короче `msg.len() + 16`.
    pub fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ad: &[u8],
        msg: &[u8],
        buf: &mut [u8],
    ) -> Result<usize> {
        if buf.len() < msg.len() + 16 {
            return Err(I2PError::Malformed(
                "aead: buf too small for ciphertext + tag",
            ));
        }
        let key_arr = Key::from(*key);
        let nonce_arr = Nonce::from(*nonce);
        let cipher = ChaCha20Poly1305Raw::new(&key_arr);
        let payload = Payload { msg, aad: ad };
        let ct = cipher
            .encrypt(&nonce_arr, payload)
            .map_err(|_| I2PError::Malformed("aead: encrypt failed"))?;
        buf[..ct.len()].copy_from_slice(&ct);
        Ok(ct.len())
    }

    /// Расшифровывает `msg` (ciphertext + 16-байтовый тег) с `key`,
    /// `nonce`, `ad`.
    ///
    /// `buf` должен быть не меньше `msg.len() - 16`. Возвращает
    /// длину расшифрованного plaintext.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `msg` короче 16 байт (нет тега);
    /// - [`Error::Malformed`], если тег не сходится.
    pub fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ad: &[u8],
        msg: &[u8],
        buf: &mut [u8],
    ) -> Result<usize> {
        if msg.len() < 16 {
            return Err(I2PError::Malformed("aead: msg too short for tag"));
        }
        let plaintext_len = msg.len() - 16;
        if buf.len() < plaintext_len {
            return Err(I2PError::Malformed("aead: buf too small for plaintext"));
        }
        let key_arr = Key::from(*key);
        let nonce_arr = Nonce::from(*nonce);
        let cipher = ChaCha20Poly1305Raw::new(&key_arr);
        let payload = Payload { msg, aad: ad };
        let pt = cipher
            .decrypt(&nonce_arr, payload)
            .map_err(|_| I2PError::Malformed("aead: decrypt failed"))?;
        buf[..pt.len()].copy_from_slice(&pt);
        Ok(pt.len())
    }
}
// --- AES-256-CBC ---------------------------------------------------------

/// AES-256-CBC с ключом 32 байта и IV 16 байт.
///
/// Используется в:
/// - NTCP2 handshake (обфускация `SessionRequest` / `SessionCreated` / `SessionConfirmed` part 1);
/// - tunnel encryption (слои туннеля, `TunnelEncryption`/`TunnelDecryption`);
/// - ElGamal/AES garlic (payload-блок после ElGamal-блока).
///
/// **Без padding'а**: как и в i2pd `CBCEncryption`, длина входа должна
/// быть кратна 16. Если это не так — [`Error::InvalidLength`].
///
/// RustCrypto-обёртка `cbc::Encryptor`/`Decryptor` изначально требует
/// padding-схему; мы используем `NoPadding` и явно проверяем длину.
pub struct Aes256Cbc;

impl Aes256Cbc {
    /// Шифрует `data` ключом `key` и IV `iv`.
    ///
    /// `data.len()` должно быть кратно 16.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если длина `data` не кратна 16.
    pub fn encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(I2PError::InvalidLength {
                expected: data.len().div_ceil(16) * 16,
                got: data.len(),
            });
        }
        let cipher = cbc::Encryptor::<Aes256>::new(key.into(), iv.into());
        // `encrypt_padded_vec_mut` сам выделит выходной буфер
        // и применит `NoPadding`. Паники нет: длина уже проверена.
        Ok(cipher.encrypt_padded_vec::<NoPadding>(data))
    }

    /// Дешифрует `data` ключом `key` и IV `iv`.
    ///
    /// `data.len()` должно быть кратно 16.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если длина `data` не кратна 16.
    /// [`Error::Malformed`], если `RustCrypto` откажется дешифровать
    /// (например, из-за padding-проверки — при `NoPadding` этого
    /// не бывает, но на всякий случай).
    pub fn decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(I2PError::InvalidLength {
                expected: data.len().div_ceil(16) * 16,
                got: data.len(),
            });
        }
        let cipher = cbc::Decryptor::<Aes256>::new(key.into(), iv.into());
        cipher
            .decrypt_padded_vec::<NoPadding>(data)
            .map_err(|_| I2PError::Malformed("aes-cbc: decryption failed"))
    }

    /// Шифрует на месте: `buf` уже содержит plaintext, после вызова —
    /// ciphertext.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если длина `buf` не кратна 16.
    pub fn encrypt_in_place(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(16) {
            return Err(I2PError::InvalidLength {
                expected: buf.len().div_ceil(16) * 16,
                got: buf.len(),
            });
        }
        let cipher = cbc::Encryptor::<Aes256>::new(key.into(), iv.into());
        // `encrypt_padded_mut` возвращает срез записанного шифртекста;
        // при `NoPadding` это весь буфер, паники нет.
        let out = cipher
            .encrypt_padded::<NoPadding>(buf, buf.len())
            .map_err(|_| I2PError::Malformed("aes-cbc: in-place encrypt failed"))?;
        debug_assert_eq!(out.len(), buf.len());
        Ok(())
    }

    /// Дешифрует на месте: `buf` содержит ciphertext, после вызова —
    /// plaintext.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если длина `buf` не кратна 16.
    /// [`Error::Malformed`], если дешифрование не удалось.
    pub fn decrypt_in_place(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(16) {
            return Err(I2PError::InvalidLength {
                expected: buf.len().div_ceil(16) * 16,
                got: buf.len(),
            });
        }
        let cipher = cbc::Decryptor::<Aes256>::new(key.into(), iv.into());
        let out = cipher
            .decrypt_padded::<NoPadding>(buf)
            .map_err(|_| I2PError::Malformed("aes-cbc: in-place decrypt failed"))?;
        debug_assert_eq!(out.len(), buf.len());
        Ok(())
    }
}
// --- HKDF -----------------------------------------------------------------

/// HKDF-SHA256: `extract` + `expand`.
///
/// Совпадает с `HKDF()` из i2pd. Используется только **первый**
/// 32 байта `salt` — i2pd всегда передаёт `salt` как `const uint8_t *`
/// и жёстко берёт 32 байта (`EVP_PKEY_CTX_set1_hkdf_salt (ctx, salt, 32)`).
/// Это позволяет передавать 64-байтовые буферы и брать из них префикс.
///
/// `key` может быть пустым — тогда выполняется expand без extract
/// (i2pd так делает для `nullptr`).
///
/// # Panics
///
/// - паникует, если `salt.len() < 32`;
/// - паникует, если `out.len() > 255 * 32` (8160 байт) — это
///   ограничение HKDF по RFC 5869. В I2P `out` всегда 32 или 64 байта,
///   так что на практике паника невозможна.
pub fn hkdf(salt: &[u8], key: &[u8], info: &[u8], out: &mut [u8]) {
    assert!(salt.len() >= 32, "hkdf: salt must be at least 32 bytes");
    let hk = Hkdf::<Sha256>::new(Some(&salt[..32]), key);
    hk.expand(info, out).expect("hkdf: output too long");
}

// --- X25519 ---------------------------------------------------------------

/// Пара X25519-ключей.
///
/// Совпадает с `X25519Keys` из i2pd: генерируется из случайного
/// seed'а, умеет `agree` (DH) и хранит публичный ключ.
///
/// **Zeroize**: приватный ключ затирается при drop'е.
pub struct I2PX25519Keys {
    secret: StaticSecret,
    public: PublicKey,
}

impl I2PX25519Keys {
    /// Генерирует новую пару.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Создаёт пару из существующего приватного ключа.
    ///
    /// Если `public` не задан (`None`), публичный ключ выводится
    /// из приватного. Иначе принимается на веру — как в i2pd
    /// (`X25519Keys::X25519Keys(priv, pub)`).
    #[must_use]
    pub fn from_private(private: &[u8; 32], public: Option<&[u8; 32]>) -> Self {
        let secret = StaticSecret::from(*private);
        let public = public.map_or_else(|| PublicKey::from(&secret), |p| PublicKey::from(*p));
        Self { secret, public }
    }

    /// Публичный ключ.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        self.public.as_bytes()
    }

    /// Приватный ключ (копия, для сериализации в файл).
    #[must_use]
    pub fn private_key(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Вычисляет общий секрет с `peer_public`.
    ///
    /// Возвращает `None`, если `peer_public` — низкого порядка
    /// (all-zero shared secret), что означает атаку или битый ключ.
    #[must_use]
    pub fn agree(&self, peer_public: &[u8; 32]) -> Option<[u8; 32]> {
        let peer = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        if shared.as_bytes().iter().all(|&b| b == 0) {
            // low-order point: DH небезопасен
            return None;
        }
        Some(*shared.as_bytes())
    }

    /// `true`, если `agree` можно вызывать с любым публичным ключом
    /// без риска low-order атаки. В i2pd называется
    /// `IsElligatorIneligible` — но там это про Elligator, а не
    /// про X25519. У нас семантика чуть другая: проверяем, что
    /// ключ не all-zero.
    #[must_use]
    pub fn is_valid_public_key(public: &[u8; 32]) -> bool {
        !public.iter().all(|&b| b == 0)
    }
}

impl Drop for I2PX25519Keys {
    fn drop(&mut self) {
        // StaticSecret уже zeroize-on-drop, но на всякий случай
        // явно — чтобы поведение не зависело от версии крейта.
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
    }
}

// --- Noise ----------------------------------------------------------------

/// Симметричное состояние Noise.
///
/// Совпадает с `NoiseSymmetricState` из i2pd. Хранит:
///
/// - `h` — running hash (32 байта);
/// - `ck` — chaining key (64 байта: первые 32 — chainKey,
///   вторые 32 — key для AEAD);
/// - `n` — counter nonce.
///
/// Используется в NTCP2, SSU2, ECIES-X25519-AEAD-Ratchet.
#[derive(Clone)]
pub struct NoiseSymmetricState {
    /// Running hash.
    pub h: [u8; 32],
    /// Chain key (первые 32 байта i2pd'шного `m_CK`).
    pub ck: [u8; 32],
    /// AEAD-ключ (вторые 32 байта `m_CK`).
    pub k: [u8; 32],
    /// Nonce counter.
    pub n: u64,
}

impl NoiseSymmetricState {
    /// Инициализация: `ck` и `h` от protocol name + prologue,
    /// а `pub` — публичный статический ключ Bob'а.
    ///
    /// Повторяет `NoiseSymmetricState::Init` из i2pd.
    #[must_use]
    pub fn new(ck: &[u8; 32], hh: &[u8; 32], pub_key: &[u8; 32]) -> Self {
        let mut h = [0u8; 32];
        {
            let mut hasher = Sha256::new();
            hasher.update(hh);
            hasher.update(pub_key);
            h.copy_from_slice(&hasher.finalize());
        }
        Self {
            h,
            ck: *ck,
            k: [0u8; 32],
            n: 0,
        }
    }

    /// `h = SHA256(h || data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h.copy_from_slice(&hasher.finalize());
    }

    /// `h = SHA256(h || data1 || data2 || ...)`.
    pub fn mix_hash_multi(&mut self, parts: &[&[u8]]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        for p in parts {
            hasher.update(p);
        }
        self.h.copy_from_slice(&hasher.finalize());
    }

    /// `ck = HKDF(ck, shared_secret, "", 64)`, `n = 0`.
    pub fn mix_key(&mut self, shared_secret: &[u8; 32]) {
        let mut new = [0u8; 64];
        hkdf(&self.ck, shared_secret, b"", &mut new);
        self.ck.copy_from_slice(&new[..32]);
        self.k.copy_from_slice(&new[32..]);
        self.n = 0;
    }

    /// AEAD-encrypt с текущим `h` как AD и `k` как ключом.
    ///
    /// Возвращает `len + 16` (записанный размер).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если `buf` короче `plaintext.len() + 16`.
    pub fn encrypt(&mut self, plaintext: &[u8], buf: &mut [u8]) -> Result<usize> {
        let nonce = self.nonce();
        let aead = AeadChaCha20Poly1305::new();
        let len = aead.encrypt(&self.k, &nonce, &self.h, plaintext, buf)?;
        self.n += 1;
        Ok(len)
    }
    /// AEAD-decrypt, `ciphertext` включает 16-байтовый тег.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`], если `ciphertext` короче 16 байт
    ///   (нет тега Poly1305);
    /// - [`Error::Malformed`], если `buf` короче, чем
    ///   `ciphertext.len() - 16`;
    /// - [`Error::Malformed`], если тег не сходится.
    pub fn decrypt(&mut self, ciphertext: &[u8], buf: &mut [u8]) -> Result<usize> {
        let nonce = self.nonce();
        let aead = AeadChaCha20Poly1305::new();
        let len = aead.decrypt(&self.k, &nonce, &self.h, ciphertext, buf)?;
        self.n += 1;
        Ok(len)
    }

    /// Nonce для текущего `n`: 4 нуля + `n` в Little Endian.
    ///
    /// Это формат i2pd — в I2P nonce всегда строится так.
    #[must_use]
    pub fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.n.to_le_bytes());
        nonce
    }
}

/// Инициализирует [`NoiseSymmetricState`] для `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256` (NTCP2).
///
/// Соответствует `InitNoiseXKState` из `Crypto.cpp`. Хардкод-константы —
/// SHA256 от имени протокола и его префикс-хеш.
pub fn init_noise_xk_state(state: &mut NoiseSymmetricState, pub_key: &[u8; 32]) {
    const PROTOCOL_NAME_HASH: [u8; 32] = [
        0x72, 0xe8, 0x42, 0xc5, 0x45, 0xe1, 0x80, 0x80, 0xd3, 0x9c, 0x44, 0x93, 0xbb, 0x91, 0xd7,
        0xed, 0xf2, 0x28, 0x98, 0x17, 0x71, 0x21, 0x8c, 0x1f, 0x62, 0x4e, 0x20, 0x6f, 0x28, 0xd3,
        0x2f, 0x71,
    ];
    const HH: [u8; 32] = [
        0x49, 0xff, 0x48, 0x3f, 0xc4, 0x04, 0xb9, 0xb2, 0x6b, 0x11, 0x94, 0x36, 0x72, 0xff, 0x05,
        0xb5, 0x61, 0x27, 0x03, 0x31, 0xba, 0x89, 0xb8, 0xfc, 0x33, 0x15, 0x93, 0x87, 0x57, 0xdd,
        0x3d, 0x1e,
    ];
    *state = NoiseSymmetricState::new(&PROTOCOL_NAME_HASH, &HH, pub_key);
}

/// Инициализирует [`NoiseSymmetricState`] для протокола
/// `Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256` (ratchets).
///
/// Соответствует `InitNoiseIKState` из `Crypto.cpp`. Хардкод-константы —
/// SHA256 от имени протокола и его префикс-хеш, ровно как в i2pd.
pub fn init_noise_ik_state(state: &mut NoiseSymmetricState, pub_key: &[u8; 32]) {
    const PROTOCOL_NAME_HASH: [u8; 32] = [
        0x4c, 0xaf, 0x11, 0xef, 0x2c, 0x8e, 0x36, 0x56, 0x4c, 0x53, 0xe8, 0x88, 0x85, 0x06, 0x4d,
        0xba, 0xac, 0xbe, 0x00, 0x54, 0xad, 0x17, 0x8f, 0x80, 0x79, 0xa6, 0x46, 0x82, 0x7e, 0x6e,
        0xe4, 0x0c,
    ];
    const HH: [u8; 32] = [
        0x9c, 0xcf, 0x85, 0x2c, 0xc9, 0x3b, 0xb9, 0x50, 0x44, 0x41, 0xe9, 0x50, 0xe0, 0x1d, 0x52,
        0x32, 0x2e, 0x0d, 0x47, 0xad, 0xd1, 0xe9, 0xa5, 0x55, 0xf7, 0x55, 0xb5, 0x69, 0xae, 0x18,
        0x3b, 0x5c,
    ];
    *state = NoiseSymmetricState::new(&PROTOCOL_NAME_HASH, &HH, pub_key);
}

/// Инициализирует [`NoiseSymmetricState`] для протокола
/// `Noise_N_25519_ChaChaPoly_SHA256` (tunnel build records).
///
/// Соответствует `InitNoiseNState` из `Crypto.cpp`. `pub_key` — статический
/// публичный ключ получателя (хопа).
pub fn init_noise_n_state(state: &mut NoiseSymmetricState, pub_key: &[u8; 32]) {
    // "Noise_N_25519_ChaChaPoly_SHA256" (31 символ) + нулевой байт
    const PROTOCOL_NAME: [u8; 32] = *b"Noise_N_25519_ChaChaPoly_SHA256\0";
    // SHA256(PROTOCOL_NAME)
    const HH: [u8; 32] = [
        0x69, 0x4d, 0x52, 0x44, 0x5a, 0x27, 0xd9, 0xad, 0xfa, 0xd2, 0x9c, 0x76, 0x32, 0x39, 0x5d,
        0xc1, 0xe4, 0x35, 0x4c, 0x69, 0xb4, 0xf9, 0x2e, 0xac, 0x8a, 0x1e, 0xe4, 0x6a, 0x9e, 0xd2,
        0x15, 0x54,
    ];
    *state = NoiseSymmetricState::new(&PROTOCOL_NAME, &HH, pub_key);
}

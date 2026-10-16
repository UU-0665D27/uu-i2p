//! `RatchetTagSet` — генерация session tags и symmetric keys для
//! ECIES-X25519-AEAD-Ratchet.
//!
//! Прямое соответствие `RatchetTagSet` из `ECIESX25519AEADRatchetSession.h`.
//! Каждая сессия хранит несколько tag-set'ов (по одному на каждый
//! DH-ratchet step), каждый из которых умеет генерировать:
//!
//! - **session tags** (по 8 байт) — для поиска входящих сообщений по
//!   первому тегу в wire-формате;
//! - **symmetric keys** (по 32 байта) — для AEAD-шифрования payload'а
//!   под конкретным тегом.
//!
//! Оба генерируются через цепочку HKDF-SHA256 (см. спек
//! `ECIES-X25519-AEAD-Ratchet`). Никакой DH здесь нет — DH живёт в
//! `DHInitialize`, которая получает `root_key` и `k` от session-state
//! machine.
//!
//! ## Цепочки
//!
//! **Session tags:**
//!
//! ```text
//!   DHInitialize(root_key, k):
//!     keydata = HKDF(root_key, k, "KDFDHRatchetStep", 64)
//!     next_root_key = keydata[0..32]
//!     [sessTag_ck, symmKey_ck] = HKDF(keydata[32..64], ZEROLEN, "TagAndKeyGenKeys", 64)
//!
//!   NextSessionTagRatchet():
//!     [sessTag_ck, sesstag_constant] = HKDF(sessTag_ck, ZEROLEN, "STInitialization", 64)
//!     next_index = 0
//!
//!   GetNextSessionTag():
//!     next_index++
//!     [sessTag_ck, tag] = HKDF(sessTag_ck, sesstag_constant, "SessionTagKeyGen", 64)
//!     return tag (первые 8 байт второй половины)
//! ```
//!
//! **Symmetric keys:**
//!
//! ```text
//!   GetSymmKey(index):  ratchet до индекса, cache intermediate
//!     [ck, key] = HKDF(ck, ZEROLEN, "SymmetricRatchet", 64)
//! ```
//!
//! ## Endianness тега
//!
//! i2pd использует `Tag<64>::GetLL()[4]`, что на LE-платформе читает
//! байты `[32..40]` как LE u64. Мы делаем то же — `u64::from_le_bytes`.
//! На BE-платформах i2pd работал бы неправильно, но на практике I2P
//! живёт только на LE.

use crate::crypto::hkdf;
use std::collections::HashMap;

/// Максимальный session tag index. При достижении — tag-set исчерпан,
/// нужен новый ratchet.
pub const MAX_TAG_INDEX: u16 = 65535;

/// `RatchetTagSet`.
#[derive(Debug, Clone)]
pub struct RatchetTagSet {
    /// [`sessTag_ck` || scratch]. [0..32] — текущий chain key; [32..64] —
    /// буфер для HKDF-выхода.
    session_tag_key_data: [u8; 64],
    /// Session tag constant — второй выход `NextSessionTagRatchet`,
    /// используется как `key` в `GetNextSessionTag`.
    sess_tag_constant: [u8; 32],
    /// Symmetric key chain key (32 байта), отделённый от
    /// `session_tag_key_data` при `DHInitialize`.
    symm_key_ck: [u8; 32],
    /// Текущий symmetric chain: [0..32] = chain key, [32..64] = current
    /// symmetric key (после `SymmetricRatchet`).
    current_symm_key_ck: [u8; 64],
    /// `next_root_key` — то, что `DHInitialize` отдаёт session'у для
    /// следующего DH-ratchet step.
    next_root_key: [u8; 32],
    /// Индекс следующего session tag (0 = ни одного не выпущено).
    pub next_index: u16,
    /// Индекс следующего symmetric key.
    next_symm_key_index: u32,
    /// Промежуточные symmetric keys (для out-of-order `GetSymmKey`).
    intermediate_symm_keys: HashMap<u32, [u8; 32]>,
    /// Tag set ID: 0, `2*keyID`, или `2*keyID+1`.
    tagset_id: u16,
}

impl RatchetTagSet {
    /// Пустой tag-set. Требует `dh_initialize` до использования.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_tag_key_data: [0u8; 64],
            sess_tag_constant: [0u8; 32],
            symm_key_ck: [0u8; 32],
            current_symm_key_ck: [0u8; 64],
            next_root_key: [0u8; 32],
            next_index: 0,
            next_symm_key_index: 0,
            intermediate_symm_keys: HashMap::new(),
            tagset_id: 0,
        }
    }

    /// `DHInitialize(root_key, k)` — первичная инициализация от
    /// результата DH.
    ///
    /// Обновляет `next_root_key` и внутреннее состояние. После вызова
    /// можно либо сделать `next_session_tag_ratchet()` (для tag-set'а
    /// приёма/отправки), либо сразу начать с индексом 0.
    pub fn dh_initialize(&mut self, root_key: &[u8; 32], k: &[u8; 32]) {
        let mut keydata = [0u8; 64];
        hkdf(root_key, k, b"KDFDHRatchetStep", &mut keydata);
        self.next_root_key.copy_from_slice(&keydata[..32]);
        hkdf(
            &keydata[32..64],
            &[],
            b"TagAndKeyGenKeys",
            &mut self.session_tag_key_data,
        );
        self.symm_key_ck
            .copy_from_slice(&self.session_tag_key_data[32..64]);
        self.next_symm_key_index = 0;
        self.intermediate_symm_keys.clear();
    }

    /// `NextSessionTagRatchet()` — переход к следующей chain-key
    /// сессии тегов. Сбрасывает `next_index` в 0.
    pub fn next_session_tag_ratchet(&mut self) {
        let mut out = [0u8; 64];
        hkdf(
            &self.session_tag_key_data,
            &[],
            b"STInitialization",
            &mut out,
        );
        self.session_tag_key_data = out;
        self.sess_tag_constant.copy_from_slice(&out[32..64]);
        self.next_index = 0;
    }

    /// `GetNextSessionTag()` — выпускает следующий тег.
    ///
    /// Возвращает `None`, если теги исчерпаны (`next_index >= 65535`).
    ///
    /// # Panics
    ///
    /// Паникует только если внутри `out` окажется меньше 40 байт —
    /// невозможно на практике, размер массива фиксирован в коде.
    /// При панике это сигнал о баге в `RatchetTagSet`, а не о
    /// проблеме входных данных.
    pub fn get_next_session_tag(&mut self) -> Option<u64> {
        if self.next_index >= MAX_TAG_INDEX - 1 {
            // i2pd инкрементирует до проверки: 65534 → 65535 → fail.
            // Мы сатурируем на 65535.
            self.next_index = MAX_TAG_INDEX;
            return None;
        }
        self.next_index += 1;

        let mut out = [0u8; 64];
        hkdf(
            &self.session_tag_key_data,
            &self.sess_tag_constant,
            b"SessionTagKeyGen",
            &mut out,
        );
        self.session_tag_key_data = out;

        // tag = keydata[32:39] (первые 8 байт второй половины)
        let tag_bytes: [u8; 8] = out[32..40].try_into().expect("8 bytes");
        Some(u64::from_le_bytes(tag_bytes))
    }
    /// Вычисляет следующий session tag **не меняя** состояние tag-set'а.
    ///
    /// Нужен, чтобы проверить тег входящего NSR без его «съедания»:
    /// реальная обработка NSR всё равно сдвинет tag-set вперёд.
    /// Реализация — клонируем и вызываем [`Self::get_next_session_tag`];
    /// struct маленький (∼200 байт + `HashMap`), клонирование дёшево.
    #[must_use]
    pub fn peek_next_session_tag(&self) -> Option<u64> {
        let mut clone = self.clone();
        clone.get_next_session_tag()
    }

    /// `GetSymmKey(index)` — возвращает symmetric key для указанного
    /// индекса тега.
    ///
    /// Может вызываться out-of-order: если запрошенный индекс меньше
    /// `next_symm_key_index`, ищем в кэше промежуточных ключей.
    /// Возвращает `None`, если ключ уже был выдан ранее или ещё не
    /// достигнут ratchet'ом.
    ///
    /// # Panics
    ///
    /// Паникует только если `self.current_symm_key_ck` окажется меньше
    /// 64 байт — невозможно на практике, размер массива фиксирован.
    /// Сигнал о баге в `RatchetTagSet`, а не о проблеме входа.
    pub fn get_symm_key(&mut self, index: u32) -> Option<[u8; 32]> {
        if index >= self.next_symm_key_index {
            let mut num = index + 1 - self.next_symm_key_index;
            if self.next_symm_key_index == 0 {
                // Первый шаг: из symm_key_ck.
                let mut out = [0u8; 64];
                hkdf(&self.symm_key_ck, &[], b"SymmetricRatchet", &mut out);
                self.current_symm_key_ck = out;
                self.next_symm_key_index = 1;
                num -= 1;
            }
            for i in 0..num {
                let mut out = [0u8; 64];
                hkdf(
                    &self.current_symm_key_ck[..32],
                    &[],
                    b"SymmetricRatchet",
                    &mut out,
                );
                self.current_symm_key_ck = out;
                if i + 1 < num {
                    let intermediate: [u8; 32] = self.current_symm_key_ck[32..64]
                        .try_into()
                        .expect("32 bytes");
                    self.intermediate_symm_keys
                        .insert(self.next_symm_key_index + i, intermediate);
                }
            }
            self.next_symm_key_index += num;
            let key: [u8; 32] = self.current_symm_key_ck[32..64]
                .try_into()
                .expect("32 bytes");
            Some(key)
        } else {
            self.intermediate_symm_keys.remove(&index)
        }
    }

    /// `DeleteSymmKey(index)` — удаляет закэшированный ключ.
    pub fn delete_symm_key(&mut self, index: u32) {
        self.intermediate_symm_keys.remove(&index);
    }

    /// `next_root_key` — результат `DHInitialize`, нужен session'у
    /// для следующего DH-ratchet step.
    #[must_use]
    pub const fn next_root_key(&self) -> &[u8; 32] {
        &self.next_root_key
    }

    /// Текущий индекс тега (число уже выпущенных тегов).
    #[must_use]
    pub const fn next_index(&self) -> u16 {
        self.next_index
    }

    /// Tag set ID.
    #[must_use]
    pub const fn tagset_id(&self) -> u16 {
        self.tagset_id
    }

    /// Устанавливает tag set ID.
    pub const fn set_tagset_id(&mut self, id: u16) {
        self.tagset_id = id;
    }

    /// `msg_id = (tagset_id << 16) | next_index` — идентификатор для
    /// Ack-механизма.
    #[must_use]
    pub const fn msg_id(&self) -> u32 {
        (self.tagset_id as u32) << 16 | self.next_index as u32
    }
}

impl Default for RatchetTagSet {
    fn default() -> Self {
        Self::new()
    }
}

//! Short tunnel build records (`ShortTunnelBuild`, I2NP type 25) —
//! только wire-структуры, без криптографии.
//!
//! Соответствует `TunnelConfig.cpp`, `TransitTunnel.cpp` и константам
//! `SHORT_*` из `I2NPProtocol.h`. Шифрование (Noise N + `ChaCha20`) —
//! отдельный слой: здесь только разбор и сборка байтов.
//!
//! ## Запись целиком (218 байт, в сообщении их до 8)
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0    16  to_peer       (первые 16 байт IdentHash хопа)
//!       16    32  ephemeral     (X25519 public key отправителя)
//!       48   170  ciphertext    (154 clear text + 16 Poly1305 tag)
//! ```
//!
//! ## Clear text запроса (154 байта)
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     4  receive_tunnel   (BE u32)
//!        4     4  next_tunnel      (BE u32)
//!        8    32  next_ident
//!       40     1  flags           (0x80 gateway, 0x40 endpoint)
//!       41     2  more_flags
//!       43     1  layer_encryption_type (0 = AES)
//!       44     4  request_time    (BE u32, минуты since epoch)
//!       48     4  request_expiration (BE u32, секунды)
//!       52     4  send_msg_id     (BE u32)
//!       56    98  options (Mapping: size(2) + `k=v;`..., дальше нули)
//! ```
//!
//! ## Plaintext ответа (202 байта + 16 байт Poly1305 tag)
//!
//! ```text
//!        0   201  options (Mapping, дальше нули)
//!      201     1  ret
//! ```
//!
//! ## Отличия от i2pd
//!
//! - Если options не помещаются в отведённую область, i2pd молча
//!   обрезает список; мы возвращаем [`I2PError::Malformed`].
//! - При разборе Mapping дубликаты ключей и нечитаемые как UTF-8
//!   строки считаются ошибкой.
//! - Options хранятся в `BTreeMap`, как `std::map` в i2pd, поэтому
//!   порядок записи ключей совпадает с i2pd (по возрастанию).

use std::collections::BTreeMap;

use crate::endian::{read_u16_be, read_u32_be, write_u16_be, write_u32_be};
use crate::error::{I2PError, Result};
use crate::tag::IdentHash;

/// Размер одной short-записи в байтах.
pub const SHORT_TUNNEL_BUILD_RECORD_SIZE: usize = 218;
/// Максимальное число записей в build-сообщении.
pub const NUM_TUNNEL_BUILD_RECORDS: usize = 8;
/// Размер поля `to_peer`.
pub const BUILD_RECORD_TO_PEER_SIZE: usize = 16;
/// Размер X25519 public key в записи.
pub const SHORT_REQUEST_RECORD_EPHEMERAL_SIZE: usize = 32;
/// Размер Poly1305 tag.
pub const POLY1305_TAG_SIZE: usize = 16;
/// Смещение зашифрованной части (`to_peer` занимает первые 16 байт).
pub const SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET: usize = 16;

/// Размер clear text запроса.
pub const SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE: usize = 154;
/// Размер шифртекста запроса (clear text + tag).
pub const SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE: usize =
    SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE + POLY1305_TAG_SIZE;

pub const SHORT_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET: usize = 0;
pub const SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET: usize = 4;
pub const SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET: usize = 8;
pub const SHORT_REQUEST_RECORD_FLAG_OFFSET: usize = 40;
pub const SHORT_REQUEST_RECORD_MORE_FLAGS_OFFSET: usize = 41;
pub const SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE: usize = 43;
pub const SHORT_REQUEST_RECORD_REQUEST_TIME_OFFSET: usize = 44;
pub const SHORT_REQUEST_RECORD_REQUEST_EXPIRATION_OFFSET: usize = 48;
pub const SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET: usize = 52;
pub const SHORT_REQUEST_RECORD_TUNNEL_BUILD_OPTIONS_OFFSET: usize = 56;

/// Размер plaintext ответа (запись минус tag).
pub const SHORT_RESPONSE_PLAINTEXT_SIZE: usize = SHORT_TUNNEL_BUILD_RECORD_SIZE - POLY1305_TAG_SIZE;
pub const SHORT_RESPONSE_RECORD_OPTIONS_OFFSET: usize = 0;
pub const SHORT_RESPONSE_RECORD_RET_OFFSET: usize = 201;

/// Флаг gateway в `flags`.
pub const TUNNEL_BUILD_RECORD_GATEWAY_FLAG: u8 = 0x80;
/// Флаг endpoint в `flags`.
pub const TUNNEL_BUILD_RECORD_ENDPOINT_FLAG: u8 = 0x40;

/// Срок жизни запроса по умолчанию (секунды), как в i2pd (+10 минут).
pub const DEFAULT_REQUEST_EXPIRATION_SECS: u32 = 600;

/// Ключ options: минимальная полоса (КБ/с), запрос.
pub const OPTION_MINIMUM_BANDWIDTH: &str = "m";
/// Ключ options: запрошенная полоса (КБ/с), запрос.
pub const OPTION_REQUESTED_BANDWIDTH: &str = "r";
/// Ключ options: лимит полосы (КБ/с).
pub const OPTION_LIMIT_BANDWIDTH: &str = "l";
/// Ключ options: доступная полоса (КБ/с), ответ.
pub const OPTION_AVAILABLE_BANDWIDTH: &str = "b";

// --- BuildOptions ----------------------------------------------------------

/// Mapping в options записей: `size(2 BE) | (len k '=' len v ';')*`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildOptions(BTreeMap<String, String>);

impl BuildOptions {
    /// Пустой набор.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Добавляет или заменяет значение.
    pub fn insert(&mut self, key: &str, value: &str) {
        self.0.insert(key.to_owned(), value.to_owned());
    }

    /// Значение по ключу.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Значение по ключу как `u32` (десятичная запись).
    #[must_use]
    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.get(key)?.parse().ok()
    }

    /// Количество пар.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Пуст ли набор.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Размер в wire-формате вместе с 2-байтным префиксом.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        2 + self
            .0
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum::<usize>()
    }

    /// Пишет Mapping в начало `out`, возвращает число записанных байт
    /// (с префиксом). Остаток `out` не трогается.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если ключ или значение длиннее 255
    /// байт, либо Mapping не помещается в `out`.
    pub fn write_into(&self, out: &mut [u8]) -> Result<usize> {
        let total = self.wire_size();
        if total > out.len() {
            return Err(I2PError::Malformed("build options do not fit in record"));
        }
        let mut pos = 2;
        for (k, v) in &self.0 {
            let (Ok(kl), Ok(vl)) = (u8::try_from(k.len()), u8::try_from(v.len())) else {
                return Err(I2PError::Malformed("build option string longer than 255"));
            };
            out[pos] = kl;
            pos += 1;
            out[pos..pos + k.len()].copy_from_slice(k.as_bytes());
            pos += k.len();
            out[pos] = b'=';
            pos += 1;
            out[pos] = vl;
            pos += 1;
            out[pos..pos + v.len()].copy_from_slice(v.as_bytes());
            pos += v.len();
            out[pos] = b';';
            pos += 1;
        }
        let Ok(size) = u16::try_from(total - 2) else {
            return Err(I2PError::Malformed("build options too large"));
        };
        write_u16_be(out, size);
        Ok(total)
    }

    /// Разбирает Mapping из начала `buf`. Байты после объявленного
    /// размера (нулевой padding) игнорируются.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — нет места под префикс;
    /// - [`I2PError::Malformed`] — размер выходит за буфер, нарушена
    ///   структура `k=v;`, не UTF-8 или дубликат ключа.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(I2PError::InvalidLength {
                expected: 2,
                got: buf.len(),
            });
        }
        let size = usize::from(read_u16_be(buf));
        let body = buf
            .get(2..2 + size)
            .ok_or(I2PError::Malformed("build options size exceeds buffer"))?;
        let mut map = BTreeMap::new();
        let mut pos = 0;
        while pos < body.len() {
            let key = read_str(body, &mut pos)?;
            expect_byte(body, &mut pos, b'=')?;
            let value = read_str(body, &mut pos)?;
            expect_byte(body, &mut pos, b';')?;
            if map.insert(key, value).is_some() {
                return Err(I2PError::Malformed("duplicate build option key"));
            }
        }
        Ok(Self(map))
    }
}

fn read_str(body: &[u8], pos: &mut usize) -> Result<String> {
    let len = usize::from(
        *body
            .get(*pos)
            .ok_or(I2PError::Malformed("build option truncated"))?,
    );
    *pos += 1;
    let bytes = body
        .get(*pos..*pos + len)
        .ok_or(I2PError::Malformed("build option truncated"))?;
    *pos += len;
    String::from_utf8(bytes.to_vec()).map_err(|_| I2PError::Malformed("build option not UTF-8"))
}

fn expect_byte(body: &[u8], pos: &mut usize, want: u8) -> Result<()> {
    if body.get(*pos) != Some(&want) {
        return Err(I2PError::Malformed("build option separator missing"));
    }
    *pos += 1;
    Ok(())
}

// --- RetCode ---------------------------------------------------------------

/// Код ответа хопа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildRetCode {
    /// Хоп принял туннель.
    Accept,
    /// Отказ по причине полосы (30) — единственный код отказа в i2pd.
    Bandwidth,
    /// Любой другой код.
    Other(u8),
}

impl BuildRetCode {
    /// Из wire-значения.
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Accept,
            30 => Self::Bandwidth,
            other => Self::Other(other),
        }
    }

    /// В wire-значение.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Accept => 0,
            Self::Bandwidth => 30,
            Self::Other(v) => v,
        }
    }

    /// Принят ли туннель.
    #[must_use]
    pub const fn is_accept(self) -> bool {
        matches!(self, Self::Accept)
    }
}

// --- Request clear text ----------------------------------------------------

/// Clear text запроса на постройку одного хопа (154 байта).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortBuildRequestRecord {
    /// Tunnel ID, на котором хоп принимает сообщения.
    pub receive_tunnel: u32,
    /// Tunnel ID на следующем хопе.
    pub next_tunnel: u32,
    /// Ident следующего хопа (или reply-роутера для endpoint).
    pub next_ident: IdentHash,
    /// Хоп — gateway.
    pub is_gateway: bool,
    /// Хоп — endpoint.
    pub is_endpoint: bool,
    /// Резервные флаги, сохраняются как есть.
    pub more_flags: [u8; 2],
    /// Тип шифрования слоя (0 = AES).
    pub layer_encryption_type: u8,
    /// Время запроса в минутах since epoch.
    pub request_time_minutes: u32,
    /// Срок жизни запроса в секундах.
    pub request_expiration_secs: u32,
    /// ID сообщения для ответа.
    pub send_msg_id: u32,
    /// Build options.
    pub options: BuildOptions,
}

impl ShortBuildRequestRecord {
    /// Байт флагов.
    #[must_use]
    pub const fn flags_byte(&self) -> u8 {
        let mut f = 0;
        if self.is_gateway {
            f |= TUNNEL_BUILD_RECORD_GATEWAY_FLAG;
        }
        if self.is_endpoint {
            f |= TUNNEL_BUILD_RECORD_ENDPOINT_FLAG;
        }
        f
    }

    /// Разбирает clear text.
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если длина не 154; ошибки
    /// [`BuildOptions::parse`].
    pub fn from_clear_text(buf: &[u8]) -> Result<Self> {
        if buf.len() != SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE,
                got: buf.len(),
            });
        }
        let flags = buf[SHORT_REQUEST_RECORD_FLAG_OFFSET];
        let next_ident = IdentHash::from_slice(
            &buf[SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET..SHORT_REQUEST_RECORD_FLAG_OFFSET],
        )
        .ok_or(I2PError::Malformed("next ident slice"))?;
        Ok(Self {
            receive_tunnel: read_u32_be(&buf[SHORT_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET..]),
            next_tunnel: read_u32_be(&buf[SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET..]),
            next_ident,
            is_gateway: flags & TUNNEL_BUILD_RECORD_GATEWAY_FLAG != 0,
            is_endpoint: flags & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG != 0,
            more_flags: [
                buf[SHORT_REQUEST_RECORD_MORE_FLAGS_OFFSET],
                buf[SHORT_REQUEST_RECORD_MORE_FLAGS_OFFSET + 1],
            ],
            layer_encryption_type: buf[SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE],
            request_time_minutes: read_u32_be(&buf[SHORT_REQUEST_RECORD_REQUEST_TIME_OFFSET..]),
            request_expiration_secs: read_u32_be(
                &buf[SHORT_REQUEST_RECORD_REQUEST_EXPIRATION_OFFSET..],
            ),
            send_msg_id: read_u32_be(&buf[SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET..]),
            options: BuildOptions::parse(&buf[SHORT_REQUEST_RECORD_TUNNEL_BUILD_OPTIONS_OFFSET..])?,
        })
    }

    /// Собирает clear text; хвост после options заполнен нулями.
    ///
    /// # Errors
    ///
    /// Ошибки [`BuildOptions::write_into`].
    pub fn to_clear_text(&self) -> Result<[u8; SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE]> {
        let mut out = [0u8; SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE];
        write_u32_be(
            &mut out[SHORT_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET..],
            self.receive_tunnel,
        );
        write_u32_be(
            &mut out[SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET..],
            self.next_tunnel,
        );
        out[SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET..SHORT_REQUEST_RECORD_FLAG_OFFSET]
            .copy_from_slice(self.next_ident.as_bytes());
        out[SHORT_REQUEST_RECORD_FLAG_OFFSET] = self.flags_byte();
        out[SHORT_REQUEST_RECORD_MORE_FLAGS_OFFSET..SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE]
            .copy_from_slice(&self.more_flags);
        out[SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE] = self.layer_encryption_type;
        write_u32_be(
            &mut out[SHORT_REQUEST_RECORD_REQUEST_TIME_OFFSET..],
            self.request_time_minutes,
        );
        write_u32_be(
            &mut out[SHORT_REQUEST_RECORD_REQUEST_EXPIRATION_OFFSET..],
            self.request_expiration_secs,
        );
        write_u32_be(
            &mut out[SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET..],
            self.send_msg_id,
        );
        self.options
            .write_into(&mut out[SHORT_REQUEST_RECORD_TUNNEL_BUILD_OPTIONS_OFFSET..])?;
        Ok(out)
    }
}

// --- Response plaintext ----------------------------------------------------

/// Plaintext ответа хопа (202 байта, без Poly1305 tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortBuildResponseRecord {
    /// Options ответа (например, доступная полоса `b`).
    pub options: BuildOptions,
    /// Код ответа.
    pub ret: BuildRetCode,
}

impl ShortBuildResponseRecord {
    /// Разбирает plaintext.
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если длина не 202; ошибки
    /// [`BuildOptions::parse`].
    pub fn from_plaintext(buf: &[u8]) -> Result<Self> {
        if buf.len() != SHORT_RESPONSE_PLAINTEXT_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SHORT_RESPONSE_PLAINTEXT_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            options: BuildOptions::parse(
                &buf[SHORT_RESPONSE_RECORD_OPTIONS_OFFSET..SHORT_RESPONSE_RECORD_RET_OFFSET],
            )?,
            ret: BuildRetCode::from_u8(buf[SHORT_RESPONSE_RECORD_RET_OFFSET]),
        })
    }

    /// Собирает plaintext; промежуток между options и `ret` — нули.
    ///
    /// # Errors
    ///
    /// Ошибки [`BuildOptions::write_into`].
    pub fn to_plaintext(&self) -> Result<[u8; SHORT_RESPONSE_PLAINTEXT_SIZE]> {
        let mut out = [0u8; SHORT_RESPONSE_PLAINTEXT_SIZE];
        self.options.write_into(
            &mut out[SHORT_RESPONSE_RECORD_OPTIONS_OFFSET..SHORT_RESPONSE_RECORD_RET_OFFSET],
        )?;
        out[SHORT_RESPONSE_RECORD_RET_OFFSET] = self.ret.to_u8();
        Ok(out)
    }
}

// --- Encrypted record ------------------------------------------------------

/// Зашифрованная запись как она лежит в сообщении (218 байт).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShortRecord {
    /// Первые 16 байт `IdentHash` хопа.
    pub to_peer: [u8; BUILD_RECORD_TO_PEER_SIZE],
    /// Эфемерный X25519 public key.
    pub ephemeral_key: [u8; SHORT_REQUEST_RECORD_EPHEMERAL_SIZE],
    /// Шифртекст запроса с tag.
    pub ciphertext: [u8; SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE],
}

impl EncryptedShortRecord {
    /// Разбирает запись.
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если длина не 218.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() != SHORT_TUNNEL_BUILD_RECORD_SIZE {
            return Err(I2PError::InvalidLength {
                expected: SHORT_TUNNEL_BUILD_RECORD_SIZE,
                got: buf.len(),
            });
        }
        let key_end = SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET + SHORT_REQUEST_RECORD_EPHEMERAL_SIZE;
        let mut to_peer = [0u8; BUILD_RECORD_TO_PEER_SIZE];
        to_peer.copy_from_slice(&buf[..BUILD_RECORD_TO_PEER_SIZE]);
        let mut ephemeral_key = [0u8; SHORT_REQUEST_RECORD_EPHEMERAL_SIZE];
        ephemeral_key.copy_from_slice(&buf[SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET..key_end]);
        let mut ciphertext = [0u8; SHORT_REQUEST_RECORD_CIPHERTEXT_SIZE];
        ciphertext.copy_from_slice(&buf[key_end..]);
        Ok(Self {
            to_peer,
            ephemeral_key,
            ciphertext,
        })
    }

    /// Сериализует запись.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SHORT_TUNNEL_BUILD_RECORD_SIZE] {
        let key_end = SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET + SHORT_REQUEST_RECORD_EPHEMERAL_SIZE;
        let mut out = [0u8; SHORT_TUNNEL_BUILD_RECORD_SIZE];
        out[..BUILD_RECORD_TO_PEER_SIZE].copy_from_slice(&self.to_peer);
        out[SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET..key_end].copy_from_slice(&self.ephemeral_key);
        out[key_end..].copy_from_slice(&self.ciphertext);
        out
    }

    /// Адресована ли запись роутеру с данным ident (сравнение первых
    /// 16 байт).
    #[must_use]
    pub fn is_for(&self, ident: &IdentHash) -> bool {
        self.to_peer[..] == ident.as_bytes()[..BUILD_RECORD_TO_PEER_SIZE]
    }
}

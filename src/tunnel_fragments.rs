//! Wire-формат сообщений внутри туннеля: delivery instructions,
//! фрагменты, контрольная сумма и padding.
//!
//! Соответствует `TunnelGatewayBuffer::CompleteCurrentTunnelDataMessage`
//! и разбору в `TunnelEndpoint::HandleDecryptedTunnelDataMsg` из i2pd.
//! Здесь только stateless-часть; сборка фрагментов в сообщения —
//! в [`crate::tunnel_gateway`] (отправка) и в endpoint (приём).
//!
//! ## Расшифрованное tunnel-сообщение (до слоёв шифрования)
//!
//! Тело [`TunnelDataBody`]: `iv` (16 байт) и `encrypted` (1008 байт):
//!
//! ```text
//!   encrypted[0..4]        checksum = SHA256(payload || iv)[..4]
//!   encrypted[4..k]        padding: случайные НЕнулевые байты
//!   encrypted[k]           0x00
//!   encrypted[k+1..1008]   payload (фрагменты), не более 1003 байт
//! ```
//!
//! ## Фрагмент: первый
//!
//! ```text
//!   flag(1)   бит 7 = 0; биты 6-5 = тип доставки; бит 3 = fragmented
//!   [tunnel_id(4)]  только тип 1 (tunnel)
//!   [hash(32)]      типы 1 (tunnel) и 2 (router)
//!   [msg_id(4)]     только если fragmented
//!   size(2)  данные(size)
//! ```
//!
//! ## Фрагмент: продолжение
//!
//! ```text
//!   flag(1)   бит 7 = 1; биты 6-1 = номер фрагмента (1..63); бит 0 = последний
//!   msg_id(4)  size(2)  данные(size)
//! ```
//!
//! ## Отличия от спецификации (как в i2pd)
//!
//! Бит 4 первого фрагмента (delay) игнорируется: i2pd не читает
//! байт задержки, и мы тоже.

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{I2PError, Result};
use crate::tag::IdentHash;
use crate::tunnel_messages::{TUNNEL_DATA_ENCRYPTED_SIZE, TUNNEL_DATA_IV_SIZE, TunnelDataBody};

/// Максимальный размер payload в одном tunnel-сообщении.
pub const TUNNEL_DATA_MAX_PAYLOAD_SIZE: usize = 1003;
/// Размер контрольной суммы.
pub const TUNNEL_CHECKSUM_SIZE: usize = 4;
/// Заголовок фрагмента-продолжения: `flag(1) + msg_id(4) + size(2)`.
pub const FOLLOW_ON_HEADER_SIZE: usize = 7;
/// Флаг: фрагмент-продолжение.
pub const FLAG_FOLLOW_ON: u8 = 0x80;
/// Флаг первого фрагмента: сообщение фрагментировано.
pub const FLAG_FRAGMENTED: u8 = 0x08;
/// Флаг продолжения: последний фрагмент.
pub const FLAG_LAST_FRAGMENT: u8 = 0x01;
/// Максимальный номер фрагмента (6 бит).
pub const MAX_FRAGMENT_NUMBER: u8 = 63;

/// Куда доставить сообщение на endpoint'е.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Локальная обработка (`eDeliveryTypeLocal`, 0).
    Local,
    /// В другой туннель (`eDeliveryTypeTunnel`, 1).
    Tunnel {
        /// Tunnel ID gateway'я.
        tunnel_id: u32,
        /// Роутер gateway'я.
        hash: IdentHash,
    },
    /// Роутеру напрямую (`eDeliveryTypeRouter`, 2).
    Router {
        /// Получатель.
        hash: IdentHash,
    },
}

impl Delivery {
    /// Тип доставки (биты 6-5 флага, уже сдвинутые вниз).
    #[must_use]
    pub const fn type_bits(&self) -> u8 {
        match self {
            Self::Local => 0,
            Self::Tunnel { .. } => 1,
            Self::Router { .. } => 2,
        }
    }

    /// Длина delivery instructions без `msg_id` и `size` (flag + поля).
    #[must_use]
    pub const fn instructions_len(&self) -> usize {
        match self {
            Self::Local => 1,
            Self::Tunnel { .. } => 1 + 4 + 32,
            Self::Router { .. } => 1 + 32,
        }
    }

    /// Дописывает flag и поля доставки (без бита fragmented).
    pub fn write_instructions(&self, out: &mut Vec<u8>) {
        out.push(self.type_bits() << 5);
        match self {
            Self::Local => {}
            Self::Tunnel { tunnel_id, hash } => {
                out.extend_from_slice(&tunnel_id.to_be_bytes());
                out.extend_from_slice(hash.as_bytes());
            }
            Self::Router { hash } => out.extend_from_slice(hash.as_bytes()),
        }
    }
}

/// I2NP-сообщение (с 16-байтным заголовком) и способ доставки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelMessageBlock {
    /// Куда доставить.
    pub delivery: Delivery,
    /// Полное I2NP-сообщение: заголовок и payload.
    pub message: Vec<u8>,
}

/// Вид фрагмента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentKind {
    /// Первый (или единственный) фрагмент сообщения.
    First {
        /// Способ доставки.
        delivery: Delivery,
        /// `Some(msg_id)`, если сообщение фрагментировано.
        msg_id: Option<u32>,
    },
    /// Продолжение.
    FollowOn {
        /// ID сообщения.
        msg_id: u32,
        /// Номер фрагмента (1..=63).
        fragment_num: u8,
        /// Последний ли.
        is_last: bool,
    },
}

/// Один фрагмент.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Вид.
    pub kind: FragmentKind,
    /// Данные фрагмента.
    pub data: Vec<u8>,
}

/// Результат разбора tunnel-сообщения.
///
/// Разбор идёт последовательно и при ошибке останавливается;
/// `fragments` содержит всё, что успели разобрать до неё (i2pd уже
/// обработал бы эти фрагменты).
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedTunnelMessage {
    /// Корректно разобранные фрагменты по порядку.
    pub fragments: Vec<Fragment>,
    /// Причина остановки разбора, если она была.
    pub error: Option<I2PError>,
}

fn nonzero_random_byte(rng: &mut impl Rng) -> u8 {
    u8::try_from(rng.next_u32() % 255).unwrap_or(0) + 1
}

fn checksum(payload: &[u8], iv: &[u8; TUNNEL_DATA_IV_SIZE]) -> [u8; TUNNEL_CHECKSUM_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.update(iv);
    let hash = hasher.finalize();
    let mut out = [0u8; TUNNEL_CHECKSUM_SIZE];
    out.copy_from_slice(&hash[..TUNNEL_CHECKSUM_SIZE]);
    out
}

/// Собирает расшифрованное tunnel-сообщение из `payload`:
/// случайный IV, padding из ненулевых байт, нулевой разделитель и
/// контрольная сумма. `tunnel_id` в результате равен 0.
///
/// # Errors
///
/// [`I2PError::Malformed`], если `payload` длиннее
/// [`TUNNEL_DATA_MAX_PAYLOAD_SIZE`].
pub fn build_plain_tunnel_message(payload: &[u8], rng: &mut impl Rng) -> Result<TunnelDataBody> {
    if payload.len() > TUNNEL_DATA_MAX_PAYLOAD_SIZE {
        return Err(I2PError::Malformed("tunnel message: payload too large"));
    }
    let mut iv = [0u8; TUNNEL_DATA_IV_SIZE];
    rng.fill_bytes(&mut iv);

    let start = TUNNEL_DATA_ENCRYPTED_SIZE - payload.len();
    let mut encrypted = Box::new([0u8; TUNNEL_DATA_ENCRYPTED_SIZE]);
    encrypted[start..].copy_from_slice(payload);
    // encrypted[start - 1] уже 0 — разделитель
    for b in &mut encrypted[TUNNEL_CHECKSUM_SIZE..start - 1] {
        *b = nonzero_random_byte(rng);
    }
    encrypted[..TUNNEL_CHECKSUM_SIZE].copy_from_slice(&checksum(payload, &iv));
    Ok(TunnelDataBody {
        tunnel_id: 0,
        iv,
        encrypted,
    })
}

/// Разбирает расшифрованное tunnel-сообщение.
///
/// # Errors
///
/// [`I2PError::Malformed`], если нет нулевого разделителя или не
/// сошлась контрольная сумма. Ошибки внутри самих фрагментов
/// возвращаются в [`ParsedTunnelMessage::error`].
pub fn parse_tunnel_message(msg: &TunnelDataBody) -> Result<ParsedTunnelMessage> {
    let enc = &*msg.encrypted;
    let zero = enc[TUNNEL_CHECKSUM_SIZE..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(I2PError::Malformed("tunnel message: no zero separator"))?
        + TUNNEL_CHECKSUM_SIZE;
    let payload = &enc[zero + 1..];
    if enc[..TUNNEL_CHECKSUM_SIZE] != checksum(payload, &msg.iv) {
        return Err(I2PError::Malformed("tunnel message: checksum mismatch"));
    }
    let (fragments, error) = parse_fragments(payload);
    Ok(ParsedTunnelMessage { fragments, error })
}

/// Читает `len` байт с позиции `*pos` и сдвигает позицию.
fn take<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let slice = buf
        .get(*pos..*pos + len)
        .ok_or(I2PError::Malformed("tunnel message: truncated fragment"))?;
    *pos += len;
    Ok(slice)
}

fn parse_fragments(payload: &[u8]) -> (Vec<Fragment>, Option<I2PError>) {
    let mut fragments = Vec::new();
    let mut pos = 0;
    while pos < payload.len() {
        match parse_one(payload, &mut pos) {
            Ok(f) => fragments.push(f),
            Err(e) => return (fragments, Some(e)),
        }
    }
    (fragments, None)
}

fn parse_one(payload: &[u8], pos: &mut usize) -> Result<Fragment> {
    let flag = take(payload, pos, 1)?[0];
    let kind = if flag & FLAG_FOLLOW_ON == 0 {
        let delivery = match (flag >> 5) & 0x03 {
            0 => Delivery::Local,
            1 => {
                let tunnel_id = read_u32_be(take(payload, pos, 4)?);
                let hash = IdentHash::from_slice(take(payload, pos, 32)?)
                    .ok_or(I2PError::Malformed("tunnel message: bad hash"))?;
                Delivery::Tunnel { tunnel_id, hash }
            }
            2 => {
                let hash = IdentHash::from_slice(take(payload, pos, 32)?)
                    .ok_or(I2PError::Malformed("tunnel message: bad hash"))?;
                Delivery::Router { hash }
            }
            _ => return Err(I2PError::Malformed("tunnel message: unknown delivery type")),
        };
        let msg_id = if flag & FLAG_FRAGMENTED == 0 {
            None
        } else {
            Some(read_u32_be(take(payload, pos, 4)?))
        };
        FragmentKind::First { delivery, msg_id }
    } else {
        FragmentKind::FollowOn {
            msg_id: read_u32_be(take(payload, pos, 4)?),
            fragment_num: (flag >> 1) & 0x3F,
            is_last: flag & FLAG_LAST_FRAGMENT != 0,
        }
    };
    let size = usize::from(read_u16_be(take(payload, pos, 2)?));
    let data = take(payload, pos, size)
        .map_err(|_| I2PError::Malformed("tunnel message: fragment size exceeds message"))?
        .to_vec();
    Ok(Fragment { kind, data })
}

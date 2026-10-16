//! Garlic-блоки — внутренний формат `ECIES-X25519-AEAD-Ratchet`.
//!
//! Garlic payload после расшифровки AEAD состоит из набора блоков
//! вида:
//!
//! ```text
//!   type:   1 байт
//!   size:   2 байта BE u16
//!   data:   size байт
//! ```
//!
//! Один блок — либо cloves (несколько I2NP-сообщений), либо
//! служебная информация: `DateTime`, `AckRequest`, Termination,
//! Padding, `NextKey`. Формат из `ECIESX25519AEADRatchetSession.cpp`.
//!
//! **Важно**: этот модуль работает с **уже расшифрованным** payload'ом.
//! Сам AEAD-слой (ChaCha20-Poly1305 + ratchet) — отдельно.

use crate::{
    IdentHash,
    endian::{read_u16_be, read_u32_be, read_u64_be},
    error::{I2PError, Result},
    i2np::I2npMessageType,
    i2np_message::I2npMessage,
};

// --- облегчённый clove -----------------------------------------------

/// Delivery-instructions для облегчённого clove'а
/// (ECIES-X25519-AEAD-Ratchet).
///
/// В wire-формате занимает 1 байт флага и, опционально, 32 или 36
/// байт адреса/туннеля. Кодирование в точности как в i2pd
/// `ECIESX25519AEADRatchetSession::CreateGarlicClove`:
///
/// - `Local` → флаг `0b000 << 5`, суффикс 0 байт;
/// - `Destination(h)` → флаг `0b001 << 5`, суффикс 32 байта;
/// - `Tunnel { gateway, tunnel_id }` → флаг `0b010 << 5`,
///   суффикс 36 байт (`gateway(32) | tunnel_id(4 BE)`);
/// - `Router(h)` → флаг `0b011 << 5`, суффикс 32 байта.
///
/// ## Отличие от [`crate::garlic::Delivery`]
///
/// Флаги совпадают (биты 5–6 байта flag), но этот тип используется
/// внутри [`EciesGarlicClove`], у которого нет отдельного
/// `clove_id`/`expiration_ms`/`certificate`. Не путать при
/// чтении/записи: `garlic::Delivery` пишется в формате
/// ElGamal/AES garlic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EciesDelivery {
    /// Доставить локально (получатель — этот роутер/сессия).
    Local,
    /// Доставить конкретному destination'у (по `IdentHash`).
    Destination(IdentHash),
    /// Доставить во вход туннеля.
    Tunnel {
        /// Gateway-роутер.
        gateway: IdentHash,
        /// `TunnelID` на gateway.
        tunnel_id: u32,
    },
    /// Доставить роутеру (по `IdentHash`).
    Router(IdentHash),
}

impl EciesDelivery {
    /// Байт-флаг (bits 5–6, без encrypted-бита).
    #[must_use]
    pub const fn flag(&self) -> u8 {
        match self {
            Self::Local => 0b000 << 5,
            Self::Destination(_) => 0b001 << 5,
            Self::Tunnel { .. } => 0b010 << 5,
            Self::Router(_) => 0b011 << 5,
        }
    }

    /// Размер суффикса в байтах (без 1-байтового флага).
    #[must_use]
    pub const fn suffix_len(&self) -> usize {
        match self {
            Self::Local => 0,
            Self::Destination(_) | Self::Router(_) => 32,
            Self::Tunnel { .. } => 36,
        }
    }
}

/// Один облегчённый garlic-clove для ECIES-X25519-AEAD-Ratchet.
///
/// ## Wire-формат
///
/// ```text
///   offset  size  field
///   ------  ----  -----
///        0     1  flag                (bits 5–6 = delivery type)
///        1     S  delivery suffix     (0, 32 или 36 байт по типу)
///      1+S     1  typeID              (I2NP message type)
///      2+S     4  msgID               (BE u32)
///      6+S     4  expiration_secs     (BE u32, seconds since epoch)
///     10+S     N  payload             (I2NP payload без заголовка)
/// ```
///
/// `S = delivery.suffix_len()`. Общая длина тела = `10 + S + N`.
///
/// ## Что здесь и чего нет
///
/// **Есть**: минимально необходимое для доставки I2NP-сообщения
/// через ECIES-X25519-AEAD garlic.
///
/// **Нет** (в отличие от [`crate::garlic::GarlicClove`]):
///
/// - `clove_id` — в ECIES-X25519-AEAD не используется;
/// - `expiration_ms` — есть только `expiration_secs`;
/// - `certificate` — 3-байтового сертификата нет;
/// - 16-байтового I2NP-заголовка — есть только `typeID`, `msgID`,
///   `expiration_secs` и payload.
///
/// Эти отличия — прямое следствие того, что i2pd реализует два
/// разных формата garlic-clove: классический (ElGamal/AES) и
/// облегчённый (ECIES-X25519-AEAD). Здесь — второй.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EciesGarlicClove {
    /// Куда доставить clove.
    pub delivery: EciesDelivery,
    /// I2NP-тип сообщения внутри.
    pub message_type: I2npMessageType,
    /// I2NP msgID.
    pub message_id: u32,
    /// Expiration I2NP-сообщения в секундах since epoch.
    pub expiration_secs: u32,
    /// I2NP payload без 16-байтового заголовка.
    pub payload: Vec<u8>,
}

impl EciesGarlicClove {
    /// Сериализует тело clove'а (без 3-байтового заголовка блока
    /// `GarlicBlock`).
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если `payload` не влезает в
    /// `u16::MAX - 10 - suffix_len`.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        let suffix_len = self.delivery.suffix_len();
        let total_payload = 1usize
            .checked_add(suffix_len)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(self.payload.len()))
            .ok_or(I2PError::Malformed("ecies_clove: size overflow"))?;
        if total_payload > u16::MAX as usize {
            return Err(I2PError::Malformed(
                "ecies_clove: payload too long for u16 block size",
            ));
        }

        let mut out = Vec::with_capacity(total_payload);

        // flag (1)
        out.push(self.delivery.flag());

        // delivery suffix
        match &self.delivery {
            EciesDelivery::Local => {}
            EciesDelivery::Destination(h) | EciesDelivery::Router(h) => {
                out.extend_from_slice(h.as_bytes());
            }
            EciesDelivery::Tunnel { gateway, tunnel_id } => {
                out.extend_from_slice(gateway.as_bytes());
                out.extend_from_slice(&tunnel_id.to_be_bytes());
            }
        }

        // typeid (1)
        out.push(self.message_type.as_u8());

        // msgid (4 BE)
        out.extend_from_slice(&self.message_id.to_be_bytes());

        // expiration_secs (4 BE)
        out.extend_from_slice(&self.expiration_secs.to_be_bytes());

        // payload
        out.extend_from_slice(&self.payload);

        Ok(out)
    }

    /// Парсит тело clove'а из `buf`, возвращает `(clove, consumed)`.
    ///
    /// `buf` начинается с flag-байта, `consumed` = длина тела.
    /// Парсинг останавливается на границе своего тела, а не на
    /// конце `buf` — то есть если после clove'а в буфере идут ещё
    /// данные (следующий блок), они не потребляются.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — `buf` короче, чем объявлено
    ///   полями внутри clove'а (flag + suffix + 9 + payload);
    /// - [`I2PError::UnknownI2npType`] — typeID не описан;
    /// - [`I2PError::Malformed`] — размер payload'а не влезает в
    ///   `usize` (недостижимо на практике).
    pub fn from_buffer(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(I2PError::InvalidLength {
                expected: 1,
                got: 0,
            });
        }
        let flag = buf[0];
        if flag & 0x80 != 0 {
            // Старший бит flag в ECIES-X25519-AEAD не используется,
            // i2pd его тоже не трактует.
            return Err(I2PError::Malformed(
                "ecies_clove: encrypted-clove bit is not defined",
            ));
        }
        let delivery_type = (flag >> 5) & 0x03;
        let mut offset = 1usize;

        // delivery suffix
        let delivery = match delivery_type {
            0 => EciesDelivery::Local,
            1 => {
                if buf.len() < offset + 32 {
                    return Err(I2PError::InvalidLength {
                        expected: offset + 32,
                        got: buf.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&buf[offset..offset + 32]);
                offset += 32;
                EciesDelivery::Destination(crate::IdentHash::from_array(h))
            }
            2 => {
                if buf.len() < offset + 36 {
                    return Err(I2PError::InvalidLength {
                        expected: offset + 36,
                        got: buf.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&buf[offset..offset + 32]);
                offset += 32;
                let tunnel_id = read_u32_be(&buf[offset..]);
                offset += 4;
                EciesDelivery::Tunnel {
                    gateway: crate::IdentHash::from_array(h),
                    tunnel_id,
                }
            }
            3 => {
                if buf.len() < offset + 32 {
                    return Err(I2PError::InvalidLength {
                        expected: offset + 32,
                        got: buf.len(),
                    });
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&buf[offset..offset + 32]);
                offset += 32;
                EciesDelivery::Router(crate::IdentHash::from_array(h))
            }
            _ => unreachable!(),
        };

        // typeid + msgid + expiration_secs
        if buf.len() < offset + 9 {
            return Err(I2PError::InvalidLength {
                expected: offset + 9,
                got: buf.len(),
            });
        }
        let message_type = I2npMessageType::from_u8(buf[offset])?;
        offset += 1;
        let message_id = read_u32_be(&buf[offset..]);
        offset += 4;
        let expiration_secs = read_u32_be(&buf[offset..]);
        offset += 4;

        // payload — до конца buf. Границу определяет вызывающий по
        // известному размеру блока (в GarlicBlock::from_buffer это
        // сделано через size из заголовка).
        let payload = buf[offset..].to_vec();
        let consumed = offset + payload.len();
        Ok((
            Self {
                delivery,
                message_type,
                message_id,
                expiration_secs,
                payload,
            },
            consumed,
        ))
    }

    /// Оборачивает [`I2npMessage`] в clove с delivery `Local`.
    ///
    /// Удобно для случая «послать одно I2NP-сообщение через garlic».
    /// `expiration_secs` берётся из `msg.expiration_ms() / 1000`.
    #[must_use]
    pub fn wrap_local(msg: &I2npMessage) -> Self {
        Self {
            delivery: EciesDelivery::Local,
            message_type: msg.message_type(),
            message_id: msg.msg_id(),
            expiration_secs: u32::try_from(msg.expiration_ms() / 1000).unwrap_or(u32::MAX),
            payload: msg.payload().to_vec(),
        }
    }

    /// Восстанавливает [`I2npMessage`] из clove'а.
    ///
    /// `msg_id` и `expiration_ms` берутся из clove'а, `payload` —
    /// из clove'а. `checksum` устанавливается в `None` (в garlic
    /// checksum не используется).
    #[must_use]
    pub fn to_i2np_message(&self) -> I2npMessage {
        let size = u16::try_from(self.payload.len()).unwrap_or(u16::MAX);
        let header = crate::i2np::I2npHeader {
            message_type: self.message_type,
            msg_id: self.message_id,
            expiration_ms: u64::from(self.expiration_secs) * 1000,
            size,
            checksum: None,
        };
        I2npMessage::with_header(header, self.payload.clone())
    }
}
// --- типы блоков ---------------------------------------------------------

/// `DateTime`: `u32 BE` (секунды since epoch).
pub const BLK_DATETIME: u8 = 0;
/// `SessionId`: raw. Обычно 2 байта (`flags`, `session_id`).
pub const BLK_SESSION_ID: u8 = 1;
/// `Termination`: `u64 BE` (seqn) + `u8` (reason).
pub const BLK_TERMINATION: u8 = 4;
/// `Options`: raw. Обычно пустой.
pub const BLK_OPTIONS: u8 = 5;
/// `NextKey`: raw. Флаги + `u16` keyID + optional pub key.
pub const BLK_NEXT_KEY: u8 = 7;
/// `Ack`: `N × (u16 tagsetid, u16 N)`.
pub const BLK_ACK: u8 = 8;
/// `AckRequest`: `[flags]`.
pub const BLK_ACK_REQUEST: u8 = 9;
/// `GarlicClove`: `GarlicClove::to_buffer()`.
pub const BLK_GARLIC_CLOVE: u8 = 11;
/// `Padding`: `size` нулей.
pub const BLK_PADDING: u8 = 254;

// --- GarlicBlock ---------------------------------------------------------

/// Один garlic-блок.
///
/// `Padding` хранит **длину** нулей, а не сами нули — они всё равно
/// всегда нули, и хранить их незачем. При сериализации пишется `size`
/// нулевых байт.
///
/// `NextKey` и `SessionId` пока хранятся как raw `Vec<u8>`: их
/// внутренняя структура нужна только session-state-machine, а не
/// самому формату блока. Разберём их в шаге 2x-2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GarlicBlock {
    /// `DateTime` (seconds since epoch).
    DateTime(u32),
    /// `SessionId` — raw.
    SessionId(Vec<u8>),
    /// Termination: `(seqn, reason)`.
    Termination { seqn: u64, reason: u8 },
    /// Options — raw.
    Options(Vec<u8>),
    /// `NextKey` — raw.
    NextKey(Vec<u8>),
    /// Ack: пары `(tagsetid, N)`.
    Ack(Vec<(u16, u16)>),
    /// `AckRequest`.
    AckRequest,
    /// `GarlicClove` в облегчённом формате ECIES-X25519-AEAD.
    ///
    /// Внутри — [`EciesGarlicClove`], а не
    /// [`crate::garlic::GarlicClove`]. Формат принципиально разный:
    /// см. доки [`EciesGarlicClove`].
    EciesGarlicClove(EciesGarlicClove),
    /// Padding: `size` нулевых байт.
    Padding(usize),
    /// Неизвестный блок — сохраняем как есть.
    Unknown { type_id: u8, data: Vec<u8> },
}

impl GarlicBlock {
    /// Тип блока.
    #[must_use]
    pub const fn type_id(&self) -> u8 {
        match self {
            Self::DateTime(_) => BLK_DATETIME,
            Self::SessionId(_) => BLK_SESSION_ID,
            Self::Termination { .. } => BLK_TERMINATION,
            Self::Options(_) => BLK_OPTIONS,
            Self::NextKey(_) => BLK_NEXT_KEY,
            Self::Ack(_) => BLK_ACK,
            Self::AckRequest => BLK_ACK_REQUEST,
            Self::EciesGarlicClove(_) => BLK_GARLIC_CLOVE,
            Self::Padding(_) => BLK_PADDING,
            Self::Unknown { type_id, .. } => *type_id,
        }
    }

    /// Сериализует блок в wire-формат.
    ///
    /// # Errors
    ///
    /// - [`Error::Malformed`] — если данные блока больше `u16::MAX`;
    /// - [`Error::Malformed`], если `clove.to_buffer()` не собрался.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let data: Vec<u8> = match self {
            Self::DateTime(secs) => secs.to_be_bytes().to_vec(),
            Self::SessionId(raw) | Self::Options(raw) | Self::NextKey(raw) => raw.clone(),
            Self::Termination { seqn, reason } => {
                let mut v = Vec::with_capacity(9);
                v.extend_from_slice(&seqn.to_be_bytes());
                v.push(*reason);
                v
            }
            Self::Ack(pairs) => {
                let mut v = Vec::with_capacity(pairs.len() * 4);
                for (tagset_id, n) in pairs {
                    v.extend_from_slice(&tagset_id.to_be_bytes());
                    v.extend_from_slice(&n.to_be_bytes());
                }
                v
            }
            Self::AckRequest => vec![0u8], // flags = 0
            Self::EciesGarlicClove(clove) => clove.body_bytes()?,
            Self::Padding(size) => vec![0u8; *size],
            Self::Unknown { data, .. } => data.clone(),
        };

        let size = u16::try_from(data.len())
            .map_err(|_| I2PError::Malformed("garlic_block: data > 65535 bytes"))?;
        let mut out = Vec::with_capacity(3 + data.len());
        out.push(self.type_id());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&data);
        Ok(out)
    }

    /// Парсит блок, возвращает `(block, consumed)`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — буфер короче 3 байт или size
    ///   выходит за границы буфера;
    /// - [`Error::Malformed`] — данные не соответствуют типу
    ///   (например, `DateTime` с size != 4);
    /// - [`Error::Unsupported`] — encrypted clove.
    pub fn from_buffer(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 3 {
            return Err(I2PError::InvalidLength {
                expected: 3,
                got: buf.len(),
            });
        }
        let type_id = buf[0];
        let size = usize::from(read_u16_be(&buf[1..]));
        if buf.len() < 3 + size {
            return Err(I2PError::InvalidLength {
                expected: 3 + size,
                got: buf.len(),
            });
        }
        let data = &buf[3..3 + size];
        let total = 3 + size;

        let block = match type_id {
            BLK_DATETIME => {
                if data.len() != 4 {
                    return Err(I2PError::Malformed(
                        "garlic_block: DateTime block must be 4 bytes",
                    ));
                }
                Self::DateTime(read_u32_be(data))
            }
            BLK_SESSION_ID => Self::SessionId(data.to_vec()),
            BLK_TERMINATION => {
                if data.len() != 9 {
                    return Err(I2PError::Malformed(
                        "garlic_block: Termination block must be 9 bytes",
                    ));
                }
                Self::Termination {
                    seqn: read_u64_be(data),
                    reason: data[8],
                }
            }
            BLK_OPTIONS => Self::Options(data.to_vec()),
            BLK_NEXT_KEY => Self::NextKey(data.to_vec()),
            BLK_ACK => {
                if !data.len().is_multiple_of(4) {
                    return Err(I2PError::Malformed(
                        "garlic_block: Ack block must be a multiple of 4 bytes",
                    ));
                }
                let (chunks, _rem) = data.as_chunks::<4>();
                let mut pairs = Vec::with_capacity(chunks.len());
                for chunk in chunks {
                    pairs.push((read_u16_be(&chunk[..2]), read_u16_be(&chunk[2..])));
                }
                Self::Ack(pairs)
            }
            BLK_ACK_REQUEST => Self::AckRequest,
            BLK_GARLIC_CLOVE => {
                // `data` — уже ограничен `size` из заголовка блока,
                // поэтому `from_buffer` может вернуть `consumed`
                // меньше `data.len()` только если в clove'е есть
                // trailing bytes — это нарушение формата.
                let (clove, consumed) = EciesGarlicClove::from_buffer(data)?;
                if consumed != data.len() {
                    return Err(I2PError::Malformed(
                        "garlic_block: ecies clove did not consume full block",
                    ));
                }
                Self::EciesGarlicClove(clove)
            }
            BLK_PADDING => Self::Padding(size),
            other => Self::Unknown {
                type_id: other,
                data: data.to_vec(),
            },
        };

        Ok((block, total))
    }
}

// --- список блоков -------------------------------------------------------

/// Парсит последовательность garlic-блоков до конца буфера.
///
/// # Errors
///
/// См. [`GarlicBlock::from_buffer`].
pub fn parse_blocks(buf: &[u8]) -> Result<Vec<GarlicBlock>> {
    let mut offset = 0;
    let mut blocks = Vec::new();
    while offset < buf.len() {
        let (block, consumed) = GarlicBlock::from_buffer(&buf[offset..])?;
        blocks.push(block);
        offset += consumed;
    }
    Ok(blocks)
}

/// Сериализует последовательность garlic-блоков.
///
/// # Errors
///
/// См. [`GarlicBlock::to_buffer`].
pub fn serialize_blocks(blocks: &[GarlicBlock]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for block in blocks {
        out.extend_from_slice(&block.to_buffer()?);
    }
    Ok(out)
}

/// Семантическое представление `NextKey`-блока.
///
/// Wire-формат: `flags(1) | keyID(2 BE) | pubkey(32, опционально)`.
/// В [`GarlicBlock::NextKey`] хранится именно этот payload как
/// `Vec<u8>`; структура нужна для семантической обработки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextKeyBlock {
    pub flags: u8,
    pub key_id: u16,
    /// Присутствует только если выставлен [`Self::KEY_PRESENT_FLAG`].
    pub public_key: Option<[u8; 32]>,
}

impl NextKeyBlock {
    /// Публичный ключ присутствует в блоке.
    pub const KEY_PRESENT_FLAG: u8 = 0x01;
    /// Это обратный ключ (ответ на forward key).
    pub const REVERSE_KEY_FLAG: u8 = 0x02;
    /// Запрос обратного ключа.
    pub const REQUEST_REVERSE_KEY_FLAG: u8 = 0x04;

    /// Разбирает payload `NextKey`-блока (без 3-байтового заголовка).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если `data` короче 3 байт или
    /// `KEY_PRESENT_FLAG` выставлен, а 32 байт на ключ нет.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(I2PError::InvalidLength {
                expected: 3,
                got: data.len(),
            });
        }
        let flags = data[0];
        let key_id = u16::from_be_bytes([data[1], data[2]]);
        let public_key = if flags & Self::KEY_PRESENT_FLAG != 0 {
            if data.len() < 35 {
                return Err(I2PError::InvalidLength {
                    expected: 35,
                    got: data.len(),
                });
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data[3..35]);
            Some(pk)
        } else {
            if data.len() != 3 {
                return Err(I2PError::Malformed(
                    "garlic_block: NextKey without KEY_PRESENT has trailing bytes",
                ));
            }
            None
        };
        Ok(Self {
            flags,
            key_id,
            public_key,
        })
    }

    /// Сериализует payload (без 3-байтового заголовка `GarlicBlock`).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(35);
        out.push(self.flags);
        out.extend_from_slice(&self.key_id.to_be_bytes());
        if let Some(pk) = &self.public_key {
            out.extend_from_slice(pk);
        }
        out
    }

    /// Удобный конструктор `NextKey`-блока с публичным ключом.
    #[must_use]
    pub const fn with_key(flags: u8, key_id: u16, public_key: [u8; 32]) -> Self {
        Self {
            flags: flags | Self::KEY_PRESENT_FLAG,
            key_id,
            public_key: Some(public_key),
        }
    }

    /// Удобный конструктор без публичного ключа.
    #[must_use]
    pub const fn without_key(flags: u8, key_id: u16) -> Self {
        Self {
            flags: flags & !Self::KEY_PRESENT_FLAG,
            key_id,
            public_key: None,
        }
    }

    #[must_use]
    pub const fn is_reverse_key(&self) -> bool {
        self.flags & Self::REVERSE_KEY_FLAG != 0
    }

    #[must_use]
    pub const fn requests_reverse_key(&self) -> bool {
        self.flags & Self::REQUEST_REVERSE_KEY_FLAG != 0
    }
}

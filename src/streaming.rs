//! `StreamingMessage` — пакет протокола I2P Streaming.
//!
//! Streaming — это TCP поверх I2NP: SYN/данные/ACK/CLOSE едут
//! обычными I2NP `Data`-сообщениями (type 20) внутри garlic-clove'ов.
//! Формат пакета — `libi2pd/Streaming.h:86-113`, поля читаются прямо
//! из `Packet::buf`.
//!
//! ## Wire-формат
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     4  sendStreamID      — id отправителя
//!        4     4  receiveStreamID   — id получателя
//!        8     4  seqn              — номер пакета
//!       12     4  ackThrough        — подтверждён «всё до» (включительно)
//!       16     1  nackCount         — сколько NACK'ов идёт следом
//!       17  4*n  nacks             — отсутствующие seqn'ы (BE u32)
//!    17+4n     1  resendDelay       — секунды до повтора
//!    18+4n     2  flags             — см. [`FLAG_SYNCHRONIZE`] и т.д.
//!    20+4n     2  optionSize        — длина options
//!    22+4n     ?  options
//!       ?     ?  payload
//! ```
//!
//! Все многобайтовые поля — big-endian.
//!
//! ## Обёртка I2NP `Data`
//!
//! Пакет едет не «как есть», а внутри gzip-контейнера, в заголовок
//! которого i2pd подмешивает порты (`Streaming.cpp:CreateDataMessage`):
//!
//! ```text
//!   payload[0..4]  — BE u32: длина gzip-контейнера
//!   payload[4..]   — gzip-контейнер, у которого перезаписаны байты:
//!                    [4..6]  fromPort (BE u16)
//!                    [6..8]  toPort   (BE u16)
//!                    [9]     protocol (6 = streaming)
//! ```
//!
//! `mtime` и `OS` в gzip-заголовке i2pd не проверяет, поэтому порты
//! спокойно живут на их месте. См. [`wrap_data_message`] /
//! [`unwrap_data_message`].

use crate::endian::{read_u16_be, read_u32_be, write_u16_be};
use crate::error::{I2PError, Result};
use crate::gzip;

/// Пакет открывает/подтверждает поток.
pub const FLAG_SYNCHRONIZE: u16 = 0x0001;
/// Закрыть поток после обработки пакета.
pub const FLAG_CLOSE: u16 = 0x0002;
/// Сбросить поток (аналог RST).
pub const FLAG_RESET: u16 = 0x0004;
/// В options лежит подпись отправителя.
pub const FLAG_SIGNATURE_INCLUDED: u16 = 0x0008;
/// Отправитель просит подпись.
pub const FLAG_SIGNATURE_REQUESTED: u16 = 0x0010;
/// В options лежит identity отправителя.
pub const FLAG_FROM_INCLUDED: u16 = 0x0020;
/// В options лежит запрошенная задержка ACK.
pub const FLAG_DELAY_REQUESTED: u16 = 0x0040;
/// В options лежит максимальный размер пакета.
pub const FLAG_MAX_PACKET_SIZE_INCLUDED: u16 = 0x0080;
/// Профиль «интерактивный» (используется для выбора MTU/окна).
pub const FLAG_PROFILE_INTERACTIVE: u16 = 0x0100;
/// Эхо-пакет (ping/pong).
pub const FLAG_ECHO: u16 = 0x0200;
/// Не подтверждать пакет.
pub const FLAG_NO_ACK: u16 = 0x0400;
/// В options лежит offline-подпись.
pub const FLAG_OFFLINE_SIGNATURE: u16 = 0x0800;

/// `PROTOCOL_TYPE_STREAMING` из `I2CP` — байт протокола в `Data`.
pub const PROTOCOL_TYPE_STREAMING: u8 = 6;

/// Минимальный размер пакета: поля до `nackCount` включительно.
const MIN_PACKET_LEN: usize = 17;

/// Заголовок I2NP `Data` до полезной нагрузки (порты и протокол).
const DATA_HEADER_LEN: usize = 10;

/// Разобранный streaming-пакет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingPacket {
    /// Id потока отправителя.
    pub send_stream_id: u32,
    /// Id потока получателя.
    pub receive_stream_id: u32,
    /// Номер этого пакета в потоке.
    pub seqn: u32,
    /// «Всё до этого номера включительно получено».
    pub ack_through: u32,
    /// Номера, которых не хватает (максимум 255).
    pub nacks: Vec<u32>,
    /// Через сколько секунд повторять, если ACK не придёт.
    pub resend_delay: u8,
    /// Битовая маска `FLAG_*`.
    pub flags: u16,
    /// Данные опций (identity, подпись, задержка…).
    pub options: Vec<u8>,
    /// Полезная нагрузка (для SYN/SYNACK обычно пусто).
    pub payload: Vec<u8>,
}

impl StreamingPacket {
    /// Пустой пакет для потока `send_stream_id` → `receive_stream_id`.
    #[must_use]
    pub const fn new(send_stream_id: u32, receive_stream_id: u32) -> Self {
        Self {
            send_stream_id,
            receive_stream_id,
            seqn: 0,
            ack_through: 0,
            nacks: Vec::new(),
            resend_delay: 0,
            flags: 0,
            options: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// SYN или SYNACK?
    #[must_use]
    pub const fn is_syn(&self) -> bool {
        self.flags & FLAG_SYNCHRONIZE != 0
    }

    /// Закрытие потока?
    #[must_use]
    pub const fn is_close(&self) -> bool {
        self.flags & FLAG_CLOSE != 0
    }

    /// Сброс потока?
    #[must_use]
    pub const fn is_reset(&self) -> bool {
        self.flags & FLAG_RESET != 0
    }

    /// Есть ли identity отправителя в опциях?
    #[must_use]
    pub const fn has_from(&self) -> bool {
        self.flags & FLAG_FROM_INCLUDED != 0
    }

    /// Собирает пакет в wire-формат.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если NACK'ов больше 255.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let nack_count = u8::try_from(self.nacks.len())
            .map_err(|_| I2PError::Malformed("streaming: more than 255 NACKs"))?;
        let option_size = u16::try_from(self.options.len())
            .map_err(|_| I2PError::Malformed("streaming: options too long"))?;

        let mut out = Vec::with_capacity(
            MIN_PACKET_LEN + self.nacks.len() * 4 + self.options.len() + self.payload.len(),
        );
        out.extend_from_slice(&self.send_stream_id.to_be_bytes());
        out.extend_from_slice(&self.receive_stream_id.to_be_bytes());
        out.extend_from_slice(&self.seqn.to_be_bytes());
        out.extend_from_slice(&self.ack_through.to_be_bytes());
        out.push(nack_count);
        for nack in &self.nacks {
            out.extend_from_slice(&nack.to_be_bytes());
        }
        out.push(self.resend_delay);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&option_size.to_be_bytes());
        out.extend_from_slice(&self.options);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Разбирает пакет.
    ///
    /// Возвращает пакет и число занятых байт (payload дочитывается
    /// до конца буфера — длина пакета определяется контекстом, как
    /// в `Packet::len` у i2pd).
    ///
    /// # Errors
    ///
    /// [`I2PError::InvalidLength`], если буфер короче заголовка или
    /// заявленных NACK'ов/options.
    pub fn from_buffer(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < MIN_PACKET_LEN {
            return Err(I2PError::InvalidLength {
                expected: MIN_PACKET_LEN,
                got: buf.len(),
            });
        }
        let send_stream_id = read_u32_be(&buf[0..4]);
        let receive_stream_id = read_u32_be(&buf[4..8]);
        let seqn = read_u32_be(&buf[8..12]);
        let ack_through = read_u32_be(&buf[12..16]);
        let nack_count = usize::from(buf[16]);

        let nacks_end = MIN_PACKET_LEN
            .checked_add(nack_count * 4)
            .ok_or(I2PError::Malformed("streaming: NACK count overflow"))?;
        // + resendDelay(1) + flags(2) + optionSize(2)
        let options_len_at = nacks_end
            .checked_add(5)
            .ok_or(I2PError::Malformed("streaming: header overflow"))?;
        if buf.len() < options_len_at {
            return Err(I2PError::InvalidLength {
                expected: options_len_at,
                got: buf.len(),
            });
        }
        let mut nacks = Vec::with_capacity(nack_count);
        for i in 0..nack_count {
            let at = MIN_PACKET_LEN + i * 4;
            nacks.push(read_u32_be(&buf[at..at + 4]));
        }
        let resend_delay = buf[nacks_end];
        let flags = read_u16_be(&buf[nacks_end + 1..nacks_end + 3]);
        let option_size = usize::from(read_u16_be(&buf[nacks_end + 3..nacks_end + 5]));
        let options_end = options_len_at
            .checked_add(option_size)
            .ok_or(I2PError::Malformed("streaming: option size overflow"))?;
        if buf.len() < options_end {
            return Err(I2PError::InvalidLength {
                expected: options_end,
                got: buf.len(),
            });
        }
        Ok((
            Self {
                send_stream_id,
                receive_stream_id,
                seqn,
                ack_through,
                nacks,
                resend_delay,
                flags,
                options: buf[options_len_at..options_end].to_vec(),
                payload: buf[options_end..].to_vec(),
            },
            buf.len(),
        ))
    }
}

/// Собирает тело I2NP `Data` из готового streaming-пакета.
///
/// Порты пишутся в gzip-заголовок — так же, как
/// `StreamingDestination::CreateDataMessage` в i2pd
/// (`Streaming.cpp:2538-2564`).
///
/// # Errors
///
/// Ошибки [`crate::gzip::compress`] и [`I2PError::Malformed`], если
/// контейнер меньше 10 байт (не должно случаться).
pub fn wrap_data_message(packet: &[u8], from_port: u16, to_port: u16) -> Result<Vec<u8>> {
    let mut container = gzip::compress(packet)?;
    if container.len() < DATA_HEADER_LEN {
        return Err(I2PError::Malformed("streaming: gzip container too short"));
    }
    write_u16_be(&mut container[4..6], from_port);
    write_u16_be(&mut container[6..8], to_port);
    container[9] = PROTOCOL_TYPE_STREAMING;

    let len = u32::try_from(container.len())
        .map_err(|_| I2PError::Malformed("streaming: container too long"))?;
    let mut out = Vec::with_capacity(4 + container.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&container);
    Ok(out)
}

/// Разобранное тело I2NP `Data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMessage {
    /// Порт отправителя.
    pub from_port: u16,
    /// Порт получателя.
    pub to_port: u16,
    /// Байт протокола (`6` — streaming).
    pub protocol: u8,
    /// Разжатая полезная нагрузка (streaming-пакет).
    pub payload: Vec<u8>,
}

/// Разбирает тело I2NP `Data` — обратная операция к
/// [`wrap_data_message`].
///
/// # Errors
///
/// [`I2PError::InvalidLength`], если буфер короче 14 байт или
/// заявленной длины; [`I2PError::Malformed`], если gzip не разжался.
pub fn unwrap_data_message(buf: &[u8]) -> Result<DataMessage> {
    // 4 (длина) + 10 (порты/протокол) — тот же минимум, что в
    // `ClientDestination::HandleDataMessage` (`Destination.cpp:1264`).
    if buf.len() < 4 + DATA_HEADER_LEN {
        return Err(I2PError::InvalidLength {
            expected: 4 + DATA_HEADER_LEN,
            got: buf.len(),
        });
    }
    let len = usize::try_from(read_u32_be(&buf[..4]))
        .map_err(|_| I2PError::Malformed("streaming: data length overflow"))?;
    if len > buf.len() - 4 {
        return Err(I2PError::InvalidLength {
            expected: 4 + len,
            got: buf.len(),
        });
    }
    let container = &buf[4..4 + len];
    let from_port = read_u16_be(&container[4..6]);
    let to_port = read_u16_be(&container[6..8]);
    let protocol = container[9];
    let payload = gzip::decompress(container)?;
    Ok(DataMessage {
        from_port,
        to_port,
        protocol,
        payload,
    })
}

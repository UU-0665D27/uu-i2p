//! `Lease` — запись в `LeaseSet`: как найти вход в inbound-туннель
//! destination'а.
//!
//! Каждый destination публикует свой `LeaseSet` — список из 1..16
//! `Lease`'ов. Каждый `Lease` указывает на gateway-роутер и `tunnel_id`,
//! через который можно доставить пакет. Это позволяет destination'у
//! получать входящие сообщения, не имея прямого соединения с сетью.
//!
//! ## Форматы
//!
//! Две версии wire-формата, отличаются размером `endDate`:
//!
//! ```text
//!   Lease1 (44 байта, LeaseSet type 1):
//!     tunnelGateway: 32 байта
//!     tunnelID:       4 байта BE u32
//!     endDate:        8 байт BE u64  — миллисекунды since epoch
//!
//!   Lease2 (40 байт, LeaseSet2 type 3/5/7):
//!     tunnelGateway: 32 байта
//!     tunnelID:       4 байта BE u32
//!     endDate:        4 байта BE u32  — секунды since epoch
//! ```
//!
//! Внутри храним всегда `end_date_ms` (миллисекунды) — как i2pd,
//! который при чтении Lease2 умножает на 1000. При сериализации
//! Lease2 делим обратно. Это значит, что для точного round-trip
//! Lease2 `end_date_ms` должен быть кратен 1000.

use crate::IdentHash;
use crate::endian::{read_u32_be, read_u64_be, write_u32_be, write_u64_be};
use crate::error::{I2PError, Result};

/// Размер `Lease` в `LeaseSet` (type 1) — 44 байта.
pub const LEASE_SIZE: usize = 44;

/// Размер `Lease` в `LeaseSet2` (type 3/5/7) — 40 байт.
pub const LEASE2_SIZE: usize = 40;

/// Максимальное количество `Lease`'ов в одном `LeaseSet`.
pub const MAX_NUM_LEASES: u8 = 16;

/// Запись в `LeaseSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lease {
    /// `IdentHash` роутера-входа в туннель.
    pub tunnel_gateway: IdentHash,
    /// ID туннеля на роутере-входе.
    pub tunnel_id: u32,
    /// Момент истечения (milliseconds since epoch). `0` — invalid.
    pub end_date_ms: u64,
}

impl Lease {
    /// Конструктор.
    #[must_use]
    pub const fn new(tunnel_gateway: IdentHash, tunnel_id: u32, end_date_ms: u64) -> Self {
        Self {
            tunnel_gateway,
            tunnel_id,
            end_date_ms,
        }
    }

    /// `end_date_ms != 0`. i2pd трактует `0` как «invalid lease».
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.end_date_ms != 0
    }

    /// Уже истёк на момент `now_ms`?
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        self.end_date_ms < now_ms
    }

    /// Истекает в течение `t_ms` от момента `now_ms`?
    ///
    /// Соответствует `Lease::ExpiresWithin` в i2pd. Jitter (fudge)
    /// в i2pd применяется к `now`, чтобы развести одновременные
    /// запросы от разных клиентов — у нас caller может сам
    /// добавить jitter к `now_ms`, если нужно.
    #[must_use]
    pub const fn expires_within(&self, t_ms: u64, now_ms: u64) -> bool {
        if self.end_date_ms < now_ms {
            return true; // уже истёк
        }
        self.end_date_ms - now_ms < t_ms
    }

    /// Ключ сортировки в порядке i2pd (`LeaseCmp`):
    /// сначала `tunnel_id`, при равенстве — `tunnel_gateway`.
    #[must_use]
    pub const fn sort_key(&self) -> (u32, IdentHash) {
        (self.tunnel_id, self.tunnel_gateway)
    }

    /// Читает `Lease` из `LeaseSet` (type 1) — 44 байта.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если буфер короче [`LEASE_SIZE`].
    pub fn parse_ls1(buf: &[u8]) -> Result<Self> {
        if buf.len() < LEASE_SIZE {
            return Err(I2PError::InvalidLength {
                expected: LEASE_SIZE,
                got: buf.len(),
            });
        }
        let mut gw = [0u8; 32];
        gw.copy_from_slice(&buf[0..32]);
        Ok(Self {
            tunnel_gateway: IdentHash::from_array(gw),
            tunnel_id: read_u32_be(&buf[32..]),
            end_date_ms: read_u64_be(&buf[36..]),
        })
    }

    /// Пишет `Lease` в формате `LeaseSet` (type 1) — 44 байта.
    #[must_use]
    pub fn to_buffer_ls1(&self) -> [u8; LEASE_SIZE] {
        let mut out = [0u8; LEASE_SIZE];
        out[0..32].copy_from_slice(self.tunnel_gateway.as_bytes());
        write_u32_be(&mut out[32..], self.tunnel_id);
        write_u64_be(&mut out[36..], self.end_date_ms);
        out
    }

    /// Читает `Lease` из `LeaseSet2` (type 3/5/7) — 40 байт.
    ///
    /// `endDate` в wire-формате — секунды, внутри храним миллисекунды.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`], если буфер короче [`LEASE2_SIZE`].
    pub fn parse_ls2(buf: &[u8]) -> Result<Self> {
        if buf.len() < LEASE2_SIZE {
            return Err(I2PError::InvalidLength {
                expected: LEASE2_SIZE,
                got: buf.len(),
            });
        }
        let mut gw = [0u8; 32];
        gw.copy_from_slice(&buf[0..32]);
        Ok(Self {
            tunnel_gateway: IdentHash::from_array(gw),
            tunnel_id: read_u32_be(&buf[32..]),
            end_date_ms: u64::from(read_u32_be(&buf[36..])) * 1000,
        })
    }

    /// Пишет `Lease` в формате `LeaseSet2` (type 3/5/7) — 40 байт.
    ///
    /// `end_date_ms` делится на 1000 (округление вниз). Если результат
    /// не влезает в `u32` (год > ~2106), пишется `u32::MAX` — i2pd
    /// ведёт себя так же.
    #[must_use]
    pub fn to_buffer_ls2(&self) -> [u8; LEASE2_SIZE] {
        let secs = self.end_date_ms / 1000;
        let secs_u32 = u32::try_from(secs).unwrap_or(u32::MAX);
        let mut out = [0u8; LEASE2_SIZE];
        out[0..32].copy_from_slice(self.tunnel_gateway.as_bytes());
        write_u32_be(&mut out[32..], self.tunnel_id);
        write_u32_be(&mut out[36..], secs_u32);
        out
    }
}

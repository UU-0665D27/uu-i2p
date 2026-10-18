//! Список забаненных адресов транспорта (i2pd `Transports::IsBanned` /
//! `Transports::AddBan`, `libi2pd/Transports.cpp:1470`).
//!
//! Один список на все транспорты: пул проверяет его при приёме нового
//! подключения (до всякой криптографии) и добавляет адрес, когда
//! собеседник доказал несоответствие — например, `s` в присланном
//! `RouterInfo` не совпал с ключом, которым шла рукопожатие
//! (i2pd `SSU2Session::ProcessSessionConfirmed` рядом с
//! `AddBan (m_RemoteEndpoint.address ())`).
//!
//! Швы: список — [`BanList`] под `Arc`, шарится между пулами; баним и
//! проверяем по точному адресу (`IpAddr`), как i2pd (`IsBanned`
//! вызывается с адресом собеседника, без приведения к сети).
//!
//! Время — миллисекунды unix-эпохи; просроченные записи убираются лениво
//! при обращении (i2pd держит `std::map` и чистит запись прямо в
//! `IsBanned`).
//!
//! `// TODO(ban):` в `InetAddress`-варианте i2pd бан смотрит и на порт? —
//! нет, только адрес; порт в списке не участвует.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, MutexGuard},
};

/// Базовая длительность бана, как i2pd `IP_BAN_TIME`
/// (`libi2pd/Transports.h:130`) — 1800 секунд.
pub const IP_BAN_TIME_MS: u64 = 1800 * 1000;

/// Разброс длительности бана, как i2pd `IP_BAN_TIME_VARIANCE`
/// (`libi2pd/Transports.h:131`) — до 540 секунд сверху.
pub const IP_BAN_TIME_VARIANCE_MS: u64 = 540 * 1000;

/// Адреса, которым запрещено подключаться до указанного момента.
///
/// Записи живут до `until_ms`; `is_banned` убирает просроченные.
#[derive(Debug, Default)]
pub struct BanList {
    banned: Mutex<HashMap<IpAddr, u64>>,
}

impl BanList {
    /// Пустой список.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Забанен ли `ip` на момент `now_ms`.
    ///
    /// Просроченная запись удаляется (i2pd делает то же самое в
    /// `IsBanned`).
    #[must_use]
    pub fn is_banned(&self, ip: IpAddr, now_ms: u64) -> bool {
        let mut banned = lock(&self.banned);
        match banned.get(&ip) {
            Some(&until) if until > now_ms => true,
            Some(_) => {
                banned.remove(&ip);
                false
            }
            None => false,
        }
    }

    /// Банит `ip` на `IP_BAN_TIME_MS` + случайный разброс.
    ///
    /// `false` — адрес уже в списке (i2pd `AddBan` возвращает результат
    /// `emplace`).
    pub fn ban(&self, ip: IpAddr, now_ms: u64) -> bool {
        let variance = if IP_BAN_TIME_VARIANCE_MS == 0 {
            0
        } else {
            rand::random::<u64>() % IP_BAN_TIME_VARIANCE_MS
        };
        let until = now_ms
            .saturating_add(IP_BAN_TIME_MS)
            .saturating_add(variance);
        lock(&self.banned).insert(ip, until).is_none()
    }

    /// Сколько адресов в списке (включая просроченные).
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.banned).len()
    }

    /// Пуст ли список.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.banned).is_empty()
    }

    /// Чистит список (тесты, ручное снятие бана).
    pub fn clear(&self) {
        lock(&self.banned).clear();
    }
}

/// Блокировка без паники при отравлении.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

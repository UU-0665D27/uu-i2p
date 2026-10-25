//! SSU2 — токены (`SSU2Server` в i2pd).
//!
//! Токен защищает `SessionRequest` от подделки адреса: сервер (Bob) выдаёт
//! случайный 64-битный токен в пакете `Retry` (или блоком `New Token`), а
//! клиент (Alice) обязан предъявить его в следующем `SessionRequest`.
//! Хранилище держит два отображения «адрес-источник → токен»:
//!
//! - **входящие** (`m_IncomingTokens`) — то, что выдаёт наш сервер;
//! - **исходящие** (`m_OutgoingTokens`) — то, что мы получили от чужих
//!   серверов и предъявляем сами.
//!
//! Зеркалит `SSU2Server::GetIncomingToken` (`SSU2.cpp:1259`),
//! `NewIncomingToken` (`:1277`), `UpdateOutgoingToken` (`:1238`),
//! `FindOutgoingToken` (`:1243`) и чистку в `SSU2.cpp:1160`.
//!
//! ## Сроки жизни
//!
//! - токен из `Retry` живёт [`SSU2_TOKEN_EXPIRATION_TIMEOUT`] секунд;
//! - токен из блока `New Token` живёт [`SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT`]
//!   секунд (с запасом, чтобы клиент успел им воспользоваться позже);
//! - за [`SSU2_TOKEN_EXPIRATION_THRESHOLD`] секунд до истечения токен уже
//!   «не найден» (и входящий при запросе перевыпускается, и исходящий
//!   считается протухшим), чтобы пакет не пришёл к серверу ровно к моменту
//!   истечения.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::ssu2_send::RandomSource;

/// Срок жизни токена из `Retry` (`SSU2_TOKEN_EXPIRATION_TIMEOUT`).
pub const SSU2_TOKEN_EXPIRATION_TIMEOUT: u32 = 9;

/// Срок жизни токена из блока `New Token`
/// (`SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT`).
pub const SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT: u32 = 52 * 60;

/// «Мёртвая зона» до истечения (`SSU2_TOKEN_EXPIRATION_THRESHOLD`).
pub const SSU2_TOKEN_EXPIRATION_THRESHOLD: u32 = 2;

/// Источник случайных токенов (в i2pd — `RAND_bytes`).
///
/// Реализован по умолчанию для любого [`RandomSource`], поэтому отдельно
/// заводить источник не нужно.
pub trait TokenSource {
    /// Следующее 64-битное значение. Ноль допустим: хранилище заменит его
    /// на единицу (как `if (!token) token = 1` в i2pd).
    fn next_token(&mut self) -> u64;
}

impl<R: RandomSource> TokenSource for R {
    fn next_token(&mut self) -> u64 {
        u64::from(self.roll()) | (u64::from(self.roll()) << 32)
    }
}

/// Токен и время его истечения (секунды Unix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// Значение токена (никогда не ноль).
    pub value: u64,
    /// Время истечения в секундах Unix.
    pub expires: u32,
}

/// Хранилище токенов по адресам (входящие и исходящие).
#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    incoming: BTreeMap<SocketAddr, Token>,
    outgoing: BTreeMap<SocketAddr, Token>,
}

impl TokenStore {
    /// Пустое хранилище.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `GetIncomingToken`: действующий входящий токен адреса, иначе — новый.
    ///
    /// Просроченный токен (или тот, которому осталось меньше
    /// [`SSU2_TOKEN_EXPIRATION_THRESHOLD`]) перевыпускается.
    pub fn incoming_token<R: TokenSource>(
        &mut self,
        remote: SocketAddr,
        now: u32,
        rng: &mut R,
    ) -> u64 {
        if let Some(token) = self.incoming.get(&remote) {
            if now.saturating_add(SSU2_TOKEN_EXPIRATION_THRESHOLD) <= token.expires {
                return token.value;
            }
            self.incoming.remove(&remote);
        }
        let value = non_zero(rng);
        self.incoming.insert(
            remote,
            Token {
                value,
                expires: now.saturating_add(SSU2_TOKEN_EXPIRATION_TIMEOUT),
            },
        );
        value
    }

    /// `NewIncomingToken`: новый входящий токен с длинным сроком жизни.
    ///
    /// Значение всегда перезаписывается (в i2pd `try_emplace` + `override`).
    pub fn new_incoming_token<R: TokenSource>(
        &mut self,
        remote: SocketAddr,
        now: u32,
        rng: &mut R,
    ) -> Token {
        let token = Token {
            value: non_zero(rng),
            expires: now.saturating_add(SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT),
        };
        self.incoming.insert(remote, token);
        token
    }

    /// `UpdateOutgoingToken`: запомнить токен чужого сервера.
    pub fn update_outgoing_token(&mut self, remote: SocketAddr, token: Token) {
        self.outgoing.insert(remote, token);
    }

    /// `FindOutgoingToken`: токен для адреса, если он ещё годен.
    ///
    /// Протухший (или близкий к истечению) токен удаляется и не возвращается.
    pub fn find_outgoing_token(&mut self, remote: SocketAddr, now: u32) -> Option<u64> {
        let token = *self.outgoing.get(&remote)?;
        if now.saturating_add(SSU2_TOKEN_EXPIRATION_THRESHOLD) > token.expires {
            self.outgoing.remove(&remote);
            return None;
        }
        Some(token.value)
    }

    /// Удаляет просроченные токены (i2pd чистит их по таймеру).
    pub fn cleanup(&mut self, now: u32) {
        self.incoming.retain(|_, token| now <= token.expires);
        self.outgoing.retain(|_, token| now <= token.expires);
    }

    /// Сколько входящих токенов помним.
    #[must_use]
    pub const fn incoming_len(&self) -> usize {
        self.incoming.len()
    }

    /// Сколько исходящих токенов помним.
    #[must_use]
    pub const fn outgoing_len(&self) -> usize {
        self.outgoing.len()
    }

    /// Входящий токен адреса «как есть» (без перевыпуска) — для тестов и
    /// сопоставления с предъявленным.
    #[must_use]
    pub fn peek_incoming(&self, remote: SocketAddr) -> Option<Token> {
        self.incoming.get(&remote).copied()
    }

    /// Исходящий токен адреса «как есть».
    #[must_use]
    pub fn peek_outgoing(&self, remote: SocketAddr) -> Option<Token> {
        self.outgoing.get(&remote).copied()
    }
}

/// Токен никогда не ноль (i2pd: `if (!token) token = 1`).
fn non_zero<R: TokenSource>(rng: &mut R) -> u64 {
    let token = rng.next_token();
    if token == 0 { 1 } else { token }
}

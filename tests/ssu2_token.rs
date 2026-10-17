//! Тесты хранилища токенов SSU2 ([`uu_i2p::ssu2_token`]).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use uu_i2p::ssu2_send::RandomSource;
use uu_i2p::ssu2_token::{
    SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT, SSU2_TOKEN_EXPIRATION_THRESHOLD,
    SSU2_TOKEN_EXPIRATION_TIMEOUT, Token, TokenSource, TokenStore,
};

/// Источник «случайных» токенов: детерминированная последовательность.
struct Seq(u64);

impl RandomSource for Seq {
    fn roll(&mut self) -> u32 {
        let low = u32::try_from(self.0 & 0xffff_ffff).unwrap_or_default();
        self.0 = self.0.wrapping_add(1);
        low
    }
}

/// Источник, всегда выдающий ноль (проверяем подмену на единицу).
struct Zero;

impl RandomSource for Zero {
    fn roll(&mut self) -> u32 {
        0
    }
}

/// Источник с постоянным значением (проверяем ширину токена).
struct Const(u32);

impl RandomSource for Const {
    fn roll(&mut self) -> u32 {
        self.0
    }
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

const T0: u32 = 1_700_000_000;

#[test]
fn incoming_token_is_issued_once_and_reused() {
    let mut store = TokenStore::new();
    let mut rng = Seq(0x0102_0304);
    let first = store.incoming_token(addr(1), T0, &mut rng);
    assert_ne!(first, 0);
    assert_eq!(store.incoming_len(), 1);
    // Пока токен годен — тот же.
    let again = store.incoming_token(addr(1), T0 + 1, &mut rng);
    assert_eq!(again, first);
}

#[test]
fn incoming_token_is_rotated_when_nearly_expired() {
    let mut store = TokenStore::new();
    let mut rng = Seq(0x0102_0304);
    let first = store.incoming_token(addr(1), T0, &mut rng);
    // Срок — 9 с; за 2 с до конца (и позже) токен перевыпускается.
    let near = T0 + SSU2_TOKEN_EXPIRATION_TIMEOUT - SSU2_TOKEN_EXPIRATION_THRESHOLD + 1;
    let second = store.incoming_token(addr(1), near, &mut rng);
    assert_ne!(second, first);
    assert_eq!(store.incoming_len(), 1);
}

#[test]
fn incoming_token_expires_at_timeout() {
    let mut store = TokenStore::new();
    let mut rng = Seq(7);
    let first = store.incoming_token(addr(1), T0, &mut rng);
    let expired = T0 + SSU2_TOKEN_EXPIRATION_TIMEOUT + 1;
    let second = store.incoming_token(addr(1), expired, &mut rng);
    assert_ne!(second, first);
    assert_eq!(
        store.peek_incoming(addr(1)).expect("token").expires,
        expired + SSU2_TOKEN_EXPIRATION_TIMEOUT
    );
}

#[test]
fn new_incoming_token_overrides_and_lives_long() {
    let mut store = TokenStore::new();
    let mut rng = Seq(11);
    let short = store.incoming_token(addr(1), T0, &mut rng);
    let long = store.new_incoming_token(addr(1), T0, &mut rng);
    assert_ne!(long.value, short);
    assert_eq!(
        long.expires,
        T0 + SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT,
        "длинный срок жизни"
    );
    assert_eq!(store.peek_incoming(addr(1)), Some(long));
    // Через минуту long-токен всё ещё действует и не перевыпускается.
    assert_eq!(store.incoming_token(addr(1), T0 + 60, &mut rng), long.value);
}

#[test]
fn outgoing_token_roundtrip_and_expiry() {
    let mut store = TokenStore::new();
    assert_eq!(store.find_outgoing_token(addr(2), T0), None);
    store.update_outgoing_token(
        addr(2),
        Token {
            value: 0xabcd_ef01,
            expires: T0 + 100,
        },
    );
    assert_eq!(store.find_outgoing_token(addr(2), T0), Some(0xabcd_ef01));
    // За 2 с до истечения токен уже не годится и удаляется.
    let near = T0 + 100 - SSU2_TOKEN_EXPIRATION_THRESHOLD + 1;
    assert_eq!(store.find_outgoing_token(addr(2), near), None);
    assert_eq!(store.outgoing_len(), 0);
}

#[test]
fn cleanup_removes_expired() {
    let mut store = TokenStore::new();
    let mut rng = Seq(3);
    let _ = store.incoming_token(addr(1), T0, &mut rng);
    store.update_outgoing_token(
        addr(2),
        Token {
            value: 5,
            expires: T0 + 4,
        },
    );
    store.cleanup(T0 + 4);
    assert_eq!(store.incoming_len(), 1, "ровно в срок ещё помним");
    assert_eq!(store.outgoing_len(), 1);
    // Исходящий истёк (T0+4), входящий ещё живёт (T0+9).
    store.cleanup(T0 + 5);
    assert_eq!(store.incoming_len(), 1);
    assert_eq!(store.outgoing_len(), 0);
    store.cleanup(T0 + SSU2_TOKEN_EXPIRATION_TIMEOUT);
    assert_eq!(store.incoming_len(), 1, "ровно в срок ещё помним");
    store.cleanup(T0 + SSU2_TOKEN_EXPIRATION_TIMEOUT + 1);
    assert_eq!(store.incoming_len(), 0);
}

#[test]
fn zero_token_becomes_one() {
    let mut store = TokenStore::new();
    let token = store.incoming_token(addr(1), T0, &mut Zero);
    assert_eq!(token, 1);
}

#[test]
fn tokens_are_per_endpoint() {
    let mut store = TokenStore::new();
    let mut rng = Seq(0x1000_0000);
    let a = store.incoming_token(addr(1), T0, &mut rng);
    let b = store.incoming_token(addr(2), T0, &mut rng);
    assert_ne!(a, b);
    assert_eq!(store.incoming_len(), 2);
    assert_eq!(store.peek_incoming(addr(1)).expect("a").value, a);
    assert_eq!(store.peek_incoming(addr(2)).expect("b").value, b);
}

#[test]
fn token_source_is_wide() {
    // Значение шире 32 бит: два `roll()` склеиваются в u64.
    let mut rng = Const(0xdead_beef);
    let token = rng.next_token();
    assert!(token > u64::from(u32::MAX));
    assert_eq!(token, 0xdead_beef_dead_beef);
}

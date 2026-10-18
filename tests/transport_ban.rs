//! Тесты списка банов транспорта ([`uu_i2p::BanList`]).

use std::net::{IpAddr, Ipv4Addr};

use uu_i2p::{BanList, IP_BAN_TIME_MS, IP_BAN_TIME_VARIANCE_MS};

const NOW_MS: u64 = 1_700_000_000_000;

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
}

#[test]
fn unknown_address_is_not_banned() {
    let list = BanList::new();
    assert!(list.is_empty());
    assert!(!list.is_banned(ip(1), NOW_MS));
    assert_eq!(list.len(), 0);
}

#[test]
fn banned_address_is_banned_until_it_expires() {
    let list = BanList::new();
    assert!(list.ban(ip(1), NOW_MS), "первый бан ставится");
    assert!(list.is_banned(ip(1), NOW_MS));
    assert!(!list.is_banned(ip(2), NOW_MS), "соседний адрес не задет");
    assert_eq!(list.len(), 1);
}

#[test]
fn repeated_ban_reports_no_change() {
    let list = BanList::new();
    assert!(list.ban(ip(1), NOW_MS));
    assert!(!list.ban(ip(1), NOW_MS), "адрес уже в списке");
    assert_eq!(list.len(), 1);
}

#[test]
fn expired_ban_is_forgotten_lazily() {
    let list = BanList::new();
    list.ban(ip(1), NOW_MS);
    // Максимальный срок бана: база + разброс.
    let until = NOW_MS + IP_BAN_TIME_MS + IP_BAN_TIME_VARIANCE_MS;
    assert!(
        !list.is_banned(ip(1), until + 1),
        "просроченный бан не держит"
    );
    assert_eq!(list.len(), 0, "просроченная запись убрана при проверке");
}

#[test]
fn clear_empties_the_list() {
    let list = BanList::new();
    list.ban(ip(1), NOW_MS);
    list.ban(ip(2), NOW_MS);
    assert_eq!(list.len(), 2);
    list.clear();
    assert!(list.is_empty());
    assert!(!list.is_banned(ip(1), NOW_MS));
}

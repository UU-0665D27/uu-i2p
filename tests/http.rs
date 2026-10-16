//! Тесты для `http.rs` — обёрток над `httparse`/`http`/`url`.
//!
//! Парсинг и сериализация сами по себе тестируются в крейтах;
//! здесь — i2p-специфичные хелперы и поведение обёрток.

use url::Url;
use uu_i2p::http::{
    HttpError, create_basic_authorization_string, is_chunked, is_gzipped, is_i2p_host,
    parse_request, parse_response, serialize_request, serialize_response, url_decode,
};

// --- parse_request -------------------------------------------------------

#[test]
fn request_minimal() {
    let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (req, n) = parse_request(raw).unwrap().unwrap();
    assert_eq!(n, raw.len());
    assert_eq!(req.method(), "GET");
    assert_eq!(req.uri().path(), "/");
    assert_eq!(req.headers().get("Host").unwrap(), "example.com");
}

#[test]
fn request_incomplete() {
    let raw = b"GET / HTTP/1.1\r\nHost: exa";
    assert!(parse_request(raw).unwrap().is_none());
}

#[test]
fn request_malformed() {
    // `httparse` не примет такой request-line.
    let raw = b"GET\r\n\r\n";
    assert!(matches!(parse_request(raw), Err(HttpError::Malformed(_))));
}

#[test]
fn request_http10_version_preserved() {
    let raw = b"GET / HTTP/1.0\r\n\r\n";
    let (req, _) = parse_request(raw).unwrap().unwrap();
    assert_eq!(req.version(), http::Version::HTTP_10);
}

#[test]
fn request_duplicate_headers_all_preserved() {
    let raw = b"GET / HTTP/1.1\r\nX-A: 1\r\nX-A: 2\r\n\r\n";
    let (req, _) = parse_request(raw).unwrap().unwrap();

    let mut iter = req.headers().get_all("X-A").iter();
    assert_eq!(iter.next().unwrap(), "1");
    assert_eq!(iter.next().unwrap(), "2");
    assert!(iter.next().is_none(), "expected exactly two X-A headers");
}

// --- parse_response ------------------------------------------------------

#[test]
fn response_minimal() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    let (res, n) = parse_response(raw).unwrap().unwrap();
    assert_eq!(n, raw.len());
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers().get("Content-Length").unwrap(), "5");
}

#[test]
fn response_incomplete() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-";
    assert!(parse_response(raw).unwrap().is_none());
}

#[test]
fn response_code_below_100_is_error() {
    // httparse разбирает ровно три цифры, `099` даёт число 99.
    // `StatusCode::from_u16(99)` отвергает: 99 < 100.
    let raw = b"HTTP/1.1 099 OK\r\n\r\n";
    assert!(matches!(parse_response(raw), Err(HttpError::Malformed(_))));
}

#[test]
fn response_unregistered_code_is_accepted() {
    // 999 — валидный (хотя и нераспределённый) код по RFC 7230.
    // `http::StatusCode` его принимает, reason-phrase берётся
    // из status-line как есть.
    let raw = b"HTTP/1.1 999 Whatever\r\n\r\n";
    let (res, _) = parse_response(raw).unwrap().unwrap();
    assert_eq!(res.status().as_u16(), 999);
    assert!(res.status().canonical_reason().is_none());
}

// --- serialize -----------------------------------------------------------

#[test]
fn request_roundtrip() {
    let raw = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (req, _) = parse_request(raw).unwrap().unwrap();
    let serialized = serialize_request(&req);
    let (req2, _) = parse_request(&serialized).unwrap().unwrap();
    assert_eq!(req2.method(), req.method());
    assert_eq!(req2.uri(), req.uri());
    assert_eq!(req2.headers().get("Host"), req.headers().get("Host"),);
}

#[test]
fn response_roundtrip() {
    let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let (res, _) = parse_response(raw).unwrap().unwrap();
    let serialized = serialize_response(&res);
    let (res2, _) = parse_response(&serialized).unwrap().unwrap();
    assert_eq!(res2.status(), res.status());
}

// --- url_decode ----------------------------------------------------------

#[test]
fn url_decode_plain() {
    assert_eq!(url_decode("hello", false), "hello");
}

#[test]
fn url_decode_basic() {
    assert_eq!(url_decode("hello%20world", false), "hello world");
}

#[test]
fn url_decode_utf8() {
    let encoded = "%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82";
    assert_eq!(url_decode(encoded, false), "привет");
}

#[test]
fn url_decode_null_disallowed() {
    // `%00` остаётся как три символа.
    assert_eq!(url_decode("a%00b", false), "a%00b");
}

#[test]
fn url_decode_null_allowed() {
    let out = url_decode("a%00b", true);
    assert_eq!(out.as_bytes(), b"a\x00b");
}

#[test]
fn url_decode_mixed() {
    // `%41` → 'A', `%00` остаётся, `%20` → ' '.
    assert_eq!(url_decode("%41%00%20", false), "A%00 ");
}

// --- basic auth ----------------------------------------------------------

#[test]
fn basic_auth_basic() {
    let s = create_basic_authorization_string("alice", "secret");
    assert_eq!(s, "Basic YWxpY2U6c2VjcmV0");
}

#[test]
fn basic_auth_empty() {
    assert_eq!(create_basic_authorization_string("", ""), "");
}

// --- is_i2p_host ---------------------------------------------------------

#[test]
fn is_i2p_host_yes() {
    let u = Url::parse("http://foo.i2p/x").unwrap();
    assert!(is_i2p_host(&u));
}

#[test]
fn is_i2p_host_no() {
    let u = Url::parse("http://example.com/x").unwrap();
    assert!(!is_i2p_host(&u));
}

#[test]
fn is_i2p_host_subdomain() {
    let u = Url::parse("http://a.b.c.i2p/x").unwrap();
    assert!(is_i2p_host(&u));
}

// --- is_chunked / is_gzipped ---------------------------------------------

#[test]
fn chunked_detection() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let (res, _) = parse_response(raw).unwrap().unwrap();
    assert!(is_chunked(res.headers()));
}

#[test]
fn chunked_case_insensitive() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n";
    let (res, _) = parse_response(raw).unwrap().unwrap();
    assert!(is_chunked(res.headers()));
}

#[test]
fn not_chunked() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (res, _) = parse_response(raw).unwrap().unwrap();
    assert!(!is_chunked(res.headers()));
}

#[test]
fn gzip_detection() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
    let (res, _) = parse_response(raw).unwrap().unwrap();
    assert!(is_gzipped(res.headers(), false));
    assert!(is_gzipped(res.headers(), true));
}

#[test]
fn i2p_gzip_only_with_flag() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Encoding: x-i2p-gzip\r\n\r\n";
    let (res, _) = parse_response(raw).unwrap().unwrap();
    assert!(!is_gzipped(res.headers(), false));
    assert!(is_gzipped(res.headers(), true));
}

// --- Url (from `url` crate) ---------------------------------------------

#[test]
fn url_parses_i2p_with_port() {
    let u = Url::parse("http://foo.i2p:8080/x?y=1").unwrap();
    assert_eq!(u.host_str(), Some("foo.i2p"));
    assert_eq!(u.port(), Some(8080));
    assert_eq!(u.path(), "/x");
    assert_eq!(u.query(), Some("y=1"));
}

#[test]
fn url_parses_ipv6() {
    let u = Url::parse("http://[::1]:8080/").unwrap();
    assert_eq!(u.host_str(), Some("[::1]"));
    assert_eq!(u.port(), Some(8080));
}

#[test]
fn url_relative_without_base_fails() {
    // `url::Url` не парсит relative URL без base — это фича, а не баг.
    // Для request-target (origin-form) caller работает с `http::Uri`,
    // который relative принимает.
    assert!(Url::parse("/path?q=1").is_err());
}

#[test]
fn uri_from_http_crate_accepts_relative() {
    // Дополняем `Url` там, где нужен relative.
    let uri: http::Uri = "/path?q=1".parse().unwrap();
    assert_eq!(uri.path(), "/path");
    assert_eq!(uri.query(), Some("q=1"));
}

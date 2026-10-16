//! HTTP-примитивы для reseed и webconsole.
//!
//! Парсинг — на [`httparse`], представление — на [`http`],
//! URL — на [`url`], percent-декодирование — на
//! [`percent_encoding`]. Своими руками только:
//!
//! - i2p-специфичные хелперы ([`url_decode`] с флагом `allow_null`,
//!   [`create_basic_authorization_string`], [`is_i2p_host`]);
//! - сериализация запросов и ответов (несколько `push_str`);
//! - тонкие обёртки [`parse_request`] / [`parse_response`],
//!   превращающие `httparse`-результат в `http::Request`/`Response`.
//!
//! Соответствует `HTTP.cpp` / `HTTP.h` в i2pd по семантике,
//! но не по внутреннему устройству.
//!
//! ## Что НЕ реализовано
//!
//! - `MergeChunkedResponse` — I/O, отдельный слой.
//! - RFC 7231 `Date` — требует форматирования GMT-времени,
//!   добавим когда понадобится.

pub use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
pub use url::Url;

use std::fmt;

// --- ошибки --------------------------------------------------------------

/// Ошибка разбора HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// Синтаксическая ошибка в request/status line или в заголовках.
    Malformed(String),
    /// Заголовок или URI не проходит валидацию `http` crate.
    BadHeader(String),
    /// Невалидный URL.
    BadUrl(String),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed HTTP: {m}"),
            Self::BadHeader(m) => write!(f, "bad header: {m}"),
            Self::BadUrl(m) => write!(f, "bad URL: {m}"),
        }
    }
}

impl std::error::Error for HttpError {}

// --- парсинг -------------------------------------------------------------

/// Разбирает HTTP-запрос из буфера.
///
/// - `Ok(Some((req, n)))` — заголовки разобраны, `n` — их длина
///   в байтах (включая `\r\n\r\n`); тело начинается с `buf[n..]`.
/// - `Ok(None)` — данных не хватает, читай ещё.
/// - `Err(_)` — синтаксическая ошибка.
///
/// Тело запроса не читается — этим занимается caller по
/// `Content-Length` / `Transfer-Encoding`.
///
/// # Errors
///
/// [`HttpError::Malformed`] — `httparse` отверг ввод;
/// [`HttpError::BadHeader`] — заголовок не влезает в `http::HeaderName`
/// или `http::HeaderValue`.
pub fn parse_request(buf: &[u8]) -> Result<Option<(Request<()>, usize)>, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            let method = req
                .method
                .ok_or_else(|| HttpError::Malformed("missing method".into()))?;
            let path = req
                .path
                .ok_or_else(|| HttpError::Malformed("missing path".into()))?;
            let version = req.version;

            let mut builder = Request::builder()
                .method(
                    Method::from_bytes(method.as_bytes())
                        .map_err(|_| HttpError::Malformed(format!("bad method {method}")))?,
                )
                .uri(path);

            // `http::Request` не хранит версию как поле — она часть
            // `Version` в extensions. Складываем её в extensions,
            // чтобы `serialize_request` мог восстановить.
            if version == Some(0) {
                builder = builder.version(http::Version::HTTP_10);
            } else {
                builder = builder.version(http::Version::HTTP_11);
            }

            let mut request = builder
                .body(())
                .map_err(|e| HttpError::Malformed(e.to_string()))?;

            for h in req.headers {
                let name = HeaderName::from_bytes(h.name.as_bytes())
                    .map_err(|e| HttpError::BadHeader(e.to_string()))?;
                let value = HeaderValue::from_bytes(h.value)
                    .map_err(|e| HttpError::BadHeader(e.to_string()))?;
                request.headers_mut().append(name, value);
            }

            Ok(Some((request, n)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(HttpError::Malformed(e.to_string())),
    }
}

/// Разбирает HTTP-ответ из буфера.
///
/// Семантика как у [`parse_request`].
///
/// # Errors
///
/// См. [`parse_request`].
pub fn parse_response(buf: &[u8]) -> Result<Option<(Response<()>, usize)>, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut res = httparse::Response::new(&mut headers);

    match res.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            let code = res
                .code
                .ok_or_else(|| HttpError::Malformed("missing status code".into()))?;
            let version = res.version;

            let status =
                StatusCode::from_u16(code).map_err(|e| HttpError::Malformed(e.to_string()))?;

            let mut builder = Response::builder().status(status);
            if version == Some(0) {
                builder = builder.version(http::Version::HTTP_10);
            } else {
                builder = builder.version(http::Version::HTTP_11);
            }

            let mut response = builder
                .body(())
                .map_err(|e| HttpError::Malformed(e.to_string()))?;

            for h in res.headers {
                let name = HeaderName::from_bytes(h.name.as_bytes())
                    .map_err(|e| HttpError::BadHeader(e.to_string()))?;
                let value = HeaderValue::from_bytes(h.value)
                    .map_err(|e| HttpError::BadHeader(e.to_string()))?;
                response.headers_mut().append(name, value);
            }

            Ok(Some((response, n)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(HttpError::Malformed(e.to_string())),
    }
}

// --- сериализация --------------------------------------------------------

/// Сериализует запрос (заголовочная часть; тело caller
/// дописывает сам).
///
/// # Panics
///
/// Паникует только если `req` собран вручную с заведомо невалидным
/// URI — этого не бывает при разборе через [`parse_request`] или
/// сборке через [`Request::builder`] с проверенным URI.
#[must_use]
pub fn serialize_request(req: &Request<()>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let version = match req.version() {
        http::Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };
    out.extend_from_slice(req.method().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.uri().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(b"\r\n");

    for (name, value) in req.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Сериализует ответ (заголовочная часть).
///
/// `Date` **не** добавляется — это отложено. `Content-Length`
/// caller выставляет сам, положив его в `res.headers()`.
#[must_use]
pub fn serialize_response(res: &Response<()>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let version = match res.version() {
        http::Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };
    let code = res.status().as_u16();
    let reason = res.status().canonical_reason().unwrap_or("Unknown Status");
    out.extend_from_slice(version.as_bytes());
    out.push(b' ');
    out.extend_from_slice(code.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    out.extend_from_slice(b"\r\n");

    for (name, value) in res.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

// --- i2p-специфичные хелперы --------------------------------------------

/// `%XX` → байт. i2p-совместимо: при `allow_null == false`
/// последовательность `%00` **не** раскодируется, остаётся
/// как три символа.
///
/// Всё остальное — `percent_encoding::percent_decode_str`.
#[must_use]
pub fn url_decode(s: &str, allow_null: bool) -> String {
    if allow_null {
        return percent_encoding::percent_decode_str(s)
            .decode_utf8_lossy()
            .into_owned();
    }
    // Особый случай: `%00` не декодируем. Обходим `percent_encoding`
    // только по этому паттерну, остальное отдаём крейту.
    if !s.as_bytes().windows(3).any(|w| w == b"%00") {
        // Быстрый путь — нет `%00`, значит поведение крейта
        // совпадает с i2p.
        return percent_encoding::percent_decode_str(s)
            .decode_utf8_lossy()
            .into_owned();
    }

    // Медленный путь: посимвольно, `%00` оставляем как есть.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() && bytes[i + 1] == b'0' && bytes[i + 2] == b'0' {
            out.extend_from_slice(b"%00");
            i += 3;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i..i + 3];
            match percent_encoding::percent_decode_str(hex).next() {
                Some(b) if b != 0 => {
                    out.push(b);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `Basic base64(user:pass)`. Пустые `user` и `pass` → пустая строка
/// (как i2pd: не генерирует заголовок для анонимного доступа).
#[must_use]
pub fn create_basic_authorization_string(user: &str, pass: &str) -> String {
    if user.is_empty() && pass.is_empty() {
        return String::new();
    }
    let credentials = format!("{user}:{pass}");
    let encoded = crate::base64::encode(credentials.as_bytes());
    format!("Basic {encoded}")
}

/// Заканчивается ли host URL на `.i2p`.
///
/// Проверка регистрозависимая: I2P-хостнеймы (`foo.i2p`,
/// `xxxxx.b32.i2p`) по конвенции lowercase, и i2pd тоже сравнивает
/// без case-fold'а (`URL::is_i2p`: `rfind(".i2p") == size - 4`).
#[must_use]
pub fn is_i2p_host(url: &Url) -> bool {
    url.host_str().is_some_and(|h| {
        h.rsplit_once('.')
            .is_some_and(|(_, suffix)| suffix == "i2p")
    })
}

/// `true`, если заголовок `Transfer-Encoding` содержит `chunked`
/// (регистронезависимо).
#[must_use]
pub fn is_chunked(headers: &HeaderMap) -> bool {
    headers
        .get("Transfer-Encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
}

/// `true`, если `Content-Encoding` содержит `gzip` (или `x-i2p-gzip`
/// при `including_i2p_gzip == true`).
///
/// `Content-Encoding` — список кодировок через запятую, применяемых
/// по порядку. Разбираем по токенам, а не ищем подстроку: `x-i2p-gzip`
/// **не** является стандартным gzip — он требует снять 2-байтовый
/// префикс длины до подачи в zlib. В i2pd здесь баг (`find("gzip")`
/// матчит `x-i2p-gzip`), мы его сознательно не повторяем.
#[must_use]
pub fn is_gzipped(headers: &HeaderMap, including_i2p_gzip: bool) -> bool {
    let Some(v) = headers
        .get("Content-Encoding")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let v = v.to_ascii_lowercase();
    for token in v.split(',') {
        let t = token.trim();
        if t == "gzip" {
            return true;
        }
        if including_i2p_gzip && t == "x-i2p-gzip" {
            return true;
        }
    }
    false
}

# Баги и уязвимости в самом i2pd

Список находок по коду i2pd (не по нашему порту). Референс-клон для разбора:
`/home/u_uu/FOR_LLM/libi2pd` (i2pd, HEAD `7ab983ac`). Нумерация — сквозная,
чтобы на неё ссылаться из коммитов и заметок.

Для каждой находки: что именно, где, как воспроизводится, чем грозит и в каком
фиксе (если есть) i2pd это починил.

---

## 1. ECIES-X25519: null-deref в `HandleNextKey` (remote crash)

- Файл: `ECIESX25519AEADRatchetSession.cpp`, `HandleNextKey` (forward-ветка).
- До фикса `m_NextReceiveRatchet->key` не проверялся, и код делал
  `m_NextReceiveRatchet->key->Agree(...)` при `key == nullptr` → SEGV в
  `i2p::crypto::X25519Keys::Agree` (`Crypto.cpp:319`).
- Триггер: established-сессия + garlic-блок `NextKey` c `flag` без
  `REVERSE_KEY_FLAG` и без `REQUEST_REVERSE_KEY_FLAG` (`newKey == false`) при
  пустом ключе свежесозданного `DHRatchet`.
- Последствие: детерминированный remote-crash роутера/дестинейшена.
- Фикс: `e5621949` — «chech ratchets payload size and key».
- Разбор: `notes/ecies-nextkey-vuln.md`.

## 2. ECIES-X25519: OOB-чтение в `HandlePayload` (усечённый заголовок блока)

- Файл: `ECIESX25519AEADRatchetSession.cpp`, `HandlePayload`.
- `while (offset < len)` при 1–2 байтах хвоста payload читает `size` за концом
  буфера (`bufbe16toh (buf + offset)`).
- Последствие: OOB-read (утечка/креш под ASan; сам по себе minor).
- Фикс: `cc77898b` — «check the whole block header fits before reading block
  size in ratchets payload» (плюс `if (len < 3) return;` из `e5621949`).

## 3. SSU2: троттлинг переотправки не работает (`Resend`)

- Файл: `SSU2Session.cpp:616`, `SSU2Session::Resend`.
- Код:
  ```cpp
  if (ts + SSU2_RESEND_ATTEMPT_MIN_INTERVAL < m_LastResendAttemptTime) return 0;
  m_LastResendAttemptTime = ts;
  ```
  `m_LastResendAttemptTime` инициализируется нулём и всегда равен `ts`
  предыдущего вызова, а `ts` монотонно растёт. Условие «предыдущая попытка
  больше чем на 3 мс в будущем» практически недостижимо, поэтому лимит
  `SSU2_RESEND_ATTEMPT_MIN_INTERVAL` (3 мс) никогда не срабатывает.
- Очевидно задумывалось наоборот: `ts < m_LastResendAttemptTime +
  SSU2_RESEND_ATTEMPT_MIN_INTERVAL` → `return 0`.
- Последствие: `Resend` можно вызвать сколько угодно часто; сам лимит
  задумывался против шторма переотправок. Не security, но логическая ошибка.
- Статус: в локальном клоне (`7ab983ac`) не исправлено.
- У нас: решение вынесено в `Ssu2Policy::can_attempt_resend`
  (`src/ssu2_policy.rs`), дефолт воспроизводит фактическое поведение i2pd
  (троттлинга нет); исправленный вариант — своя реализация трейта. Тик
  переотправки — `SessionTimers::resend_step` (`src/ssu2_timers.rs`).

## 4. `std::string_view`: assert при подсчёте длины — точка DoS

- `std::string_view::substr (pos, ...)` требует `pos <= size()`: иначе в
  libstdc++ бросается `std::out_of_range`, а с `-D_GLIBCXX_ASSERTIONS` (в
  релизных сборках часто включено харденингом) срабатывает
  `__glibcxx_assert` → `abort`.
- Так как `string_view`'ы в i2pd строятся прямо над сетевыми буферами
  (HTTP/reseed/webconsole, разбор `Host`/заголовков, Base32/Base64,
  `ExtractIdentHashes`), необработанное исключение/ассерт = remote DoS:
  процесс роняет не атакующий код, а сам парсер.
- **Считаем этот класс точкой DoS**, наравне с сетевыми входами. Конкретные
  места под подтверждение (TODO): `HTTP.cpp` (`HTTPReq::parse`, `strsplit`,
  `parse_header_line`, `URL::parse`), `Identity.cpp::ExtractIdentHashes`,
  `Tag.h::FromBase64`, `Base.h/.cpp` (`Base32ToByteStream`,
  `Base64ToByteStream`).
- TODO(uu): найти конкретный вход с атакующим `pos`/`length`, оформить
  отдельным пунктом с точным стеком.

---

## Шаблон новой записи

```markdown
## N. Краткое имя (категория: crash / DoS / OOB / логика)

- Файл: `...`, функция.
- Что не так: ...
- Триггер: ...
- Последствие: ...
- Фикс в i2pd: `хеш` или «не исправлено на `7ab983ac`».
- Разбор/репро: ссылка.
```

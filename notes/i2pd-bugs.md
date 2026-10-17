# Баги и уязвимости в самом i2pd

Список находок по коду i2pd (не по нашему порту). Референс-клон для разбора:
`/home/u_uu/FOR_LLM/libi2pd` (i2pd, HEAD `79ae673d`). Нумерация — сквозная,
чтобы на неё ссылаться из коммитов и заметок.

Пункты 1-4 найдены на HEAD `7ab983ac`, пункты 5-6 — на `79ae673d`; на момент
проверки ни один из них не исправлен.

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
- Подтверждено живым POC (2026-10-17): `examples/uu-i2p-poc-i2pd-dest-nextkey.rs`
  доводит destination i2pd (httpproxy) до строки фикса
  `Garlic: Forward next key received, but key is not set` — до фикса здесь был
  null-deref. Разбор и полный лог: `notes/ecies-nextkey-vuln.md` §7.
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

## 5. SSU2: `TokenRequest` и `Retry` не переотправляются

- Файл: `SSU2Session.cpp`, `SendTokenRequest` (`:1475`), `SendRetry` (`:1562`).
- Каждый handshake-пакет, который i2pd умеет повторять, кладётся в
  `m_SentHandshakePacket` (`SendSessionRequest` `:733`, `SendSessionCreated`
  `:963`, `SendSessionConfirmed` `:1135`), а `Resend` раз в
  `SSU2_HANDSHAKE_RESEND_INTERVAL` (1 с) зовёт `ResendHandshakePacket`
  (`:619-625`). `SendTokenRequest` и `SendRetry` в `m_SentHandshakePacket`
  ничего не кладут, поэтому повторить их нечем.
- При этом `Resend` для них всё равно вызывается: `SSU2Server::HandleResendTimer`
  обходит и `m_PendingOutgoingSessions` (`SSU2.cpp:1232`), где живёт сессия
  Alice до `ProcessSessionCreated`.
- Последствие: одна потерянная UDP-датаграмма (`TokenRequest` от Alice или
  `Retry` от Bob) лечится только `SSU2_CONNECT_TIMEOUT` (5 с) — сессия просто
  падает по таймауту, хотя у i2pd есть всё, чтобы повторить пакет.
  Состояния на стороне Bob при этом не остаётся вовсе: `ProcessTokenRequest`
  (`:1519`) возвращает `true`, но сессию в `m_Sessions` добавляет только
  `ProcessSessionRequest` (`m_Server.AddSession`), так что временный объект
  сессии из `ProcessNextPacket` (`SSU2.cpp:778-782`) умирает вместе с
  обработчиком.
- Статус: в локальном клоне (`79ae673d`) не исправлено.
- У нас: `ConnReport::packets` повторяются одинаково для всех handshake-пакетов
  (`Ssu2Connection::remember_handshake` + `poll_resend`), так что `TokenRequest`
  и `Retry` переотправляются как в исправленном варианте.

## 6. SSU2: повторный `SessionRequest` в `SessionCreatedSent` игнорируется

- Файлы: `SSU2.cpp:712-718`, `SSU2Session.cpp:1227-1232`.
- Пакет для сессии в состоянии `SessionCreatedSent` уходит в
  `ProcessSessionConfirmed`, потому что диспетчер i2pd выбирает обработчик по
  состоянию сессии, а не по типу пакета. Тот снимает маску второй половины
  заголовка ключом `k_header_2` из Noise-состояния, видит там `SessionRequest`
  вместо `SessionConfirmed` и возвращает `true`, не отвечая ничего
  (`// TODO: queue up`).
- То есть повторный `SessionRequest` от Alice не приводит ни к повтору
  `SessionCreated`, ни к завершению сессии: i2pd полагается на свой
  `SSU2_HANDSHAKE_RESEND_INTERVAL` (1 с) для повтора `SessionCreated`.
- Последствие: при потере `SessionCreated` рукопожатие ждёт до секунды, хотя
  повторный `SessionRequest` — явный сигнал, что пакет не дошёл. Плюс сессия
  висит в `m_Sessions` до общего таймаута.
- Статус: в локальном клоне (`79ae673d`) не исправлено.
- У нас: поведение повторено намеренно (`PoolState::deliver`, проверка типа по
  `session_confirmed_header_key()`) — иначе расходились бы с i2pd; в коде это
  отмечено комментарием (исправленный вариант — отвечать на повторный
  `SessionRequest` повтором `SessionCreated`).

## 7. SSU2: запись `m_PendingOutgoingSessions` переживает неудачное подключение

- Файлы: `SSU2.cpp`, `RemoveSession` (`:504`), `HandleConnectTimer` /
  `Terminate` (`SSU2Session.cpp:146`, `:279`), разбор в `SSU2Server::ProcessNextPacket`
  (`:755-766`), очистка в `HandleTerminationTimer` (`SSU2.cpp:1094-1105`).
- Исходящая сессия живёт в `m_PendingOutgoingSessions` (ключ — endpoint) до
  принятого `SessionCreated`. Запись удаляется ровно в двух местах: успешный
  `ProcessSessionCreated` (`SSU2.cpp:762`) и `HandleTerminationTimer`, когда
  `IsTerminationTimeoutExpired` (`:1099`).
- Connect-таймаут (`SSU2_CONNECT_TIMEOUT`, 5 с) зовёт `Terminate()`, тот —
  `m_Server.RemoveSession (m_SourceConnID)` (`SSU2Session.cpp:308`), а
  `RemoveSession` чистит только `m_Sessions`; `m_PendingOutgoingSessions` не
  трогает. (`HandleTerminationTimer` рядом специально закомментировал
  `Terminate()` — расчёт на то, что запись уберёт метла.)
- Метла (`HandleTerminationTimer`) ходит раз в `SSU2_TERMINATION_CHECK_TIMEOUT`
  (23 с) ± 5 с, а порог для ещё не установленной сессии — тот же
  `SSU2_CONNECT_TIMEOUT` (5 с: базовый конструктор `TransportSession` получает
  его как termination timeout, `Established()` поднимает до
  `SSU2_TERMINATION_TIMEOUT` только после установления).
- Последствие: после одной неудачной попытки подключения (`CreateSession` →
  таймаут) запись живёт ещё ~23-28 с, и всё это время
  `CheckPendingOutgoingSession` (`SSU2.cpp:865`) заставляет `CreateSession`
  для того же endpoint вернуть `false`, а входящие пакеты с этого endpoint
  уходят в уже завершённую сессию (`ProcessRetry`), а не в новую. То есть
  повторное подключение к узлу откладывается на десятки секунд.
- Статус: в локальном клоне (`79ae673d`) не исправлено.
- У нас: `remove_session` чистит `by_endpoint`/`by_ident` вместе с сессией, так
  что endpoint освобождается сразу; зафиксировано тестом
  `pending_endpoint_blocks_duplicate_connect_until_session_dies`
  (`tests/ssu2_pool.rs`).

## 8. SSU2: рассинхрон часов в рукопожатии — причина завершения вместо решения

- Файлы: `SSU2Session.cpp` — `HandleDateTime` (`:1964`), `ProcessSessionRequest`
  (`:944-955`), `SendRetry` (`:1562`), `ProcessRetry` (`:1602`),
  `HandlePayload`/Termination (`:1843`), `SendTermination` (`:3286`).
- Что не так: `HandleDateTime` в фазах `SessionRequestReceived`,
  `TokenRequestReceived`, `Established` при `|offset| > SSU2_CLOCK_SKEW` (60 с)
  просто пишет `m_TerminationReason = ClockSkew` и ничего больше. А эта
  переменная в рукопожатии используется как **управляющий флаг**: сразу после
  `HandlePayload` в `ProcessSessionRequest` стоит
  `if (m_TerminationReason == NormalClose) SendSessionCreated(); else SendRetry();`.
  То есть рассинхрон часов превращается в «ответить `Retry` вместо
  `SessionCreated`».
- Усугубляет `SendRetry`: токен он кладёт только при `NormalClose`
  (`:1577`), а `Termination`-блок — наоборот, только когда причина **не**
  `NormalClose` (`:1586`). Значит `Retry` про рассинхрон часов всегда приходит
  с нулевым токеном.
- На стороне Alice `ProcessRetry` разбирает payload (`HandlePayload` видит
  `Termination` с причиной `ClockSkew` и делает `Done()`), после чего упирается
  в `if (!token) return false` и пишет в лог `SSU2: Retry token is zero`
  (комментарий рядом: «we should handle payload even for zero token to handle
  Datetime block and adjust clock in case of clock skew»). В итоге в логе
  причина — «нулевой токен», а не рассинхрон часов.
- Там же мёртвый код: `if (m_TerminationReason == IncompatibleVersion) m_Version = 2;`
  (`:1639`) стоит **до** проверки нулевого токена, а `Retry` с
  `Termination(IncompatibleVersion)` всегда с нулевым токеном (см. выше).
  Значит понижение версии (PQ → 2) в рамках одной попытки недостижимо: вместо
  повторного `SessionRequest` на версии 2 Alice просто ждёт connect-таймаут.
- В установленной сессии та же запись `m_TerminationReason = ClockSkew` не
  читается никем: в data-пути этой переменной не пользуются (только
  `SendRetry`/`SendSessionCreated`, обработка блока `Termination` и
  `SendTermination`). Рассинхрон часов молча игнорируется, а если сессия
  позже закроется по другой причине, `SendTermination` (`:3286`) отправит
  `reason = ClockSkew` — неверную причину.
- Триггер: разница часов между роутерами больше 60 с (или подмена
  `DateTime`-блока в `SessionRequest`).
- Последствие: установление соединения срывается, причём в логах Alice причина
  выглядит как «Retry token is zero»; в установленной сессии рассинхрон часов
  не приводит ни к чему, зато портит причину в `Termination`.
- Статус: в локальном клоне (`79ae673d`) не исправлено.
- У нас: поведение разобрано и повторено на уровне решений — фаза для
  `DateTime` считается по состоянию сессии (`ssu2_engine::handshake_phase`),
  решение отдаётся наружу (`ConnReport::datetime`, `RecvReport::datetime`), а
  `Retry` с блоком `Termination` отвергает соединение сразу
  (`ConnReport::rejected`, `recv_retry`) — без опоры на нулевой токен и с
  понятной причиной в логе. (В i2pd `Termination` вместе с **ненулевым**
  токеном привёл бы к попытке продолжить уже завершённую сессию; такого
  сочетания i2pd не отправляет, у нас это тоже отказ.)

## 9. SSU2: смена адреса собеседника — уборка убивает сессию, а параметры урезаются навсегда

- Файлы: `SSU2Session.cpp` — `ProcessData` (`:1752`), `SendPathChallenge`
  (`:3405`), `CleanUp` (`:3506`), `AdjustMaxPayloadSize` (`:2879`); `SSU2.cpp:1131`
  (`ScheduleCleanup`), `SSU2.h:31` (`SSU2_CLEANUP_INTERVAL = 72`).
- Что не так:
  1. `CleanUp` закрывает сессию по «висящему» челленджу без сверки времени:
     `if (m_PathChallenge) RequestTermination (NormalClose);` (`:3506`).
     Зовётся `CleanUp` по общему таймеру уборки — раз в
     `SSU2_CLEANUP_INTERVAL` (72 с). То есть срок ожидания `Path Response`
     гуляет от «почти сразу» до 72 с: если челлендж отправили незадолго до
     очередного тика уборки, сессию закроют через пару миллисекунд. Для
     законного NAT rebinding этого достаточно, чтобы оборвать живую сессию —
     при том, что данные по старому адресу продолжали бы ходить.
  2. `SendPathChallenge` делает `AdjustMaxPayloadSize (SSU2_MIN_PACKET_SIZE)` и
     `m_WindowSize = SSU2_MIN_WINDOW_SIZE` («reduce to minimum»). После любой
     смены пути сессия **навсегда** отправляет пакеты с payload ≤ 1220 байт
     вместо 1440 (`AdjustMaxPayloadSize` считает от mtu: 1280 против 1500),
     окно — 16 пакетов вместо рассчитанного. Назад параметры не
     восстанавливаются ни при подтверждении пути, ни где-либо ещё. Урезается
     при этом сторона **отправки** — в ответ на изменение **входящего** пути.
- Триггер: собеседник сменил адрес источника (NAT rebinding, смена интерфейса)
  либо адрес подменили (спуфинг).
- Последствие: (1) сессия может закрыться сразу после отправки челленджа —
  обрыв при смене адреса; (2) после смены пути сессия до конца жизни шлёт
  меньше данных в пакете и держит минимальное окно.
- Статус: не исправлено на `79ae673d`.
- У нас: `Path Challenge`/`Path Response` реализованы полностью
  (`ssu2_pool::maybe_send_path_challenge`/`send_path_challenge`/
  `send_path_response`; адрес `remote` меняется только по совпавшему ответу).
  Расхождения осознанные: (а) висящий челлендж закрывает сессию **ровно** через
  `SSU2_CLEANUP_INTERVAL` от отправки (сравниваем время, а не «попали в тик»);
  (б) `max payload` и окно не урезаем — челлендж уходит обычным пакетом.

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

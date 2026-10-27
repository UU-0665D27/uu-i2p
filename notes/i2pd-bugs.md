# Баги и уязвимости в самом i2pd

Список находок по коду i2pd (не по нашему порту). Референс-клон для разбора:
`/home/u_uu/FOR_LLM/libi2pd` (i2pd, HEAD `5bcf6101`, см.
`notes/i2pd-baseline.md`). Нумерация — сквозная, чтобы на неё ссылаться из
коммитов и заметок.

Пункты 1-4 найдены на HEAD `7ab983ac`, пункты 5-11 — на `79ae673d`,
пункт 12 — на `5bcf6101` (там же он и исправлен), пункт 13 — на
`3.0.0-40-g67714be7` (не исправлен). При обновлении зеркала до
`5bcf6101` (2026-10-25) статусы 1-11 перепроверены по diff'у: в
`9725b8b2..5bcf6101` менялись только `libi2pd/Signature.cpp`,
`libi2pd_client/Torrents*`, `Makefile.linux` и UPnP-патч, ни один из
пунктов 1-11 эти файлы не затрагивает — значит, все они по-прежнему не
исправлены.

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

## 10. `IsInReservedRange`: перевёрнутая граница диапазона `198.18.0.0/15` (логика)

- Файл: `libi2pd/util.cpp:825` (`i2p::util::net::IsInReservedRange`).
- Что не так: в таблице `reservedIPv4Ranges` строка
  `address_pair_v4("198.18.0.0", "192.19.255.255")` — верхняя граница
  (`192.19.255.255`) **меньше** нижней (`198.18.0.0`). Проверка в цикле
  `if (ipv4_address >= it.first && ipv4_address <= it.second)` для такого
  диапазона не выполняется ни разу (очевидно, опечатка: должно быть
  `198.19.255.255`).
- Что теряется: диапазон `198.18.0.0/15` (IETF benchmarking, RFC 2544) и,
  из-за опечатки, вообще любой адрес в него не считается reserved —
  `IsInReservedRange` для них возвращает `false`.
- Триггер: адрес источника/собеседника из `198.18.0.0/15`.
- Последствие: проверка «reserved» в `Transports` (`reservedrange = true`,
  по умолчанию) пропускает эти адреса. Там, где на неё рассчитывают как на
  фильтр (подключения к приватным/служебным сетям — рядом соседствуют
  `10.0.0.0/8`, `192.168.0.0/16`, `169.254.0.0/16`), защиты нет: i2pd
  готов подключаться к хостам в `198.18.0.0/15` и принимать входящие
  сессии оттуда.
- Статус: не исправлено на `79ae673d` и на `3.0.0-5-g9725b8b2`
  (`libi2pd/util.cpp:826` — граница та же).
- У нас: граница правильная (`is_reserved_v4`, `198.18.0.0`–`198.19.255.255`),
  в коде есть комментарий со ссылкой сюда.

---

## 11. `Tunnels::Run`: потерянный wakeup и молчаливый дроп очереди (логика)

- Файлы: `libi2pd/Tunnel.cpp:602-612` (`Tunnels::Run`),
  `libi2pd/Queue.h:75` (`Queue::Wait`). В 2.61.0 код тот же.
- Что не так:
  (а) `Tunnels::Run` разбирает `m_Queue` только когда `m_Queue.Wait (1,0)`
  вернул `true`, а `Queue::Wait` — это `wait_for` без проверки
  `IsEmpty ()`. `Put` уведомляет `m_NonEmpty` под мьютексом, поэтому
  уведомление, пришедшее, пока туннельный поток занят другим делом,
  теряется; следующий `Wait` отсиживает свою секунду, возвращает `false`,
  и сообщение остаётся в очереди до следующего `Put`;
  (б) просроченные элементы очереди отбрасываются **молча** —
  `if (!msg || msg->IsExpired (mts)) continue;` без единого лога.
- Триггер: `TunnelData`/`TunnelGateway` (в том числе `DeliveryStatus` в
  публикации `LeaseSet` и `TunnelTest`) приходят в момент, когда
  туннельный поток занят `ManageTunnels`/`ManageTunnelPools`.
- Последствие: сообщение не обрабатывается и ничем не отмечается в логе.
  Для `TunnelGateway` это потеря `DeliveryStatus` публикации (отправитель
  ретраит публикацию), для `TunnelTest` — вечное «тест не пройден»,
  для `TunnelData` — потеря данных входящего туннеля. В одиночной
  конфигурации (нет транзитного трафика) эффект устойчив.
- Наблюдение живьём: i2pd 2.61.0 принимает наш `TunnelGateway` на уровне
  SSU2 (`SSU2: Block type 3 of size 43`, `SSU2: I2NP message`), но
  туннельный слой не пишет ни `Tunnel: Gateway of ...`, ни `Tunnel: Tunnel
  not found`; копия того же сообщения с `expiration +1 час` тоже исчезает
  молча; при этом собственный `Tunnels: Test of tunnel <id> failed` для
  0-hop inbound-туннеля i2pd вылетает с самого старта, задолго до нашего
  подключения.
- Статус: не исправлено на `79ae673d`; механизм подтверждён только
  чтением кода, отдельного репро на живом трафике (2+ роутера) нет.
  На `3.0.0-5-g9725b8b2` эффект **не воспроизводится**: 0-hop туннели
  проходят тест, наш `TunnelGateway` с `DeliveryStatus` доходит до
  destination. `Tunnel.cpp`/`Queue.h` в диапазоне
  `79ae673d..9725b8b2` не менялись, так что гипотеза о потерянном
  wakeup остаётся неподтверждённой — прежнее наблюдение могло быть
  следствием окружения (debug-сборка/тайминг), а не этого кода.
- Разбор: `notes/router-live-i2pd.md`, раздел «Флудфилл: что видно
  живьём».

## 12. `DSASigner::Sign`: NULL-deref и неинициализированная подпись при отказе OpenSSL (crash)

- Файл: `libi2pd/Signature.cpp`, `DSASigner::Sign` (две ветки: `EVP_DigestSign`).
- Что не так: результат `EVP_DigestSignInit`/`EVP_DigestSign` не проверялся;
  при провале `sign[]` оставался неинициализированным, `l` — равным
  `DSA_SIGNATURE_LENGTH + 8`, `d2i_DSA_SIG` возвращал `nullptr`, и дальше
  шло `DSA_SIG_get0 (sig, ...)` с `sig == nullptr` → разыменование NULL в
  `bn2buf (r, ...)`. Во второй ветке то же самое с `DSA_do_sign`.
- Триггер: OpenSSL 3 без legacy-провайдера (Fedora/RHEL, где DSA-SHA1
  выпилен) — роутер/дестинейшн с DSA-ключом пытается подписать
  `RouterInfo`/`LeaseSet`.
- Последствие: локальный крэш подписавшего; до падения в буфер подписи
  успевали попасть байты стека, то есть даже без падения на проводе
  оказалась бы мусорная подпись.
- Фикс: `b31431ba` (PR #2606) — проверка контекста, результата подписи и
  `d2i_DSA_SIG`, обнуление `signature` перед работой, логирование ошибки.
  Приехал в зеркало с обновлением до `5bcf6101`.
- Разбор: чтение кода, репро не снималось — в нашем порте DSA-подписи нет
  (`src/signature.rs` знает только тип `DsaSha1`, без sign/verify), так что
  баг для нас пока теоретический. Урок общий: выходной буфер не оставлять
  неинициализированным, а `None`/`nullptr` от крипто-бэкенда проверять до
  `get0`.

---

## 13. Streaming: `packet->from` — use-after-free при CLOSE/RESET из сохранённого пакета (crash)

- Файл: `libi2pd/Streaming.cpp`, `Stream::ProcessOptions` (CLOSE/RESET-ветка,
  строка 578) + `Stream::SavePacket` (406).
- Что не так: `SavePacket` кладёт `Packet*` в `m_SavedPackets` вместе с
  `packet->from` — **сырым** указателем на
  `ECIESX25519AEADRatchetSession`. Сессия живёт только на время
  `GarlicDestination::HandleGarlicMessage` (`Garlic.cpp:550`, локальный
  `shared_ptr` умирает на выходе). Когда отложенный пакет позже достаёт
  цикл `Stream::HandleNextPacket` (301-310), `ProcessOptions` для флагов
  CLOSE/RESET делает `packet->from->GetRemoteStaticKey()` на уже
  освобождённой сессии.
- Триггер (все условия обязательны):
  1. у потокового destination'а i2pd уже есть **живая** сессия S2 с нашим
     static-ключом (`ECIESX25519_RESTART_TIMEOUT` = 120 c ещё не вышло);
  2. приходит garlic с **New Session** от того же static-ключа: i2pd
     создаёт одноразовую сессию S, `AddECIESx25519Session`
     (`Garlic.cpp:1108`) видит S2, `CanBeRestarted()` = false, пишет
     `ECIESx25519 session with static key ... already exists` и делает
     `return`, **не сохраняя S**;
  3. внутри этого NS лежит clove `I2NP Data` со streaming-пакетом с
     «дыркой» по seqn (например `seqn=2 | FLAG_CLOSE` при ожидаемом 1) —
     `HandlePayload` обрабатывает его несмотря на отказ, а S идёт в
     `packet->from`;
  4. NS должен прийти не раньше `INCOMING_SESSIONS_MINIMAL_INTERVAL`
     = 200 мс после предыдущего входящего NS (`Garlic.h:58`), иначе он
     вообще не разбирается (`Garlic: Incoming sessions come too often`);
  5. по живой S2 приходит пакет с закрывающим дырку seqn — срабатывает
     цикл сохранённых пакетов и читается освобождённая S.
- Последствие: чтение 32 байт из освобождённой кучи; под ASan —
  `heap-use-after-free` в `memcmp`, без ASan — сравнение с мусором
  (ложный `Remote LeaseSet static key mismatch`/рассинхрон состояния) и
  потенциальный remote-crash.
- Почему не спасает соседняя ветка: в `StreamingDestination::HandleNextPacket`
  (`Streaming.cpp:2331`) перед сохранением пакета для **неизвестного**
  потока стоит `packet->from = nullptr;` (комментарий «session might be
  invalid when saved packet gets handled»). Для **известного** потока
  (`m_IncomingStreams`/`m_Streams`) вызов идёт напрямую в
  `Stream::HandleNextPacket`, обнуления нет — дыра остаётся.
- Фикс в i2pd: не исправлено на `3.0.0-40-g67714be7` (issue #2617).
- Репро: `examples/uu-i2p-poc-i2pd-streaming-uaf.rs`. Снятый трейс
  (i2pd `3.0.0-40-g67714be7`, ASan+UBSan):

  ```text
  ERROR: AddressSanitizer: heap-use-after-free ... READ of size 32
      #0 memcmp
      #2 Stream::ProcessOptions            Streaming.cpp:578
      #3 Stream::ProcessPacket             Streaming.cpp:418
      #4 Stream::HandleNextPacket          Streaming.cpp:304
      #6 StreamingDestination::HandleDataMessagePayload  Streaming.cpp:2532
  0x... is located 202 bytes inside of 544-byte region ...
  freed by thread T20 here:
      #12 GarlicDestination::HandleGarlicMessage  Garlic.cpp:550
  ```

  Плюс UBSan до ASan:
  `Streaming.cpp:578:32: runtime error: member call on address ... which
  does not point to an object of type 'ECIESX25519AEADRatchetSession'`.

### Как воспроизвести (ран-бук)

Нужен destination i2pd, который сам пойдёт на наш адрес, — HTTP-прокси
стенда. Со стороны uu-i2p POC играет сервер D и флудфилл:

```sh
# 1. чистый стенд, лог в файл (ASan пишет в stderr!)
~/.local/opt/i2pd-uu/run-ssu2.sh > /tmp/opencode/i2pd-ssu2.log 2>&1 &

# 2. наполнить netDb: без ~20 роутеров i2pd не публикует LS destination'а
#    и не доходит до LeaseSet-lookup. Соседи — НЕ флудфиллы, иначе
#    GetClosestFloodfill уводит lookup от POC к соседу.
for i in $(seq 1 50); do
    UU_I2P_FLOODFILL=0 UU_I2P_SECS=1800 \
    UU_I2P_LIVE_RI=~/.local/opt/i2pd-uu/datadir/router.info \
    UU_I2P_LIVE_SSU2=127.0.0.1:12345 \
        target/debug/examples/uu-i2p-router-i2pd >/dev/null 2>&1 &
done

# 3. POC и запрос через прокси
UU_I2P_LIVE_RI=~/.local/opt/i2pd-uu/datadir/router.info \
UU_I2P_LIVE_SSU2=127.0.0.1:12345 \
    target/debug/examples/uu-i2p-poc-i2pd-streaming-uaf &
curl -x http://127.0.0.1:4445 --max-time 30 http://<b32-адрес из вывода POC>/
```

Что должно быть в логе: `ECIESx25519 session with static key ... already
exists`, затем `Streaming: Process seqn=2, flags=2` и ASan-трейс.

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

# Баг от rotten_egg: детерминированный remote-crash i2pd в ECIES-X25519-AEAD-ратчете

Эта заметка — разбор для будущего POC (первый вариант атаки). Пока роутер не
готов работать в сети, POC не делаем; здесь только зафиксированы факты и
точные строки i2pd.

Референс: `/home/u_uu/FOR_LLM/libi2pd` (i2pd, HEAD `7ab983ac`, **уже с фиксом**).
Файл: `libi2pd/ECIESX25519AEADRatchetSession.cpp`.

## 1. Null-deref в `HandleNextKey` (forward-ветка)

Фикс: `e5621949` — «chech ratchets payload size and key» (2026-09-09).

До фикса, ветка forward-key (`else`, т.е. без `REVERSE_KEY_FLAG`), не проверяла,
что локальный ключ уже сгенерирован:

```cpp
else
    m_NextReceiveRatchet->newKey = false;      // <- key может быть nullptr
auto tagsetID = m_NextReceiveRatchet->GetReceiveTagSetID ();
if (flag & ECIESX25519_NEXT_KEY_KEY_PRESENT_FLAG)
    memcpy (m_NextReceiveRatchet->remote, buf, 32);

uint8_t sharedSecret[32], tagsetKey[32];
m_NextReceiveRatchet->key->Agree (m_NextReceiveRatchet->remote, sharedSecret); // line 529: NULL DEREF
```

После фикса:

```cpp
else
{
    if (!m_NextReceiveRatchet->key)
    {
        LogPrint (eLogError, "Garlic: Forward next key received, but key is not set");
        return;
    }
    m_NextReceiveRatchet->newKey = false;
}
```

`DHRatchet::key` — `std::shared_ptr<X25519Keys>`, у свежесозданного
(`new DHRatchet ()`) он `nullptr`. Крушение — на `i2p::crypto::X25519Keys::Agree`
(`Crypto.cpp:319`).

**Условия триггера:** установленная (`eSessionStateEstablished`) сессия; garlic-payload,
расшифрованный тегом, содержит блок `eECIESx25519BlkNextKey`, у которого
`flag` без `REVERSE_KEY_FLAG` и без `REQUEST_REVERSE_KEY_FLAG` (`newKey == false`),
при этом `m_NextReceiveRatchet->key == nullptr` (ратчета ещё нет либо его ключ не
сгенерирован, т.к. предыдущий forward-блок был преждевременным).

**Стек из репорта (uu):**

```
Crypto.cpp:319                                   X25519Keys::Agree
ECIESX25519AEADRatchetSession.cpp:529            HandleNextKey
ECIESX25519AEADRatchetSession.cpp:418            HandlePayload
ECIESX25519AEADRatchetSession.cpp:965            HandleExistingSessionMessage
ECIESX25519AEADRatchetSession.cpp:1016           HandleNextMessage
ECIESX25519AEADRatchetSession.cpp:128            ReceiveRatchetTagSet::HandleNextMessage
Garlic.cpp:567                                   GarlicDestination::HandleECIESx25519TagMessage
Garlic.cpp:504                                   GarlicDestination::HandleGarlicMessage
Destination.cpp:347                              LeaseSetDestination::ProcessGarlicMessage
```

Второй прогон под ASan даёт `SEGV ... READ` на адресе `0x20` — то же место.

## 2. OOB-чтение в `HandlePayload` (усечённый заголовок блока)

Фикс: `cc77898b` — «check the whole block header fits before reading block size in
ratchets payload» (2026-09-09, PobreGato). Ремарка rotten_egg: «very minor, OOB read
when the buffer has a truncated header (1 or 2 bytes) at the end of the payload».

До фикса:

```cpp
if (len < 3) return;          // добавлено e5621949
size_t offset = 0;
while (offset < len)          // <- при 1–2 байтах хвоста читаем за концом
{
    uint8_t blk = buf[offset];
    offset++;
    auto size = bufbe16toh (buf + offset);   // OOB READ
```

После `cc77898b`:

```cpp
// the block header is three bytes: without all of them the size field below
// would be read past the end of the payload
while (offset + 3 <= len)
```

## 3. Что у нас в `uu-i2p`

- `src/ecies_ratchet.rs::handle_forward_key` (стр. ~719–784) **уже содержит**
  safety-guard из фикса: при `ratchet.key.is_none()` возвращает
  `Err(I2PError::Malformed("... forward key without local key"))`, а не дереференсит.
  Т.е. наш порт повторяет **исправленный** i2pd.
- `src/garlic_block.rs::NextKeyBlock` уже умеет парсить блок (`key_id`,
  `public_key`, флаги `is_reverse_key()` / `requests_reverse_key()`).
- Лог-строки из фикса («Garlic: Unexpected next key block», «Garlic: Forward next
  key received, but key is not set») соответствуют веткам
  `eECIESx25519BlkNextKey` без `receiveTagset` и forward-key без локального ключа.

## 4. План POC (позже, поверх готового роутера)

POC должен воспроизвести баг «как было», не ломая совместимость. Вариант,
согласованный по духу трейт-подхода:

- на уровне решения ввести режим/трейт, где forward-ветка `handle_next_key_block`
  ведёт себя **как до фикса** (опционально, только для POC) — тогда наш Rust
  воспроизводит краш-путь на своём же входе (паника вместо null-deref);
- либо POC генерирует валидное до-фиксовое враждебное garlic-сообщение
  (`NextKey` c `flag` без reverse/request-reverse) и проверяет его на уязвимой
  сборке C++ i2pd.

Точный вариант выберем, когда дойдём до POC.

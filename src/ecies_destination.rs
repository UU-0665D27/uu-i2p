//! `ECIES-X25519-AEAD-Ratchet` destination — менеджер сессий.
//!
//! `EciesGarlicDestination` держит пул [`RatchetSession`], по одной на
//! каждый remote static X25519-ключ, и прячет NS / NSR / existing
//! session от вызывающего кода:
//!
//! - `send_blocks(remote_static, now_ms, blocks)` — «отправить garlic
//!   такому-то роутеру». Внутри: найти/создать сессию → `wrap_blocks`.
//! - `handle_message(wire)` — «принять входящий garlic». Внутри:
//!   найти сессию по тегу или создать новую (NS) → `handle_blocks`.
//!
//! Модель поведения скопирована с `GarlicDestination` из
//! `libi2pd/Garlic.cpp`, но содержит только ECIES-X25519-AEAD-Ratchet
//! часть — ElGamal/AES не реализован.
//!
//! ## Что НЕ реализовано
//!
//! - ElGamal/AES сессии (`ElGamalAESSession`);
//! - автоматическая очистка неактивных сессий (i2pd делает это через
//!   `CleanupExpiredTags`, у нас caller сам решает, когда вызвать
//!   [`EciesGarlicDestination::remove_session`] —
//!   [`EciesGarlicDestination::cleanup_unconfirmed_tags`] по той же
//!   причине вызывается вручную).
//!
//! ## Разделение обязанностей
//!
//! [`RatchetSession`] умеет ровно одну сессию и хранит свой
//! session-tag-map. `EciesGarlicDestination` нужен **только** для того,
//! чтобы по входящему wire-сообщению понять, **какой** сессии оно
//! принадлежит. Пока сессий одна-две, это можно было бы делать и без
//! отдельного слоя, но с ростом числа пиров нужна O(1)-диспетчеризация
//! (в i2pd — `m_ECIESx25519Tags` уровня destination).

use crate::{
    EciesGarlicClove,
    crypto::I2PX25519Keys,
    ecies_ratchet::{RatchetSession, SessionState},
    error::{I2PError, Result},
    garlic_block::GarlicBlock,
};
use std::collections::HashMap;

/// Результат [`EciesGarlicDestination::handle_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleResult {
    /// Remote static X25519-ключ сессии, обработавшей сообщение.
    ///
    /// Это ключ «с той стороны»: для Bob — static Alice, для Alice —
    /// static Bob. Именно его нужно передавать в
    /// [`EciesGarlicDestination::send_blocks`], чтобы ответить.
    pub remote_static: [u8; 32],
    /// Извлечённые garlic-cloves (облегчённый формат ECIES-X25519-AEAD).
    ///
    /// Служебные блоки (`Ack`, `AckRequest`, `NextKey`, `DateTime`,
    /// `Padding`) обрабатываются внутри [`RatchetSession`] и сюда
    /// не попадают.
    pub blocks: Vec<EciesGarlicClove>,
    /// `true`, если сессия ждёт ответа до того, как сможет принимать
    /// обычные (existing-session) сообщения.
    ///
    /// Сейчас единственный случай — `NewReceived` (Bob только что
    /// разобрал NS). Caller обязан вызвать
    /// [`EciesGarlicDestination::send_blocks`] с ответными блоками
    /// (обычно пустыми) — внутри уйдёт NSR, и сессия перейдёт в
    /// `NewReplySent`.
    pub needs_reply: bool,
    /// `true`, если сессия была закрыта полученным `Termination`-блоком.
    ///
    /// `EciesGarlicDestination` уже удалил её из своего пула. Слать
    /// что-либо в ответ бессмысленно — следующий `send_blocks` к тому
    /// же `remote_static` создаст **новую** сессию (с NS).
    pub terminated: bool,
}

/// Пул `RatchetSession`, по одной на каждый remote static ключ.
pub struct EciesGarlicDestination {
    local_static: I2PX25519Keys,
    sessions: HashMap<[u8; 32], RatchetSession>,
}

impl EciesGarlicDestination {
    /// Создаёт destination с указанным локальным static-ключом.
    #[must_use]
    pub fn new(local_static: I2PX25519Keys) -> Self {
        Self {
            local_static,
            sessions: HashMap::new(),
        }
    }

    /// Локальный static public key.
    #[must_use]
    pub fn local_static_public(&self) -> &[u8; 32] {
        self.local_static.public_key()
    }

    /// Количество активных сессий (для тестов/диагностики).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Есть ли сессия с указанным remote static.
    #[must_use]
    pub fn has_session(&self, remote_static: &[u8; 32]) -> bool {
        self.sessions.contains_key(remote_static)
    }

    /// Состояние сессии с указанным remote static, если есть.
    #[must_use]
    pub fn session_state(&self, remote_static: &[u8; 32]) -> Option<SessionState> {
        self.sessions.get(remote_static).map(RatchetSession::state)
    }

    /// Удаляет сессию. Возвращает её, если была.
    ///
    /// В i2pd сессии удаляются автоматически по `CheckExpired`, у нас
    /// caller сам решает, когда чистить. Обычно — по таймауту
    /// неактивности или после получения Termination-блока.
    pub fn remove_session(&mut self, remote_static: &[u8; 32]) -> Option<RatchetSession> {
        self.sessions.remove(remote_static)
    }

    /// Отправляет garlic-cloves удалённому пиру.
    ///
    /// Если сессии с `remote_static` ещё нет — создаётся новая
    /// initiator-сессия, и это сообщение будет **NS**. Если сессия уже
    /// есть — используется её текущее состояние:
    ///
    /// - `New` → NS (первое сообщение);
    /// - `NewReceived` → NSR (ответ Bob'а);
    /// - `NewReplySent` / `Established` → existing-session message;
    /// - `NewSent` → ошибка (ждём NSR от пира).
    ///
    /// `now_ms` — текущее время; нужно session'у для расписания
    /// `AckRequest` (см. [`RatchetSession::wrap_blocks`]).
    ///
    /// # Errors
    ///
    /// Ошибки [`RatchetSession::wrap_blocks`].
    pub fn send_blocks(
        &mut self,
        remote_static: [u8; 32],
        now_ms: u64,
        cloves: &[EciesGarlicClove],
    ) -> Result<Vec<u8>> {
        self.send_blocks_extra(remote_static, now_ms, cloves, &[])
    }

    /// То же, что [`Self::send_blocks`], но с дополнительными
    /// garlic-блоками — см. [`RatchetSession::wrap_blocks_extra`].
    ///
    /// # Errors
    ///
    /// Ошибки [`RatchetSession::wrap_blocks_extra`].
    pub fn send_blocks_extra(
        &mut self,
        remote_static: [u8; 32],
        now_ms: u64,
        cloves: &[EciesGarlicClove],
        extra: &[GarlicBlock],
    ) -> Result<Vec<u8>> {
        let session = self.sessions.entry(remote_static).or_insert_with(|| {
            RatchetSession::new_initiator(clone_x25519_keys(&self.local_static), remote_static)
        });
        session.wrap_blocks_extra(now_ms, cloves, extra)
    }

    /// `msgID`, подтверждённые пиром (пришли в `Ack`-блоках) —
    /// i2pd `MessageConfirmed`. Список сессии опустошается.
    ///
    /// Возвращает пустой список, если сессии с таким `remote_static`
    /// нет.
    #[must_use]
    pub fn take_confirmed_msg_ids(&mut self, remote_static: &[u8; 32]) -> Vec<u32> {
        self.sessions
            .get_mut(remote_static)
            .map_or_else(Vec::new, RatchetSession::take_confirmed_msg_ids)
    }

    /// i2pd `CleanupUnconfirmedTags`: забыть неотвеченный `AckRequest`
    /// сессии. `true`, если сессия что-то забыла; для неизвестной сессии
    /// — `false`.
    #[must_use]
    pub fn cleanup_unconfirmed_tags(&mut self, remote_static: &[u8; 32]) -> bool {
        self.sessions
            .get_mut(remote_static)
            .is_some_and(RatchetSession::cleanup_unconfirmed_tags)
    }

    /// Разбирает входящее garlic-сообщение.
    ///
    /// Алгоритм:
    ///
    /// 1. Если в `wire` есть 8-байтовый тег, который лежит в
    ///    `receive_tags` какой-либо сессии — отдаём сообщение этой
    ///    сессии (existing-session message).
    /// 2. Если тег совпадает с ожидаемым NSR-тегом сессии в состоянии
    ///    `NewSent` — отдаём ей (NSR на стороне Alice).
    /// 3. Иначе создаём новую incoming-сессию и пытаемся разобрать
    ///    сообщение как NS.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] — `wire` короче 8 байт;
    /// - ошибки обработки конкретного сообщения;
    /// - [`Error::Malformed`], если NS успешно разобран, но remote
    ///   static так и не появился (не должно случаться).
    pub fn handle_message(&mut self, wire: &[u8]) -> Result<HandleResult> {
        if wire.len() < 8 {
            return Err(I2PError::InvalidLength {
                expected: 8,
                got: wire.len(),
            });
        }
        // Тег — первые 8 байт little-endian, как в `RatchetSession`.
        let mut tag_bytes = [0u8; 8];
        tag_bytes.copy_from_slice(&wire[..8]);
        let tag = u64::from_le_bytes(tag_bytes);

        // 1. Existing-session message: ищем сессию по тегу.
        let existing = self
            .sessions
            .iter()
            .find_map(|(k, s)| s.has_receive_tag(tag).then_some(*k));
        if let Some(key) = existing {
            return self.handle_in_existing_session(key, wire);
        }

        // 2. NSR на стороне Alice: сессия в состоянии `NewSent`,
        //    следующий NSR-тег совпадает.
        let nsr = self
            .sessions
            .iter()
            .find_map(|(k, s)| s.matches_nsr_tag(tag).then_some(*k));
        if let Some(key) = nsr {
            return self.handle_in_existing_session(key, wire);
        }

        // 3. NS: новая incoming-сессия.
        let mut session = RatchetSession::new_responder(clone_x25519_keys(&self.local_static));
        let blocks = session.handle_blocks(wire)?;
        let remote_static = session.remote_static().copied().ok_or(I2PError::Malformed(
            "ecies_dest: NS did not yield remote static",
        ))?;
        let needs_reply = session.needs_reply();
        let terminated = session.is_terminated();
        self.sessions.insert(remote_static, session);
        if terminated {
            self.sessions.remove(&remote_static);
        }
        Ok(HandleResult {
            remote_static,
            blocks,
            needs_reply,
            terminated,
        })
    }

    /// Общий путь обработки в уже существующей сессии (existing
    /// session message или NSR). Удаляет сессию из пула, если она
    /// терминировалась.
    fn handle_in_existing_session(&mut self, key: [u8; 32], wire: &[u8]) -> Result<HandleResult> {
        let session = self
            .sessions
            .get_mut(&key)
            .ok_or(I2PError::Malformed("ecies_dest: session vanished"))?;
        let blocks = session.handle_blocks(wire)?;
        let needs_reply = session.needs_reply();
        let terminated = session.is_terminated();
        if terminated {
            self.sessions.remove(&key);
        }
        Ok(HandleResult {
            remote_static: key,
            blocks,
            needs_reply,
            terminated,
        })
    }

    /// Отправляет `Termination`-блок указанной сессии и удаляет её.
    ///
    /// Возвращает wire для отправки. После успеха сессии в пуле нет;
    /// повторный вызов к тому же `remote_static` создаст новую.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], если сессии с таким `remote_static` нет
    /// или она уже терминирована.
    pub fn send_termination(&mut self, remote_static: &[u8; 32]) -> Result<Vec<u8>> {
        let Some(session) = self.sessions.get_mut(remote_static) else {
            return Err(I2PError::Malformed(
                "ecies_dest: send_termination for unknown session",
            ));
        };
        let wire = session.send_termination()?;
        self.sessions.remove(remote_static);
        Ok(wire)
    }
}

/// Клонирует пару X25519-ключей.
///
/// `X25519Keys` не реализует `Clone` (secret zeroize'ится на drop, и
/// копирование секрета — операция, которую не стоит делать неявно),
/// поэтому делаем явный конструктор из priv + pub.
fn clone_x25519_keys(keys: &I2PX25519Keys) -> I2PX25519Keys {
    I2PX25519Keys::from_private(&keys.private_key(), Some(keys.public_key()))
}

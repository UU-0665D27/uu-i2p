#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::{TcpListener, TcpStream};
    use uu_i2p::{
        I2PError, I2PTag, IdentHash, Ntcp2Local, Ntcp2Pool, PoolEvent,
        crypto::I2PX25519Keys,
        i2np::I2npMessageType,
        i2np_message::I2npMessage,
        ntcp2::{Ntcp2Block, Ntcp2LocalConfig, Ntcp2Session, Ntcp2TerminationReason},
        ntcp2_pool::Ntcp2Timers,
        private_keys::I2PPrivateKeys,
        router_info::{FullRouterInfo, RouterInfo},
        router_info_address::I2PAddress,
    };

    struct Side {
        keys: I2PPrivateKeys,
        ntcp2_static: I2PX25519Keys,
        static_private: [u8; 32],
        ntcp2_iv: [u8; 16],
        ri_bytes: Vec<u8>,
    }

    impl Side {
        /// `socket_addr` — реальный адрес listener'а; используется
        /// в `Address::ntcp2_published`, чтобы remote мог подключиться.
        fn new(iv_byte: u8, socket_addr: SocketAddr) -> Self {
            Self::with_published(iv_byte, socket_addr)
        }

        /// То же, но опубликованный в RI адрес задан отдельно: так
        /// проверяется `connect_to` (адрес из RI намеренно недоступен).
        fn with_published(iv_byte: u8, published: SocketAddr) -> Self {
            let keys = I2PPrivateKeys::generate_default().unwrap();
            let ntcp2_static = I2PX25519Keys::generate();
            let static_private = ntcp2_static.private_key();
            let ntcp2_iv = [iv_byte; 16];
            let mut static_bytes = [0u8; 32];
            static_bytes.copy_from_slice(ntcp2_static.public_key());
            let addr = I2PAddress::ntcp2_published(
                published.ip(),
                published.port(),
                I2PTag::from_array(static_bytes),
                ntcp2_iv,
            );
            let body = RouterInfo::builder()
                .timestamp(1_700_000_000_000)
                .add_address(addr)
                .build();
            let ri_bytes = FullRouterInfo::from_keys(&keys, body)
                .unwrap()
                .to_buffer()
                .unwrap();
            Self {
                keys,
                ntcp2_static,
                static_private,
                ntcp2_iv,
                ri_bytes,
            }
        }

        fn ident_hash(&self) -> IdentHash {
            *self.keys.public().ident_hash()
        }

        fn config(&self) -> Ntcp2LocalConfig<'_> {
            Ntcp2LocalConfig {
                static_keys: &self.ntcp2_static,
                ident_hash: self.ident_hash().into(),
                iv: self.ntcp2_iv,
                ri_bytes: &self.ri_bytes,
                net_id: 2,
            }
        }

        /// Владеющая версия конфига — для пула.
        fn local(&self) -> Ntcp2Local {
            Ntcp2Local::new(
                I2PX25519Keys::from_private(
                    &self.static_private,
                    Some(self.ntcp2_static.public_key()),
                ),
                self.ident_hash().into(),
                self.ntcp2_iv,
                self.ri_bytes.clone(),
                2,
            )
        }
    }

    fn fast_timers() -> Ntcp2Timers {
        Ntcp2Timers {
            establish_timeout: Duration::from_secs(5),
            termination_timeout: Duration::from_millis(80),
            termination_timeout_variance: Duration::ZERO,
            termination_check_interval: Duration::from_millis(20),
            termination_check_interval_variance: Duration::ZERO,
            router_info_resend_interval: Duration::from_secs(3600),
            router_info_resend_variance: Duration::ZERO,
        }
    }

    /// Ждёт первое `PoolEvent::Message` от указанного пира, пропуская
    /// `Established`, `RouterInfo` и `Disconnected`.
    async fn recv_message_from(pool: &Ntcp2Pool, expected_from: IdentHash) -> I2npMessage {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for PoolEvent::Message"
            );

            let event = tokio::time::timeout(remaining, pool.next_event())
                .await
                .expect("timeout waiting for PoolEvent")
                .expect("pool.next_event");

            match event {
                PoolEvent::Message { from, message } => {
                    assert_eq!(from, expected_from, "message from unexpected peer");
                    return message;
                }
                PoolEvent::RouterInfo { from, ri_bytes } => {
                    // Пропускаем, но проверяем, что RI валиден и от того же пира.
                    assert_eq!(from, expected_from, "RouterInfo from unexpected peer");
                    let ri =
                        FullRouterInfo::from_buffer(&ri_bytes).expect("peer RI failed to parse");
                    assert_eq!(ri.ident_hash(), &expected_from, "RI ident mismatch");
                }
                PoolEvent::Established { .. } | PoolEvent::Disconnected { .. } => {}
            }
        }
    }

    /// Ждёт `PoolEvent::Established` от указанного пира.
    async fn recv_established(pool: &Ntcp2Pool) -> IdentHash {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for PoolEvent::Established"
            );
            let event = tokio::time::timeout(remaining, pool.next_event())
                .await
                .expect("timeout waiting for PoolEvent")
                .expect("pool.next_event");
            if let PoolEvent::Established { ident } = event {
                return ident;
            }
        }
    }

    /// Ждёт `Disconnected` от указанного пира.
    async fn recv_disconnected(pool: &Ntcp2Pool, expected_from: IdentHash) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for PoolEvent::Disconnected"
            );
            let event = tokio::time::timeout(remaining, pool.next_event())
                .await
                .expect("timeout waiting for PoolEvent")
                .expect("pool.next_event");
            match event {
                PoolEvent::Disconnected { ident } => {
                    assert_eq!(ident, expected_from, "Disconnected from unexpected peer");
                    return;
                }
                PoolEvent::Established { .. }
                | PoolEvent::Message { .. }
                | PoolEvent::RouterInfo { .. } => {}
            }
        }
    }

    /// Читает фреймы до блока, удовлетворяющего `pred`, с таймаутом.
    async fn read_until(
        read: &mut uu_i2p::ntcp2::Ntcp2SessionRead,
        mut pred: impl FnMut(&Ntcp2Block) -> bool,
    ) -> Ntcp2Block {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for frame");
            let blocks = tokio::time::timeout(remaining, read.read_frame())
                .await
                .expect("timeout waiting for frame")
                .expect("read_frame");
            if let Some(block) = blocks.into_iter().find(|b| pred(b)) {
                return block;
            }
        }
    }

    #[tokio::test]
    async fn pool_empty_initially() {
        let pool = Ntcp2Pool::new();
        assert!(pool.is_empty().await);
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn pool_connect_send_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x11, server_addr);
        let bob = Side::new(0x22, server_addr);
        let bob_ident = bob.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        // Bob принимает в фоне.
        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        // Alice — через pool.
        let alice_pool = Ntcp2Pool::new();
        alice_pool.set_local(Arc::new(alice.local()));
        let connected_ident = alice_pool
            .connect(&bob_ri_bytes)
            .await
            .expect("pool.connect");

        assert_eq!(connected_ident, bob_ident);
        assert!(alice_pool.has_session(&bob_ident).await);
        assert_eq!(alice_pool.len().await, 1);

        // Первое событие — `Established` (пул сообщает о готовности).
        match alice_pool.next_event().await.unwrap() {
            PoolEvent::Established { ident } => assert_eq!(ident, bob_ident),
            other => panic!("expected PoolEvent::Established, got {other:?}"),
        }

        // Ждём завершения handshake на стороне Bob'а.
        let mut bob_session = bob_task.await.unwrap().expect("bob handshake");

        // Bob (responder) сразу после handshake отослал свой RI
        // отдельным фреймом — как i2pd `SendLocalRouterInfo`.
        // Забираем его из очереди сейчас, чтобы дальше получать
        // только I2NP-сообщения.
        match alice_pool.next_event().await.unwrap() {
            PoolEvent::RouterInfo { from, ri_bytes } => {
                assert_eq!(from, bob_ident);
                let ri = FullRouterInfo::from_buffer(&ri_bytes).expect("peer RI parse");
                assert_eq!(ri.ident_hash(), &bob_ident);
            }
            message @ PoolEvent::Message { .. } => {
                panic!("expected PoolEvent::RouterInfo first, got {message:?}");
            }
            other => panic!("unexpected event {other:?}"),
        }

        // Alice → Bob через pool.
        let m1 = I2npMessage::new(I2npMessageType::Data, vec![1, 2, 3]);
        alice_pool.send_to(&bob_ident, m1).await.unwrap();

        let got = bob_session.recv_i2np().await.unwrap();
        assert_eq!(got.message_type(), I2npMessageType::Data);
        assert_eq!(got.payload(), &[1, 2, 3]);

        // Bob → Alice напрямую; Alice получает через pool.
        let m2 = I2npMessage::new(I2npMessageType::DeliveryStatus, vec![9]);
        bob_session.send_i2np(&m2).await.unwrap();

        let message = recv_message_from(&alice_pool, bob_ident).await;
        assert_eq!(message.message_type(), I2npMessageType::DeliveryStatus);
        assert_eq!(message.payload(), &[9]);
    }

    /// `connect_to` игнорирует адрес из RI (он недоступен) и идёт по
    /// заданному — так же, как `Ssu2Pool::connect_to` в live-тестах.
    #[tokio::test]
    async fn pool_connect_to_uses_explicit_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x55, server_addr);
        // Опубликован заведомо недоступный порт (1).
        let bob = Side::with_published(0x66, "127.0.0.1:1".parse().expect("bogus addr"));
        let bob_ident = bob.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        let alice_pool = Ntcp2Pool::new();
        alice_pool.set_local(Arc::new(alice.local()));
        let ident = alice_pool
            .connect_to(&bob_ri_bytes, server_addr)
            .await
            .expect("pool.connect_to");

        assert_eq!(ident, bob_ident);
        assert!(alice_pool.has_session(&bob_ident).await);
        assert!(bob_task.await.unwrap().is_ok());
    }

    /// Закрытие: `Termination(NormalClose)` уходит peer'у, событие
    /// `Disconnected` — ровно одно, сессия исчезает из карты.
    #[tokio::test]
    async fn pool_close_sends_termination_and_emits_disconnected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x77, server_addr);
        let bob = Side::new(0x88, server_addr);
        let bob_ident = bob.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        let alice_pool = Ntcp2Pool::new();
        alice_pool.set_local(Arc::new(alice.local()));
        alice_pool.connect(&bob_ri_bytes).await.unwrap();
        let bob_session = bob_task.await.unwrap().expect("bob handshake");
        let (mut bob_read, _bob_write) = bob_session.split();

        assert!(alice_pool.remove_session(&bob_ident).await);
        assert!(!alice_pool.has_session(&bob_ident).await);
        assert!(
            !alice_pool.remove_session(&bob_ident).await,
            "повторное закрытие — false"
        );
        // Повторное закрытие не должно прислать второе событие.

        recv_disconnected(&alice_pool, bob_ident).await;

        // Bob читает `Termination` из фрейма: сначала свой RI он уже
        // отправил, теперь ждём блок в data phase.
        let block = read_until(&mut bob_read, |b| {
            matches!(b, Ntcp2Block::Termination { .. })
        })
        .await;
        match block {
            Ntcp2Block::Termination { reason, .. } => {
                assert_eq!(reason, Ntcp2TerminationReason::NormalClose);
            }
            other => panic!("expected Termination, got {other:?}"),
        }
    }

    /// `Termination` от peer'а — тоже `Disconnected`, без ответа.
    #[tokio::test]
    async fn pool_peer_termination_emits_disconnected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x99, server_addr);
        let bob = Side::new(0xAA, server_addr);
        let bob_ident = bob.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        let alice_pool = Ntcp2Pool::new();
        alice_pool.set_local(Arc::new(alice.local()));
        alice_pool.connect(&bob_ri_bytes).await.unwrap();
        let bob_session = bob_task.await.unwrap().expect("bob handshake");
        let (_read, mut write) = bob_session.split();

        write
            .send_termination(Ntcp2TerminationReason::NormalClose)
            .await
            .unwrap();

        recv_disconnected(&alice_pool, bob_ident).await;
        // Сессия убрана из карты задачей, а не нами.
        assert!(!alice_pool.has_session(&bob_ident).await);
    }

    #[tokio::test]
    async fn pool_send_to_unknown_peer_fails() {
        let pool = Ntcp2Pool::new();
        let unknown = IdentHash::from_array([0xAB; 32]);
        let m = I2npMessage::new(I2npMessageType::Data, vec![]);

        let r = pool.send_to(&unknown, m).await;
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }

    #[tokio::test]
    async fn pool_remove_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x33, server_addr);
        let bob = Side::new(0x44, server_addr);
        let bob_ident = bob.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        let alice_pool = Ntcp2Pool::new();
        alice_pool.set_local(Arc::new(alice.local()));
        alice_pool.connect(&bob_ri_bytes).await.unwrap();
        assert!(alice_pool.has_session(&bob_ident).await);

        // Удаляем.
        assert!(alice_pool.remove_session(&bob_ident).await);
        assert!(!alice_pool.has_session(&bob_ident).await);
        // Повторное удаление — no-op.
        assert!(!alice_pool.remove_session(&bob_ident).await);

        // Bob-задача сама завершится, когда listener/stream закроются.
        let _ = bob_task.await;
    }

    /// Повторный `connect` к тому же пиру не создаёт вторую сессию
    /// (i2pd `AddNTCP2Session` для исходящей отвергает новую).
    #[tokio::test]
    async fn pool_connect_skips_when_session_exists() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x0b, server_addr);
        let bob = Side::new(0x0c, server_addr);
        let bob_ident = bob.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        let alice_pool = Ntcp2Pool::new();
        alice_pool.set_local(Arc::new(alice.local()));
        alice_pool.connect(&bob_ri_bytes).await.unwrap();
        let second = alice_pool
            .connect(&bob_ri_bytes)
            .await
            .expect("повторный connect");
        assert_eq!(second, bob_ident);
        assert_eq!(alice_pool.len().await, 1);
        assert!(bob_task.await.unwrap().is_ok());
    }

    /// Приём: пул поднимает listener и обслуживает входящую сессию —
    /// `Established`, обмен I2NP в обе стороны.
    #[tokio::test]
    async fn pool_listen_accepts_incoming() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let bob = Side::new(0x21, server_addr);
        let alice = Side::new(0x22, server_addr);
        let alice_ident = alice.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_pool = Ntcp2Pool::new();
        // Loopback — reserved-адрес; для теста включаем приём.
        bob_pool.set_local(Arc::new(bob.local().with_accept_reserved(true)));
        bob_pool.listen(listener).expect("pool.listen");

        // Alice звонит сама, руками.
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let mut alice_session = Ntcp2Session::connect(stream, &alice.config(), &bob_ri_bytes)
            .await
            .expect("alice handshake");

        // Пул (Bob) сообщает об установке.
        let ident = recv_established(&bob_pool).await;
        assert_eq!(ident, alice_ident);
        assert_eq!(bob_pool.len().await, 1);

        // Alice → Bob.
        let m1 = I2npMessage::new(I2npMessageType::Data, vec![7, 8]);
        alice_session.send_i2np(&m1).await.unwrap();
        let got = recv_message_from(&bob_pool, alice_ident).await;
        assert_eq!(got.message_type(), I2npMessageType::Data);
        assert_eq!(got.payload(), &[7, 8]);

        // Bob → Alice через пул.
        let m2 = I2npMessage::new(I2npMessageType::DeliveryStatus, vec![5]);
        bob_pool.send_to(&alice_ident, m2).await.unwrap();
        let got = alice_session.recv_i2np().await.unwrap();
        assert_eq!(got.message_type(), I2npMessageType::DeliveryStatus);
        assert_eq!(got.payload(), &[5]);
    }

    /// `listen` без локальной идентичности — ошибка (i2pd не поднял бы
    /// сервер без ключей).
    #[tokio::test]
    async fn pool_listen_without_local_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool = Ntcp2Pool::new();
        let result = pool.listen(listener);
        assert!(matches!(result, Err(I2PError::Unsupported(_))));
    }

    /// Входящее с reserved-адреса (loopback) отвергается, пока
    /// `accept_reserved` выключен (i2pd `Transports::IsInReservedRange`).
    #[tokio::test]
    async fn pool_listen_rejects_reserved_source() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let bob = Side::new(0x31, server_addr);
        let alice = Side::new(0x32, server_addr);
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_pool = Ntcp2Pool::new();
        bob_pool.set_local(Arc::new(bob.local())); // accept_reserved = false
        bob_pool.listen(listener).expect("pool.listen");

        let stream = TcpStream::connect(server_addr).await.unwrap();
        let result = Ntcp2Session::connect(stream, &alice.config(), &bob_ri_bytes).await;
        assert!(
            result.is_err(),
            "входящее с loopback должно быть отвергнуто"
        );
        assert!(bob_pool.is_empty().await);
    }

    /// Idle-таймаут: сессия без активности получает
    /// `Termination(IdleTimeout)` и уходит из карты.
    #[tokio::test]
    async fn pool_idle_timeout_terminates_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x41, server_addr);
        let bob = Side::new(0x42, server_addr);
        let bob_ident = bob.ident_hash();
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        let alice_pool = Ntcp2Pool::with_timers(fast_timers());
        alice_pool.set_local(Arc::new(alice.local()));
        alice_pool.connect(&bob_ri_bytes).await.unwrap();
        let bob_session = bob_task.await.unwrap().expect("bob handshake");
        let (mut bob_read, _bob_write) = bob_session.split();

        // Bob молчит — Alice шлёт Termination(IdleTimeout).
        let block = read_until(&mut bob_read, |b| {
            matches!(b, Ntcp2Block::Termination { .. })
        })
        .await;
        match block {
            Ntcp2Block::Termination { reason, .. } => {
                assert_eq!(reason, Ntcp2TerminationReason::IdleTimeout);
            }
            other => panic!("expected Termination, got {other:?}"),
        }

        recv_disconnected(&alice_pool, bob_ident).await;
        assert!(!alice_pool.has_session(&bob_ident).await);
    }

    /// Плановый повтор своего RI: раз в интервал сессия шлёт
    /// `RouterInfo` ещё раз (i2pd `SendLocalRouterInfo(update = true)`).
    #[tokio::test]
    async fn pool_resends_router_info() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let alice = Side::new(0x51, server_addr);
        let alice_ident = alice.ident_hash();
        let bob = Side::new(0x52, server_addr);
        let bob_ri_bytes = bob.ri_bytes.clone();

        let bob_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let cfg = bob.config();
            Ntcp2Session::accept(stream, &cfg).await
        });

        let timers = Ntcp2Timers {
            router_info_resend_interval: Duration::from_millis(60),
            router_info_resend_variance: Duration::ZERO,
            termination_timeout: Duration::from_secs(60),
            ..fast_timers()
        };
        let alice_pool = Ntcp2Pool::with_timers(timers);
        alice_pool.set_local(Arc::new(alice.local()));
        alice_pool.connect(&bob_ri_bytes).await.unwrap();
        let bob_session = bob_task.await.unwrap().expect("bob handshake");
        let (mut bob_read, _bob_write) = bob_session.split();

        let block = read_until(&mut bob_read, |b| {
            matches!(b, Ntcp2Block::RouterInfo { .. })
        })
        .await;
        match block {
            Ntcp2Block::RouterInfo { ri_bytes, .. } => {
                let ri = FullRouterInfo::from_buffer(&ri_bytes).expect("RI parse");
                assert_eq!(ri.ident_hash(), &alice_ident);
            }
            other => panic!("expected RouterInfo, got {other:?}"),
        }
    }
}

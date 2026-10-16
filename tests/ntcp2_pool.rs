#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use uu_i2p::{
        I2PError, I2PTag, IdentHash, Ntcp2Pool, PoolEvent,
        crypto::I2PX25519Keys,
        i2np::I2npMessageType,
        i2np_message::I2npMessage,
        ntcp2::{Ntcp2LocalConfig, Ntcp2Session},
        private_keys::I2PPrivateKeys,
        router_info::{FullRouterInfo, RouterInfo},
        router_info_address::I2PAddress,
    };

    struct Side {
        keys: I2PPrivateKeys,
        ntcp2_static: I2PX25519Keys,
        ntcp2_iv: [u8; 16],
        ri_bytes: Vec<u8>,
    }

    impl Side {
        /// `socket_addr` — реальный адрес listener'а; используется
        /// в `Address::ntcp2_published`, чтобы remote мог подключиться.
        fn new(iv_byte: u8, socket_addr: SocketAddr) -> Self {
            let keys = I2PPrivateKeys::generate_default().unwrap();
            let ntcp2_static = I2PX25519Keys::generate();
            let ntcp2_iv = [iv_byte; 16];
            let mut static_bytes = [0u8; 32];
            static_bytes.copy_from_slice(ntcp2_static.public_key());
            let addr = I2PAddress::ntcp2_published(
                socket_addr.ip(),
                socket_addr.port(),
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
    }

    /// Ждёт первое `PoolEvent::Message` от указанного пира, пропуская
    /// `PoolEvent::RouterInfo` (их шлёт responder сразу после handshake —
    /// поведение i2pd: `Transports::PeerConnected` → `SendLocalRouterInfo`).
    ///
    /// В проде эти события поглощает `RouterContext`, кладя RI в netdb.
    /// Пул сам в netdb не ходит, поэтому транслирует их наружу.
    async fn recv_message_from(pool: &Ntcp2Pool, expected_from: IdentHash) -> I2npMessage {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
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
        let alice_cfg = alice.config();
        let connected_ident = alice_pool
            .connect(&alice_cfg, &bob_ri_bytes)
            .await
            .expect("pool.connect");

        assert_eq!(connected_ident, bob_ident);
        assert!(alice_pool.has_session(&bob_ident).await);
        assert_eq!(alice_pool.len().await, 1);

        // Ждём завершения handshake на стороне Bob'а.
        let mut bob_session = bob_task.await.unwrap().expect("bob handshake");

        // Bob (responder) сразу после handshake отослал свой RI
        // отдельным фреймом — как i2pd `SendLocalRouterInfo`.
        // Забираем его из очереди сейчас, чтобы дальше получать
        // только I2NP-сообщения.
        let ri_event = alice_pool.next_event().await.unwrap();
        match ri_event {
            PoolEvent::RouterInfo { from, ri_bytes } => {
                assert_eq!(from, bob_ident);
                let ri = FullRouterInfo::from_buffer(&ri_bytes).expect("peer RI parse");
                assert_eq!(ri.ident_hash(), &bob_ident);
            }
            message @ PoolEvent::Message { .. } => {
                panic!("expected PoolEvent::RouterInfo first, got {message:?}");
            }
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
        let alice_cfg = alice.config();
        alice_pool.connect(&alice_cfg, &bob_ri_bytes).await.unwrap();
        assert!(alice_pool.has_session(&bob_ident).await);

        // Удаляем.
        assert!(alice_pool.remove_session(&bob_ident).await);
        assert!(!alice_pool.has_session(&bob_ident).await);
        // Повторное удаление — no-op.
        assert!(!alice_pool.remove_session(&bob_ident).await);

        // Bob-задача сама завершится, когда listener/stream закроются.
        let _ = bob_task.await;
    }
}

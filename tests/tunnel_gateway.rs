#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use uu_i2p::tunnel_fragments::*;
    use uu_i2p::tunnel_gateway::TunnelGatewayBuffer;
    use uu_i2p::tunnel_messages::TunnelDataBody;
    use uu_i2p::{I2PError, IdentHash};

    fn rng() -> StdRng {
        StdRng::seed_from_u64(5)
    }

    /// I2NP-сообщение: 16-байтный заголовок с заданным `msg_id` и payload.
    fn i2np(id: u32, total_len: usize) -> Vec<u8> {
        assert!(total_len >= 16);
        let mut m: Vec<u8> = (0..total_len)
            .map(|i| u8::try_from((i * 7 + 3) & 0xFF).unwrap())
            .collect();
        m[0] = 10;
        m[1..5].copy_from_slice(&id.to_be_bytes());
        m
    }

    fn local(msg: Vec<u8>) -> TunnelMessageBlock {
        TunnelMessageBlock {
            delivery: Delivery::Local,
            message: msg,
        }
    }

    fn flush(buf: &mut TunnelGatewayBuffer, tunnel_id: u32) -> Vec<TunnelDataBody> {
        buf.flush(&mut rng(), tunnel_id, |m| Ok(m.clone())).unwrap()
    }

    /// Длина payload в tunnel-сообщении (после нулевого разделителя).
    fn payload_len(m: &TunnelDataBody) -> usize {
        let zero = m.encrypted[4..].iter().position(|&b| b == 0).unwrap() + 4;
        1008 - (zero + 1)
    }

    /// Простейшая сборка: возвращает завершённые сообщения по порядку
    /// завершения вместе со способом доставки.
    fn reassemble(msgs: &[TunnelDataBody]) -> Vec<(Delivery, Vec<u8>)> {
        let mut done = Vec::new();
        let mut open: BTreeMap<u32, (Delivery, Vec<u8>, u8)> = BTreeMap::new();
        for m in msgs {
            let parsed = parse_tunnel_message(m).unwrap();
            assert_eq!(parsed.error, None);
            // padding — ненулевые байты
            let start = 1008 - payload_len(m);
            assert!(m.encrypted[4..start - 1].iter().all(|&b| b != 0));
            for f in parsed.fragments {
                match f.kind {
                    FragmentKind::First {
                        delivery,
                        msg_id: None,
                    } => done.push((delivery, f.data)),
                    FragmentKind::First {
                        delivery,
                        msg_id: Some(id),
                    } => {
                        assert!(open.insert(id, (delivery, f.data, 1)).is_none());
                    }
                    FragmentKind::FollowOn {
                        msg_id,
                        fragment_num,
                        is_last,
                    } => {
                        let entry = open.get_mut(&msg_id).expect("first fragment seen");
                        assert_eq!(entry.2, fragment_num, "fragment order");
                        entry.1.extend_from_slice(&f.data);
                        entry.2 += 1;
                        if is_last {
                            let (d, data, _) = open.remove(&msg_id).unwrap();
                            done.push((d, data));
                        }
                    }
                }
            }
        }
        assert!(open.is_empty(), "unfinished messages: {:?}", open.keys());
        done
    }

    // ---- одно сообщение --------------------------------------------------------

    #[test]
    fn single_local_message() {
        let msg = i2np(1, 100);
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(msg.clone()), &mut rng()).unwrap();
        assert_eq!(buf.completed_len(), 0);
        assert!(buf.has_open_message());
        let out = flush(&mut buf, 0xAABB_CCDD);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tunnel_id, 0xAABB_CCDD);
        assert_eq!(payload_len(&out[0]), 1 + 2 + 100);
        assert_eq!(reassemble(&out), vec![(Delivery::Local, msg)]);
        assert!(!buf.has_open_message());
        assert_eq!(buf.completed_len(), 0);
    }

    #[test]
    fn delivery_instruction_sizes() {
        let msg = i2np(2, 50);
        let cases = [
            (Delivery::Local, 1 + 2 + 50),
            (
                Delivery::Tunnel {
                    tunnel_id: 77,
                    hash: IdentHash::from_array([3; 32]),
                },
                37 + 2 + 50,
            ),
            (
                Delivery::Router {
                    hash: IdentHash::from_array([4; 32]),
                },
                33 + 2 + 50,
            ),
        ];
        for (delivery, expected_payload) in cases {
            let mut buf = TunnelGatewayBuffer::new();
            let block = TunnelMessageBlock {
                delivery: delivery.clone(),
                message: msg.clone(),
            };
            buf.put_message(&block, &mut rng()).unwrap();
            let out = flush(&mut buf, 1);
            assert_eq!(payload_len(&out[0]), expected_payload);
            assert_eq!(reassemble(&out), vec![(delivery, msg.clone())]);
        }
    }

    #[test]
    fn empty_flush_returns_nothing() {
        let mut buf = TunnelGatewayBuffer::new();
        assert!(flush(&mut buf, 1).is_empty());
    }

    // ---- упаковка нескольких сообщений ---------------------------------------------

    #[test]
    fn small_messages_are_packed_together() {
        let msgs: Vec<Vec<u8>> = (0..3).map(|i| i2np(10 + i, 100)).collect();
        let mut buf = TunnelGatewayBuffer::new();
        for m in &msgs {
            buf.put_message(&local(m.clone()), &mut rng()).unwrap();
        }
        assert_eq!(buf.completed_len(), 0);
        let out = flush(&mut buf, 5);
        assert_eq!(out.len(), 1);
        assert_eq!(payload_len(&out[0]), 3 * (1 + 2 + 100));
        let got: Vec<Vec<u8>> = reassemble(&out).into_iter().map(|(_, d)| d).collect();
        assert_eq!(got, msgs);
    }

    #[test]
    fn exact_fit_completes_immediately() {
        // 1 (flag) + 2 (длина) + 1000 = 1003
        let msg = i2np(3, 1000);
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(msg.clone()), &mut rng()).unwrap();
        assert_eq!(buf.completed_len(), 1);
        assert!(!buf.has_open_message());
        let out = flush(&mut buf, 9);
        assert_eq!(out.len(), 1);
        assert_eq!(payload_len(&out[0]), 1003);
        assert_eq!(reassemble(&out), vec![(Delivery::Local, msg)]);
    }

    // ---- фрагментация ----------------------------------------------------------------

    #[test]
    fn fragmentation_of_3000_bytes() {
        let msg = i2np(0x1234_5678, 3000);
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(msg.clone()), &mut rng()).unwrap();
        let out = flush(&mut buf, 1);
        assert_eq!(out.len(), 4);

        let sizes: Vec<Vec<usize>> = out
            .iter()
            .map(|m| {
                parse_tunnel_message(m)
                    .unwrap()
                    .fragments
                    .iter()
                    .map(|f| f.data.len())
                    .collect()
            })
            .collect();
        // первый фрагмент: 1003 - 1 (flag) - 6 (msg_id + size) = 996
        assert_eq!(sizes, vec![vec![996], vec![996], vec![996], vec![12]]);
        assert_eq!(payload_len(&out[0]), 1003);
        assert_eq!(payload_len(&out[1]), 1003);
        assert_eq!(payload_len(&out[3]), 12 + 7);

        let first = &parse_tunnel_message(&out[0]).unwrap().fragments[0];
        assert_eq!(
            first.kind,
            FragmentKind::First {
                delivery: Delivery::Local,
                msg_id: Some(0x1234_5678)
            }
        );
        let last = &parse_tunnel_message(&out[3]).unwrap().fragments[0];
        assert_eq!(
            last.kind,
            FragmentKind::FollowOn {
                msg_id: 0x1234_5678,
                fragment_num: 3,
                is_last: true
            }
        );
        assert_eq!(reassemble(&out), vec![(Delivery::Local, msg)]);
    }

    #[test]
    fn tunnel_delivery_shrinks_first_fragment() {
        let msg = i2np(4, 2000);
        let block = TunnelMessageBlock {
            delivery: Delivery::Tunnel {
                tunnel_id: 5,
                hash: IdentHash::from_array([6; 32]),
            },
            message: msg.clone(),
        };
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&block, &mut rng()).unwrap();
        let out = flush(&mut buf, 1);
        // 1003 - 37 - 6 = 960
        let first = &parse_tunnel_message(&out[0]).unwrap().fragments[0];
        assert_eq!(first.data.len(), 960);
        assert_eq!(reassemble(&out), vec![(block.delivery, msg)]);
    }

    #[test]
    fn maximum_size_message_fits_in_63_fragments() {
        let msg = i2np(0xFEED_F00D, 62_708);
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(msg.clone()), &mut rng()).unwrap();
        let out = flush(&mut buf, 1);
        // 996 в первом + ceil(61712 / 996) = 62 продолжения
        assert_eq!(out.len(), 63);
        let last = &parse_tunnel_message(&out[62]).unwrap().fragments[0];
        assert!(matches!(
            last.kind,
            FragmentKind::FollowOn {
                fragment_num: 62,
                is_last: true,
                ..
            }
        ));
        assert_eq!(reassemble(&out), vec![(Delivery::Local, msg)]);
    }

    #[test]
    fn fragmented_message_follows_small_one_without_closing() {
        // A занимает 103 байта, остаток 900; хвост B помещается — не закрываем
        let a = i2np(1, 100);
        let b = i2np(2, 1500);
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(a.clone()), &mut rng()).unwrap();
        buf.put_message(&local(b.clone()), &mut rng()).unwrap();
        let out = flush(&mut buf, 1);
        assert_eq!(out.len(), 2);
        assert_eq!(payload_len(&out[0]), 1003); // A + начало B
        assert_eq!(payload_len(&out[1]), 7 + (1500 - 893));
        let got = reassemble(&out);
        assert_eq!(got[0].1, a);
        assert_eq!(got[1].1, b);
    }

    #[test]
    fn current_message_is_closed_when_tail_does_not_fit() {
        // A занимает 903 байта, остаток 100 < хвоста B — A закрывается
        let a = i2np(1, 900);
        let b = i2np(2, 1500);
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(a.clone()), &mut rng()).unwrap();
        buf.put_message(&local(b.clone()), &mut rng()).unwrap();
        assert_eq!(buf.completed_len(), 2); // A закрыто, первый фрагмент B закрыт
        let out = flush(&mut buf, 1);
        assert_eq!(out.len(), 3);
        assert_eq!(payload_len(&out[0]), 903);
        assert_eq!(payload_len(&out[1]), 1003);
        assert_eq!(payload_len(&out[2]), 7 + 504);
        let got = reassemble(&out);
        assert_eq!(got[0].1, a);
        assert_eq!(got[1].1, b);
    }

    #[test]
    fn many_mixed_messages_roundtrip() {
        let sizes = [
            16usize, 17, 200, 999, 1000, 1001, 1002, 1500, 2100, 5000, 40, 3000,
        ];
        let msgs: Vec<Vec<u8>> = sizes
            .iter()
            .enumerate()
            .map(|(i, &s)| i2np(u32::try_from(i).unwrap() + 100, s))
            .collect();
        let mut buf = TunnelGatewayBuffer::new();
        for m in &msgs {
            buf.put_message(&local(m.clone()), &mut rng()).unwrap();
        }
        let out = flush(&mut buf, 1);
        let got: Vec<Vec<u8>> = reassemble(&out).into_iter().map(|(_, d)| d).collect();
        assert_eq!(got, msgs);
    }

    #[test]
    fn mixed_delivery_types_roundtrip() {
        let blocks = vec![
            TunnelMessageBlock {
                delivery: Delivery::Router {
                    hash: IdentHash::from_array([1; 32]),
                },
                message: i2np(1, 700),
            },
            TunnelMessageBlock {
                delivery: Delivery::Tunnel {
                    tunnel_id: 9,
                    hash: IdentHash::from_array([2; 32]),
                },
                message: i2np(2, 1800),
            },
            local(i2np(3, 60)),
        ];
        let mut buf = TunnelGatewayBuffer::new();
        for b in &blocks {
            buf.put_message(b, &mut rng()).unwrap();
        }
        let out = flush(&mut buf, 1);
        let got = reassemble(&out);
        let expected: Vec<(Delivery, Vec<u8>)> = blocks
            .into_iter()
            .map(|b| (b.delivery, b.message))
            .collect();
        assert_eq!(got, expected);
    }

    // ---- валидация ---------------------------------------------------------------------

    #[test]
    fn invalid_sizes_rejected_and_buffer_untouched() {
        let mut buf = TunnelGatewayBuffer::new();
        assert!(matches!(
            buf.put_message(&local(vec![0u8; 15]), &mut rng()),
            Err(I2PError::Malformed(_))
        ));
        assert!(
            buf.put_message(&local(vec![0u8; 62_709]), &mut rng())
                .is_err()
        );
        assert!(!buf.has_open_message());
        assert_eq!(buf.completed_len(), 0);
        // 62708 допустимо
        assert!(buf.put_message(&local(i2np(1, 62_708)), &mut rng()).is_ok());
    }

    // ---- flush ---------------------------------------------------------------------------

    #[test]
    fn flush_encrypts_each_message_and_sets_tunnel_id() {
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(i2np(1, 3000)), &mut rng()).unwrap();
        let mut calls = 0;
        let out = buf
            .flush(&mut rng(), 0xCAFE, |m| {
                calls += 1;
                let mut e = m.clone();
                e.iv[0] ^= 0xFF;
                Ok(e)
            })
            .unwrap();
        assert_eq!(calls, 4);
        assert_eq!(out.len(), 4);
        assert!(out.iter().all(|m| m.tunnel_id == 0xCAFE));
        // шифрование реально применено: контрольная сумма больше не сходится
        assert!(parse_tunnel_message(&out[0]).is_err());
    }

    #[test]
    fn flush_propagates_encrypt_error() {
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(i2np(1, 100)), &mut rng()).unwrap();
        let r = buf.flush(&mut rng(), 1, |_| Err(I2PError::Malformed("boom")));
        assert!(matches!(r, Err(I2PError::Malformed("boom"))));
    }

    #[test]
    fn second_flush_returns_only_new_messages() {
        let mut buf = TunnelGatewayBuffer::new();
        buf.put_message(&local(i2np(1, 100)), &mut rng()).unwrap();
        assert_eq!(flush(&mut buf, 1).len(), 1);
        buf.put_message(&local(i2np(2, 100)), &mut rng()).unwrap();
        let out = flush(&mut buf, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(reassemble(&out)[0].1, i2np(2, 100));
    }

    #[test]
    fn output_is_deterministic_for_same_seed() {
        let run = |seed: u64| {
            let mut buf = TunnelGatewayBuffer::new();
            let mut r = StdRng::seed_from_u64(seed);
            buf.put_message(&local(i2np(1, 1500)), &mut r).unwrap();
            buf.flush(&mut r, 1, |m| Ok(m.clone())).unwrap()
        };
        assert_eq!(run(1), run(1));
        assert_ne!(run(1), run(2));
    }
}

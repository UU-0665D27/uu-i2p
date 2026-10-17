#[cfg(test)]
mod tests {
    use uu_i2p::{
        error::I2PError,
        ssu2_crypto::DataPhaseKey,
        ssu2_data::{SSU2_DATA_OVERHEAD, decode_data_packet, encode_data_packet},
        ssu2_header::{ConnectionId, SSU2_MIN_PACKET_SIZE, ShortHeader, Ssu2MessageType},
    };

    // ---- helpers --------------------------------------------------------

    fn hx(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        let d = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("bad hex"),
            }
        };
        s.as_bytes()
            .chunks(2)
            .map(|p| (d(p[0]) << 4) | d(p[1]))
            .collect()
    }

    fn key() -> DataPhaseKey {
        DataPhaseKey {
            k_data: [0x22; 32],
            k_header_2: [0x33; 32],
        }
    }

    fn data_header(packet_num: u32, flags: u8) -> ShortHeader {
        ShortHeader {
            dest_conn_id: ConnectionId([1, 2, 3, 4, 5, 6, 7, 8]),
            packet_num,
            msg_type: Ssu2MessageType::Data,
            flags: [flags, 0, 0],
        }
    }

    // ---- golden vector --------------------------------------------------

    /// Вектор сгенерирован независимо (Python `cryptography`, `ChaCha20` +
    /// `ChaCha20-Poly1305`) — см. `gen_data_vector.py`.
    const GOLDEN_PACKET: &str =
        "ffe4f1f6f070560543c93620204acd85a2a5c24964f6a016aa6f394483377a167ce607d15c9a875a";

    #[test]
    fn golden_data_packet_matches_independent_vector() {
        let intro = [0x11u8; 32];
        let payload: Vec<u8> = (0..8).collect();
        let header = data_header(0x0A0B_0C0D, 0x01);
        let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
        let n = encode_data_packet(&header, &intro, &key(), &payload, &mut out).unwrap();
        assert_eq!(n, 40);
        assert_eq!(out, hx(GOLDEN_PACKET));

        // Разбор того же вектора.
        let mut packet = hx(GOLDEN_PACKET);
        let mut plain = vec![0u8; payload.len()];
        let (parsed, got) = decode_data_packet(&mut packet, &intro, &key(), &mut plain).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(got, &payload[..]);
    }

    // ---- roundtrip ------------------------------------------------------

    #[test]
    fn data_packet_roundtrip_arbitrary_payload() {
        let intro = [0xAB; 32];
        let payload: Vec<u8> = (0..200u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let header = data_header(0xDEAD_BEEF, 0);
        let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
        let n = encode_data_packet(&header, &intro, &key(), &payload, &mut out).unwrap();
        assert_eq!(n, payload.len() + SSU2_DATA_OVERHEAD);

        let mut plain = vec![0u8; payload.len()];
        let (parsed, got) = decode_data_packet(&mut out, &intro, &key(), &mut plain).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(got, &payload[..]);
    }

    #[test]
    fn data_packet_header_is_obfuscated() {
        let intro = [0x11u8; 32];
        let payload = [0u8; 8];
        let header = data_header(1, 0);
        let plain_header = header.to_bytes();
        let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
        encode_data_packet(&header, &intro, &key(), &payload, &mut out).unwrap();
        // Первые 16 байт на wire отличаются от незашифрованного заголовка.
        assert_ne!(out[..16], plain_header[..]);
    }

    #[test]
    fn data_packet_preserves_flags() {
        let intro = [0x77; 32];
        let payload = [0xAAu8; 8];
        let mut header = data_header(7, 0);
        header.set_immediate_ack_requested(true);
        let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
        encode_data_packet(&header, &intro, &key(), &payload, &mut out).unwrap();

        let mut packet = out.clone();
        let mut plain = vec![0u8; payload.len()];
        let (parsed, _) = decode_data_packet(&mut packet, &intro, &key(), &mut plain).unwrap();
        assert!(parsed.immediate_ack_requested());
        assert_eq!(parsed, header);
    }

    // ---- границы и ошибки ----------------------------------------------

    #[test]
    fn data_packet_min_payload_length() {
        let intro = [0u8; 32];
        let key = key();
        // payload = 8 -> ровно минимум 40.
        let mut out = vec![0u8; 40];
        assert!(encode_data_packet(&data_header(1, 0), &intro, &key, &[0u8; 8], &mut out).is_ok());
        // payload = 7 -> 39 < 40.
        let mut out = vec![0u8; 64];
        assert!(matches!(
            encode_data_packet(&data_header(1, 0), &intro, &key, &[0u8; 7], &mut out),
            Err(I2PError::InvalidLength {
                expected: 40,
                got: 39
            })
        ));
    }

    #[test]
    fn data_packet_rejects_non_data_type() {
        let intro = [0u8; 32];
        let mut header = data_header(1, 0);
        header.msg_type = Ssu2MessageType::SessionConfirmed;
        let mut out = vec![0u8; 64];
        assert!(matches!(
            encode_data_packet(&header, &intro, &key(), &[0u8; 8], &mut out),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn data_packet_encode_out_too_small() {
        let intro = [0u8; 32];
        let mut out = vec![0u8; 41]; // нужно 48 для payload 16
        assert!(matches!(
            encode_data_packet(&data_header(1, 0), &intro, &key(), &[0u8; 16], &mut out),
            Err(I2PError::InvalidLength {
                expected: 48,
                got: 41
            })
        ));
    }

    #[test]
    fn decode_rejects_short_packet() {
        let intro = [0u8; 32];
        let mut packet = vec![0u8; SSU2_MIN_PACKET_SIZE - 1];
        let mut plain = vec![0u8; 64];
        assert!(matches!(
            decode_data_packet(&mut packet, &intro, &key(), &mut plain),
            Err(I2PError::InvalidLength {
                expected: 40,
                got: 39
            })
        ));
    }

    #[test]
    fn decode_rejects_tampered_ciphertext() {
        let intro = [0x11u8; 32];
        let payload = [0u8; 8];
        let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
        encode_data_packet(&data_header(1, 0), &intro, &key(), &payload, &mut out).unwrap();

        // Портим байт в AEAD-ciphertext (после 16-байтового заголовка).
        out[16 + 5] ^= 0xFF;
        let mut plain = vec![0u8; payload.len()];
        assert!(matches!(
            decode_data_packet(&mut out, &intro, &key(), &mut plain),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn decode_rejects_wrong_key() {
        let intro = [0x11u8; 32];
        let payload = [0u8; 8];
        let mut out = vec![0u8; payload.len() + SSU2_DATA_OVERHEAD];
        encode_data_packet(&data_header(1, 0), &intro, &key(), &payload, &mut out).unwrap();

        let wrong = DataPhaseKey {
            k_data: [0x44; 32],
            k_header_2: [0x33; 32],
        };
        let mut plain = vec![0u8; payload.len()];
        assert!(matches!(
            decode_data_packet(&mut out, &intro, &wrong, &mut plain),
            Err(I2PError::Malformed(_))
        ));
    }
}

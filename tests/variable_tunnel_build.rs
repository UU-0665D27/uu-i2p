#[cfg(test)]
mod tests {
    use uu_i2p::I2PError;
    use uu_i2p::variable_tunnel_build::*;

    fn record(n: u8) -> EncryptedLongRecord {
        EncryptedLongRecord {
            to_peer: [n; 16],
            ephemeral_key: [n.wrapping_add(1); 32],
            ciphertext: [n.wrapping_add(2); 480],
        }
    }

    fn body(n: u8) -> VariableTunnelBuildBody {
        VariableTunnelBuildBody::new((0..n).map(record).collect()).unwrap()
    }

    #[test]
    fn constants() {
        assert_eq!(TUNNEL_BUILD_RECORD_SIZE, 528);
        assert_eq!(
            LONG_RECORD_TO_PEER_SIZE + LONG_RECORD_EPHEMERAL_SIZE + LONG_RECORD_CIPHERTEXT_SIZE,
            528
        );
    }

    #[test]
    fn record_layout_and_roundtrip() {
        let mut raw = [0u8; 528];
        raw[..16].fill(1);
        raw[16..48].fill(2);
        raw[48..].fill(3);
        let r = EncryptedLongRecord::from_bytes(&raw).unwrap();
        assert_eq!(r.to_peer, [1; 16]);
        assert_eq!(r.ephemeral_key, [2; 32]);
        assert_eq!(r.ciphertext, [3; 480]);
        assert_eq!(r.to_bytes(), raw);
    }

    #[test]
    fn record_wrong_length() {
        assert_eq!(
            EncryptedLongRecord::from_bytes(&[0; 527]),
            Err(I2PError::InvalidLength {
                expected: 528,
                got: 527
            })
        );
    }

    #[test]
    fn body_roundtrip_0_to_8() {
        for n in 0..=8u8 {
            let b = body(n);
            let buf = b.to_buffer().unwrap();
            assert_eq!(buf.len(), 1 + usize::from(n) * 528);
            assert_eq!(buf.len(), b.wire_size());
            assert_eq!(buf[0], n);
            assert_eq!(VariableTunnelBuildBody::from_buffer(&buf).unwrap(), b);
        }
    }

    #[test]
    fn body_golden_second_record_offset() {
        let buf = body(2).to_buffer().unwrap();
        assert_eq!(&buf[1 + 528..1 + 528 + 16], &[1u8; 16]);
    }

    #[test]
    fn body_trailing_ignored() {
        let b = body(2);
        let mut buf = b.to_buffer().unwrap();
        buf.extend_from_slice(&[0xFF; 7]);
        assert_eq!(VariableTunnelBuildBody::from_buffer(&buf).unwrap(), b);
    }

    #[test]
    fn body_errors() {
        assert_eq!(
            VariableTunnelBuildBody::from_buffer(&[]),
            Err(I2PError::InvalidLength {
                expected: 1,
                got: 0
            })
        );
        let mut buf = vec![9u8];
        buf.extend(vec![0u8; 9 * 528]);
        assert!(matches!(
            VariableTunnelBuildBody::from_buffer(&buf),
            Err(I2PError::Malformed(_))
        ));
        let mut buf = body(2).to_buffer().unwrap();
        buf.pop();
        assert_eq!(
            VariableTunnelBuildBody::from_buffer(&buf),
            Err(I2PError::InvalidLength {
                expected: 1 + 2 * 528,
                got: 1 + 2 * 528 - 1
            })
        );
    }

    #[test]
    fn body_new_and_to_buffer_reject_nine() {
        let recs: Vec<_> = (0..9).map(record).collect();
        assert!(VariableTunnelBuildBody::new(recs.clone()).is_err());
        let b = VariableTunnelBuildBody { records: recs };
        assert!(b.to_buffer().is_err());
    }
}

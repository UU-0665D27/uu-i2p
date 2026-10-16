#[cfg(test)]
mod tests {
    use uu_i2p::short_tunnel_build::*;
    use uu_i2p::tunnel_build_record::{
        EncryptedShortRecord, NUM_TUNNEL_BUILD_RECORDS, SHORT_TUNNEL_BUILD_RECORD_SIZE,
    };
    use uu_i2p::{I2PError, IdentHash};

    fn record(n: u8) -> EncryptedShortRecord {
        EncryptedShortRecord {
            to_peer: [n; 16],
            ephemeral_key: [n.wrapping_add(1); 32],
            ciphertext: [n.wrapping_add(2); 170],
        }
    }

    fn body(n: u8) -> ShortTunnelBuildBody {
        ShortTunnelBuildBody::new((0..n).map(record).collect()).unwrap()
    }

    #[test]
    fn header_size_constant() {
        assert_eq!(SHORT_TUNNEL_BUILD_HEADER_SIZE, 1);
    }

    #[test]
    fn empty_body_golden() {
        let b = ShortTunnelBuildBody::default();
        assert_eq!(b.to_buffer().unwrap(), vec![0]);
        assert_eq!(b.wire_size(), 1);
    }

    #[test]
    fn golden_layout() {
        let b = body(2);
        let buf = b.to_buffer().unwrap();
        assert_eq!(buf.len(), 1 + 2 * 218);
        assert_eq!(buf[0], 2);
        assert_eq!(&buf[1..17], &[0u8; 16]); // to_peer первой записи (n=0)
        assert_eq!(&buf[1 + 218..1 + 218 + 16], &[1u8; 16]); // второй (n=1)
        assert_eq!(buf.len(), b.wire_size());
    }

    #[test]
    fn roundtrip_various_counts() {
        for n in 0..=u8::try_from(NUM_TUNNEL_BUILD_RECORDS).unwrap() {
            let b = body(n);
            let buf = b.to_buffer().unwrap();
            assert_eq!(
                buf.len(),
                1 + usize::from(n) * SHORT_TUNNEL_BUILD_RECORD_SIZE
            );
            assert_eq!(ShortTunnelBuildBody::from_buffer(&buf).unwrap(), b);
        }
    }

    #[test]
    fn trailing_bytes_ignored() {
        let b = body(3);
        let mut buf = b.to_buffer().unwrap();
        buf.extend_from_slice(&[0xFF; 50]);
        assert_eq!(ShortTunnelBuildBody::from_buffer(&buf).unwrap(), b);
    }

    #[test]
    fn empty_buffer_invalid() {
        assert_eq!(
            ShortTunnelBuildBody::from_buffer(&[]),
            Err(I2PError::InvalidLength {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn too_many_records_on_parse() {
        let mut buf = vec![9u8];
        buf.extend(vec![0u8; 9 * 218]);
        assert!(matches!(
            ShortTunnelBuildBody::from_buffer(&buf),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn truncated_buffer() {
        let mut buf = body(2).to_buffer().unwrap();
        buf.pop();
        assert_eq!(
            ShortTunnelBuildBody::from_buffer(&buf),
            Err(I2PError::InvalidLength {
                expected: 1 + 2 * 218,
                got: 1 + 2 * 218 - 1,
            })
        );
    }

    #[test]
    fn count_without_records_is_truncated() {
        assert_eq!(
            ShortTunnelBuildBody::from_buffer(&[1]),
            Err(I2PError::InvalidLength {
                expected: 219,
                got: 1
            })
        );
    }

    #[test]
    fn new_rejects_too_many() {
        let recs: Vec<_> = (0..9).map(record).collect();
        assert!(matches!(
            ShortTunnelBuildBody::new(recs),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn to_buffer_rejects_too_many_via_public_field() {
        let b = ShortTunnelBuildBody {
            records: (0..9).map(record).collect(),
        };
        assert!(matches!(b.to_buffer(), Err(I2PError::Malformed(_))));
    }

    #[test]
    fn find_record_for_ident() {
        let b = body(4);
        let (idx, rec) = b
            .find_record_for(&IdentHash::from_array([2; 32]))
            .expect("record for ident 2");
        assert_eq!(idx, 2);
        assert_eq!(rec.to_peer, [2; 16]);
        assert!(b.find_record_for(&IdentHash::from_array([9; 32])).is_none());
    }

    #[test]
    fn find_record_returns_first_of_duplicates() {
        let b = ShortTunnelBuildBody::new(vec![record(5), record(6), record(5)]).unwrap();
        let (idx, _) = b.find_record_for(&IdentHash::from_array([5; 32])).unwrap();
        assert_eq!(idx, 0);
    }
}

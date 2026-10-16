#[cfg(test)]
mod tests {
    use uu_i2p::I2PError;
    use uu_i2p::tunnel_messages::*;

    fn tunnel_data() -> TunnelDataBody {
        TunnelDataBody {
            tunnel_id: 0x0102_0304,
            iv: [0x11; 16],
            encrypted: Box::new([0x22; 1008]),
        }
    }

    // ---- constants ------------------------------------------------------

    #[test]
    fn constants() {
        assert_eq!(TUNNEL_DATA_MSG_SIZE, 1028);
        assert_eq!(4 + TUNNEL_DATA_IV_SIZE + TUNNEL_DATA_ENCRYPTED_SIZE, 1028);
        assert_eq!(TUNNEL_GATEWAY_HEADER_SIZE, 6);
        assert_eq!(TUNNEL_TEST_SIZE, 12);
    }

    // ---- TunnelData -----------------------------------------------------

    #[test]
    fn tunnel_data_golden() {
        let buf = tunnel_data().to_buffer();
        assert_eq!(buf.len(), 1028);
        assert_eq!(&buf[0..4], &[1, 2, 3, 4]);
        assert_eq!(&buf[4..20], &[0x11; 16]);
        assert!(buf[20..].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn tunnel_data_roundtrip() {
        let b = tunnel_data();
        assert_eq!(TunnelDataBody::from_buffer(&b.to_buffer()).unwrap(), b);
    }

    #[test]
    fn tunnel_data_short_buffer() {
        assert_eq!(
            TunnelDataBody::from_buffer(&[0u8; 1027]),
            Err(I2PError::InvalidLength {
                expected: 1028,
                got: 1027
            })
        );
    }

    #[test]
    fn tunnel_data_trailing_ignored() {
        let b = tunnel_data();
        let mut buf = b.to_buffer();
        buf.extend_from_slice(&[0xFF; 10]);
        assert_eq!(TunnelDataBody::from_buffer(&buf).unwrap(), b);
    }

    // ---- TunnelGateway --------------------------------------------------

    #[test]
    fn gateway_golden() {
        let b = TunnelGatewayBody {
            tunnel_id: 0xAABB_CCDD,
            data: vec![9, 8, 7],
        };
        assert_eq!(
            b.to_buffer().unwrap(),
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x03, 9, 8, 7]
        );
    }

    #[test]
    fn gateway_roundtrip_and_empty() {
        for data in [vec![], vec![1u8; 1], vec![0x55; 1000]] {
            let b = TunnelGatewayBody { tunnel_id: 7, data };
            let buf = b.to_buffer().unwrap();
            assert_eq!(TunnelGatewayBody::from_buffer(&buf).unwrap(), b);
        }
    }

    #[test]
    fn gateway_trailing_ignored() {
        let mut buf = vec![0, 0, 0, 1, 0, 2, 0xAA, 0xBB, 0xCC, 0xDD];
        let b = TunnelGatewayBody::from_buffer(&buf).unwrap();
        assert_eq!(b.data, vec![0xAA, 0xBB]);
        buf.truncate(8);
        assert_eq!(TunnelGatewayBody::from_buffer(&buf).unwrap(), b);
    }

    #[test]
    fn gateway_errors() {
        assert_eq!(
            TunnelGatewayBody::from_buffer(&[0; 5]),
            Err(I2PError::InvalidLength {
                expected: 6,
                got: 5
            })
        );
        // length=3, но данных 2
        assert!(matches!(
            TunnelGatewayBody::from_buffer(&[0, 0, 0, 1, 0, 3, 1, 2]),
            Err(I2PError::Malformed(_))
        ));
    }

    #[test]
    fn gateway_too_large_rejected() {
        let b = TunnelGatewayBody {
            tunnel_id: 1,
            data: vec![0; 65536],
        };
        assert!(matches!(b.to_buffer(), Err(I2PError::Malformed(_))));
        let ok = TunnelGatewayBody {
            tunnel_id: 1,
            data: vec![0; 65535],
        };
        assert_eq!(ok.to_buffer().unwrap().len(), 6 + 65535);
    }

    // ---- TunnelTest -----------------------------------------------------

    #[test]
    fn tunnel_test_golden_and_roundtrip() {
        let t = TunnelTestBody {
            msg_id: 0x0102_0304,
            timestamp: 0x1122_3344_5566_7788,
        };
        let buf = t.to_buffer();
        assert_eq!(
            buf,
            [1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(TunnelTestBody::from_buffer(&buf).unwrap(), t);
    }

    #[test]
    fn tunnel_test_short_and_trailing() {
        assert_eq!(
            TunnelTestBody::from_buffer(&[0; 11]),
            Err(I2PError::InvalidLength {
                expected: 12,
                got: 11
            })
        );
        let t = TunnelTestBody {
            msg_id: 1,
            timestamp: 2,
        };
        let mut buf = t.to_buffer().to_vec();
        buf.push(0xEE);
        assert_eq!(TunnelTestBody::from_buffer(&buf).unwrap(), t);
    }
}

#[cfg(test)]
mod tests {
    use uu_i2p::{DELIVERY_STATUS_SIZE, DeliveryStatus, I2PError};

    #[test]
    fn size_constant() {
        assert_eq!(DELIVERY_STATUS_SIZE, 12);
        assert_eq!(DELIVERY_STATUS_SIZE, 4 + 8);
    }

    #[test]
    fn roundtrip() {
        let ds = DeliveryStatus::new(0xDEAD_BEEF, 1_700_000_000_000);
        let buf = ds.to_buffer();
        assert_eq!(buf.len(), DELIVERY_STATUS_SIZE);
        let back = DeliveryStatus::from_buffer(&buf).unwrap();
        assert_eq!(back, ds);
    }

    #[test]
    fn golden_bytes() {
        let ds = DeliveryStatus::new(0x1122_3344, 0x0102_0304_0506_0708);
        let buf = ds.to_buffer();
        assert_eq!(
            buf,
            [
                0x11, 0x22, 0x33, 0x44, // msg_id
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // timestamp
            ]
        );
    }

    #[test]
    fn parse_golden() {
        let buf = [
            0xAA, 0xBB, 0xCC, 0xDD, // msg_id
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // timestamp
        ];
        let ds = DeliveryStatus::from_buffer(&buf).unwrap();
        assert_eq!(ds.msg_id, 0xAABB_CCDD);
        assert_eq!(ds.timestamp_ms, 1);
    }

    #[test]
    fn zero_msg_id_and_zero_timestamp() {
        // SSU2 establishment case: msg_id=0, timestamp=net_id
        let ds = DeliveryStatus::new(0, 2); // net_id = 2
        let buf = ds.to_buffer();
        let back = DeliveryStatus::from_buffer(&buf).unwrap();
        assert_eq!(back.msg_id, 0);
        assert_eq!(back.timestamp_ms, 2);
    }

    #[test]
    fn trailing_bytes_ignored() {
        let ds = DeliveryStatus::new(1, 2);
        let mut buf = ds.to_buffer().to_vec();
        buf.extend_from_slice(b"--- garbage ---");
        let back = DeliveryStatus::from_buffer(&buf).unwrap();
        assert_eq!(back, ds);
    }

    #[test]
    fn empty_buffer_invalid() {
        let r = DeliveryStatus::from_buffer(&[]);
        assert!(matches!(r, Err(I2PError::InvalidLength { .. })));
    }

    #[test]
    fn short_buffer_invalid() {
        let r = DeliveryStatus::from_buffer(&[0u8; 11]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 12,
                got: 11,
            })
        );
    }

    #[test]
    fn now_sets_recent_timestamp() {
        let ds = DeliveryStatus::now(0x42);
        assert_eq!(ds.msg_id, 0x42);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let now = u64::try_from(now_ms).unwrap();
        // timestamp должен быть не дальше секунды от now
        assert!(ds.timestamp_ms >= now - 1000);
        assert!(ds.timestamp_ms <= now + 1000);
    }
}

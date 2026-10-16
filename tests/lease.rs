#[cfg(test)]
mod tests {
    use uu_i2p::{I2PError, IdentHash, LEASE_SIZE, LEASE2_SIZE, Lease, MAX_NUM_LEASES};

    fn ident(n: u8) -> IdentHash {
        IdentHash::from_array([n; 32])
    }

    #[test]
    fn lease_size_constants() {
        assert_eq!(LEASE_SIZE, 44);
        assert_eq!(LEASE2_SIZE, 40);
        assert_eq!(LEASE_SIZE, 32 + 4 + 8);
        assert_eq!(LEASE2_SIZE, 32 + 4 + 4);
        assert_eq!(MAX_NUM_LEASES, 16);
    }

    #[test]
    fn ls1_roundtrip() {
        let lease = Lease::new(ident(0xAB), 0xDEAD_BEEF, 1_700_000_000_000);
        let bytes = lease.to_buffer_ls1();
        assert_eq!(bytes.len(), LEASE_SIZE);
        let back = Lease::parse_ls1(&bytes).unwrap();
        assert_eq!(back, lease);
    }

    #[test]
    fn ls1_golden_bytes() {
        let lease = Lease::new(ident(0xFF), 0x1122_3344, 0x0102_0304_0506_0708);
        let buf = lease.to_buffer_ls1();
        assert_eq!(&buf[0..32], &[0xFF; 32]);
        assert_eq!(&buf[32..36], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(
            &buf[36..44],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn ls1_parse_too_short() {
        let r = Lease::parse_ls1(&[0u8; 43]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 44,
                got: 43
            })
        );
    }

    #[test]
    fn ls1_parse_takes_only_44_bytes() {
        let mut buf = [0u8; 50];
        buf[32..36].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // endDate = 0
        let lease = Lease::parse_ls1(&buf).unwrap();
        assert_eq!(lease.tunnel_id, 0xAABB_CCDD);
        assert_eq!(lease.end_date_ms, 0);
    }

    #[test]
    fn ls2_roundtrip_with_whole_seconds() {
        let lease = Lease::new(ident(0x42), 0x1234_5678, 1_700_000_000_000);
        let bytes = lease.to_buffer_ls2();
        assert_eq!(bytes.len(), LEASE2_SIZE);
        let back = Lease::parse_ls2(&bytes).unwrap();
        assert_eq!(back, lease);
    }

    #[test]
    fn ls2_end_date_is_seconds_in_wire() {
        let lease = Lease::new(ident(0x42), 0x1234_5678, 1_700_000_000_000);
        let buf = lease.to_buffer_ls2();
        // 1_700_000_000 в big-endian u32 = 0x6553F100
        assert_eq!(&buf[36..40], &[0x65, 0x53, 0xF1, 0x00]);
    }

    #[test]
    fn ls2_end_date_is_millis_inside() {
        let mut buf = [0u8; LEASE2_SIZE];
        buf[36..40].copy_from_slice(&[0x65, 0x53, 0xF1, 0x00]);
        let lease = Lease::parse_ls2(&buf).unwrap();
        assert_eq!(lease.end_date_ms, 1_700_000_000_000);
    }

    #[test]
    fn ls2_parse_too_short() {
        let r = Lease::parse_ls2(&[0u8; 39]);
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 40,
                got: 39
            })
        );
    }

    #[test]
    fn is_valid_zero_end_date() {
        let lease = Lease::new(ident(1), 1, 0);
        assert!(!lease.is_valid());
    }

    #[test]
    fn is_valid_nonzero_end_date() {
        let lease = Lease::new(ident(1), 1, 1000);
        assert!(lease.is_valid());
    }

    #[test]
    fn is_expired_boundary() {
        let lease = Lease::new(ident(1), 1, 1000);
        assert!(!lease.is_expired(999));
        // равенство не считается истёкшим: `<`, не `<=`
        assert!(!lease.is_expired(1000));
        assert!(lease.is_expired(1001));
    }

    #[test]
    fn expires_within_already_expired() {
        let lease = Lease::new(ident(1), 1, 1000);
        // уже истёк → true независимо от t
        assert!(lease.expires_within(0, 2000));
        assert!(lease.expires_within(1000, 2000));
    }

    #[test]
    fn expires_within_future() {
        let lease = Lease::new(ident(1), 1, 10_000);
        // now=1000, t=8000 → 10000-1000 = 9000 > 8000 → false
        assert!(!lease.expires_within(8000, 1000));
        // now=1000, t=9000 → 9000 == 9000 → false (строго <)
        assert!(!lease.expires_within(9000, 1000));
        // now=1000, t=9001 → 9000 < 9001 → true
        assert!(lease.expires_within(9001, 1000));
    }

    #[test]
    fn sort_key_order_by_id_then_gateway() {
        let a = Lease::new(ident(1), 10, 0);
        let b = Lease::new(ident(2), 5, 0);
        let c = Lease::new(ident(1), 5, 0);

        let mut v = [a, b, c];
        v.sort_by_key(Lease::sort_key);

        // id=5 у {b, c}, id=10 у {a}; при равном id — по gateway
        // (c.gateway = ident(1) < b.gateway = ident(2))
        assert_eq!(v, [c, b, a]);
    }

    #[test]
    fn ls1_and_ls2_sizes_differ_by_4_bytes() {
        assert_ne!(LEASE_SIZE, LEASE2_SIZE);
        assert_eq!(LEASE_SIZE - LEASE2_SIZE, 4); // 8 - 4
    }

    #[test]
    fn ls2_to_ls1_round_trip_preserves_fields() {
        let orig = Lease::new(ident(0x99), 42, 1_700_000_000_000);
        let bytes = orig.to_buffer_ls2();
        let back = Lease::parse_ls2(&bytes).unwrap();
        assert_eq!(back.tunnel_gateway, orig.tunnel_gateway);
        assert_eq!(back.tunnel_id, orig.tunnel_id);
        assert_eq!(back.end_date_ms, 1_700_000_000_000);
    }

    #[test]
    fn ls2_sub_second_precision_lost() {
        // end_date_ms не кратен 1000 — при round-trip через LS2
        // миллисекунды «оседают» на границу секунды.
        let orig = Lease::new(ident(1), 1, 1_700_000_000_500);
        let back = Lease::parse_ls2(&orig.to_buffer_ls2()).unwrap();
        assert_eq!(back.end_date_ms, 1_700_000_000_000);
    }
}

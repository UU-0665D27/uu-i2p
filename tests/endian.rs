#[cfg(test)]
mod tests {
    use uu_i2p::endian::{
        read_u16_be, read_u16_le, read_u32_be, read_u32_le, read_u64_be, read_u64_le, write_u16_be,
        write_u16_le, write_u32_be, write_u32_le, write_u64_be, write_u64_le,
    };

    // ---- golden vectors -------------------------------------------------

    #[test]
    fn read_u16_be_golden() {
        assert_eq!(read_u16_be(&[0x12, 0x34]), 0x1234);
        assert_eq!(read_u16_be(&[0xff, 0xff]), 0xffff);
        assert_eq!(read_u16_be(&[0x00, 0x00]), 0x0000);
    }

    #[test]
    fn read_u32_be_golden() {
        assert_eq!(read_u32_be(&[0x12, 0x34, 0x56, 0x78]), 0x1234_5678);
        assert_eq!(read_u32_be(&[0xde, 0xad, 0xbe, 0xef]), 0xdead_beef);
    }

    #[test]
    fn read_u64_be_golden() {
        assert_eq!(
            read_u64_be(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn read_u16_le_golden() {
        assert_eq!(read_u16_le(&[0x34, 0x12]), 0x1234);
    }

    #[test]
    fn read_u32_le_golden() {
        assert_eq!(read_u32_le(&[0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
    }

    #[test]
    fn read_u64_le_golden() {
        assert_eq!(
            read_u64_le(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
            0x0102_0304_0506_0708
        );
    }

    // ---- write golden ---------------------------------------------------

    #[test]
    fn write_u32_be_golden() {
        let mut buf = [0u8; 4];
        write_u32_be(&mut buf, 0xdead_beef);
        assert_eq!(buf, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn write_u64_le_golden() {
        let mut buf = [0u8; 8];
        write_u64_le(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(buf, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    // ---- roundtrip ------------------------------------------------------

    #[test]
    fn roundtrip_u16_be() {
        for v in [0u16, 1, 0x00ff, 0x0100, 0x7fff, 0x8000, 0xffff] {
            let mut buf = [0u8; 2];
            write_u16_be(&mut buf, v);
            assert_eq!(read_u16_be(&buf), v, "v={v:#06x}");
        }
    }

    #[test]
    fn roundtrip_u32_be() {
        for v in [0u32, 1, 0x00ff_ffff, 0x8000_0000, 0xdead_beef, u32::MAX] {
            let mut buf = [0u8; 4];
            write_u32_be(&mut buf, v);
            assert_eq!(read_u32_be(&buf), v, "v={v:#010x}");
        }
    }

    #[test]
    fn roundtrip_u64_be() {
        for v in [0u64, 1, 0x8000_0000_0000_0000, u64::MAX] {
            let mut buf = [0u8; 8];
            write_u64_be(&mut buf, v);
            assert_eq!(read_u64_be(&buf), v, "v={v:#018x}");
        }
    }

    #[test]
    fn roundtrip_u16_le() {
        for v in [0u16, 1, 0x00ff, 0x0100, 0x7fff, 0x8000, 0xffff] {
            let mut buf = [0u8; 2];
            write_u16_le(&mut buf, v);
            assert_eq!(read_u16_le(&buf), v);
        }
    }

    #[test]
    fn roundtrip_u32_le() {
        for v in [0u32, 1, 0xdead_beef, u32::MAX] {
            let mut buf = [0u8; 4];
            write_u32_le(&mut buf, v);
            assert_eq!(read_u32_le(&buf), v);
        }
    }

    #[test]
    fn roundtrip_u64_le() {
        for v in [0u64, 1, 0xdead_beef_cafe_babe, u64::MAX] {
            let mut buf = [0u8; 8];
            write_u64_le(&mut buf, v);
            assert_eq!(read_u64_le(&buf), v);
        }
    }

    // ---- "longer slice" -------------------------------------------------

    #[test]
    fn reads_only_first_bytes() {
        // read/write всегда работают с началом среза, остальное не трогают
        let mut buf = [0xaa; 8];
        write_u32_be(&mut buf, 0x1122_3344);
        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44, 0xaa, 0xaa, 0xaa, 0xaa]);

        let mut buf = [0xaa; 8];
        write_u32_le(&mut buf, 0x1122_3344);
        assert_eq!(buf, [0x44, 0x33, 0x22, 0x11, 0xaa, 0xaa, 0xaa, 0xaa]);
    }

    // ---- реальный I2NP-пример ------------------------------------------

    #[test]
    fn i2np_header_layout() {
        // I2NP header: typeID(1) | msgID(4 BE) | expiration(8 BE) | size(2 BE) | chks(1)
        let mut header = [0u8; 16];
        header[0] = 0x01; // typeID = DatabaseStore
        write_u32_be(&mut header[1..], 0xdead_beef); // msgID
        write_u64_be(&mut header[5..], 1_700_000_000_000); // expiration (ms)
        write_u16_be(&mut header[13..], 1024); // size

        assert_eq!(header[0], 0x01);
        assert_eq!(read_u32_be(&header[1..]), 0xdead_beef);
        assert_eq!(read_u64_be(&header[5..]), 1_700_000_000_000);
        assert_eq!(read_u16_be(&header[13..]), 1024);
    }

    #[test]
    fn ssu2_nonce_layout() {
        // SSU2 nonce: 4 нулевых байта + 8 байт LE от packetNum
        let packet_num: u64 = 0x1122_3344_5566_7788;
        let mut nonce = [0u8; 12];
        write_u64_le(&mut nonce[4..], packet_num);

        assert_eq!(&nonce[..4], &[0, 0, 0, 0]);
        assert_eq!(read_u64_le(&nonce[4..]), packet_num);
        assert_eq!(nonce[4..], [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }
}

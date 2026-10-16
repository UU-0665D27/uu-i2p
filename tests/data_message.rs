#[cfg(test)]
mod tests {
    use uu_i2p::I2PError;
    use uu_i2p::data_message::*;

    #[test]
    fn golden() {
        let b = DataBody {
            data: vec![0xDE, 0xAD],
        };
        assert_eq!(b.to_buffer().unwrap(), vec![0, 0, 0, 2, 0xDE, 0xAD]);
        assert_eq!(DATA_MESSAGE_HEADER_SIZE, 4);
    }

    #[test]
    fn roundtrip_incl_empty() {
        for data in [vec![], vec![1u8], vec![0x77; 5000]] {
            let b = DataBody { data };
            assert_eq!(DataBody::from_buffer(&b.to_buffer().unwrap()).unwrap(), b);
        }
    }

    #[test]
    fn trailing_ignored() {
        let b = DataBody::from_buffer(&[0, 0, 0, 1, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(b.data, vec![0xAA]);
    }

    #[test]
    fn short_prefix() {
        assert_eq!(
            DataBody::from_buffer(&[0, 0, 0]),
            Err(I2PError::InvalidLength {
                expected: 4,
                got: 3
            })
        );
    }

    #[test]
    fn length_exceeds_payload() {
        assert!(matches!(
            DataBody::from_buffer(&[0, 0, 0, 5, 1, 2]),
            Err(I2PError::Malformed(_))
        ));
        // огромный length не приводит к панике/переполнению
        assert!(matches!(
            DataBody::from_buffer(&[0xFF, 0xFF, 0xFF, 0xFF, 1]),
            Err(I2PError::Malformed(_))
        ));
    }
}

#[cfg(test)]
mod tests {
    use uu_i2p::{
        I2PTag, IdentHash,
        error::{I2PError, Result},
    };

    #[test]
    fn len_const() {
        assert_eq!(I2PTag::<32>::LEN, 32);
        assert_eq!(I2PTag::<16>::LEN, 16);
        assert_eq!(IdentHash::LEN, 32);
    }

    #[test]
    fn from_array_roundtrip() {
        let arr = [1u8, 2, 3, 4];
        let t = I2PTag::from_array(arr);
        assert_eq!(t.as_bytes(), &arr);
        assert_eq!(t.as_slice(), &arr[..]);
        let back: [u8; 4] = t.into();
        assert_eq!(back, arr);
    }

    #[test]
    fn from_slice_exact_len() {
        let t = I2PTag::<4>::from_slice(&[1, 2, 3, 4]).unwrap();
        assert_eq!(t.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn from_slice_short() {
        assert!(I2PTag::<4>::from_slice(&[1, 2, 3]).is_none());
    }

    #[test]
    fn from_slice_long() {
        assert!(I2PTag::<4>::from_slice(&[1, 2, 3, 4, 5]).is_none());
    }

    #[test]
    fn from_slice_empty_for_zero_len() {
        assert!(I2PTag::<0>::from_slice(&[]).is_some());
        assert!(I2PTag::<0>::from_slice(&[1]).is_none());
    }

    #[test]
    fn try_from_slice_error_carries_lengths() {
        let r: Result<I2PTag<4>> = (&[1u8, 2, 3][..]).try_into();
        assert_eq!(
            r,
            Err(I2PError::InvalidLength {
                expected: 4,
                got: 3
            })
        );
    }

    #[test]
    fn is_zero_true() {
        assert!(I2PTag::<4>::from_array([0, 0, 0, 0]).is_zero());
    }

    #[test]
    fn is_zero_false() {
        assert!(!I2PTag::<4>::from_array([0, 0, 0, 1]).is_zero());
    }

    #[test]
    fn is_zero_empty_is_true() {
        assert!(I2PTag::<0>::from_array([]).is_zero());
    }

    #[test]
    fn random_fills_all_bytes() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let t = I2PTag::<32>::random(&mut rng);
            assert!(!t.is_zero(), "rng produced all-zero tag (32 bytes)");
        }
    }

    #[test]
    fn random_zero_len_never_panics() {
        let mut rng = rand::thread_rng();
        let t = I2PTag::<0>::random(&mut rng);
        assert!(t.is_zero());
    }

    #[test]
    fn equality_and_hash_semantics() {
        use std::collections::HashSet;
        let a = I2PTag::<4>::from_array([1, 2, 3, 4]);
        let b = I2PTag::<4>::from_array([1, 2, 3, 4]);
        let c = I2PTag::<4>::from_array([1, 2, 3, 5]);
        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn ord_is_lexicographic() {
        let a = I2PTag::<4>::from_array([1, 2, 3, 4]);
        let b = I2PTag::<4>::from_array([1, 2, 3, 5]);
        let c = I2PTag::<4>::from_array([2, 0, 0, 0]);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn debug_shows_hex() {
        let t = I2PTag::<2>::from_array([0xab, 0xcd]);
        assert_eq!(format!("{t:?}"), "Tag<2>(abcd)");
    }

    #[test]
    fn as_ref_works_as_slice() {
        let t = I2PTag::<3>::from_array([0xde, 0xad, 0xbe]);
        let s: &[u8] = t.as_ref();
        assert_eq!(s, &[0xde, 0xad, 0xbe]);
    }
}

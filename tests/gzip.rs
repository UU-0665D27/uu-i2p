#[cfg(test)]
mod tests {
    use uu_i2p::{
        I2PError,
        gzip::{compress, decompress},
    };

    #[test]
    fn roundtrip_small() {
        let data = b"hello, i2p";
        let compressed = compress(data).unwrap();
        assert_ne!(&compressed[..], &data[..]);
        // gzip magic
        assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
        let back = decompress(&compressed).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn roundtrip_empty() {
        let compressed = compress(b"").unwrap();
        let back = decompress(&compressed).unwrap();
        assert!(back.is_empty(), "expected empty output");
    }

    #[test]
    fn roundtrip_1k_random() {
        // ~1 KB псевдослучайных данных (плохо сжимается, но
        // gzip-контейнер всё равно валидный)
        let mut data = vec![0u8; 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = u8::try_from((i * 131 + 17) & 0xff).expect("fits");
        }
        let compressed = compress(&data).unwrap();
        let back = decompress(&compressed).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn roundtrip_highly_compressible() {
        // Много повторов — deflate сожмёт сильно
        let data = vec![0xABu8; 4096];
        let compressed = compress(&data).unwrap();
        assert!(compressed.len() < data.len() / 4);
        let back = decompress(&compressed).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn decompress_garbage_fails() {
        let r = decompress(&[0x00, 0x01, 0x02, 0x03]);
        assert!(matches!(r, Err(I2PError::Malformed(_))));
    }
}

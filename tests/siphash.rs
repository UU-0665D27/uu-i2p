#[cfg(test)]
mod tests {
    use uu_i2p::siphash::siphash24;

    /// Ключ из референсных тестов `SipHash`:
    /// `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f`.
    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    /// Строит входной буфер `00 01 02 ... (n-1)`.
    fn input(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from(i & 0xff).expect("fits"))
            .collect()
    }

    /// Векторы из референсного репозитория `SipHash`
    /// (`veorq/SipHash`, файл `vectors.h`).
    ///
    /// Первые 16 значений — с покрытием всех длин от 0 до 15.
    /// Остальные выбраны из середины для проверки 8-байтовых
    /// блоков и хвоста.
    #[test]
    fn reference_vectors() {
        let cases: &[(usize, u64)] = &[
            (0, 0x726f_db47_dd0e_0e31),
            (1, 0x74f8_39c5_93dc_67fd),
            (2, 0x0d6c_8009_d9a9_4f5a),
            (3, 0x8567_6696_d7fb_7e2d),
            (4, 0xcf27_94e0_2771_87b7),
            (5, 0x1876_5564_cd99_a68d),
            (6, 0xcbc9_466e_58fe_e3ce),
            (7, 0xab02_00f5_8b01_d137),
            (8, 0x93f5_f579_9a93_2462),
            (9, 0x9e00_82df_0ba9_e4b0),
            (10, 0x7a5d_bbc5_94dd_b9f3),
            (11, 0xf4b3_2f46_226b_ada7),
            (12, 0x751e_8fbc_860e_e5fb),
            (13, 0x14ea_5627_c084_3d90),
            (14, 0xf723_ca90_8e7a_f2ee),
            (15, 0xa129_ca61_49be_45e5),
            (16, 0x3f2a_cc7f_57c2_9bdb),
            (17, 0x699a_e9f5_2cbe_4794),
            (18, 0x4bc1_b3f0_968d_d39c),
            (19, 0xbb6d_c91d_a779_61bd),
            (20, 0xbed6_5cf2_1aa2_ee98),
            (21, 0xd0f2_cbb0_2e3b_67c7),
            (22, 0x9353_6795_e3a3_3e88),
            (23, 0xa80c_038c_cd5c_cec8),
            (24, 0xb8ad_50c6_f649_af94),
        ];
        for &(n, expected) in cases {
            let data = input(n);
            assert_eq!(
                siphash24(&data, &KEY),
                expected,
                "siphash24 mismatch for input length {n}"
            );
        }
    }

    /// Пустой вход — отдельный случай: finalization-блок содержит
    /// только длину (ноль) и ничего больше.
    #[test]
    fn empty_input() {
        assert_eq!(siphash24(&[], &KEY), 0x726f_db47_dd0e_0e31);
    }

    /// Проверка, что ключ действительно влияет на результат:
    /// разные ключи — разные хеши на одинаковом входе.
    #[test]
    fn different_keys_different_output() {
        let mut key2 = KEY;
        key2[0] ^= 0x01;
        assert_ne!(siphash24(b"hello", &KEY), siphash24(b"hello", &key2));
    }

    /// Детерминизм: один вход + один ключ → один результат.
    #[test]
    fn deterministic() {
        let a = siphash24(b"deterministic", &KEY);
        let b = siphash24(b"deterministic", &KEY);
        assert_eq!(a, b);
    }

    /// Инкрементальный вход неотличим по хешу от «одного буфера»,
    /// потому что у нас и нет потокового API — это проверка, что
    /// `as_chunks` корректно обрабатывает длину, кратную 8.
    #[test]
    fn multiple_of_eight_bytes() {
        // 8, 16, 24 байта — не должно падать и не должно совпадать
        // с пустым или одним лишним байтом.
        let h8 = siphash24(&input(8), &KEY);
        let h16 = siphash24(&input(16), &KEY);
        let h24 = siphash24(&input(24), &KEY);
        assert_ne!(h8, h16);
        assert_ne!(h16, h24);
        assert_ne!(h8, h24);
    }

    /// Один байт данных меняется — хеш меняется «заметно».
    /// Не строгий тест (`SipHash` — не cryptographic collision-resistant
    /// в обычном смысле), но отлавливает грубые ошибки.
    #[test]
    fn input_bit_change() {
        let a = siphash24(&[0u8; 16], &KEY);
        let mut b_data = [0u8; 16];
        b_data[7] ^= 0x01;
        let b = siphash24(&b_data, &KEY);
        assert_ne!(a, b);
    }
}

//! Integration tests for hash-inversion.
//!
//! These tests verify the public API works correctly.

use hash_inversion::{
    inverse_simple_hash, md5_16bit, md5_8bit, mini_md5, mini_sha256, sha256_16bit, sha256_8bit,
    simple_hash, HashLookupTable, SIMPLE_MOD, VERSION,
};

mod simple_hash_integration_tests {
    use super::*;

    #[test]
    fn test_simple_hash_full_roundtrip() {
        // Test that every value in the domain [0, SIMPLE_MOD) can be round-tripped
        for x in 0..SIMPLE_MOD {
            let h = simple_hash(x);
            let x_back = inverse_simple_hash(h);
            assert_eq!(x, x_back, "Failed roundtrip for x={x}");
        }
    }

    #[test]
    fn test_simple_hash_is_bijection() {
        // Verify all hash outputs are unique (bijection property)
        let mut seen = std::collections::HashSet::new();
        for x in 0..SIMPLE_MOD {
            let h = simple_hash(x);
            assert!(seen.insert(h), "Hash collision at x={x}, h={h}");
        }
        assert_eq!(seen.len(), SIMPLE_MOD as usize);
    }

    #[test]
    fn test_simple_hash_range() {
        // All outputs should be in [0, SIMPLE_MOD)
        for x in 0..SIMPLE_MOD {
            let h = simple_hash(x);
            assert!((0..SIMPLE_MOD).contains(&h), "Hash out of range: {h}");
        }
    }
}

mod md5_integration_tests {
    use super::*;

    #[test]
    fn test_md5_8bit_lookup_roundtrip() {
        let table = HashLookupTable::new_md5_8bit();

        // Verify we can find a preimage for every possible 8-bit hash value
        for hash_value in 0..=255u32 {
            let preimage = table
                .lookup(hash_value)
                .expect("Should have preimage for every 8-bit hash");
            let computed_hash = u32::from(md5_8bit(preimage));
            assert_eq!(computed_hash, hash_value);
        }
    }

    #[test]
    fn test_md5_16bit_high_coverage() {
        let table = HashLookupTable::new_md5_16bit();

        // With 2^20 inputs for 2^16 outputs, we should have excellent coverage
        assert!(
            table.coverage_percent() > 99.0,
            "16-bit MD5 should have >99% coverage, got {:.2}%",
            table.coverage_percent()
        );
    }

    #[test]
    fn test_md5_produces_consistent_hashes() {
        // Same input should always produce same hash
        let input = b"consistent test input";
        let h1 = md5_8bit(input);
        let h2 = md5_8bit(input);
        let h3 = md5_8bit(input);
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);

        let h16_1 = md5_16bit(input);
        let h16_2 = md5_16bit(input);
        assert_eq!(h16_1, h16_2);
    }
}

mod sha256_integration_tests {
    use super::*;

    #[test]
    fn test_sha256_8bit_lookup_roundtrip() {
        let table = HashLookupTable::new_sha256_8bit();

        for hash_value in 0..=255u32 {
            let preimage = table
                .lookup(hash_value)
                .expect("Should have preimage for every 8-bit hash");
            let computed_hash = u32::from(sha256_8bit(preimage));
            assert_eq!(computed_hash, hash_value);
        }
    }

    #[test]
    fn test_sha256_16bit_high_coverage() {
        let table = HashLookupTable::new_sha256_16bit();

        assert!(
            table.coverage_percent() > 99.0,
            "16-bit SHA-256 should have >99% coverage, got {:.2}%",
            table.coverage_percent()
        );
    }

    #[test]
    fn test_sha256_produces_consistent_hashes() {
        let input = b"another consistent test";
        let h1 = sha256_8bit(input);
        let h2 = sha256_8bit(input);
        assert_eq!(h1, h2);

        let h16_1 = sha256_16bit(input);
        let h16_2 = sha256_16bit(input);
        assert_eq!(h16_1, h16_2);
    }
}

mod lookup_table_integration_tests {
    use super::*;

    #[test]
    fn test_lookup_table_metadata() {
        let md5_8 = HashLookupTable::new_md5_8bit();
        assert_eq!(md5_8.bits(), 8);
        assert_eq!(md5_8.hash_name(), "MD5");
        assert_eq!(md5_8.max_hash_values(), 256);

        let md5_16 = HashLookupTable::new_md5_16bit();
        assert_eq!(md5_16.bits(), 16);
        assert_eq!(md5_16.max_hash_values(), 65536);

        let sha_8 = HashLookupTable::new_sha256_8bit();
        assert_eq!(sha_8.bits(), 8);
        assert_eq!(sha_8.hash_name(), "SHA-256");

        let sha_16 = HashLookupTable::new_sha256_16bit();
        assert_eq!(sha_16.bits(), 16);
        assert_eq!(sha_16.hash_name(), "SHA-256");
    }

    #[test]
    fn test_lookup_arbitrary_strings() {
        // Test that we can find preimages for hashes of arbitrary strings
        let test_strings: &[&[u8]] = &[
            b"hello world",
            b"test123",
            b"The quick brown fox jumps over the lazy dog",
            b"",
            b"\x00\x01\x02",
        ];

        let md5_table = HashLookupTable::new_md5_8bit();
        let sha_table = HashLookupTable::new_sha256_8bit();

        for input in test_strings {
            // MD5 8-bit
            let md5_hash = md5_8bit(input);
            let md5_preimage = md5_table.lookup(u32::from(md5_hash)).unwrap();
            assert_eq!(md5_8bit(md5_preimage), md5_hash);

            // SHA-256 8-bit
            let sha_hash = sha256_8bit(input);
            let sha_preimage = sha_table.lookup(u32::from(sha_hash)).unwrap();
            assert_eq!(sha256_8bit(sha_preimage), sha_hash);
        }
    }
}

mod custom_hash_integration_tests {
    use super::*;

    #[test]
    fn test_mini_md5_lookup_roundtrip() {
        let table = HashLookupTable::new_mini_md5();

        // Verify we can find a preimage for every possible 8-bit hash value
        for hash_value in 0..=255u32 {
            let preimage = table
                .lookup(hash_value)
                .expect("Should have preimage for every 8-bit hash");
            let computed_hash = u32::from(mini_md5(preimage));
            assert_eq!(computed_hash, hash_value);
        }
    }

    #[test]
    fn test_mini_sha256_lookup_roundtrip() {
        let table = HashLookupTable::new_mini_sha256();

        for hash_value in 0..=255u32 {
            let preimage = table
                .lookup(hash_value)
                .expect("Should have preimage for every 8-bit hash");
            let computed_hash = u32::from(mini_sha256(preimage));
            assert_eq!(computed_hash, hash_value);
        }
    }

    #[test]
    fn test_mini_md5_produces_consistent_hashes() {
        let input = b"custom hash test input";
        let h1 = mini_md5(input);
        let h2 = mini_md5(input);
        let h3 = mini_md5(input);
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn test_mini_sha256_produces_consistent_hashes() {
        let input = b"another custom hash test";
        let h1 = mini_sha256(input);
        let h2 = mini_sha256(input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_custom_hash_lookup_table_metadata() {
        let mini_md5_table = HashLookupTable::new_mini_md5();
        assert_eq!(mini_md5_table.bits(), 8);
        assert_eq!(mini_md5_table.hash_name(), "MiniMD5");
        assert_eq!(mini_md5_table.max_hash_values(), 256);
        assert_eq!(mini_md5_table.coverage(), 256);

        let mini_sha_table = HashLookupTable::new_mini_sha256();
        assert_eq!(mini_sha_table.bits(), 8);
        assert_eq!(mini_sha_table.hash_name(), "MiniSHA256");
        assert_eq!(mini_sha_table.max_hash_values(), 256);
        assert_eq!(mini_sha_table.coverage(), 256);
    }

    #[test]
    fn test_custom_hash_lookup_arbitrary_strings() {
        // Test that we can find preimages for hashes of arbitrary strings
        let test_strings: &[&[u8]] = &[
            b"hello world",
            b"test123",
            b"The quick brown fox jumps over the lazy dog",
            b"",
            b"\x00\x01\x02",
        ];

        let mini_md5_table = HashLookupTable::new_mini_md5();
        let mini_sha_table = HashLookupTable::new_mini_sha256();

        for input in test_strings {
            // MiniMD5
            let md5_hash = mini_md5(input);
            let md5_preimage = mini_md5_table.lookup(u32::from(md5_hash)).unwrap();
            assert_eq!(mini_md5(md5_preimage), md5_hash);

            // MiniSHA256
            let sha_hash = mini_sha256(input);
            let sha_preimage = mini_sha_table.lookup(u32::from(sha_hash)).unwrap();
            assert_eq!(mini_sha256(sha_preimage), sha_hash);
        }
    }
}

mod version_tests {
    use super::*;

    #[test]
    fn test_version_is_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_version_matches_cargo_toml() {
        assert!(VERSION.starts_with("0."));
    }
}

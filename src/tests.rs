//! Unit tests for hash-inversion library.
//!
//! These tests verify the internal implementation of hash functions
//! and lookup tables.

use super::*;

mod simple_hash_tests {
    use super::*;

    #[test]
    fn test_simple_hash_known_values() {
        // h(0) = (7*0 + 3) mod 101 = 3
        assert_eq!(simple_hash(0), 3);
        // h(10) = (7*10 + 3) mod 101 = 73
        assert_eq!(simple_hash(10), 73);
        // h(14) = (7*14 + 3) mod 101 = 101 mod 101 = 0
        assert_eq!(simple_hash(14), 0);
    }

    #[test]
    fn test_inverse_simple_hash_known_values() {
        // inverse(3) should be 0
        assert_eq!(inverse_simple_hash(3), 0);
        // inverse(73) should be 10
        assert_eq!(inverse_simple_hash(73), 10);
        // inverse(0) should be 14
        assert_eq!(inverse_simple_hash(0), 14);
    }

    #[test]
    fn test_simple_hash_roundtrip_all_values() {
        // Verify that inverse_hash(hash(x)) == x for all x in [0, 100]
        for x in 0..SIMPLE_MOD {
            let h = simple_hash(x);
            let x_back = inverse_simple_hash(h);
            assert_eq!(x, x_back, "Roundtrip failed: x={x}, h={h}, x_back={x_back}");
        }
    }

    #[test]
    fn test_simple_hash_bijection() {
        // Verify that hash is a bijection: all outputs are unique
        let mut outputs: Vec<i32> = (0..SIMPLE_MOD).map(simple_hash).collect();
        outputs.sort_unstable();
        outputs.dedup();
        assert_eq!(outputs.len(), SIMPLE_MOD as usize);
    }
}

mod md5_tests {
    use super::*;

    #[test]
    fn test_md5_8bit_deterministic() {
        let h1 = md5_8bit(b"hello");
        let h2 = md5_8bit(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_md5_16bit_deterministic() {
        let h1 = md5_16bit(b"hello");
        let h2 = md5_16bit(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_md5_8bit_different_inputs_produce_output() {
        // Verify that different inputs produce valid hash outputs
        // Note: We don't test for h1 != h2 because collisions are expected
        // with only 8 bits of output space
        let _h1 = md5_8bit(b"hello");
        let _h2 = md5_8bit(b"world");
        // If we get here without panic, both inputs produced valid u8 hashes
    }
}

mod sha256_tests {
    use super::*;

    #[test]
    fn test_sha256_8bit_deterministic() {
        let h1 = sha256_8bit(b"hello");
        let h2 = sha256_8bit(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_16bit_deterministic() {
        let h1 = sha256_16bit(b"hello");
        let h2 = sha256_16bit(b"hello");
        assert_eq!(h1, h2);
    }
}

mod custom_hash_tests {
    use super::*;

    #[test]
    fn test_mini_md5_deterministic() {
        let h1 = mini_md5(b"hello");
        let h2 = mini_md5(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_mini_md5_different_inputs() {
        // Different inputs should generally produce different hashes
        // (though collisions are possible with 8 bits)
        let h1 = mini_md5(b"hello");
        let h2 = mini_md5(b"world");
        // We just verify they produce valid u8 output (function compiles and runs)
        let _ = h1;
        let _ = h2;
    }

    #[test]
    fn test_mini_md5_empty_input() {
        // Verify empty input doesn't panic
        let h = mini_md5(b"");
        let _ = h;
    }

    #[test]
    fn test_mini_md5_produces_varied_output() {
        // Test that mini_md5 produces varied output across different inputs
        let mut hashes = std::collections::HashSet::new();
        for i in 0u8..=255 {
            let h = mini_md5(&[i]);
            hashes.insert(h);
        }
        // With 8-bit output and single-byte inputs, we expect reasonable distribution
        // but not perfect coverage (collisions are expected)
        assert!(
            hashes.len() >= 100,
            "MiniMD5 should produce varied output, got {} unique values",
            hashes.len()
        );
    }

    #[test]
    fn test_mini_sha256_deterministic() {
        let h1 = mini_sha256(b"hello");
        let h2 = mini_sha256(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_mini_sha256_different_inputs() {
        let h1 = mini_sha256(b"hello");
        let h2 = mini_sha256(b"world");
        // We just verify they produce valid u8 output (function compiles and runs)
        let _ = h1;
        let _ = h2;
    }

    #[test]
    fn test_mini_sha256_empty_input() {
        // Verify empty input doesn't panic
        let h = mini_sha256(b"");
        let _ = h;
    }

    #[test]
    fn test_mini_sha256_produces_varied_output() {
        let mut hashes = std::collections::HashSet::new();
        for i in 0u8..=255 {
            let h = mini_sha256(&[i]);
            hashes.insert(h);
        }
        // With 8-bit output and single-byte inputs, we expect reasonable distribution
        // but not perfect coverage (collisions are expected)
        assert!(
            hashes.len() >= 100,
            "MiniSHA256 should produce varied output, got {} unique values",
            hashes.len()
        );
    }

    #[test]
    fn test_mini_md5_length_affects_output() {
        // Different length inputs should produce different hashes
        let h1 = mini_md5(b"a");
        let h2 = mini_md5(b"aa");
        let h3 = mini_md5(b"aaa");
        // At least one should differ (extremely unlikely all three collide)
        assert!(h1 != h2 || h2 != h3 || h1 != h3);
    }

    #[test]
    fn test_mini_sha256_length_affects_output() {
        let h1 = mini_sha256(b"a");
        let h2 = mini_sha256(b"aa");
        let h3 = mini_sha256(b"aaa");
        assert!(h1 != h2 || h2 != h3 || h1 != h3);
    }
}

mod lookup_table_tests {
    use super::*;

    #[test]
    fn test_md5_8bit_lookup_table_coverage() {
        let table = HashLookupTable::new_md5_8bit();
        // Should have preimages for all 256 possible 8-bit values
        assert_eq!(table.coverage(), 256);
        assert_eq!(table.bits(), 8);
        assert_eq!(table.hash_name(), "MD5");
    }

    #[test]
    fn test_md5_8bit_lookup_table_inversion() {
        let table = HashLookupTable::new_md5_8bit();

        // Test that looking up any hash gives a valid preimage
        for hash in 0..=255u32 {
            let preimage = table.lookup(hash).expect("Should have preimage");
            let computed_hash = u32::from(md5_8bit(preimage));
            assert_eq!(
                computed_hash, hash,
                "Preimage should hash to expected value"
            );
        }
    }

    #[test]
    fn test_sha256_8bit_lookup_table_coverage() {
        let table = HashLookupTable::new_sha256_8bit();
        assert_eq!(table.coverage(), 256);
        assert_eq!(table.bits(), 8);
        assert_eq!(table.hash_name(), "SHA-256");
    }

    #[test]
    fn test_sha256_8bit_lookup_table_inversion() {
        let table = HashLookupTable::new_sha256_8bit();

        for hash in 0..=255u32 {
            let preimage = table.lookup(hash).expect("Should have preimage");
            let computed_hash = u32::from(sha256_8bit(preimage));
            assert_eq!(computed_hash, hash);
        }
    }

    #[test]
    fn test_md5_16bit_lookup_table_high_coverage() {
        let table = HashLookupTable::new_md5_16bit();
        // Should have very high coverage with 2^20 inputs for 2^16 outputs
        assert!(
            table.coverage_percent() > 99.0,
            "Should have >99% coverage, got {}%",
            table.coverage_percent()
        );
    }

    #[test]
    fn test_sha256_16bit_lookup_table_high_coverage() {
        let table = HashLookupTable::new_sha256_16bit();
        assert!(
            table.coverage_percent() > 99.0,
            "Should have >99% coverage, got {}%",
            table.coverage_percent()
        );
    }

    #[test]
    fn test_lookup_table_inversion_of_arbitrary_input() {
        let table = HashLookupTable::new_md5_8bit();

        // Hash an arbitrary string
        let original = b"The quick brown fox";
        let hash = md5_8bit(original);

        // Look up a preimage
        let preimage = table.lookup(u32::from(hash)).expect("Should find preimage");

        // Verify it hashes to the same value
        assert_eq!(md5_8bit(preimage), hash);
    }

    #[test]
    fn test_mini_md5_lookup_table_coverage() {
        let table = HashLookupTable::new_mini_md5();
        // Should have preimages for all 256 possible 8-bit values
        assert_eq!(table.coverage(), 256);
        assert_eq!(table.bits(), 8);
        assert_eq!(table.hash_name(), "MiniMD5");
    }

    #[test]
    fn test_mini_md5_lookup_table_inversion() {
        let table = HashLookupTable::new_mini_md5();

        // Test that looking up any hash gives a valid preimage
        for hash in 0..=255u32 {
            let preimage = table.lookup(hash).expect("Should have preimage");
            let computed_hash = u32::from(mini_md5(preimage));
            assert_eq!(
                computed_hash, hash,
                "Preimage should hash to expected value"
            );
        }
    }

    #[test]
    fn test_mini_sha256_lookup_table_coverage() {
        let table = HashLookupTable::new_mini_sha256();
        assert_eq!(table.coverage(), 256);
        assert_eq!(table.bits(), 8);
        assert_eq!(table.hash_name(), "MiniSHA256");
    }

    #[test]
    fn test_mini_sha256_lookup_table_inversion() {
        let table = HashLookupTable::new_mini_sha256();

        for hash in 0..=255u32 {
            let preimage = table.lookup(hash).expect("Should have preimage");
            let computed_hash = u32::from(mini_sha256(preimage));
            assert_eq!(computed_hash, hash);
        }
    }

    #[test]
    fn test_mini_md5_lookup_arbitrary_input() {
        let table = HashLookupTable::new_mini_md5();

        // Hash an arbitrary string
        let original = b"The quick brown fox jumps over the lazy dog";
        let hash = mini_md5(original);

        // Look up a preimage
        let preimage = table.lookup(u32::from(hash)).expect("Should find preimage");

        // Verify it hashes to the same value (full hash inversion!)
        assert_eq!(mini_md5(preimage), hash);
    }

    #[test]
    fn test_mini_sha256_lookup_arbitrary_input() {
        let table = HashLookupTable::new_mini_sha256();

        let original = b"Hello, World! This is a test of custom hash inversion.";
        let hash = mini_sha256(original);

        let preimage = table.lookup(u32::from(hash)).expect("Should find preimage");
        assert_eq!(mini_sha256(preimage), hash);
    }
}

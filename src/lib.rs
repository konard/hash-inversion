//! Hash Inversion Library
//!
//! This library explores hash function inversion through two approaches:
//!
//! 1. **Mathematical inverse**: For simple hash functions that are bijective
//!    on a given domain, we can compute the exact inverse mathematically.
//!
//! 2. **Lookup table inverse**: For cryptographic hashes truncated to small
//!    sizes (8-bit or 16-bit), we can build a complete precomputation table
//!    that maps every possible hash value back to an input that produces it.
//!
//! # Background
//!
//! True cryptographic hash functions (MD5, SHA-256, etc.) are designed to be
//! one-way functions - computationally infeasible to invert. However, when we
//! truncate these hashes to very small sizes:
//! - 8-bit: Only 256 possible output values
//! - 16-bit: Only 65,536 possible output values
//!
//! We can exhaustively enumerate all possible inputs in a reasonable domain
//! and build a lookup table for "inversion" (finding any preimage).
//!
//! Note: This is NOT breaking the hash function - we're simply exploiting
//! the small output space. Multiple inputs will hash to the same truncated value.

use md5::{Digest, Md5};
use sha2::Sha256;
use std::collections::HashMap;

/// Package version (matches Cargo.toml version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ============================================================================
// Simple Toy Hash Function (Mathematical Inverse)
// ============================================================================

/// Modulus for the simple toy hash function.
/// Using a prime number (101) ensures the function is bijective on [0, 100].
pub const SIMPLE_MOD: i32 = 101;

/// Simple toy "hash" function: h(x) = (7x + 3) mod 101
///
/// This function is a bijection on the interval [0, 100], meaning
/// every input maps to a unique output and vice versa.
///
/// # Arguments
///
/// * `x` - Input value
///
/// # Returns
///
/// Hash value in range [0, 100]
///
/// # Examples
///
/// ```
/// use hash_inversion::simple_hash;
/// let h = simple_hash(10);
/// assert_eq!(h, 73); // (7 * 10 + 3) mod 101 = 73
/// ```
#[must_use]
pub const fn simple_hash(x: i32) -> i32 {
    (7 * x + 3).rem_euclid(SIMPLE_MOD)
}

/// Inverse of the simple hash function on the first period [0, 100].
///
/// The modular inverse of 7 modulo 101 is 29, because 7 * 29 = 203 = 2 * 101 + 1 ≡ 1 (mod 101).
///
/// Given y = (7x + 3) mod 101, we solve for x:
/// - y - 3 ≡ 7x (mod 101)
/// - x ≡ 29(y - 3) (mod 101)
///
/// # Arguments
///
/// * `y` - Hash value to invert
///
/// # Returns
///
/// Original input value x such that `simple_hash(x) == y`
///
/// # Examples
///
/// ```
/// use hash_inversion::{simple_hash, inverse_simple_hash};
///
/// for x in 0..101 {
///     let h = simple_hash(x);
///     let x_back = inverse_simple_hash(h);
///     assert_eq!(x, x_back);
/// }
/// ```
#[must_use]
pub const fn inverse_simple_hash(y: i32) -> i32 {
    const INV_7: i32 = 29; // Modular inverse of 7 mod 101
    (INV_7 * (y - 3)).rem_euclid(SIMPLE_MOD)
}

// ============================================================================
// Truncated MD5 Hash (8-bit and 16-bit)
// ============================================================================

/// Compute the full MD5 hash of a byte slice.
fn md5_full(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute 8-bit truncated MD5 hash.
///
/// Takes the first byte of the MD5 digest.
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 8-bit hash value (0-255)
///
/// # Examples
///
/// ```
/// use hash_inversion::md5_8bit;
/// let h = md5_8bit(b"hello");
/// assert!(h <= 255);
/// ```
#[must_use]
pub fn md5_8bit(data: &[u8]) -> u8 {
    md5_full(data)[0]
}

/// Compute 16-bit truncated MD5 hash.
///
/// Takes the first two bytes of the MD5 digest as big-endian u16.
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 16-bit hash value (0-65535)
///
/// # Examples
///
/// ```
/// use hash_inversion::md5_16bit;
/// let h = md5_16bit(b"hello");
/// assert!(h <= 65535);
/// ```
#[must_use]
pub fn md5_16bit(data: &[u8]) -> u16 {
    let hash = md5_full(data);
    u16::from_be_bytes([hash[0], hash[1]])
}

// ============================================================================
// Truncated SHA-256 Hash (8-bit and 16-bit)
// ============================================================================

/// Compute the full SHA-256 hash of a byte slice.
fn sha256_full(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute 8-bit truncated SHA-256 hash.
///
/// Takes the first byte of the SHA-256 digest.
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 8-bit hash value (0-255)
///
/// # Examples
///
/// ```
/// use hash_inversion::sha256_8bit;
/// let h = sha256_8bit(b"hello");
/// assert!(h <= 255);
/// ```
#[must_use]
pub fn sha256_8bit(data: &[u8]) -> u8 {
    sha256_full(data)[0]
}

/// Compute 16-bit truncated SHA-256 hash.
///
/// Takes the first two bytes of the SHA-256 digest as big-endian u16.
///
/// # Arguments
///
/// * `data` - Input data to hash
///
/// # Returns
///
/// 16-bit hash value (0-65535)
///
/// # Examples
///
/// ```
/// use hash_inversion::sha256_16bit;
/// let h = sha256_16bit(b"hello");
/// assert!(h <= 65535);
/// ```
#[must_use]
pub fn sha256_16bit(data: &[u8]) -> u16 {
    let hash = sha256_full(data);
    u16::from_be_bytes([hash[0], hash[1]])
}

// ============================================================================
// Lookup Table for Hash Inversion
// ============================================================================

/// A lookup table for inverting truncated hash functions.
///
/// This table maps hash values back to inputs that produce them.
/// For 8-bit hashes, we can store all 256 preimages.
/// For 16-bit hashes, we can store all 65,536 preimages.
///
/// Note: Since hash functions are not injective (many inputs map to same output),
/// we store only ONE preimage per hash value. The goal is to find ANY input
/// that produces the desired hash, not the original input.
#[derive(Debug, Clone)]
pub struct HashLookupTable {
    /// Maps hash value to a preimage (input that produces that hash).
    /// Using u32 as key to handle both 8-bit and 16-bit hashes.
    table: HashMap<u32, Vec<u8>>,
    /// Number of bits in the hash (8 or 16).
    bits: u8,
    /// Name of the hash function for display purposes.
    hash_name: String,
}

impl HashLookupTable {
    /// Create a new lookup table for 8-bit MD5 inversion.
    ///
    /// Generates preimages by hashing integers 0 to 255.
    ///
    /// # Returns
    ///
    /// A lookup table that can invert 8-bit MD5 hashes.
    ///
    /// # Examples
    ///
    /// ```
    /// use hash_inversion::{HashLookupTable, md5_8bit};
    ///
    /// let table = HashLookupTable::new_md5_8bit();
    /// let original = b"test";
    /// let hash = md5_8bit(original);
    /// let preimage = table.lookup(u32::from(hash)).unwrap();
    /// // Verify the preimage hashes to the same value
    /// assert_eq!(md5_8bit(preimage), hash);
    /// ```
    #[must_use]
    pub fn new_md5_8bit() -> Self {
        let mut table = HashMap::new();

        // For 8-bit, enumerate small integers to fill all 256 buckets
        for i in 0u32..=65535 {
            let data = i.to_le_bytes();
            let hash = u32::from(md5_8bit(&data));
            table.entry(hash).or_insert_with(|| data.to_vec());
        }

        Self {
            table,
            bits: 8,
            hash_name: "MD5".to_string(),
        }
    }

    /// Create a new lookup table for 16-bit MD5 inversion.
    ///
    /// Generates preimages by hashing integers 0 to 65535.
    ///
    /// # Returns
    ///
    /// A lookup table that can invert 16-bit MD5 hashes.
    ///
    /// # Examples
    ///
    /// ```
    /// use hash_inversion::{HashLookupTable, md5_16bit};
    ///
    /// let table = HashLookupTable::new_md5_16bit();
    /// let original = b"test";
    /// let hash = md5_16bit(original);
    /// let preimage = table.lookup(u32::from(hash)).unwrap();
    /// // Verify the preimage hashes to the same value
    /// assert_eq!(md5_16bit(preimage), hash);
    /// ```
    #[must_use]
    pub fn new_md5_16bit() -> Self {
        let mut table = HashMap::new();

        // For 16-bit, we need more inputs to cover all 65536 possible outputs
        // Enumerate integers 0 to 2^20 to have good coverage
        for i in 0u32..=1_048_575 {
            let data = i.to_le_bytes();
            let hash = u32::from(md5_16bit(&data));
            table.entry(hash).or_insert_with(|| data.to_vec());
        }

        Self {
            table,
            bits: 16,
            hash_name: "MD5".to_string(),
        }
    }

    /// Create a new lookup table for 8-bit SHA-256 inversion.
    ///
    /// # Returns
    ///
    /// A lookup table that can invert 8-bit SHA-256 hashes.
    ///
    /// # Examples
    ///
    /// ```
    /// use hash_inversion::{HashLookupTable, sha256_8bit};
    ///
    /// let table = HashLookupTable::new_sha256_8bit();
    /// let original = b"test";
    /// let hash = sha256_8bit(original);
    /// let preimage = table.lookup(u32::from(hash)).unwrap();
    /// // Verify the preimage hashes to the same value
    /// assert_eq!(sha256_8bit(preimage), hash);
    /// ```
    #[must_use]
    pub fn new_sha256_8bit() -> Self {
        let mut table = HashMap::new();

        for i in 0u32..=65535 {
            let data = i.to_le_bytes();
            let hash = u32::from(sha256_8bit(&data));
            table.entry(hash).or_insert_with(|| data.to_vec());
        }

        Self {
            table,
            bits: 8,
            hash_name: "SHA-256".to_string(),
        }
    }

    /// Create a new lookup table for 16-bit SHA-256 inversion.
    ///
    /// # Returns
    ///
    /// A lookup table that can invert 16-bit SHA-256 hashes.
    ///
    /// # Examples
    ///
    /// ```
    /// use hash_inversion::{HashLookupTable, sha256_16bit};
    ///
    /// let table = HashLookupTable::new_sha256_16bit();
    /// let original = b"test";
    /// let hash = sha256_16bit(original);
    /// let preimage = table.lookup(u32::from(hash)).unwrap();
    /// // Verify the preimage hashes to the same value
    /// assert_eq!(sha256_16bit(preimage), hash);
    /// ```
    #[must_use]
    pub fn new_sha256_16bit() -> Self {
        let mut table = HashMap::new();

        for i in 0u32..=1_048_575 {
            let data = i.to_le_bytes();
            let hash = u32::from(sha256_16bit(&data));
            table.entry(hash).or_insert_with(|| data.to_vec());
        }

        Self {
            table,
            bits: 16,
            hash_name: "SHA-256".to_string(),
        }
    }

    /// Look up a preimage for the given hash value.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash value to find a preimage for
    ///
    /// # Returns
    ///
    /// `Some(&[u8])` containing a preimage if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use hash_inversion::{HashLookupTable, md5_8bit};
    ///
    /// let table = HashLookupTable::new_md5_8bit();
    /// // Look up preimage for hash value 42
    /// if let Some(preimage) = table.lookup(42) {
    ///     assert_eq!(md5_8bit(preimage), 42);
    /// }
    /// ```
    #[must_use]
    pub fn lookup(&self, hash: u32) -> Option<&[u8]> {
        self.table.get(&hash).map(Vec::as_slice)
    }

    /// Returns the number of bits in the hash.
    #[must_use]
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// Returns the name of the hash function.
    #[must_use]
    pub fn hash_name(&self) -> &str {
        &self.hash_name
    }

    /// Returns the number of unique hash values that have preimages in the table.
    #[must_use]
    pub fn coverage(&self) -> usize {
        self.table.len()
    }

    /// Returns the maximum possible hash values for this bit size.
    #[must_use]
    pub const fn max_hash_values(&self) -> usize {
        1 << self.bits
    }

    /// Returns the coverage percentage (how many possible hashes have preimages).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn coverage_percent(&self) -> f64 {
        (self.coverage() as f64 / self.max_hash_values() as f64) * 100.0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
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
    }
}

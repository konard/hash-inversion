//! Precomputed 8-bit lookup tables for hash inversion.
//!
//! This module provides O(1) hash inversion for 8-bit hash functions using
//! precomputed lookup tables embedded as const arrays.
//!
//! ## Available Lookup Functions
//!
//! - [`lookup_md5_8bit_preimage`] - Invert truncated MD5 (8-bit)
//! - [`lookup_sha256_8bit_preimage`] - Invert truncated SHA-256 (8-bit)
//! - [`lookup_mini_md5_preimage`] - Invert `MiniMD5` (custom 8-bit)
//! - [`lookup_mini_sha256_preimage`] - Invert `MiniSHA256` (custom 8-bit)
//!
//! ## Usage
//!
//! ```
//! use hash_inversion::{md5_8bit, lookup_md5_8bit_preimage};
//!
//! // Get a preimage for any hash value
//! let hash_value = 42u8;
//! let preimage = lookup_md5_8bit_preimage(hash_value);
//!
//! // Verify it produces the correct hash
//! assert_eq!(md5_8bit(preimage), hash_value);
//! ```
//!
//! To regenerate the tables, run: `cargo run --example generate_tables`

mod lookup_data_mini;
mod lookup_data_standard;

pub use lookup_data_mini::{MINI_MD5_8BIT_PREIMAGES, MINI_SHA256_8BIT_PREIMAGES};
pub use lookup_data_standard::{MD5_8BIT_PREIMAGES, SHA256_8BIT_PREIMAGES};

/// Look up a preimage for the given 8-bit MD5 hash value using the embedded table.
///
/// This function provides O(1) hash inversion by using a precomputed lookup table.
/// Every possible 8-bit hash value (0-255) has a valid preimage in the table.
///
/// # Arguments
///
/// * `hash` - The 8-bit hash value (0-255)
///
/// # Returns
///
/// A byte slice containing a preimage that hashes to the given value.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn lookup_md5_8bit_preimage(hash: u8) -> &'static [u8] {
    let (len, b0, b1) = MD5_8BIT_PREIMAGES[hash as usize];
    if len == 1 {
        // Return single-byte preimage
        // Safety: i ranges from 0 to 255, which fits in u8
        static SINGLE_BYTE: [[u8; 1]; 256] = {
            let mut arr = [[0u8; 1]; 256];
            let mut i = 0;
            while i < 256 {
                arr[i] = [i as u8];
                i += 1;
            }
            arr
        };
        &SINGLE_BYTE[b0 as usize]
    } else {
        // For 2-byte preimages, we need to return the actual bytes
        lookup_two_byte_preimage(b0, b1)
    }
}

/// Look up a preimage for the given 8-bit SHA-256 hash value using the embedded table.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn lookup_sha256_8bit_preimage(hash: u8) -> &'static [u8] {
    let (len, b0, b1) = SHA256_8BIT_PREIMAGES[hash as usize];
    if len == 1 {
        // Safety: i ranges from 0 to 255, which fits in u8
        static SINGLE_BYTE: [[u8; 1]; 256] = {
            let mut arr = [[0u8; 1]; 256];
            let mut i = 0;
            while i < 256 {
                arr[i] = [i as u8];
                i += 1;
            }
            arr
        };
        &SINGLE_BYTE[b0 as usize]
    } else {
        lookup_two_byte_preimage(b0, b1)
    }
}

/// Look up a preimage for the given `MiniMD5` hash value using the embedded table.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn lookup_mini_md5_preimage(hash: u8) -> &'static [u8] {
    let (len, b0, b1) = MINI_MD5_8BIT_PREIMAGES[hash as usize];
    if len == 1 {
        // Safety: i ranges from 0 to 255, which fits in u8
        static SINGLE_BYTE: [[u8; 1]; 256] = {
            let mut arr = [[0u8; 1]; 256];
            let mut i = 0;
            while i < 256 {
                arr[i] = [i as u8];
                i += 1;
            }
            arr
        };
        &SINGLE_BYTE[b0 as usize]
    } else {
        lookup_two_byte_preimage(b0, b1)
    }
}

/// Look up a preimage for the given `MiniSHA256` hash value using the embedded table.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn lookup_mini_sha256_preimage(hash: u8) -> &'static [u8] {
    let (len, b0, b1) = MINI_SHA256_8BIT_PREIMAGES[hash as usize];
    if len == 1 {
        // Safety: i ranges from 0 to 255, which fits in u8
        static SINGLE_BYTE: [[u8; 1]; 256] = {
            let mut arr = [[0u8; 1]; 256];
            let mut i = 0;
            while i < 256 {
                arr[i] = [i as u8];
                i += 1;
            }
            arr
        };
        &SINGLE_BYTE[b0 as usize]
    } else {
        lookup_two_byte_preimage(b0, b1)
    }
}

/// Helper to return a static reference to a two-byte preimage.
/// Uses a lookup table of all possible 2-byte combinations.
#[allow(clippy::cast_possible_truncation)]
fn lookup_two_byte_preimage(b0: u8, b1: u8) -> &'static [u8] {
    // Create a static array of all possible 2-byte combinations
    // This is 64KB but allows O(1) lookup
    // Safety: (i & 0xFF) always fits in u8, (i >> 8) fits in u8 for i < 65536
    static TWO_BYTE_TABLE: [[u8; 2]; 65536] = {
        let mut arr = [[0u8; 2]; 65536];
        let mut i: usize = 0;
        while i < 65536 {
            arr[i] = [(i & 0xFF) as u8, (i >> 8) as u8];
            i += 1;
        }
        arr
    };

    let index = (b0 as usize) | ((b1 as usize) << 8);
    &TWO_BYTE_TABLE[index]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{md5_8bit, mini_md5, mini_sha256, sha256_8bit};

    #[test]
    fn test_embedded_md5_8bit_lookup() {
        for hash in 0..=255u8 {
            let preimage = lookup_md5_8bit_preimage(hash);
            let computed = md5_8bit(preimage);
            assert_eq!(
                computed, hash,
                "MD5 preimage for hash {hash} failed: got {computed}"
            );
        }
    }

    #[test]
    fn test_embedded_sha256_8bit_lookup() {
        for hash in 0..=255u8 {
            let preimage = lookup_sha256_8bit_preimage(hash);
            let computed = sha256_8bit(preimage);
            assert_eq!(
                computed, hash,
                "SHA256 preimage for hash {hash} failed: got {computed}"
            );
        }
    }

    #[test]
    fn test_embedded_mini_md5_lookup() {
        for hash in 0..=255u8 {
            let preimage = lookup_mini_md5_preimage(hash);
            let computed = mini_md5(preimage);
            assert_eq!(
                computed, hash,
                "MiniMD5 preimage for hash {hash} failed: got {computed}"
            );
        }
    }

    #[test]
    fn test_embedded_mini_sha256_lookup() {
        for hash in 0..=255u8 {
            let preimage = lookup_mini_sha256_preimage(hash);
            let computed = mini_sha256(preimage);
            assert_eq!(
                computed, hash,
                "MiniSHA256 preimage for hash {hash} failed: got {computed}"
            );
        }
    }
}

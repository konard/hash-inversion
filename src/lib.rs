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

pub mod lookup_tables;
pub use lookup_tables::{
    lookup_md5_8bit_preimage, lookup_mini_md5_preimage, lookup_mini_sha256_preimage,
    lookup_sha256_8bit_preimage, MD5_8BIT_PREIMAGES, MINI_MD5_8BIT_PREIMAGES,
    MINI_SHA256_8BIT_PREIMAGES, SHA256_8BIT_PREIMAGES,
};

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
// Custom 8-bit Hash Functions (Native Small Output Size)
// ============================================================================
//
// These hash functions are designed from the ground up to output only 8 bits.
// Unlike the truncated versions above, these put their FULL output into the
// lookup table, enabling true "full hash inversion" for small hash sizes.
//
// Design philosophy:
// - MiniMD5: Inspired by MD5's structure with 4 rounds and different mixing functions
// - MiniSHA256: Inspired by SHA-256's structure with working variables and message schedule

/// Constants for `MiniMD5` (derived from sine function, like MD5).
/// These are floor(256 * abs(sin(i))) for i = 1..16.
const MINI_MD5_K: [u8; 16] = [
    212, 232, 35, 195, 245, 71, 164, 253, 103, 219, 228, 14, 122, 175, 239, 48,
];

/// `MiniMD5`: An 8-bit hash function inspired by MD5's structure.
///
/// This implements a simplified version of MD5's approach:
/// - Single 8-bit state (vs MD5's 4×32-bit A, B, C, D)
/// - 4 rounds with different mixing functions (F, G, H, I)
/// - Modular addition and bit rotations
/// - Constants derived from sine function
///
/// **Important**: This is NOT cryptographically secure. It's designed for
/// educational exploration of hash inversion with small output spaces.
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
/// use hash_inversion::mini_md5;
/// let h1 = mini_md5(b"hello");
/// let h2 = mini_md5(b"hello");
/// assert_eq!(h1, h2); // Deterministic
/// assert!(h1 <= 255);
/// ```
#[must_use]
#[allow(clippy::many_single_char_names)] // MD5 traditionally uses a, b, c, d, f, g, h for state
pub fn mini_md5(data: &[u8]) -> u8 {
    // Initialize state with multiple variables (inspired by MD5's A, B, C, D)
    let mut a: u8 = 0x67; // From MD5's 0x67452301
    let mut b: u8 = 0xef; // From MD5's 0xefcdab89
    let mut c: u8 = 0x98; // From MD5's 0x98badcfe
    let mut d: u8 = 0x10; // From MD5's 0x10325476

    // Process each byte of input with all 4 round functions
    for (i, &byte) in data.iter().enumerate() {
        let k_idx = i % 16;

        // Round 1: F function - (b AND c) OR ((NOT b) AND d)
        let f = (b & c) | ((!b) & d);
        let temp = a
            .wrapping_add(f)
            .wrapping_add(byte)
            .wrapping_add(MINI_MD5_K[k_idx]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(temp.rotate_left(3));

        // Round 2: G function - (d AND b) OR (c AND (NOT d))
        let g = (d & b) | (c & (!d));
        let temp = a
            .wrapping_add(g)
            .wrapping_add(byte ^ 0x5a) // XOR for more mixing
            .wrapping_add(MINI_MD5_K[(k_idx + 5) % 16]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(temp.rotate_left(5));

        // Round 3: H function - b XOR c XOR d
        let h = b ^ c ^ d;
        let temp = a
            .wrapping_add(h)
            .wrapping_add(byte.rotate_left(4)) // Rotate input
            .wrapping_add(MINI_MD5_K[(k_idx + 7) % 16]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(temp.rotate_left(7));

        // Round 4: I function - c XOR (b OR (NOT d))
        let ii = c ^ (b | (!d));
        let temp = a
            .wrapping_add(ii)
            .wrapping_add(!byte) // Complement input
            .wrapping_add(MINI_MD5_K[(k_idx + 11) % 16]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(temp.rotate_left(2));
    }

    // Handle empty input with multiple rounds of mixing
    if data.is_empty() {
        for i in 0..4 {
            a = a.wrapping_add(MINI_MD5_K[i]).rotate_left(3);
            b = b.wrapping_add(MINI_MD5_K[i + 4]).rotate_left(5);
            c = c.wrapping_add(MINI_MD5_K[i + 8]).rotate_left(7);
            d = d.wrapping_add(MINI_MD5_K[i + 12]).rotate_left(2);
        }
    }

    // Final mixing: XOR all state variables with each other
    #[allow(clippy::cast_possible_truncation)]
    let len_byte = data.len() as u8;
    let result = a ^ b.rotate_left(2) ^ c.rotate_left(4) ^ d.rotate_left(6);
    result.wrapping_add(len_byte.wrapping_mul(179)) // Prime multiplier
}

/// Constants for `MiniSHA256` (derived from square roots of primes, like SHA-256).
/// These are the first 8 bits of fractional parts of sqrt(2), sqrt(3), sqrt(5), etc.
const MINI_SHA256_H: [u8; 8] = [
    0x6a, // from 0x6a09e667 (sqrt(2))
    0xbb, // from 0xbb67ae85 (sqrt(3))
    0x3c, // from 0x3c6ef372 (sqrt(5))
    0xa5, // from 0xa54ff53a (sqrt(7))
    0x51, // from 0x510e527f (sqrt(11))
    0x9b, // from 0x9b05688c (sqrt(13))
    0x1f, // from 0x1f83d9ab (sqrt(17))
    0x5b, // from 0x5be0cd19 (sqrt(19))
];

/// Round constants for `MiniSHA256` (derived from cube roots of primes).
/// These are the first 8 bits of fractional parts of cbrt(2), cbrt(3), ..., cbrt(19).
const MINI_SHA256_K: [u8; 8] = [
    0x42, // from 0x428a2f98 (cbrt(2))
    0x71, // from 0x71374491 (cbrt(3))
    0xb5, // from 0xb5c0fbcf (cbrt(5))
    0xe9, // from 0xe9b5dba5 (cbrt(7))
    0x39, // from 0x3956c25b (cbrt(11))
    0x59, // from 0x59f111f1 (cbrt(13))
    0x92, // from 0x923f82a4 (cbrt(17))
    0xab, // from 0xab1c5ed5 (cbrt(19))
];

/// `MiniSHA256`: An 8-bit hash function inspired by SHA-256's structure.
///
/// This implements a simplified version of SHA-256's approach:
/// - 8 working variables compressed into operations on 8-bit state
/// - Sigma functions (bitwise rotations and XOR)
/// - Choice (Ch) and Majority (Maj) functions
/// - Message schedule with expansion
///
/// **Important**: This is NOT cryptographically secure. It's designed for
/// educational exploration of hash inversion with small output spaces.
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
/// use hash_inversion::mini_sha256;
/// let h1 = mini_sha256(b"hello");
/// let h2 = mini_sha256(b"hello");
/// assert_eq!(h1, h2); // Deterministic
/// assert!(h1 <= 255);
/// ```
#[must_use]
#[allow(clippy::many_single_char_names)]
pub fn mini_sha256(data: &[u8]) -> u8 {
    // Initialize working variables (a through h, compressed to single bytes)
    // Note: Single-character names are intentional to match SHA-256 specification
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    // Process each byte of input
    for (i, &byte) in data.iter().enumerate() {
        let k = MINI_SHA256_K[i % 8];

        // Message schedule expansion (simplified, truncation is intentional)
        #[allow(clippy::cast_possible_truncation)]
        let i_byte = i as u8;
        let w = byte.wrapping_add(k).wrapping_add(i_byte.rotate_left(3));

        // Sigma1(e): rotate and XOR operations (simplified from SHA-256)
        let sigma1 = e.rotate_right(2) ^ e.rotate_right(4) ^ (e >> 3);

        // Ch(e, f, g): Choice function - (e AND f) XOR ((NOT e) AND g)
        let ch = (e & f) ^ ((!e) & g);

        // Temp1 = h + Sigma1 + Ch + k + w
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w);

        // Sigma0(a): rotate and XOR operations
        let sigma0 = a.rotate_right(1) ^ a.rotate_right(3) ^ (a >> 2);

        // Maj(a, b, c): Majority function - (a AND b) XOR (a AND c) XOR (b AND c)
        let maj = (a & b) ^ (a & c) ^ (b & c);

        // Temp2 = Sigma0 + Maj
        let temp2 = sigma0.wrapping_add(maj);

        // Update working variables
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Handle empty input
    if data.is_empty() {
        a = a.wrapping_add(MINI_SHA256_K[0]);
    }

    // Final mixing with non-linear operations to break linear relationship
    // The naive sum of all working variables creates a linear relationship,
    // so we use XOR with rotations and prime multipliers instead.
    #[allow(clippy::cast_possible_truncation)]
    let len_byte = data.len() as u8;

    // Layer 1: XOR all together with different rotation amounts
    let mut result = a ^ b.rotate_left(1) ^ c.rotate_left(2) ^ d.rotate_left(3);
    result ^= e.rotate_left(4) ^ f.rotate_left(5) ^ g.rotate_left(6) ^ h.rotate_left(7);

    // Layer 2: Feistel-like mixing with prime multipliers
    result = result.wrapping_add(a.wrapping_mul(3));
    result ^= b.wrapping_mul(5);
    result = result.wrapping_add(c.wrapping_mul(7));
    result ^= d.wrapping_mul(11);
    result = result.wrapping_add(e.wrapping_mul(13));
    result ^= f.wrapping_mul(17);
    result = result.wrapping_add(g.wrapping_mul(19));
    result ^= h.wrapping_mul(23);

    result.wrapping_add(len_byte.wrapping_mul(179))
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

    /// Create a new lookup table for `MiniMD5` (custom 8-bit hash) inversion.
    ///
    /// Unlike truncated MD5, `MiniMD5` natively produces 8-bit output, so this
    /// lookup table contains the FULL hash function output (not truncated).
    /// This enables true "full hash inversion" for the custom algorithm.
    ///
    /// # Returns
    ///
    /// A lookup table that can invert `MiniMD5` hashes with 100% coverage.
    ///
    /// # Examples
    ///
    /// ```
    /// use hash_inversion::{HashLookupTable, mini_md5};
    ///
    /// let table = HashLookupTable::new_mini_md5();
    /// let original = b"test";
    /// let hash = mini_md5(original);
    /// let preimage = table.lookup(u32::from(hash)).unwrap();
    /// // Verify the preimage hashes to the same value
    /// assert_eq!(mini_md5(preimage), hash);
    /// ```
    #[must_use]
    pub fn new_mini_md5() -> Self {
        let mut table = HashMap::new();

        // For 8-bit output, we only need to enumerate enough inputs to cover all 256 values
        // Using single bytes 0-255 as inputs provides compact preimages
        for i in 0u8..=255 {
            let data = [i];
            let hash = u32::from(mini_md5(&data));
            table.entry(hash).or_insert_with(|| data.to_vec());
        }

        // If we missed any hash values, fill them with 2-byte inputs
        if table.len() < 256 {
            for i in 0u16..=65535 {
                if table.len() >= 256 {
                    break;
                }
                let data = i.to_le_bytes();
                let hash = u32::from(mini_md5(&data));
                table.entry(hash).or_insert_with(|| data.to_vec());
            }
        }

        Self {
            table,
            bits: 8,
            hash_name: "MiniMD5".to_string(),
        }
    }

    /// Create a new lookup table for `MiniSHA256` (custom 8-bit hash) inversion.
    ///
    /// Unlike truncated SHA-256, `MiniSHA256` natively produces 8-bit output, so this
    /// lookup table contains the FULL hash function output (not truncated).
    /// This enables true "full hash inversion" for the custom algorithm.
    ///
    /// # Returns
    ///
    /// A lookup table that can invert `MiniSHA256` hashes with 100% coverage.
    ///
    /// # Examples
    ///
    /// ```
    /// use hash_inversion::{HashLookupTable, mini_sha256};
    ///
    /// let table = HashLookupTable::new_mini_sha256();
    /// let original = b"test";
    /// let hash = mini_sha256(original);
    /// let preimage = table.lookup(u32::from(hash)).unwrap();
    /// // Verify the preimage hashes to the same value
    /// assert_eq!(mini_sha256(preimage), hash);
    /// ```
    #[must_use]
    pub fn new_mini_sha256() -> Self {
        let mut table = HashMap::new();

        // For 8-bit output, we only need to enumerate enough inputs to cover all 256 values
        for i in 0u8..=255 {
            let data = [i];
            let hash = u32::from(mini_sha256(&data));
            table.entry(hash).or_insert_with(|| data.to_vec());
        }

        // If we missed any hash values, fill them with 2-byte inputs
        if table.len() < 256 {
            for i in 0u16..=65535 {
                if table.len() >= 256 {
                    break;
                }
                let data = i.to_le_bytes();
                let hash = u32::from(mini_sha256(&data));
                table.entry(hash).or_insert_with(|| data.to_vec());
            }
        }

        Self {
            table,
            bits: 8,
            hash_name: "MiniSHA256".to_string(),
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
mod tests;

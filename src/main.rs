//! Hash Inversion Demonstration
//!
//! This binary demonstrates the hash inversion functionality:
//! 1. Simple mathematical inverse for toy hash function
//! 2. Lookup table inversion for truncated MD5 and SHA-256
//! 3. Custom 8-bit hash functions with full hash inversion (`MiniMD5`, `MiniSHA256`)

use hash_inversion::{
    inverse_simple_hash, md5_16bit, md5_8bit, mini_md5, mini_sha256, sha256_16bit, sha256_8bit,
    simple_hash, HashLookupTable, SIMPLE_MOD, VERSION,
};

fn main() {
    println!("Hash Inversion Prototype v{VERSION}");
    println!("{}", "=".repeat(60));
    println!();

    // Part 1: Simple toy hash with mathematical inverse
    demonstrate_simple_hash();

    // Part 2: Truncated MD5 with lookup table
    demonstrate_md5_lookup();

    // Part 3: Truncated SHA-256 with lookup table
    demonstrate_sha256_lookup();

    // Part 4: Show that lookup tables find ANY preimage, not the original
    demonstrate_preimage_concept();

    // Part 5: Custom 8-bit hash functions (full hash inversion)
    demonstrate_custom_hashes();

    println!("\n{}", "=".repeat(60));
    println!("Demonstration complete!");
}

fn demonstrate_simple_hash() {
    println!("PART 1: Simple Toy Hash Function (Mathematical Inverse)");
    println!("{}", "-".repeat(60));
    println!();
    println!("Function: h(x) = (7x + 3) mod 101");
    println!("Inverse:  h^-1(y) = 29(y - 3) mod 101");
    println!();
    println!("Testing roundtrip for first 10 values:");
    println!("x -> hash(x) -> inverse_hash(hash(x))");
    println!();

    for x in 0..10 {
        let h = simple_hash(x);
        let x_back = inverse_simple_hash(h);
        println!("{x:3} -> {h:3} -> {x_back:3}  {}", check_mark(x == x_back));
    }

    // Verify all values
    let mut all_passed = true;
    for x in 0..SIMPLE_MOD {
        let h = simple_hash(x);
        let x_back = inverse_simple_hash(h);
        if x != x_back {
            all_passed = false;
            break;
        }
    }

    println!();
    if all_passed {
        println!("All {SIMPLE_MOD} values verified: inverse function works correctly!");
    } else {
        println!("ERROR: Some values failed verification!");
    }
    println!();
}

fn demonstrate_md5_lookup() {
    println!("PART 2: Truncated MD5 Hash (Lookup Table Inverse)");
    println!("{}", "-".repeat(60));
    println!();

    // 8-bit MD5
    println!("Building 8-bit MD5 lookup table...");
    let table_8bit = HashLookupTable::new_md5_8bit();
    println!(
        "Coverage: {}/{} ({:.2}%)",
        table_8bit.coverage(),
        table_8bit.max_hash_values(),
        table_8bit.coverage_percent()
    );

    let test_inputs: &[&[u8]] = &[b"hello", b"world", b"test", b"hash", b"inversion"];
    println!("\nTesting 8-bit MD5 inversion:");
    for input in test_inputs {
        let hash = md5_8bit(input);
        let preimage = table_8bit.lookup(u32::from(hash));
        let verified = preimage.is_some_and(|p| md5_8bit(p) == hash);
        println!(
            "  {:?} -> hash={:3} -> preimage found: {} {}",
            String::from_utf8_lossy(input),
            hash,
            preimage.is_some(),
            check_mark(verified)
        );
    }

    // 16-bit MD5
    println!("\nBuilding 16-bit MD5 lookup table...");
    let table_16bit = HashLookupTable::new_md5_16bit();
    println!(
        "Coverage: {}/{} ({:.2}%)",
        table_16bit.coverage(),
        table_16bit.max_hash_values(),
        table_16bit.coverage_percent()
    );

    println!("\nTesting 16-bit MD5 inversion:");
    for input in test_inputs {
        let hash = md5_16bit(input);
        let preimage = table_16bit.lookup(u32::from(hash));
        let verified = preimage.is_some_and(|p| md5_16bit(p) == hash);
        println!(
            "  {:?} -> hash={:5} -> preimage found: {} {}",
            String::from_utf8_lossy(input),
            hash,
            preimage.is_some(),
            check_mark(verified)
        );
    }
    println!();
}

fn demonstrate_sha256_lookup() {
    println!("PART 3: Truncated SHA-256 Hash (Lookup Table Inverse)");
    println!("{}", "-".repeat(60));
    println!();

    // 8-bit SHA-256
    println!("Building 8-bit SHA-256 lookup table...");
    let table_8bit = HashLookupTable::new_sha256_8bit();
    println!(
        "Coverage: {}/{} ({:.2}%)",
        table_8bit.coverage(),
        table_8bit.max_hash_values(),
        table_8bit.coverage_percent()
    );

    let test_inputs: &[&[u8]] = &[b"hello", b"world", b"test"];
    println!("\nTesting 8-bit SHA-256 inversion:");
    for input in test_inputs {
        let hash = sha256_8bit(input);
        let preimage = table_8bit.lookup(u32::from(hash));
        let verified = preimage.is_some_and(|p| sha256_8bit(p) == hash);
        println!(
            "  {:?} -> hash={:3} -> preimage found: {} {}",
            String::from_utf8_lossy(input),
            hash,
            preimage.is_some(),
            check_mark(verified)
        );
    }

    // 16-bit SHA-256
    println!("\nBuilding 16-bit SHA-256 lookup table...");
    let table_16bit = HashLookupTable::new_sha256_16bit();
    println!(
        "Coverage: {}/{} ({:.2}%)",
        table_16bit.coverage(),
        table_16bit.max_hash_values(),
        table_16bit.coverage_percent()
    );

    println!("\nTesting 16-bit SHA-256 inversion:");
    for input in test_inputs {
        let hash = sha256_16bit(input);
        let preimage = table_16bit.lookup(u32::from(hash));
        let verified = preimage.is_some_and(|p| sha256_16bit(p) == hash);
        println!(
            "  {:?} -> hash={:5} -> preimage found: {} {}",
            String::from_utf8_lossy(input),
            hash,
            preimage.is_some(),
            check_mark(verified)
        );
    }
    println!();
}

fn demonstrate_preimage_concept() {
    println!("PART 4: Understanding Preimages");
    println!("{}", "-".repeat(60));
    println!();
    println!("Note: The lookup table finds ANY input that produces the hash,");
    println!("not necessarily the ORIGINAL input. This is expected because:");
    println!("1. Hash functions map many inputs to the same output (collisions)");
    println!("2. Truncating to 8/16 bits increases collision rate dramatically");
    println!();

    let table = HashLookupTable::new_md5_8bit();
    let original = b"secret message";
    let hash = md5_8bit(original);
    let preimage = table.lookup(u32::from(hash)).unwrap();

    println!("Example:");
    println!("  Original input: {:?}", String::from_utf8_lossy(original));
    println!("  8-bit MD5 hash: {hash}");
    println!("  Found preimage: {preimage:?} (as bytes)");
    println!("  Preimage hash:  {}", md5_8bit(preimage));
    println!();

    if preimage == original {
        println!("  (Preimage happens to match original - rare!)");
    } else {
        println!("  (Preimage differs from original - this is expected)");
        println!("  Both inputs hash to the same 8-bit value (a collision).");
    }
}

fn demonstrate_custom_hashes() {
    println!("PART 5: Custom 8-bit Hash Functions (Full Hash Inversion)");
    println!("{}", "-".repeat(60));
    println!();
    println!("Unlike truncated hashes, these custom functions natively output 8 bits.");
    println!("This means the lookup table contains the FULL hash function output,");
    println!("enabling true 'full hash inversion' rather than truncated inversion.");
    println!();

    // MiniMD5
    println!("=== MiniMD5 (inspired by MD5's structure) ===");
    println!("Building MiniMD5 lookup table...");
    let mini_md5_table = HashLookupTable::new_mini_md5();
    println!(
        "Coverage: {}/{} ({:.2}%)",
        mini_md5_table.coverage(),
        mini_md5_table.max_hash_values(),
        mini_md5_table.coverage_percent()
    );

    let test_inputs: &[&[u8]] = &[b"hello", b"world", b"test", b"hash", b"inversion"];
    println!("\nTesting MiniMD5 inversion:");
    for input in test_inputs {
        let hash = mini_md5(input);
        let preimage = mini_md5_table.lookup(u32::from(hash));
        let verified = preimage.is_some_and(|p| mini_md5(p) == hash);
        println!(
            "  {:?} -> hash={:3} -> preimage found: {} {}",
            String::from_utf8_lossy(input),
            hash,
            preimage.is_some(),
            check_mark(verified)
        );
    }

    // MiniSHA256
    println!("\n=== MiniSHA256 (inspired by SHA-256's structure) ===");
    println!("Building MiniSHA256 lookup table...");
    let mini_sha256_table = HashLookupTable::new_mini_sha256();
    println!(
        "Coverage: {}/{} ({:.2}%)",
        mini_sha256_table.coverage(),
        mini_sha256_table.max_hash_values(),
        mini_sha256_table.coverage_percent()
    );

    println!("\nTesting MiniSHA256 inversion:");
    for input in test_inputs {
        let hash = mini_sha256(input);
        let preimage = mini_sha256_table.lookup(u32::from(hash));
        let verified = preimage.is_some_and(|p| mini_sha256(p) == hash);
        println!(
            "  {:?} -> hash={:3} -> preimage found: {} {}",
            String::from_utf8_lossy(input),
            hash,
            preimage.is_some(),
            check_mark(verified)
        );
    }

    // Compare truncated vs custom
    println!("\n=== Comparison: Truncated vs Custom Hash ===");
    println!("Truncated approach: Take 8 bits from 128/256-bit hash");
    println!("Custom approach: Hash function designed to output exactly 8 bits");
    println!();
    println!("Both achieve 100% coverage for 8-bit output, but the custom");
    println!("approach stores the FULL function output in the lookup table.");
    println!();
}

const fn check_mark(success: bool) -> &'static str {
    if success {
        "[OK]"
    } else {
        "[FAIL]"
    }
}

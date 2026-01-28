//! Basic usage example for hash-inversion.
//!
//! This example demonstrates the hash inversion functionality.
//!
//! Run with: `cargo run --example basic_usage`

use hash_inversion::{
    inverse_simple_hash, md5_8bit, sha256_8bit, simple_hash, HashLookupTable, SIMPLE_MOD,
};

fn main() {
    println!("Hash Inversion Example");
    println!("======================\n");

    // Example 1: Simple toy hash function with mathematical inverse
    println!("1. Simple Toy Hash Function");
    println!("   Function: h(x) = (7x + 3) mod 101");
    println!();

    for x in [0, 5, 10, 50, 100] {
        let h = simple_hash(x);
        let x_back = inverse_simple_hash(h);
        println!("   x={x:3} -> hash={h:3} -> inverse={x_back:3}");
    }
    println!();

    // Verify all values round-trip correctly
    let all_pass = (0..SIMPLE_MOD).all(|x| inverse_simple_hash(simple_hash(x)) == x);
    println!("   All {SIMPLE_MOD} values round-trip correctly: {all_pass}\n");

    // Example 2: Truncated MD5 with lookup table
    println!("2. Truncated MD5 (8-bit) with Lookup Table");
    println!();

    let md5_table = HashLookupTable::new_md5_8bit();
    println!(
        "   Table coverage: {}/{}",
        md5_table.coverage(),
        md5_table.max_hash_values()
    );
    println!();

    let test_inputs = ["hello", "world", "test"];
    for input in test_inputs {
        let hash = md5_8bit(input.as_bytes());
        let preimage = md5_table.lookup(u32::from(hash)).unwrap();
        println!(
            "   Input: {:?} -> hash: {:3} -> found preimage that hashes to: {:3}",
            input,
            hash,
            md5_8bit(preimage)
        );
    }
    println!();

    // Example 3: Truncated SHA-256 with lookup table
    println!("3. Truncated SHA-256 (8-bit) with Lookup Table");
    println!();

    let sha_table = HashLookupTable::new_sha256_8bit();
    println!(
        "   Table coverage: {}/{}",
        sha_table.coverage(),
        sha_table.max_hash_values()
    );
    println!();

    for input in test_inputs {
        let hash = sha256_8bit(input.as_bytes());
        let preimage = sha_table.lookup(u32::from(hash)).unwrap();
        println!(
            "   Input: {:?} -> hash: {:3} -> found preimage that hashes to: {:3}",
            input,
            hash,
            sha256_8bit(preimage)
        );
    }
    println!();

    // Example 4: Understanding preimages
    println!("4. Note on Preimages");
    println!("   The lookup table returns ANY input that produces the hash,");
    println!("   not necessarily the original input. This is expected because");
    println!("   hash functions are many-to-one (especially when truncated).");
}

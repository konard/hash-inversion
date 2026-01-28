//! Generate hash data for 256x256 visualization plots.
//!
//! This example computes hash values for all single-byte inputs (0-255)
//! for each 8-bit hash function and outputs the data as JSON.
//!
//! Run with: `cargo run --example generate_hash_data`

use hash_inversion::{md5_8bit, mini_md5, mini_sha256, sha256_8bit};

fn main() {
    // Generate data for each hash function
    let mut md5_data: Vec<u8> = Vec::with_capacity(256);
    let mut sha256_data: Vec<u8> = Vec::with_capacity(256);
    let mut mini_md5_data: Vec<u8> = Vec::with_capacity(256);
    let mut mini_sha256_data: Vec<u8> = Vec::with_capacity(256);

    for i in 0u8..=255 {
        let input = [i];
        md5_data.push(md5_8bit(&input));
        sha256_data.push(sha256_8bit(&input));
        mini_md5_data.push(mini_md5(&input));
        mini_sha256_data.push(mini_sha256(&input));
    }

    // Output as JSON for easy parsing by plotting script
    println!("{{");
    println!(r#"  "md5_8bit": {md5_data:?},"#);
    println!(r#"  "sha256_8bit": {sha256_data:?},"#);
    println!(r#"  "mini_md5": {mini_md5_data:?},"#);
    println!(r#"  "mini_sha256": {mini_sha256_data:?}"#);
    println!("}}");
}

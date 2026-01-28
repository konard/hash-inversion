//! Experiment to analyze and debug mini_sha256 behavior
//!
//! Run with: cargo run --example analyze_mini_sha256

/// Constants for MiniSHA256 (from lib.rs)
const MINI_SHA256_H: [u8; 8] = [0x6a, 0xbb, 0x3c, 0xa5, 0x51, 0x9b, 0x1f, 0x5b];

const MINI_SHA256_K: [u8; 8] = [0x42, 0x71, 0xb5, 0xe9, 0x39, 0x59, 0x92, 0xab];

/// Original mini_sha256 implementation (buggy - linear output)
fn mini_sha256_original(data: &[u8]) -> u8 {
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    for (i, &byte) in data.iter().enumerate() {
        let k = MINI_SHA256_K[i % 8];
        let i_byte = i as u8;
        let w = byte.wrapping_add(k).wrapping_add(i_byte.rotate_left(3));

        let sigma1 = e.rotate_right(2) ^ e.rotate_right(4) ^ (e >> 3);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w);

        let sigma0 = a.rotate_right(1) ^ a.rotate_right(3) ^ (a >> 2);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    if data.is_empty() {
        a = a.wrapping_add(MINI_SHA256_K[0]);
    }

    let len_byte = data.len() as u8;
    a.wrapping_add(b)
        .wrapping_add(c)
        .wrapping_add(d)
        .wrapping_add(e)
        .wrapping_add(f)
        .wrapping_add(g)
        .wrapping_add(h)
        ^ len_byte
}

/// Fixed mini_sha256 with XOR-based final mixing
fn mini_sha256_fixed(data: &[u8]) -> u8 {
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    for (i, &byte) in data.iter().enumerate() {
        let k = MINI_SHA256_K[i % 8];
        let i_byte = i as u8;
        let w = byte.wrapping_add(k).wrapping_add(i_byte.rotate_left(3));

        let sigma1 = e.rotate_right(2) ^ e.rotate_right(4) ^ (e >> 3);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w);

        let sigma0 = a.rotate_right(1) ^ a.rotate_right(3) ^ (a >> 2);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    if data.is_empty() {
        a = a.wrapping_add(MINI_SHA256_K[0]);
    }

    // Final mixing: XOR with rotations to break linear relationship
    let len_byte = data.len() as u8;
    let result = a
        ^ b.rotate_left(1)
        ^ c.rotate_left(2)
        ^ d.rotate_left(3)
        ^ e.rotate_left(4)
        ^ f.rotate_left(5)
        ^ g.rotate_left(6)
        ^ h.rotate_left(7);
    result.wrapping_add(len_byte.wrapping_mul(179))
}

/// Fixed mini_sha256 v2: multiple rounds of mixing
fn mini_sha256_fixed_v2(data: &[u8]) -> u8 {
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    for (i, &byte) in data.iter().enumerate() {
        let k = MINI_SHA256_K[i % 8];
        let i_byte = i as u8;
        let w = byte.wrapping_add(k).wrapping_add(i_byte.rotate_left(3));

        let sigma1 = e.rotate_right(2) ^ e.rotate_right(4) ^ (e >> 3);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w);

        let sigma0 = a.rotate_right(1) ^ a.rotate_right(3) ^ (a >> 2);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    if data.is_empty() {
        a = a.wrapping_add(MINI_SHA256_K[0]);
    }

    // Final mixing with multiple rounds
    let len_byte = data.len() as u8;

    // Round 1: XOR all together with shifts
    let mut result = a ^ b.rotate_left(1) ^ c.rotate_left(2) ^ d.rotate_left(3);
    result ^= e.rotate_left(4) ^ f.rotate_left(5) ^ g.rotate_left(6) ^ h.rotate_left(7);

    // Round 2: Feistel-like mixing
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

/// Fixed mini_sha256 v3: additional mixing in the loop itself
fn mini_sha256_fixed_v3(data: &[u8]) -> u8 {
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    // Additional accumulator for better mixing
    let mut acc: u8 = 0;

    for (i, &byte) in data.iter().enumerate() {
        let k = MINI_SHA256_K[i % 8];
        let i_byte = i as u8;
        let w = byte.wrapping_add(k).wrapping_add(i_byte.rotate_left(3));

        let sigma1 = e.rotate_right(2) ^ e.rotate_right(4) ^ (e >> 3);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w);

        let sigma0 = a.rotate_right(1) ^ a.rotate_right(3) ^ (a >> 2);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);

        // Accumulate into acc with non-linear mixing
        acc ^= temp1.wrapping_mul(byte.wrapping_add(i_byte).wrapping_add(1));
    }

    if data.is_empty() {
        a = a.wrapping_add(MINI_SHA256_K[0]);
        acc = 0x42;
    }

    // Final mixing using acc and working variables
    let len_byte = data.len() as u8;
    let result = acc
        ^ a.rotate_left(1)
        ^ b.rotate_left(2)
        ^ c.rotate_left(3)
        ^ d.rotate_left(4)
        ^ e.rotate_left(5)
        ^ f.rotate_left(6)
        ^ g.rotate_left(7)
        ^ h;

    result.wrapping_add(len_byte.wrapping_mul(179))
}

fn test_hash_quality(name: &str, hash_fn: fn(&[u8]) -> u8) {
    println!("\n=== Testing {} ===", name);

    // Check if output is linear
    let mut is_linear = true;
    let h0 = hash_fn(&[0]);
    let h1 = hash_fn(&[1]);
    let expected_diff = h1.wrapping_sub(h0);

    for i in 1u8..255 {
        let h_i = hash_fn(&[i]);
        let h_i1 = hash_fn(&[i + 1]);
        let diff = h_i1.wrapping_sub(h_i);
        if diff != expected_diff {
            is_linear = false;
            break;
        }
    }
    println!(
        "  Is linear: {} {}",
        is_linear,
        if is_linear {
            format!("(constant difference: {})", expected_diff)
        } else {
            String::new()
        }
    );

    // Count unique outputs
    let mut outputs = std::collections::HashSet::new();
    for i in 0u8..=255 {
        outputs.insert(hash_fn(&[i]));
    }
    println!("  Unique outputs for inputs 0-255: {}/256", outputs.len());

    // Show first 10 outputs
    print!("  First 10 outputs: ");
    for i in 0u8..10 {
        print!("{} ", hash_fn(&[i]));
    }
    println!();
}

/// Fixed mini_sha256 v4: Process data multiple times to get better mixing
fn mini_sha256_fixed_v4(data: &[u8]) -> u8 {
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    // Process data multiple times (4 rounds like real SHA-256 block processing)
    for round in 0..4 {
        for (i, &byte) in data.iter().enumerate() {
            let k = MINI_SHA256_K[(i + round) % 8];
            let i_byte = (i as u8).wrapping_add(round as u8 * 64);
            let w = byte
                .wrapping_add(k)
                .wrapping_add(i_byte.rotate_left((round % 8) as u32));

            let sigma1 = e.rotate_right(2) ^ e.rotate_right(4) ^ (e >> 3);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sigma1)
                .wrapping_add(ch)
                .wrapping_add(k)
                .wrapping_add(w);

            let sigma0 = a.rotate_right(1) ^ a.rotate_right(3) ^ (a >> 2);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sigma0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
    }

    if data.is_empty() {
        // Extra mixing for empty input
        for i in 0..8 {
            let k = MINI_SHA256_K[i];
            a = a.wrapping_add(k).rotate_left(3);
        }
    }

    // Final mixing
    let len_byte = data.len() as u8;
    let result = a.wrapping_mul(3)
        ^ b.wrapping_mul(5).rotate_left(1)
        ^ c.wrapping_mul(7).rotate_left(2)
        ^ d.wrapping_mul(11).rotate_left(3)
        ^ e.wrapping_mul(13).rotate_left(4)
        ^ f.wrapping_mul(17).rotate_left(5)
        ^ g.wrapping_mul(19).rotate_left(6)
        ^ h.wrapping_mul(23).rotate_left(7);

    result.wrapping_add(len_byte.wrapping_mul(179))
}

/// Fixed mini_sha256 v5: like MiniMD5's final mixing
fn mini_sha256_fixed_v5(data: &[u8]) -> u8 {
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    for (i, &byte) in data.iter().enumerate() {
        let k = MINI_SHA256_K[i % 8];
        let i_byte = i as u8;
        let w = byte.wrapping_add(k).wrapping_add(i_byte.rotate_left(3));

        let sigma1 = e.rotate_right(2) ^ e.rotate_right(4) ^ (e >> 3);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(sigma1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w);

        let sigma0 = a.rotate_right(1) ^ a.rotate_right(3) ^ (a >> 2);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sigma0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    if data.is_empty() {
        a = a.wrapping_add(MINI_SHA256_K[0]);
    }

    // MiniMD5-style final mixing: XOR with rotations
    let len_byte = data.len() as u8;
    let result = a
        ^ b.rotate_left(1)
        ^ c.rotate_left(2)
        ^ d.rotate_left(3)
        ^ e.rotate_left(4)
        ^ f.rotate_left(5)
        ^ g.rotate_left(6)
        ^ h.rotate_left(7);
    result.wrapping_add(len_byte.wrapping_mul(179))
}

/// Fixed mini_sha256 v6: Completely re-designed with better mixing
fn mini_sha256_fixed_v6(data: &[u8]) -> u8 {
    let mut a = MINI_SHA256_H[0];
    let mut b = MINI_SHA256_H[1];
    let mut c = MINI_SHA256_H[2];
    let mut d = MINI_SHA256_H[3];
    let mut e = MINI_SHA256_H[4];
    let mut f = MINI_SHA256_H[5];
    let mut g = MINI_SHA256_H[6];
    let mut h = MINI_SHA256_H[7];

    for (i, &byte) in data.iter().enumerate() {
        let k = MINI_SHA256_K[i % 8];
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

    // New final mixing: XOR with different rotations to break symmetry
    let len_byte = data.len() as u8;

    // First layer: XOR each variable with adjacent ones at different rotations
    let x1 = a ^ b.rotate_left(2) ^ c.rotate_left(4) ^ d.rotate_left(6);
    let x2 = e ^ f.rotate_left(1) ^ g.rotate_left(3) ^ h.rotate_left(5);

    // Second layer: combine with additional mixing
    let result = x1.wrapping_add(x2.rotate_left(4)) ^ (x1.wrapping_mul(7));

    result.wrapping_add(len_byte.wrapping_mul(179))
}

fn main() {
    println!("Analyzing mini_sha256 behavior...");

    test_hash_quality("Original mini_sha256", mini_sha256_original);
    test_hash_quality("Fixed mini_sha256 v2", mini_sha256_fixed_v2);
    test_hash_quality("Fixed mini_sha256 v6", mini_sha256_fixed_v6);
}

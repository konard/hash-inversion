#!/usr/bin/env node
/**
 * Generate embedded 8-bit lookup tables for hash inversion.
 *
 * This script runs a Rust program to compute the lookup tables and outputs
 * them as Rust const arrays that can be embedded in the code.
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, '..');

// Run the Rust program to generate lookup tables
const generateTables = () => {
    console.log('Running Rust program to generate lookup tables...');

    // Build and run the lookup table generator
    const output = execSync(
        'cargo run --bin generate-tables 2>/dev/null || cargo run --example generate_tables 2>/dev/null',
        {
            cwd: projectRoot,
            encoding: 'utf-8',
            maxBuffer: 10 * 1024 * 1024 // 10MB buffer
        }
    );

    return output;
};

try {
    const output = generateTables();
    console.log(output);
} catch (error) {
    console.error('Error generating lookup tables:', error.message);
    console.log('\nNote: You need to create the generate_tables example first.');
    process.exit(1);
}

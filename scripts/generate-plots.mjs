#!/usr/bin/env node
/**
 * Generate 256x256 hash visualization plots as SVG files.
 *
 * This script runs a Rust program to compute hash values for inputs 0-255,
 * then generates SVG scatter plots showing the hash function behavior.
 *
 * Each plot shows:
 * - X-axis: Input value (0-255)
 * - Y-axis: Output hash value (0-255)
 *
 * Run with: node scripts/generate-plots.mjs [--output-dir <dir>]
 */

import { execSync } from 'child_process';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, '..');

// Parse CLI arguments
const args = process.argv.slice(2);
const getArg = (name, defaultValue) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : defaultValue;
};

const outputDir = getArg('output-dir', join(projectRoot, 'plots'));

// Ensure output directory exists
if (!existsSync(outputDir)) {
  mkdirSync(outputDir, { recursive: true });
}

/**
 * Generate hash data by running the Rust example
 * @returns {Object} Hash data for all functions
 */
function generateHashData() {
  console.log('Running Rust program to generate hash data...');

  const output = execSync('cargo run --example generate_hash_data 2>/dev/null', {
    cwd: projectRoot,
    encoding: 'utf-8',
    maxBuffer: 10 * 1024 * 1024,
  });

  return JSON.parse(output);
}

/**
 * Generate an SVG scatter plot for a hash function
 * @param {string} name - Function name
 * @param {number[]} data - Array of 256 hash output values
 * @returns {string} SVG content
 */
function generateSvgPlot(name, data) {
  const width = 540;
  const height = 540;
  const margin = 60;
  const plotSize = 256;
  const scale = (width - 2 * margin) / plotSize;

  // Create SVG header
  let svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <style>
    .title { font: bold 16px sans-serif; }
    .axis-label { font: 12px sans-serif; }
    .tick-label { font: 10px sans-serif; }
    .grid { stroke: #e0e0e0; stroke-width: 0.5; }
    .axis { stroke: #333; stroke-width: 1; }
    .point { fill: #2563eb; }
  </style>

  <!-- Background -->
  <rect width="${width}" height="${height}" fill="white"/>

  <!-- Title -->
  <text x="${width / 2}" y="25" text-anchor="middle" class="title">${name} Hash Function (8-bit)</text>

  <!-- Grid lines -->
  <g class="grid">`;

  // Add vertical grid lines (every 32 units)
  for (let x = 0; x <= 256; x += 32) {
    const px = margin + x * scale;
    svg += `\n    <line x1="${px}" y1="${margin}" x2="${px}" y2="${margin + plotSize * scale}"/>`;
  }

  // Add horizontal grid lines (every 32 units)
  for (let y = 0; y <= 256; y += 32) {
    const py = margin + (256 - y) * scale;
    svg += `\n    <line x1="${margin}" y1="${py}" x2="${margin + plotSize * scale}" y2="${py}"/>`;
  }

  svg += `
  </g>

  <!-- Axes -->
  <g class="axis">
    <line x1="${margin}" y1="${margin + plotSize * scale}" x2="${margin + plotSize * scale}" y2="${margin + plotSize * scale}"/>
    <line x1="${margin}" y1="${margin}" x2="${margin}" y2="${margin + plotSize * scale}"/>
  </g>

  <!-- Axis labels -->
  <text x="${width / 2}" y="${height - 10}" text-anchor="middle" class="axis-label">Input (0-255)</text>
  <text x="15" y="${height / 2}" text-anchor="middle" class="axis-label" transform="rotate(-90, 15, ${height / 2})">Output Hash (0-255)</text>

  <!-- Tick labels -->
  <g class="tick-label">`;

  // X-axis tick labels
  for (let x = 0; x <= 256; x += 64) {
    const px = margin + x * scale;
    svg += `\n    <text x="${px}" y="${margin + plotSize * scale + 15}" text-anchor="middle">${x}</text>`;
  }

  // Y-axis tick labels
  for (let y = 0; y <= 256; y += 64) {
    const py = margin + (256 - y) * scale;
    svg += `\n    <text x="${margin - 8}" y="${py + 4}" text-anchor="end">${y}</text>`;
  }

  svg += `
  </g>

  <!-- Data points -->
  <g class="point">`;

  // Plot each data point
  for (let input = 0; input < 256; input++) {
    const output = data[input];
    const px = margin + input * scale;
    const py = margin + (255 - output) * scale;
    svg += `\n    <circle cx="${px.toFixed(2)}" cy="${py.toFixed(2)}" r="2"/>`;
  }

  svg += `
  </g>
</svg>`;

  return svg;
}

/**
 * Main function
 */
async function main() {
  try {
    // Generate hash data from Rust
    const hashData = generateHashData();

    // Define hash functions to plot
    const functions = [
      { key: 'md5_8bit', name: 'MD5 (truncated to 8-bit)' },
      { key: 'sha256_8bit', name: 'SHA-256 (truncated to 8-bit)' },
      { key: 'mini_md5', name: 'MiniMD5 (custom 8-bit)' },
      { key: 'mini_sha256', name: 'MiniSHA256 (custom 8-bit)' },
    ];

    // Generate SVG plots for each function
    for (const func of functions) {
      const data = hashData[func.key];
      if (!data) {
        console.error(`Warning: No data for ${func.key}`);
        continue;
      }

      const svg = generateSvgPlot(func.name, data);
      const filename = `${func.key}.svg`;
      const filepath = join(outputDir, filename);

      writeFileSync(filepath, svg);
      console.log(`Generated: ${filepath}`);
    }

    console.log(`\nAll plots generated in: ${outputDir}`);
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();

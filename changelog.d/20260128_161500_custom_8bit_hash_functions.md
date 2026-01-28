### Added

- Custom 8-bit hash functions for full hash inversion:
  - `MiniMD5`: An 8-bit hash function inspired by MD5's structure with 4 rounds, F/G/H/I mixing functions, and sine-derived constants
  - `MiniSHA256`: An 8-bit hash function inspired by SHA-256's structure with 8 working variables and square root-derived constants
- New `HashLookupTable` constructors for custom hash functions:
  - `new_mini_md5()`: Creates lookup table for MiniMD5 with 100% coverage
  - `new_mini_sha256()`: Creates lookup table for MiniSHA256 with 100% coverage
- Unlike truncated hashes, these custom functions natively output 8 bits, enabling true "full hash inversion" where the lookup table contains the complete hash function output

### Changed

- Lookup table construction now uses two-pass enumeration (1-byte then 2-byte inputs) to achieve 100% coverage for 8-bit hash functions

### Added

- Hash inversion prototype with two approaches:
  - Simple toy hash function `h(x) = (7x + 3) mod 101` with mathematical inverse
  - Lookup table-based inversion for truncated cryptographic hashes (MD5 and SHA-256)
- Support for 8-bit and 16-bit truncated hash variants
- `HashLookupTable` struct for building and querying preimage lookup tables
- Comprehensive test suite including unit tests and integration tests
- Example demonstrating hash inversion functionality

### Changed

- Updated package name from `my-package` to `hash-inversion`
- Replaced placeholder arithmetic functions with hash inversion implementation
- Updated dependencies to include `md-5` and `sha2` crates for cryptographic hashing

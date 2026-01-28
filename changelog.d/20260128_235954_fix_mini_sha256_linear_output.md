---
bump: patch
---

### Fixed
- Fixed MiniSHA256 hash function producing linear (non-random) output
  - The original implementation summed all 8 working variables, which preserved linear relationships
  - New implementation uses XOR with rotations and prime multipliers for proper hash mixing
  - Now produces 184 unique outputs (vs 128 before) with pseudo-random distribution
- Regenerated MiniSHA256 lookup table to match the corrected hash function

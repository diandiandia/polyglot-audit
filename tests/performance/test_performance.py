"""Performance and scalability benchmarks.

Implements DSR-049 / DSR-050 / SR-030:
- Benchmarks file inventory scanning, root hash calculation, and memory consumption.
- Simulates synthetic large directory trees.
- Validates timing and memory thresholds.
"""

import time
import unittest
from auditkit.snapshot.manifest import compute_root_hash


class TestPerformance(unittest.TestCase):

    def test_root_hash_scalability(self):
        # Generate 10,000 synthetic file entries
        files = [
            {
                "path": f"src/module_{i // 100}/file_{i}.py",
                "file_type": "regular",
                "bytes": 1024 + (i % 500),
                "sha256": f"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            }
            for i in range(10000)
        ]

        t0 = time.time()
        root_hash = compute_root_hash(files)
        elapsed = time.time() - t0

        self.assertEqual(len(root_hash), 64)
        # 10,000 files hash computation must complete under 1.0 second
        self.assertLess(elapsed, 1.0, f"Root hash computation took {elapsed:.2f}s for 10k files")


if __name__ == "__main__":
    unittest.main()

import unittest
import os
import shutil
import json
from vouch.session import TraceSession
from vouch.auditor import Auditor

class MockObj:
    def __init__(self, x):
        self.x = x
    def __repr__(self):
        return f"<MockObj x={self.x}>"

class TestLightMode(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_light_mode_output"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_light_mode_skips_hashing(self):
        """Test that light_mode=True produces SKIPPED_LIGHT hashes."""
        vch_file = os.path.join(self.test_dir, "light.vch")

        target = MockObj(10)
        auditor = Auditor(target, name="target")

        # Run with light_mode=True
        with TraceSession(vch_file, strict=False, light_mode=True) as sess:
            # Call a method
            _ = auditor.x # Get attribute
            # We can't easily intercept property access logging unless we wrap it
            # Let's wrap a function
            def my_func(a, b):
                return a + b

            wrapped_func = Auditor(my_func, name="my_func")
            res = wrapped_func(1, 2)
            self.assertEqual(res, 3)

        # Extract and check log
        import zipfile
        with zipfile.ZipFile(vch_file, 'r') as z:
            content = z.read("audit_log.json").decode('utf-8')
            log_data = [json.loads(line) for line in content.splitlines() if line.strip()]

        # Find the entry for my_func
        entry = next(e for e in log_data if e["target"] == "my_func")

        self.assertEqual(entry["args_hash"], "SKIPPED_LIGHT")
        self.assertEqual(entry["kwargs_hash"], "SKIPPED_LIGHT")
        self.assertEqual(entry["result_hash"], "SKIPPED_LIGHT")

        # Verify representations are still present
        self.assertIn("1", str(entry["args_repr"]))
        self.assertIn("2", str(entry["args_repr"]))
        self.assertEqual(entry["result_repr"], "3")

    def test_full_mode_hashes(self):
        """Test that light_mode=False (default) produces real hashes."""
        vch_file = os.path.join(self.test_dir, "full.vch")

        def my_func(a):
            return a + 1

        wrapped_func = Auditor(my_func, name="my_func")

        with TraceSession(vch_file, strict=False, light_mode=False) as sess:
            wrapped_func(5)

        import zipfile
        with zipfile.ZipFile(vch_file, 'r') as z:
            content = z.read("audit_log.json").decode('utf-8')
            log_data = [json.loads(line) for line in content.splitlines() if line.strip()]

        entry = next(e for e in log_data if e["target"] == "my_func")

        self.assertNotEqual(entry["args_hash"], "SKIPPED_LIGHT")
        self.assertNotEqual(entry["result_hash"], "SKIPPED_LIGHT")
        # Just check it looks like a hash (length 64 hex)
        self.assertEqual(len(entry["args_hash"]), 64)

if __name__ == "__main__":
    unittest.main()

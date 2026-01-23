import unittest
import os
import shutil
import tempfile
import json
import vouch
import pandas as pd

class TestIndexAudit(unittest.TestCase):
    def setUp(self):
        self.output_file = tempfile.mktemp(suffix=".vch")

    def tearDown(self):
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    def test_index_constructor_audited(self):
        """Test that pd.Index() is intercepted and methods are logged."""
        with vouch.vouch(self.output_file, strict=False):
            # Import inside to ensure wrapping if not already wrapped
            import pandas as pd

            # Create an Index
            idx = pd.Index([1, 2, 3], name="test_idx")

            # Perform an operation
            idx_max = idx.max()

            # Check type to ensure it's still usable
            self.assertEqual(idx_max, 3)

        # Verify log
        # We don't need Verifier for this check, just read the zip
        import zipfile
        with zipfile.ZipFile(self.output_file, 'r') as z:
            log_data = z.read("audit_log.json").decode("utf-8")

        # Parse NDJSON
        logs = [json.loads(line) for line in log_data.splitlines()]

        # Search for Index calls
        constructor_found = False
        method_found = False

        for entry in logs:
            target = entry.get("target", "")
            if "Index" in target:
                # Accept various forms of logging for the constructor/factory call
                if "Index.__init__" in target or target.endswith(".Index") or "Index(...)" in target:
                        constructor_found = True
                if "max" in target:
                    method_found = True

        # Note: Depending on implementation details of Auditor, the target name might vary slightly.
        # But we expect at least some mention of Index.

        # Let's print targets if failure for debugging
        if not constructor_found or not method_found:
                targets = [e.get("target") for e in logs]
                print(f"DEBUG: Logged targets: {targets}")

        self.assertTrue(constructor_found, "pd.Index constructor should be audited")
        self.assertTrue(method_found, "pd.Index method (max) should be audited")

if __name__ == "__main__":
    unittest.main()

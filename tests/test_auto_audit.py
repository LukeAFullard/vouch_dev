import unittest
import sys
import os
import shutil
import tempfile
import json
import zipfile
from vouch import auto_audit, Auditor, TraceSession

class TestAutoAudit(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vch_file = os.path.join(self.test_dir, "auto.vch")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_auto_audit_wraps_pandas(self):
        # We assume pandas is installed
        try:
            import pandas as pd
            # If it's already wrapped from previous tests, we can't easily test the transition from unwrapped->wrapped
            # But we can test that inside the block it IS wrapped.
            was_wrapped = isinstance(pd, Auditor)
        except ImportError:
            self.skipTest("pandas not installed")

        with auto_audit():
            # Should be wrapped now
            import pandas as pd2
            self.assertTrue(isinstance(pd2, Auditor), "Pandas should be wrapped inside auto_audit")
            self.assertTrue(isinstance(sys.modules["pandas"], Auditor))

            # If we access attributes, they should be wrapped or callable
            self.assertTrue(callable(pd2.DataFrame))

        # After exit
        import pandas as pd3
        # If it wasn't wrapped before, it should be unwrapped now
        if not was_wrapped:
            self.assertFalse(isinstance(pd3, Auditor), "Pandas should be unwrapped after auto_audit")
        else:
            # If it was already wrapped, we probably kept it wrapped?
            # My implementation restores 'original_modules'.
            # If 'pd' was already Auditor, 'original_modules' skipped it.
            # So sys.modules["pandas"] wasn't touched.
            self.assertTrue(isinstance(pd3, Auditor))

    def test_logging_via_auto_audit(self):
        try:
            import pandas
        except ImportError:
            self.skipTest("pandas not installed")

        with TraceSession(self.vch_file) as sess:
            with auto_audit():
                import pandas as pd
                # pd should be wrapped
                # Call something simple
                try:
                    df = pd.DataFrame({"a": [1]})
                except Exception as e:
                    self.fail(f"pd.DataFrame raised exception: {e}")

        # Verify log
        with zipfile.ZipFile(self.vch_file, 'r') as z:
            log = json.loads(z.read("audit_log.json"))

        found = False
        for entry in log:
            if "DataFrame" in entry.get("target", ""):
                found = True
                break
        self.assertTrue(found, "pd.DataFrame call was not logged")

if __name__ == "__main__":
    unittest.main()

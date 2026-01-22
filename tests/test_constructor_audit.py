import pandas as pd
import vouch
import unittest
import os
import shutil
from vouch.auditor import Auditor, AuditorMixin
from vouch.session import TraceSession

class TestConstructorGap(unittest.TestCase):
    def test_constructor_gap_solved(self):
        # Start a trace session
        with vouch.vouch(strict=False) as session:
            # Direct constructor call
            df = pd.DataFrame({"a": [1, 2, 3]})

            # 1. It should be a DataFrame (isinstance preserved)
            self.assertTrue(isinstance(df, pd.DataFrame), "pd.DataFrame() result should be instance of DataFrame")

            # 2. It should be an AuditorMixin (AuditedWrapper inherits AuditorMixin)
            self.assertTrue(isinstance(df, AuditorMixin), "pd.DataFrame() result should be instance of AuditorMixin")

            # 3. Methods should be audited
            # Call a method
            m = df.mean()
            print(f"Mean: {m}")

            # Flush log? Streaming logger writes immediately usually.

            # Read log
            log_path = os.path.join(session.temp_dir, "audit_log.json")
            with open(log_path, "r") as f:
                log_content = f.read()
                print("Log content:", log_content)

                # We expect "DataFrame.mean"
                # The name of the object is "DataFrame(...)"
                # Method name is "mean"
                # Log call uses "name.method"
                self.assertIn("DataFrame", log_content)
                self.assertIn("mean", log_content)

if __name__ == "__main__":
    unittest.main()

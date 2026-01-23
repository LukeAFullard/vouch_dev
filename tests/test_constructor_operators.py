import pandas as pd
import vouch
import unittest
import os
import shutil

class TestConstructorOperators(unittest.TestCase):
    def test_constructor_operator_auditing(self):
        log_content = ""
        with vouch.vouch(strict=False) as session:
            df = pd.DataFrame({"a": [1, 2]})

            # This should be audited
            df2 = df + 10

            self.assertEqual(df2.iloc[0, 0], 11)

            # Verify original object iloc works too
            self.assertEqual(df.iloc[0, 0], 1)

            log_path = os.path.join(session.temp_dir, "audit_log.json")

            # Copy log out or read inside
            if os.path.exists(log_path):
                with open(log_path, "r") as f:
                    log_content = f.read()
            else:
                self.fail(f"Log file not found at {log_path}")

        print("Log content:", log_content)
        self.assertIn("add", log_content, "Addition operator should be audited")

if __name__ == "__main__":
    unittest.main()

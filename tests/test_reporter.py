import unittest
import os
import shutil
import json
import sys
from vouch.session import TraceSession
from vouch.crypto import CryptoManager
from vouch.reporter import Reporter

class TestReporter(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_reporter_output"
        os.makedirs(self.test_dir, exist_ok=True)
        self.priv_key = os.path.join(self.test_dir, "id_rsa")
        self.pub_key = os.path.join(self.test_dir, "id_rsa.pub")
        CryptoManager.generate_keys(self.priv_key, self.pub_key)

        self.vch_path = os.path.join(self.test_dir, "report_test.vch")
        self.html_path = os.path.join(self.test_dir, "report.html")

        # Create a session with some data
        with TraceSession(self.vch_path, private_key_path=self.priv_key, allow_ephemeral=True) as sess:
            sess.logger.log_call("test_function", ["arg1"], {"kw": "val"}, "result")

            artifact_path = os.path.join(self.test_dir, "artifact.txt")
            with open(artifact_path, "w") as f:
                f.write("artifact content")
            sess.add_artifact(artifact_path)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        # Clean up .vch file if it leaked to cwd
        if os.path.exists(self.vch_path) and os.getcwd() == os.path.dirname(self.vch_path):
             os.remove(self.vch_path)

    def test_generate_report(self):
        # Generate report
        success = Reporter.generate_report(self.vch_path, self.html_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.html_path))

        # Check content
        with open(self.html_path, "r") as f:
            content = f.read()

        self.assertIn("Vouch Audit Report", content)
        self.assertIn("test_function", content)
        self.assertIn("artifact.txt", content)
        self.assertIn("Session Summary", content)
        self.assertIn("Audit Log", content)

    def test_generate_report_md(self):
        md_path = os.path.join(self.test_dir, "report.md")
        success = Reporter.generate_report(self.vch_path, md_path, format="md")
        self.assertTrue(success)
        self.assertTrue(os.path.exists(md_path))

        with open(md_path, "r") as f:
            content = f.read()

        self.assertIn("# Vouch Audit Report", content)
        self.assertIn("**File:**", content)
        self.assertIn("test_function", content)
        self.assertIn("artifact.txt", content)

    def test_cli_report_command(self):
        # Test via CLI wrapper simulation
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "vouch.cli", "report", self.vch_path, self.html_path],
            capture_output=True,
            text=True
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn(f"Report saved to {self.html_path}", result.stdout)
        self.assertTrue(os.path.exists(self.html_path))

if __name__ == '__main__':
    unittest.main()

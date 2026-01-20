import unittest
import os
import shutil
import tempfile
import sys
from io import StringIO
from unittest.mock import patch
from vouch.session import TraceSession
from vouch.cli import main as cli_main

class TestDiff(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.file1 = os.path.join(self.test_dir, "session1.vch")
        self.file2 = os.path.join(self.test_dir, "session2.vch")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def create_session(self, filepath, operations, artifacts=None):
        with TraceSession(filepath, allow_ephemeral=True) as sess:
            for op in operations:
                sess.logger.log_call(op["name"], op.get("args", []), op.get("kwargs", {}), op.get("result", None))

            if artifacts:
                for name, content in artifacts.items():
                    path = os.path.join(self.test_dir, name)
                    # Use unique filename to avoid collision if run quickly
                    # But we reuse name in artifacts dict, so file on disk needs unique name per test?
                    # Actually we are in temp dir.
                    # But if we create multiple sessions in same test_dir, we might overwrite.
                    # That's fine as long as add_artifact copies it.
                    with open(path, "w") as f:
                        f.write(content)
                    sess.add_artifact(path, arcname=name)

    def run_diff(self, file1, file2, extra_args=[]):
        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            with patch("sys.argv", ["vouch", "diff", file1, file2] + extra_args):
                cli_main()
        return captured_output.getvalue()

    def test_identical_structure(self):
        ops = [{"name": "foo"}]
        self.create_session(self.file1, ops)
        # Create identical session (timestamps/hashes will differ, but structure same)
        self.create_session(self.file2, ops)

        output = self.run_diff(self.file1, self.file2)
        self.assertIn("Environment matches", output)
        self.assertIn("Logs have identical structure", output)
        self.assertIn("Artifacts match", output) # No artifacts

    def test_different_operations(self):
        self.create_session(self.file1, [{"name": "foo"}])
        self.create_session(self.file2, [{"name": "bar"}])

        output = self.run_diff(self.file1, self.file2)
        self.assertIn("Mismatch at entry", output)
        self.assertIn("< call foo", output)
        self.assertIn("> call bar", output)

    def test_different_artifacts(self):
        self.create_session(self.file1, [], {"data.txt": "content1"})
        self.create_session(self.file2, [], {"data.txt": "content2"})

        output = self.run_diff(self.file1, self.file2, ["--show-hashes"])
        self.assertIn("Artifact mismatch: data.txt", output)
        # Check hashes are shown
        self.assertIn("<", output)
        self.assertIn(">", output)

    def test_missing_artifact(self):
        self.create_session(self.file1, [], {"data.txt": "content"})
        self.create_session(self.file2, [], {})

        output = self.run_diff(self.file1, self.file2, ["--show-hashes"])
        self.assertIn("Artifact mismatch: data.txt", output)
        self.assertIn("MISSING", output)

if __name__ == "__main__":
    unittest.main()

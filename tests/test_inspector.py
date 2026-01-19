import unittest
import os
import shutil
import tempfile
import json
import zipfile
from unittest.mock import patch
from io import StringIO
from vouch.inspector import InspectorShell
from vouch.session import TraceSession

class TestInspector(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vch_file = os.path.join(self.test_dir, "inspect.vch")

        # Create a session to inspect
        with TraceSession(self.vch_file, capture_script=False) as sess:
            sess.logger.log_call("func1", [], {}, "result")
            # Create dummy artifact
            art_path = os.path.join(self.test_dir, "art.txt")
            with open(art_path, "w") as f:
                f.write("content")
            sess.add_artifact(art_path)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def run_cmd(self, command_str):
        # Instantiate shell
        shell = InspectorShell(self.vch_file)

        # Capture output
        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            shell.onecmd(command_str)
            shell.do_quit(None) # Cleanup temp dir

        return captured_output.getvalue()

    def test_summary(self):
        output = self.run_cmd("summary")
        self.assertIn("Audit Package Summary", output)
        self.assertIn("Total Log Entries: 1", output)
        self.assertIn("Total Artifacts: 1", output)

    def test_timeline(self):
        output = self.run_cmd("timeline")
        self.assertIn("Timeline", output)
        self.assertIn("func1", output)

    def test_timeline_limit(self):
        output = self.run_cmd("timeline 1")
        self.assertIn("Timeline", output)
        self.assertIn("func1", output)

    def test_show_entry(self):
        output = self.run_cmd("show 0")
        self.assertIn("Log Entry #0", output)
        self.assertIn('"target": "func1"', output)

    def test_show_invalid_index(self):
        output = self.run_cmd("show 99")
        self.assertIn("Index out of range", output)

    def test_artifacts(self):
        output = self.run_cmd("artifacts")
        self.assertIn("art.txt", output)

    def test_loading_error(self):
        # Create bad zip
        bad_file = os.path.join(self.test_dir, "bad.vch")
        with open(bad_file, "w") as f:
            f.write("not a zip")

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            shell = InspectorShell(bad_file)

        output = captured_output.getvalue()
        self.assertIn("Error loading package", output)

if __name__ == "__main__":
    unittest.main()

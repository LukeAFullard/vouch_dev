import unittest
import os
import shutil
import json
import subprocess
from unittest.mock import patch
from vouch.session import TraceSession
from vouch.verifier import Verifier
from vouch.git_tools import GitTracker

class TestGit(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_git_output"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_git_capture(self):
        # Mock git commands
        with patch("vouch.git_tools.subprocess.call") as mock_call:
            # Simulate inside git repo
            mock_call.return_value = 0

            with patch("vouch.git_tools.subprocess.check_output") as mock_out:
                def side_effect(cmd, **kwargs):
                    if "HEAD" in cmd and "--abbrev-ref" in cmd:
                        return b"main"
                    if "HEAD" in cmd:
                        return b"abcdef123456"
                    if "status" in cmd:
                        return b"" # Clean
                    return b""

                mock_out.side_effect = side_effect

                vch_file = os.path.join(self.test_dir, "git.vch")
                with TraceSession(vch_file, strict=False, capture_git=True):
                    pass

                # Verify file contains git_metadata.json
                import zipfile
                with zipfile.ZipFile(vch_file, 'r') as z:
                    self.assertIn("git_metadata.json", z.namelist())
                    meta = json.loads(z.read("git_metadata.json"))
                    self.assertEqual(meta["commit_sha"], "abcdef123456")
                    self.assertEqual(meta["branch"], "main")
                    self.assertFalse(meta["is_dirty"])

    def test_git_dirty_capture(self):
         with patch("vouch.git_tools.subprocess.call") as mock_call:
            mock_call.return_value = 0
            with patch("vouch.git_tools.subprocess.check_output") as mock_out:
                def side_effect(cmd, **kwargs):
                    if "HEAD" in cmd and "--abbrev-ref" in cmd:
                        return b"dev"
                    if "HEAD" in cmd:
                        return b"123456abcdef"
                    if "status" in cmd:
                        return b"M file.py" # Dirty
                    if "diff" in cmd:
                        return b"diff content"
                    return b""

                mock_out.side_effect = side_effect

                vch_file = os.path.join(self.test_dir, "dirty.vch")
                with TraceSession(vch_file, strict=False):
                    pass

                import zipfile
                with zipfile.ZipFile(vch_file, 'r') as z:
                    meta = json.loads(z.read("git_metadata.json"))
                    self.assertTrue(meta["is_dirty"])
                    self.assertEqual(meta["diff"], "diff content")

if __name__ == "__main__":
    unittest.main()

import unittest
import os
import shutil
import tempfile
import sys
from io import StringIO
from unittest.mock import patch
import vouch
from vouch.cli import main
from vouch.session import TraceSession
from vouch.crypto import CryptoManager

class TestUsabilityFeatures(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.test_dir)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.test_dir)

    def test_vouch_init(self):
        """Test 'vouch init' command"""
        test_args = ["vouch", "init"]
        with patch.object(sys, 'argv', test_args):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                main()
                output = fake_out.getvalue()

        # Check .vouch directory exists
        self.assertTrue(os.path.exists(".vouch"))
        self.assertTrue(os.path.isdir(".vouch"))

        # Check keys exist
        self.assertTrue(os.path.exists(".vouch/id_rsa"))
        self.assertTrue(os.path.exists(".vouch/id_rsa.pub"))

        self.assertIn("Keys generated successfully", output)

    def test_trace_session_defaults(self):
        """Test TraceSession picks up default keys"""
        # Create default keys manually
        os.makedirs(".vouch")
        CryptoManager.generate_keys(".vouch/id_rsa", ".vouch/id_rsa.pub")

        # Init session without keys
        sess = TraceSession("test.vch", allow_ephemeral=True)
        self.assertEqual(sess.private_key_path, os.path.abspath(".vouch/id_rsa"))

    def test_vouch_audit_wrapper(self):
        """Test vouch.audit high-level wrapper"""
        # Create keys so signing works
        os.makedirs(".vouch")
        CryptoManager.generate_keys(".vouch/id_rsa", ".vouch/id_rsa.pub")

        # Use the wrapper
        with vouch.audit("wrapper.vch", targets=["json"], allow_ephemeral=True) as sess:
            # Check session is active
            self.assertIsNotNone(vouch.TraceSession.get_active_session())

            # Check auto-audit works (we mock json as target since we know it exists)
            import json
            self.assertTrue(isinstance(json, vouch.Auditor))

        # Check file created
        self.assertTrue(os.path.exists("wrapper.vch"))

if __name__ == "__main__":
    unittest.main()

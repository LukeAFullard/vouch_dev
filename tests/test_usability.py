import unittest
import os
import shutil
import tempfile
import json
import sys
from io import StringIO
from unittest.mock import patch
from vouch.session import TraceSession
from vouch.crypto import CryptoManager
from vouch.cli import verify
from argparse import Namespace

class TestUsability(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.priv_key = os.path.join(self.test_dir, "id_rsa")
        self.pub_key = os.path.join(self.test_dir, "id_rsa.pub")

        # Generate a key with password
        CryptoManager.generate_keys(self.priv_key, self.pub_key, password="correct")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_incorrect_password_message(self):
        """Test that incorrect password raises informative error"""
        vch_file = os.path.join(self.test_dir, "test.vch")

        # Should raise RuntimeError with "Incorrect password" inside the message or cause chain
        # TraceSession wraps exceptions in RuntimeError or prints warning based on strict mode.
        # Let's test CryptoManager directly first for the specific ValueError

        with self.assertRaises(ValueError) as cm:
            CryptoManager.load_private_key(self.priv_key, password="wrong")
        self.assertIn("Incorrect password", str(cm.exception))

        # Now test via TraceSession (strict=True)
        with self.assertRaises(RuntimeError) as cm:
            with TraceSession(vch_file, private_key_path=self.priv_key, private_key_password="wrong", strict=True) as sess:
                pass

        # Check multiline error message
        msg = str(cm.exception)
        self.assertIn("Failed to sign artifacts", msg)
        self.assertIn(f"Key path: {self.priv_key}", msg)
        self.assertIn("Incorrect password", msg)

    def test_missing_key_message(self):
        """Test that missing key file raises informative error"""
        missing_key = os.path.join(self.test_dir, "missing_key")
        vch_file = os.path.join(self.test_dir, "test.vch")

        with self.assertRaises(FileNotFoundError) as cm:
             with TraceSession(vch_file, private_key_path=missing_key, strict=True) as sess:
                pass

        msg = str(cm.exception)
        self.assertIn("Private key not found", msg)

    def test_progress_indicator(self):
        """Test that progress is printed for >10 artifacts"""
        vch_file = os.path.join(self.test_dir, "progress.vch")

        # Create 15 artifacts
        artifacts = []
        for i in range(15):
            path = os.path.join(self.test_dir, f"file_{i}.txt")
            with open(path, "w") as f:
                f.write("data")
            artifacts.append(path)

        # Capture stdout
        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            with TraceSession(vch_file, capture_script=False) as sess:
                for path in artifacts:
                    sess.add_artifact(path)
            # Session exit triggers _package_artifacts -> _process_artifacts -> printing

        output = captured_output.getvalue()
        # Should contain "Packaging artifacts..."
        self.assertIn("Packaging artifacts...", output)
        self.assertIn("15/15", output)

    def test_auto_data_verification(self):
        """Test the --auto-data verification flag"""
        vch_file = os.path.join(self.test_dir, "auto_verify.vch")
        data_file = os.path.join(self.test_dir, "external_data.csv")

        with open(data_file, 'w') as f:
            f.write("column1,column2\n1,2")

        # Create a session that tracks this file
        # Use private key to sign, as verify expects signatures
        with TraceSession(vch_file, strict=True, private_key_path=self.priv_key, private_key_password="correct") as sess:
            sess.track_file(data_file)

        # Run verify with --auto-data
        args = Namespace(
            file=vch_file,
            data=None,
            auto_data=True,
            auto_data_dir=self.test_dir
        )

        captured_output = StringIO()
        with patch("sys.stdout", captured_output):
            verify(args)

        output = captured_output.getvalue()

        # Should find valid
        self.assertIn("Auto-verifying referenced files", output)
        self.assertIn("[OK] Auto-Data Verification: Valid", output)
        self.assertIn(f"[OK] {data_file}", output)

if __name__ == "__main__":
    unittest.main()

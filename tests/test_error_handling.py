import unittest
import os
import shutil
import tempfile
import zipfile
import json
import sys
from unittest.mock import patch
from vouch.cli import main as cli_main

# Helper to run CLI
def run_cli_verify(vch_file):
    with patch("sys.argv", ["vouch", "verify", vch_file]):
        try:
            cli_main()
            return 0 # Success
        except SystemExit as e:
            return e.code

class TestErrorHandling(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vch_file = os.path.join(self.test_dir, "valid.vch")

        # Create a valid minimal Vouch package manually to start with
        # We need audit_log.json, environment.lock, public_key.pem, signature.sig
        # For this test we can mock the signature verification check if needed,
        # or create dummy files that suffice for structural checks.

        # Create dummy content
        self.audit_log = [{"op": "start", "previous_entry_hash": "0"*64}]
        self.env_lock = {"python_version": sys.version, "vouch_version": "0.1.0"}

        # Create valid zip
        with zipfile.ZipFile(self.vch_file, 'w') as z:
            z.writestr("audit_log.json", json.dumps(self.audit_log))
            z.writestr("environment.lock", json.dumps(self.env_lock))
            z.writestr("public_key.pem", "dummy key")
            z.writestr("signature.sig", "dummy sig")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_corrupted_zip(self):
        """Test verification of a truncated/corrupted zip file"""
        corrupt_file = os.path.join(self.test_dir, "corrupt.vch")
        with open(self.vch_file, "rb") as f:
            content = f.read()

        # Truncate it
        with open(corrupt_file, "wb") as f:
            f.write(content[:len(content)//2])

        # Verify should fail (BadZipFile)
        # Note: run_cli_verify catches SystemExit
        with patch("builtins.print") as mock_print:
            code = run_cli_verify(corrupt_file)
            self.assertNotEqual(code, 0)
            # Check if print called with "Invalid Vouch file"
            # We can inspect mock_print.call_args_list or stringify
            output = "\n".join([str(call) for call in mock_print.call_args_list])
            self.assertIn("Invalid Vouch file", output)

    def test_missing_component(self):
        """Test verification when a required component is missing"""
        missing_file = os.path.join(self.test_dir, "missing_log.vch")

        # Create zip without audit_log.json
        with zipfile.ZipFile(missing_file, 'w') as z:
            z.writestr("environment.lock", json.dumps(self.env_lock))
            z.writestr("public_key.pem", "dummy key")
            z.writestr("signature.sig", "dummy sig")

        with patch("builtins.print") as mock_print:
            code = run_cli_verify(missing_file)
            self.assertNotEqual(code, 0)
            output = "\n".join([str(call) for call in mock_print.call_args_list])
            self.assertIn("Missing audit_log.json", output)

    def test_missing_artifact_signature(self):
        """Test verification when artifacts.json exists but signature is missing"""
        unsigned_file = os.path.join(self.test_dir, "unsigned_artifacts.vch")

        with zipfile.ZipFile(unsigned_file, 'w') as z:
            z.writestr("audit_log.json", json.dumps(self.audit_log))
            z.writestr("environment.lock", json.dumps(self.env_lock))
            z.writestr("public_key.pem", "dummy key")
            z.writestr("signature.sig", "dummy sig")
            z.writestr("artifacts.json", "{}")
            # No artifacts.json.sig

        # We need to mock CryptoManager because "dummy sig" and "dummy key" will fail signature check
        # before we get to artifacts check.
        # But we want to test specifically the artifact signature check.
        # We can mock CryptoManager.verify_file to pass the log signature check.

        with patch("vouch.crypto.CryptoManager.verify_file") as mock_verify:
            with patch("vouch.crypto.CryptoManager.load_public_key"):
                 # First verify_file call (audit_log) passes
                 # Second verify_file call (artifacts) shouldn't happen if sig is missing
                 # The code checks for existence of artifacts.json.sig

                with patch("builtins.print") as mock_print:
                    code = run_cli_verify(unsigned_file)
                    self.assertNotEqual(code, 0)
                    output = "\n".join([str(call) for call in mock_print.call_args_list])
                    self.assertIn("Artifact Manifest Signature: Missing", output)

    def test_broken_log_chain(self):
        """Test verification of a broken hash chain"""
        broken_file = os.path.join(self.test_dir, "broken_chain.vch")

        # Create log with bad chain
        bad_log = [
            {"op": "start", "previous_entry_hash": "0"*64},
            {"op": "next", "previous_entry_hash": "WRONG_HASH"}
        ]

        with zipfile.ZipFile(broken_file, 'w') as z:
            z.writestr("audit_log.json", json.dumps(bad_log))
            z.writestr("environment.lock", json.dumps(self.env_lock))
            z.writestr("public_key.pem", "dummy key")
            z.writestr("signature.sig", "dummy sig")

        with patch("vouch.crypto.CryptoManager.verify_file"):
            with patch("vouch.crypto.CryptoManager.load_public_key"):
                with patch("builtins.print") as mock_print:
                    code = run_cli_verify(broken_file)
                    self.assertNotEqual(code, 0)
                    output = "\n".join([str(call) for call in mock_print.call_args_list])
                    self.assertIn("Log Chain Integrity: Broken", output)

if __name__ == "__main__":
    unittest.main()

import unittest
import os
import shutil
import tempfile
import zipfile
from unittest.mock import patch, MagicMock
from vouch.verifier import Verifier

class TestVerifierSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.vch_path = os.path.join(self.temp_dir, "test_security.vch")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def create_dummy_vch(self):
        with zipfile.ZipFile(self.vch_path, 'w') as z:
            z.writestr("audit_log.json", "[]")
            z.writestr("signature.sig", b"DUMMY_SIG")
            z.writestr("public_key.pem", b"DUMMY_KEY")
            z.writestr("environment.lock", "{}")
            z.writestr("environment.lock.sig", b"DUMMY_SIG") # Added this
            z.writestr("audit_log.tsr", b"DUMMY_TSR")

    @patch("vouch.verifier.CryptoManager")
    @patch("vouch.timestamp.TimestampClient")
    def test_invalid_timestamp_fails_in_normal_mode(self, MockTSClient, MockCrypto):
        """
        Security Test: If a timestamp is present but invalid (e.g. hash mismatch),
        verification MUST fail even in Normal Mode (strict=False).
        """
        self.create_dummy_vch()

        # Mock Crypto to pass signature checks
        MockCrypto.load_public_key.return_value = MagicMock()
        MockCrypto.verify_file.return_value = None

        # Mock TimestampClient to return False (Verification Failed)
        mock_client = MockTSClient.return_value
        mock_client.verify_timestamp.return_value = False

        verifier = Verifier(self.vch_path)

        # Test strict=False
        result = verifier.verify(strict=False)

        self.assertFalse(result, "Verification passed despite invalid timestamp in Normal Mode!")

    @patch("vouch.verifier.CryptoManager")
    @patch("vouch.timestamp.TimestampClient")
    def test_trusted_key_verification(self, MockTSClient, MockCrypto):
        """
        Security Test: Verify that trusted_public_key_path uses the provided key,
        not the bundled key.
        """
        self.create_dummy_vch()

        # Mock loaded keys
        mock_bundled_key = MagicMock()
        mock_trusted_key = MagicMock()

        # We need side_effect to return different keys based on path
        def load_key_side_effect(path):
            if "trusted" in path:
                return mock_trusted_key
            return mock_bundled_key

        MockCrypto.load_public_key.side_effect = load_key_side_effect
        MockCrypto.verify_file.return_value = None

        # Mock timestamp verification to pass
        MockTSClient.return_value.verify_timestamp.return_value = True

        verifier = Verifier(self.vch_path)

        # Create a dummy trusted key file
        trusted_key_path = os.path.join(self.temp_dir, "trusted.pem")
        with open(trusted_key_path, "w") as f:
            f.write("TRUSTED")

        # 1. Verify WITH trusted key
        result = verifier.verify(trusted_public_key_path=trusted_key_path)

        self.assertTrue(result)

        # Ensure verification used the TRUSTED key, not the bundled key
        # verify_file called 4 times (log, artifacts, env, git)
        # We check the first call (for audit_log.json)
        args, _ = MockCrypto.verify_file.call_args_list[0]
        used_key = args[0]
        self.assertEqual(used_key, mock_trusted_key, "Verification did not use the trusted key!")

    @patch("vouch.verifier.CryptoManager")
    def test_trusted_key_missing_fails(self, MockCrypto):
        """Test failure when trusted key file is missing"""
        self.create_dummy_vch()
        verifier = Verifier(self.vch_path)

        # Verify with non-existent key
        result = verifier.verify(trusted_public_key_path="/non/existent/path")

        self.assertFalse(result, "Verification should fail if trusted key is missing")

if __name__ == "__main__":
    unittest.main()

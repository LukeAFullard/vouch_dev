import unittest
import os
import shutil
import tempfile
import zipfile
import json
from unittest.mock import patch, MagicMock
import vouch
from vouch.verifier import Verifier

class TestVerificationLogic(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.vch_path = os.path.join(self.temp_dir, "test.vch")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def create_dummy_vch(self):
        # Create a minimal valid Vouch package
        with zipfile.ZipFile(self.vch_path, 'w') as z:
            z.writestr("audit_log.json", "")
            z.writestr("signature.sig", b"DUMMY_SIG")
            z.writestr("public_key.pem", b"DUMMY_KEY")
            z.writestr("environment.lock", "{}")
            z.writestr("audit_log.tsr", b"DUMMY_TSR") # Add TSR to trigger verification logic

    @patch("vouch.verifier.CryptoManager")
    @patch("vouch.timestamp.TimestampClient")
    def test_timestamp_failure_fails_verification(self, MockTSClient, MockCrypto):
        """
        Regression Test: Ensure that if timestamp verification fails,
        the overall verification returns False (even in strict=False mode if possible,
        or at least in strict=True).

        The bug was that the return value of _verify_timestamp was ignored.
        """
        self.create_dummy_vch()

        # Mock Crypto to pass signature check
        MockCrypto.load_public_key.return_value = MagicMock()
        MockCrypto.verify_file.return_value = None # No exception = success

        # Mock TimestampClient to return False (Verification Failed)
        mock_client = MockTSClient.return_value
        mock_client.verify_timestamp.return_value = False

        verifier = Verifier(self.vch_path)

        # Test strict=True
        # It should fail because verify_timestamp returns False
        result = verifier.verify(strict=True)
        self.assertFalse(result, "Verification should fail if timestamp is invalid (strict=True)")
        self.assertIn("Timestamp Verification Failed", verifier.status["checks"]["timestamp"]["message"])

    @patch("vouch.verifier.CryptoManager")
    @patch("vouch.timestamp.TimestampClient")
    def test_timestamp_exception_fails_verification(self, MockTSClient, MockCrypto):
        """
        Regression Test: Ensure exception in timestamp verification causes failure.
        """
        self.create_dummy_vch()

        MockCrypto.load_public_key.return_value = MagicMock()
        MockCrypto.verify_file.return_value = None

        mock_client = MockTSClient.return_value
        mock_client.verify_timestamp.side_effect = RuntimeError("Simulated Error")

        verifier = Verifier(self.vch_path)

        # Test strict=True
        result = verifier.verify(strict=True)
        self.assertFalse(result, "Verification should fail on timestamp exception (strict=True)")
        self.assertIn("Timestamp Error: Simulated Error", verifier.status["checks"]["timestamp"]["message"])

if __name__ == "__main__":
    unittest.main()

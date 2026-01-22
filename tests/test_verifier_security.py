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
        # This currently returns True (PASS) which is the bug.
        # We assert False because we WANT it to fail.
        result = verifier.verify(strict=False)

        self.assertFalse(result, "Verification passed despite invalid timestamp in Normal Mode!")

if __name__ == "__main__":
    unittest.main()

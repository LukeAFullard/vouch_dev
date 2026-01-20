import unittest
import os
import shutil
import zipfile
import json
from vouch.crypto import CryptoManager
from vouch.session import TraceSession
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class TestCryptoEncryption(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_crypto_output"
        os.makedirs(self.test_dir, exist_ok=True)
        self.priv_key_path = os.path.join(self.test_dir, "encrypted_id_rsa")
        self.pub_key_path = os.path.join(self.test_dir, "encrypted_id_rsa.pub")
        self.password = "strong_password_123"

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        # Clean up any .vch files created in current dir
        for f in os.listdir("."):
            if f.endswith(".vch"):
                os.remove(f)

    def test_key_generation_and_loading_with_password(self):
        # Generate keys with password
        CryptoManager.generate_keys(
            self.priv_key_path,
            self.pub_key_path,
            password=self.password
        )

        # Try to load without password (should fail)
        with self.assertRaises(ValueError):
             # cryptography raises TypeError or ValueError if password is required but not provided or wrong type
             # Actually, serialization.load_pem_private_key raises TypeError if password is missing for encrypted key
             CryptoManager.load_private_key(self.priv_key_path, password=None)

        # Try to load with wrong password (should fail)
        with self.assertRaises(ValueError):
             CryptoManager.load_private_key(self.priv_key_path, password="wrong_password")

        # Load with correct password
        priv_key = CryptoManager.load_private_key(self.priv_key_path, password=self.password)
        self.assertIsNotNone(priv_key)

    def test_trace_session_with_encrypted_key(self):
        # Generate keys with password
        CryptoManager.generate_keys(
            self.priv_key_path,
            self.pub_key_path,
            password=self.password
        )

        vch_path = os.path.join(self.test_dir, "encrypted_session.vch")

        # Run session with encrypted key
        with TraceSession(
            vch_path,
            private_key_path=self.priv_key_path,
            private_key_password=self.password
        , allow_ephemeral=True) as sess:
            sess.logger.log_call("test_func", [], {}, None)

        # Verify artifacts were signed
        with zipfile.ZipFile(vch_path, 'r') as z:
            self.assertIn("signature.sig", z.namelist())

            # Verify signature manually
            with open(self.pub_key_path, "rb") as f:
                pub_key_bytes = f.read()
            pub_key = serialization.load_pem_public_key(pub_key_bytes)

            sig = z.read("signature.sig")
            log_data = z.read("audit_log.json")

            # This should not raise
            from cryptography.hazmat.primitives import hashes, padding
            from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

            pub_key.verify(
                sig,
                log_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

    def test_trace_session_fails_with_wrong_password(self):
        # Generate keys with password
        CryptoManager.generate_keys(
            self.priv_key_path,
            self.pub_key_path,
            password=self.password
        )

        vch_path = os.path.join(self.test_dir, "fail_session.vch")

        # Run session with WRONG password
        # The strict mode should raise RuntimeError or similar when signing fails
        with self.assertRaises(RuntimeError):
            with TraceSession(
                vch_path,
                private_key_path=self.priv_key_path,
                private_key_password="wrong"
            , allow_ephemeral=True) as sess:
                pass

if __name__ == '__main__':
    unittest.main()

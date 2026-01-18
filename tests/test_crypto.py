import unittest
import os
import shutil
from vouch.crypto import CryptoManager

class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_crypto_output"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)
        self.priv = os.path.join(self.test_dir, "key")
        self.pub = os.path.join(self.test_dir, "key.pub")
        self.data_file = os.path.join(self.test_dir, "data.txt")
        with open(self.data_file, "wb") as f:
            f.write(b"hello world")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_keygen_sign_verify(self):
        CryptoManager.generate_keys(self.priv, self.pub)
        self.assertTrue(os.path.exists(self.priv))
        self.assertTrue(os.path.exists(self.pub))

        priv_key = CryptoManager.load_private_key(self.priv)
        pub_key = CryptoManager.load_public_key(self.pub)

        signature = CryptoManager.sign_file(priv_key, self.data_file)

        # Verify should pass
        CryptoManager.verify_file(pub_key, self.data_file, signature)

        # Verify should fail on modified data
        with open(self.data_file, "wb") as f:
            f.write(b"hello world modified")

        with self.assertRaises(Exception):
             CryptoManager.verify_file(pub_key, self.data_file, signature)

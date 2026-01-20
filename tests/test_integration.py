import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from vouch.auditor import Auditor
from vouch.session import TraceSession
from vouch.crypto import CryptoManager
from vouch.cli import main as cli_main

# Helper to run CLI
def run_cli(args):
    with patch("sys.argv", ["vouch"] + args):
        try:
            cli_main()
            return True
        except SystemExit as e:
            return e.code == 0

class MockPandas:
    def read_csv(self, filepath):
        return "data"

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_artifacts"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

        self.priv_key = os.path.join(self.test_dir, "id_rsa")
        self.pub_key = os.path.join(self.test_dir, "id_rsa.pub")
        CryptoManager.generate_keys(self.priv_key, self.pub_key)

        self.data_file = os.path.join(self.test_dir, "data.csv")
        with open(self.data_file, "w") as f:
            f.write("col1,col2\n1,2")

        self.vch_file = os.path.join(self.test_dir, "audit.vch")
        if os.path.exists(self.vch_file):
            os.remove(self.vch_file)

    def tearDown(self):
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_workflow(self):
        # 1. Analyst runs script
        original_pandas = MockPandas()
        pandas = Auditor(original_pandas, name="pandas")

        with TraceSession(self.vch_file, private_key_path=self.priv_key, allow_ephemeral=True):
            df = pandas.read_csv(self.data_file)

        self.assertTrue(os.path.exists(self.vch_file))

        # 2. Auditor verifies package
        print("\n--- Testing Verification (Success Case) ---")
        success = run_cli(["verify", self.vch_file, "--data", self.data_file])
        self.assertTrue(success)

        # 3. Auditor verifies with tampered data
        print("\n--- Testing Verification (Tampered Data) ---")
        tampered_data = os.path.join(self.test_dir, "tampered.csv")
        with open(tampered_data, "w") as f:
            f.write("col1,col2\n1,3") # Changed data

        # Should fail (exit code 1)
        with patch("sys.argv", ["vouch", "verify", self.vch_file, "--data", tampered_data]):
             with self.assertRaises(SystemExit) as cm:
                 cli_main()
             self.assertNotEqual(cm.exception.code, 0)

if __name__ == "__main__":
    unittest.main()

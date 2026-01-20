import os
import unittest
import zipfile
import json
import shutil
from vouch.session import TraceSession
from vouch.crypto import CryptoManager
from vouch.cli import main as cli_main
from unittest.mock import patch

class TestArtifactCapture(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_artifacts_capture"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

        self.priv_key = os.path.join(self.test_dir, "id_rsa")
        self.pub_key = os.path.join(self.test_dir, "id_rsa.pub")
        CryptoManager.generate_keys(self.priv_key, self.pub_key)

        self.vch_file = os.path.join(self.test_dir, "capture.vch")

        # Create some dummy files to capture
        self.input_file = os.path.join(self.test_dir, "input.txt")
        with open(self.input_file, "w") as f:
            f.write("Input data")

        self.output_file = os.path.join(self.test_dir, "output.txt")
        with open(self.output_file, "w") as f:
            f.write("Result data")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_capture_artifacts(self):
        # 1. Run session and add artifacts
        with TraceSession(self.vch_file, private_key_path=self.priv_key, allow_ephemeral=True) as session:
            # Simulate processing
            session.add_artifact(self.input_file)
            session.add_artifact(self.output_file, arcname="result.txt")

        self.assertTrue(os.path.exists(self.vch_file))

        # 2. Inspect Zip content
        with zipfile.ZipFile(self.vch_file, 'r') as z:
            names = z.namelist()
            self.assertIn("data/input.txt", names)
            self.assertIn("data/result.txt", names)
            self.assertIn("artifacts.json", names)

            # Check manifest content
            with z.open("artifacts.json") as f:
                manifest = json.load(f)
                self.assertIn("input.txt", manifest)
                self.assertIn("result.txt", manifest)

    def test_verify_artifacts(self):
        # 1. Create package
        with TraceSession(self.vch_file, private_key_path=self.priv_key, allow_ephemeral=True) as session:
            session.add_artifact(self.input_file)

        # 2. Verify success
        with patch("sys.argv", ["vouch", "verify", self.vch_file]):
            try:
                cli_main()
            except SystemExit as e:
                self.assertEqual(e.code, None) # None implies success (or at least not exit(1))

    def test_verify_tampered_artifact(self):
         # 1. Create package
        with TraceSession(self.vch_file, private_key_path=self.priv_key, allow_ephemeral=True) as session:
            session.add_artifact(self.input_file)

        # 2. Tamper with the zip
        # Extract, modify file, repack
        extract_dir = os.path.join(self.test_dir, "extracted")
        with zipfile.ZipFile(self.vch_file, 'r') as z:
            z.extractall(extract_dir)

        # Modify the captured data file
        with open(os.path.join(extract_dir, "data", "input.txt"), "w") as f:
            f.write("Tampered data")

        # Re-zip
        tampered_vch = os.path.join(self.test_dir, "tampered.vch")
        with zipfile.ZipFile(tampered_vch, 'w', zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, extract_dir)
                    z.write(file_path, arcname)

        # 3. Verify failure
        with patch("sys.argv", ["vouch", "verify", tampered_vch]):
            with self.assertRaises(SystemExit) as cm:
                cli_main()
            self.assertNotEqual(cm.exception.code, 0)

if __name__ == "__main__":
    unittest.main()

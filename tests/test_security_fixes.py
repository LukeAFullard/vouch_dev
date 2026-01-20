import unittest
import os
import shutil
import json
import random
import sys
from vouch.session import TraceSession
from vouch.crypto import CryptoManager

# Mock numpy if not installed for testing logic
try:
    import numpy as np
except ImportError:
    np = None

class TestWeaknesses(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_weakness_output"
        os.makedirs(self.test_dir, exist_ok=True)
        self.pub_key = os.path.join(self.test_dir, "id_rsa.pub")
        self.priv_key = os.path.join(self.test_dir, "id_rsa")
        CryptoManager.generate_keys(self.priv_key, self.pub_key)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        # Clean up any .vch files created
        for f in os.listdir("."):
            if f.endswith(".vch"):
                os.remove(f)

    def test_seed_not_enforced(self):
        # Run two sessions with the same seed
        # If seed is enforced, random numbers should be identical

        # Session 1
        vch1 = os.path.join(self.test_dir, "session1.vch")
        rand1 = []
        with TraceSession(vch1, seed=12345, private_key_path=self.priv_key, allow_ephemeral=True) as sess:
            rand1.append(random.random())
            if np:
                rand1.append(np.random.rand())

        # Session 2
        vch2 = os.path.join(self.test_dir, "session2.vch")
        rand2 = []
        # We need to reset random state potentially or rely on session to do it
        # But if session doesn't do it, they might be different (continuation) or same if global state wasn't changed much
        # To be sure, let's burn some random numbers between sessions
        random.random()

        with TraceSession(vch2, seed=12345, private_key_path=self.priv_key, allow_ephemeral=True) as sess:
            rand2.append(random.random())
            if np:
                rand2.append(np.random.rand())

        # If seed is enforced, rand1 and rand2 must be identical
        self.assertEqual(rand1, rand2, "Random output should be deterministic with same seed")

    def test_log_chaining_missing(self):
        vch = os.path.join(self.test_dir, "chain.vch")
        with TraceSession(vch, private_key_path=self.priv_key, allow_ephemeral=True) as sess:
            sess.logger.log_call("func1", [], {}, "result1")
            sess.logger.log_call("func2", [], {}, "result2")

        # Unzip and check audit_log.json
        import zipfile
        with zipfile.ZipFile(vch, 'r') as z:
            log_data = json.loads(z.read("audit_log.json"))

        # Check if entries have chaining info
        for entry in log_data:
            self.assertIn("previous_entry_hash", entry, "Log entry missing previous_entry_hash")
            self.assertIn("sequence_number", entry, "Log entry missing sequence_number")

    def test_artifacts_not_signed(self):
        vch = os.path.join(self.test_dir, "unsigned_artifact.vch")
        artifact_path = os.path.join(self.test_dir, "data.txt")
        with open(artifact_path, "w") as f:
            f.write("secret data")

        with TraceSession(vch, private_key_path=self.priv_key, allow_ephemeral=True) as sess:
            sess.add_artifact(artifact_path)

        # Unzip and check for artifacts.json.sig (or similar)
        import zipfile
        with zipfile.ZipFile(vch, 'r') as z:
            files = z.namelist()
            self.assertIn("artifacts.json", files)
            # We expect a signature for artifacts.json
            self.assertIn("artifacts.json.sig", files, "artifacts.json is not signed")

    def test_track_file(self):
        vch = os.path.join(self.test_dir, "track.vch")
        track_path = os.path.join(self.test_dir, "trackme.txt")
        with open(track_path, "w") as f:
            f.write("tracked content")

        with TraceSession(vch, private_key_path=self.priv_key, allow_ephemeral=True) as sess:
            sess.track_file(track_path)

        # Unzip and check audit_log.json
        import zipfile
        with zipfile.ZipFile(vch, 'r') as z:
            log_data = json.loads(z.read("audit_log.json"))

        found = False
        for entry in log_data:
            if entry["target"] == "track_file":
                if "extra_hashes" in entry and "tracked_file_hash" in entry["extra_hashes"]:
                    found = True
                    break
        self.assertTrue(found, "track_file did not log file hash")

    def test_verify_command(self):
        vch = os.path.join(self.test_dir, "verify.vch")
        artifact_path = os.path.join(self.test_dir, "data.txt")
        with open(artifact_path, "w") as f:
            f.write("data")

        with TraceSession(vch, private_key_path=self.priv_key, allow_ephemeral=True) as sess:
            sess.add_artifact(artifact_path)

        # Run verify command
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "vouch.cli", "verify", vch],
            capture_output=True,
            text=True
        )

        self.assertEqual(result.returncode, 0, f"Verify failed: {result.stderr}")
        self.assertIn("[OK] Artifact Manifest Signature: Valid", result.stdout)
        self.assertIn("[OK] Log Chain Integrity: Valid", result.stdout)
        self.assertIn("[OK] Environment: Python version matches", result.stdout)

if __name__ == '__main__':
    unittest.main()

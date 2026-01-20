import unittest
import os
import json
import tempfile
import zipfile
from vouch.session import TraceSession
import vouch

class TestEnvironmentCapture(unittest.TestCase):
    def test_extended_environment_capture(self):
        """Test that cpu_info and blas_info are captured in environment.lock"""
        with tempfile.TemporaryDirectory() as temp_dir:
            vch_file = os.path.join(temp_dir, "test.vch")
            with TraceSession(vch_file, allow_ephemeral=True) as sess:
                pass

            with zipfile.ZipFile(vch_file, 'r') as z:
                with z.open("environment.lock") as f:
                    env_info = json.load(f)

                    # Check keys exist
                    self.assertIn("cpu_info", env_info)
                    self.assertIn("blas_info", env_info)

                    # Check content structure
                    self.assertIsInstance(env_info["cpu_info"], dict)
                    self.assertIn("machine", env_info["cpu_info"])
                    self.assertIn("processor", env_info["cpu_info"])

                    # Check BLAS info contains something reasonable
                    # (NumPy is installed in this env)
                    self.assertIsInstance(env_info["blas_info"], str)
                    self.assertNotEqual(env_info["blas_info"], "NumPy not installed")

if __name__ == "__main__":
    unittest.main()

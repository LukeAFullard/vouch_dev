import unittest
import os
import sys
import shutil
import json
import zipfile
import tempfile
from unittest.mock import patch, MagicMock
from vouch.session import TraceSession

class TestGPUCapture(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.test_dir, "test_gpu.vch")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    @patch('shutil.which')
    @patch('subprocess.check_output')
    def test_gpu_capture_nvidia_smi(self, mock_subprocess, mock_which):
        # Mock nvidia-smi existence and output
        mock_which.side_effect = lambda x: "/usr/bin/nvidia-smi" if x == "nvidia-smi" else None
        mock_subprocess.return_value = b"Tesla T4\nTesla T4"

        # Ensure torch is not present for this test (simulating not installed)
        # We set it to None to simulate failed import or use patch.dict to remove it
        # But removing from sys.modules is tricky if it's already there.
        # patch.dict(sys.modules) with 'torch': None is the standard way to mock missing module
        with patch.dict(sys.modules, {'torch': None}):
             with TraceSession(self.output_path, strict=False) as session:
                 pass

        # Verify environment.lock
        with zipfile.ZipFile(self.output_path, 'r') as z:
            with z.open("environment.lock") as f:
                env_info = json.load(f)

        self.assertIn("gpu_info", env_info)
        self.assertEqual(env_info["gpu_info"], "Tesla T4, Tesla T4")

    def test_gpu_capture_torch(self):
        # Mock torch
        mock_torch = MagicMock()
        mock_torch.cuda.is_available.return_value = True
        mock_torch.cuda.device_count.return_value = 1
        mock_torch.cuda.get_device_name.return_value = "Mock GPU"

        with patch.dict(sys.modules, {'torch': mock_torch}):
             with TraceSession(self.output_path, strict=False) as session:
                 pass

        with zipfile.ZipFile(self.output_path, 'r') as z:
            with z.open("environment.lock") as f:
                env_info = json.load(f)

        self.assertIn("gpu_info", env_info)
        self.assertEqual(env_info["gpu_info"], "Mock GPU")

    def test_gpu_capture_none(self):
        # Mock no GPU
        with patch('shutil.which', return_value=None):
             with patch.dict(sys.modules, {'torch': None}):
                 with TraceSession(self.output_path, strict=False) as session:
                     pass

        with zipfile.ZipFile(self.output_path, 'r') as z:
            with z.open("environment.lock") as f:
                env_info = json.load(f)

        self.assertEqual(env_info["gpu_info"], "N/A")

if __name__ == '__main__':
    unittest.main()

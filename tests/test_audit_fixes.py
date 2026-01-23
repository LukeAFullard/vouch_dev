import unittest
import os
import sys
import tempfile
import shutil
import zipfile
from unittest.mock import patch, MagicMock
from vouch.session import TraceSession
import vouch

class TestAuditFixes(unittest.TestCase):
    def test_symlink_rejection(self):
        """Test that adding a symlink as an artifact is rejected"""
        with tempfile.TemporaryDirectory() as temp_dir:
            target_file = os.path.join(temp_dir, "target.txt")
            with open(target_file, "w") as f:
                f.write("secret data")

            link_file = os.path.join(temp_dir, "link.txt")
            try:
                os.symlink(target_file, link_file)
            except OSError:
                print("Skipping symlink test (OS support missing)")
                return

            vch_file = os.path.join(temp_dir, "test.vch")
            # We explicitly test add_artifact via context manager setup or direct call.
            # To isolate, let's use the context manager.

            try:
                with TraceSession(vch_file, strict=True, allow_ephemeral=True) as sess:
                     sess.add_artifact(link_file)
                self.fail("Should have raised ValueError for symlink")
            except ValueError as e:
                self.assertIn("Symlinks are not allowed", str(e))
            except Exception as e:
                 self.fail(f"Raised wrong exception: {e}")

    def test_rng_strict_enforcement(self):
        """Test that unseeded RNG libraries trigger error in strict mode"""
        with tempfile.TemporaryDirectory() as temp_dir:
            vch_file = os.path.join(temp_dir, "test.vch")

            # Mock sys.modules to include torch
            with patch.dict(sys.modules, {'torch': MagicMock()}):
                try:
                    with TraceSession(vch_file, strict=True, allow_ephemeral=True) as sess:
                        pass
                    self.fail("Should have raised RuntimeError for unseeded torch in strict mode")
                except RuntimeError as e:
                    self.assertIn("PyTorch detected", str(e))
                except Exception as e:
                    self.fail(f"Raised wrong exception: {e}")

            # Mock sys.modules to include tensorflow
            with patch.dict(sys.modules, {'tensorflow': MagicMock()}):
                try:
                    with TraceSession(vch_file, strict=True, allow_ephemeral=True) as sess:
                        pass
                    self.fail("Should have raised RuntimeError for unseeded tensorflow in strict mode")
                except RuntimeError as e:
                    self.assertIn("TensorFlow detected", str(e))

    def test_timestamp_integration(self):
        """Test timestamp request and inclusion in package"""
        with tempfile.TemporaryDirectory() as temp_dir:
            vch_file = os.path.join(temp_dir, "test.vch")

            # Mock TimestampClient to return dummy data
            with patch('vouch.timestamp.TimestampClient') as MockClient:
                mock_instance = MockClient.return_value
                mock_instance.request_timestamp.return_value = b"dummy_tsr_data"

                with TraceSession(vch_file, tsa_url="http://fake.tsa", allow_ephemeral=True) as sess:
                    pass

                # Verify request_timestamp called
                mock_instance.request_timestamp.assert_called_once()

            # Verify audit_log.tsr is in zip
            with zipfile.ZipFile(vch_file, 'r') as z:
                self.assertIn("audit_log.tsr", z.namelist())
                with z.open("audit_log.tsr") as f:
                    self.assertEqual(f.read(), b"dummy_tsr_data")

    def test_timestamp_strict_failure(self):
        """Test strict mode raises exception on timestamp failure"""
        with tempfile.TemporaryDirectory() as temp_dir:
            vch_file = os.path.join(temp_dir, "test.vch")

            with patch('vouch.timestamp.TimestampClient') as MockClient:
                mock_instance = MockClient.return_value
                mock_instance.request_timestamp.side_effect = RuntimeError("TSA Down")

                try:
                    with TraceSession(vch_file, strict=True, tsa_url="http://fake.tsa", allow_ephemeral=True) as sess:
                        pass
                    self.fail("Should have raised RuntimeError")
                except RuntimeError as e:
                    self.assertIn("Timestamping failed", str(e))

    def test_timestamp_client_logic(self):
        from vouch.timestamp import TimestampClient
        client = TimestampClient()

        # Test request_timestamp logic (pure python)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"data")
            tf.close()

            try:
                # We mock asn1crypto objects to avoid complex setup
                with patch('vouch.timestamp.tsp.TimeStampReq') as mock_req, \
                     patch('vouch.timestamp.tsp.TimeStampResp') as mock_resp_cls, \
                     patch('urllib.request.urlopen') as mock_urlopen:

                     # Mock request construction
                     mock_req_instance = mock_req.return_value
                     mock_req_instance.dump.return_value = b"der_request"

                     # Mock urllib response
                     mock_response = MagicMock()
                     mock_response.status = 200
                     mock_response.read.return_value = b"tsr_data"
                     mock_urlopen.return_value.__enter__.return_value = mock_response

                     # Mock response parsing (just check status)
                     mock_resp_instance = MagicMock()
                     mock_resp_instance.__getitem__.return_value.__getitem__.return_value.native = "granted"
                     mock_resp_cls.load.return_value = mock_resp_instance

                     tsr = client.request_timestamp(tf.name, "http://tsa")
                     self.assertEqual(tsr, b"tsr_data")

                     # Verify we hashed the file
                     # (Implicitly verified by no error, and we passed a real file)
            finally:
                os.remove(tf.name)

    def test_verify_command_with_timestamp(self):
        """Test verify command handles timestamp"""
        with tempfile.TemporaryDirectory() as temp_dir:
            vch_file = os.path.join(temp_dir, "test.vch")
            key_path = os.path.join(temp_dir, "key.pem")
            pub_path = os.path.join(temp_dir, "key.pub")

            # Generate keys
            from vouch.crypto import CryptoManager
            CryptoManager.generate_keys(key_path, pub_path)

            # Create a session with timestamp
            with patch('vouch.timestamp.TimestampClient') as MockClient:
                mock_instance = MockClient.return_value
                mock_instance.request_timestamp.return_value = b"dummy_tsr_data"

                with TraceSession(vch_file, private_key_path=key_path, tsa_url="http://fake.tsa", allow_ephemeral=True) as sess:
                    pass

            # Mock args
            args = MagicMock()
            args.file = vch_file
            args.data = None
            args.auto_data = False
            args.public_key = None
            args.strict = False

            # Run verify
            from vouch.cli import verify

            # We need to mock TimestampClient in cli logic too
            # Note: cli does `from .timestamp import TimestampClient`
            with patch('vouch.timestamp.TimestampClient') as MockClient:
                mock_instance = MockClient.return_value
                mock_instance.verify_timestamp.return_value = True

                # Capture stdout/stderr to avoid noise
                with patch('sys.stdout'), patch('sys.stderr'):
                    # Mock sys.exit to prevent test exit
                    with patch('sys.exit') as mock_exit:
                        verify(args)
                        # Ensure no exit(1) called
                        for call in mock_exit.call_args_list:
                             if call[0][0] != 0:
                                  self.fail(f"Verify failed with code {call[0][0]}")

if __name__ == "__main__":
    unittest.main()

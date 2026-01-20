import unittest
import tempfile
import os
import shutil
import json
import threading
import uuid
import sys
from unittest.mock import patch, MagicMock

import pandas as pd
import vouch
from vouch.hasher import Hasher
from vouch.session import TraceSession
from vouch.cli import verify as cli_verify

class TestAuditReportFixes(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.temp_dir)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.temp_dir)

    def test_cross_platform_pandas_hash(self):
        """Verify .vch created on Windows validates on Linux (mocked)"""
        df = pd.DataFrame({"col": [1.0, 2.0, 3.0]})

        # Hash with Windows line endings
        with patch('os.linesep', '\r\n'):
            h1 = Hasher.hash_object(df)

        # Hash with Linux line endings
        with patch('os.linesep', '\n'):
            h2 = Hasher.hash_object(df)

        self.assertEqual(h1, h2, "Pandas hash should be platform-independent")

    def test_thread_safety(self):
        """Test concurrent sessions in different threads"""

        def run_session(filename):
            with TraceSession(filename, allow_ephemeral=True) as sess:
                sess.logger.log_call("test", [], {}, None)

        t1 = threading.Thread(target=run_session, args=("t1.vch",))
        t2 = threading.Thread(target=run_session, args=("t2.vch",))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertTrue(os.path.exists("t1.vch"))
        self.assertTrue(os.path.exists("t2.vch"))

    def test_session_uuid(self):
        """Test that session UUID is generated and logged"""
        with TraceSession("uuid.vch", allow_ephemeral=True) as sess:
            self.assertTrue(hasattr(sess, 'session_id'))
            uuid.UUID(sess.session_id) # Should validate

        # Inspect the log
        # Extract zip
        import zipfile
        with zipfile.ZipFile("uuid.vch", 'r') as z:
            with z.open("audit_log.json") as f:
                log = json.load(f)

        # First entry should be session.initialize
        init_entry = log[0]
        self.assertEqual(init_entry['target'], 'session.initialize')
        self.assertEqual(init_entry['extra_hashes']['session_id'], sess.session_id)
        self.assertIn('timestamp', init_entry['extra_hashes'])

    def test_chain_verification_failure(self):
        """Test that verify exits with 1 on broken chain"""
        # Create a valid session
        with TraceSession("valid.vch", allow_ephemeral=True) as sess:
            sess.logger.log_call("test", [], {}, None)

        # Tamper with it
        import zipfile
        with zipfile.ZipFile("valid.vch", 'r') as z:
            z.extractall("tampered")

        with open("tampered/audit_log.json", "r") as f:
            log = json.load(f)

        # Modify an entry argument but keep previous hashes intact
        # This will cause a mismatch when verifying the NEXT entry's previous_entry_hash
        # Or if we modify the last entry, its hash won't match what we expect?
        # Verify calculates hash of entry[i] and checks it against entry[i+1]['previous_entry_hash']
        # If we modify entry[0], then hash(entry[0]) != entry[1]['previous_entry_hash']

        if len(log) > 0:
            log[0]["args"] = ["tampered"]
        else:
            self.fail("Log is empty")

        with open("tampered/audit_log.json", "w") as f:
            json.dump(log, f)

        # Generate keys to re-sign (since signature verification happens first)
        from vouch.crypto import CryptoManager
        CryptoManager.generate_keys("key", "key.pub")
        pk = CryptoManager.load_private_key("key")

        # Sign tampered log
        sig = CryptoManager.sign_file(pk, "tampered/audit_log.json")
        with open("tampered/signature.sig", "wb") as f:
            f.write(sig)

        # Put new public key
        shutil.copy("key.pub", "tampered/public_key.pem")

        # Re-zip again
        with zipfile.ZipFile("tampered_signed.vch", "w") as z:
             for root, dirs, files in os.walk("tampered"):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, "tampered")
                    z.write(file_path, arcname)

        class Args:
            file = "tampered_signed.vch"
            data = None
            auto_data = False
            tsa_ca_file = None
            auto_data_dir = None

        with patch('sys.exit') as mock_exit:
            cli_verify(Args())
            mock_exit.assert_called_with(1)

if __name__ == "__main__":
    unittest.main()

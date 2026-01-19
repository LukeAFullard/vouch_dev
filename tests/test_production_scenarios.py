import unittest
import os
import shutil
import tempfile
import sys
from vouch.session import TraceSession
from vouch.auditor import Auditor
from vouch.importer import auto_audit

class TestProductionScenarios(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.vch_path = os.path.join(self.test_dir, "test.vch")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_concurrent_sessions_fails(self):
        # Ensure no active session from previous tests
        TraceSession._active_session = None

        with TraceSession(os.path.join(self.test_dir, "s1.vch")):
            with self.assertRaisesRegex(RuntimeError, "Nested TraceSessions are not supported"):
                with TraceSession(os.path.join(self.test_dir, "s2.vch")):
                    pass

    def test_code_capture(self):
        with TraceSession(self.vch_path, capture_script=True) as sess:
            pass

        # We need to verify that the script was added to artifacts
        # Accessing private member for testing
        script_artifacts = [k for k in sess.artifacts.keys() if "__script__" in k]
        # This test might fail if run from a way where inspect can't find the source file (e.g. repl),
        # but in unittest it should work as this file exists.
        self.assertTrue(len(script_artifacts) > 0, "Current script should be captured")

    def test_path_traversal_blocked(self):
        with TraceSession(self.vch_path, strict=True) as sess:
            # We need to create a dummy file to add
            dummy = os.path.join(self.test_dir, "dummy.txt")
            with open(dummy, 'w') as f:
                f.write("test")

            with self.assertRaises(ValueError):
                sess.add_artifact(dummy, arcname="../../../etc/passwd")

    def test_global_io_hook(self):
        dummy = os.path.join(self.test_dir, "io_test.txt")
        with open(dummy, 'w') as f:
            f.write("content")

        with TraceSession(self.vch_path, auto_track_io=True) as sess:
            # Reading a file should trigger tracking
            with open(dummy, 'r') as f:
                content = f.read()

        # Verify it was tracked
        # We can inspect the logger
        logs = sess.logger.log
        track_entries = [e for e in logs if e['action'] == 'call' and e['target'] == 'track_file']
        self.assertTrue(len(track_entries) > 0, "File open should be tracked")

        found = False
        for entry in track_entries:
            # The args are logged. arg[0] is the filepath.
            if entry['args_repr']:
                 # Check if dummy path is in the args representation
                 # Note: args_repr is a list of strings
                 if any(dummy in a for a in entry['args_repr']):
                     found = True
        self.assertTrue(found, f"File {dummy} should be in track logs")

    def test_custom_auto_audit_targets(self):
        import json
        # json is a built-in package, it should be wrappable
        with auto_audit(targets=["json"]):
            self.assertTrue(isinstance(sys.modules['json'], Auditor), "json module should be wrapped")

        # Outside, it should be restored (unless it was already wrapped before, which it wasn't)
        self.assertFalse(isinstance(sys.modules['json'], Auditor), "json module should be unwrapped")

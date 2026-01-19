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

    def test_artifact_size_limit(self):
        large_file = os.path.join(self.test_dir, "large.txt")
        with open(large_file, 'w') as f:
            f.write("A" * 1024) # 1KB

        # Test with strict mode (should raise)
        with TraceSession(self.vch_path, strict=True, max_artifact_size=512) as sess:
            with self.assertRaisesRegex(ValueError, "Artifact exceeds maximum size"):
                sess.add_artifact(large_file)

        # Test with non-strict mode (should warn but not crash, although add_artifact doesn't return anything)
        # The skipping happens during processing (__exit__), but we can't easily assert print output here without patching stdout.
        # But we can verify it's NOT in the zip.

        vch_path2 = os.path.join(self.test_dir, "test2.vch")
        with TraceSession(vch_path2, strict=False, max_artifact_size=512) as sess:
            # add_artifact won't raise in strict=False for size?
            # Wait, my implementation raises in add_artifact ONLY if strict=True.
            # If strict=False, it adds to the list, but _process_artifacts skips it.
            sess.add_artifact(large_file)

        # Verify it's not in the zip
        import zipfile
        with zipfile.ZipFile(vch_path2, 'r') as z:
            self.assertNotIn("data/large.txt", z.namelist())

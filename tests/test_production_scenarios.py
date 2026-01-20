import unittest
import os
import shutil
import tempfile
import sys
import json
import zipfile
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
        if hasattr(TraceSession._active_session, 'session'):
            TraceSession._active_session.session = None

        with TraceSession(os.path.join(self.test_dir, "s1.vch"), allow_ephemeral=True):
            with self.assertRaisesRegex(RuntimeError, "Nested TraceSessions are not supported"):
                with TraceSession(os.path.join(self.test_dir, "s2.vch"), allow_ephemeral=True):
                    pass

    def test_code_capture(self):
        with TraceSession(self.vch_path, capture_script=True, allow_ephemeral=True) as sess:
            pass
        script_artifacts = [k for k in sess.artifacts.keys() if "__script__" in k]
        self.assertTrue(len(script_artifacts) > 0, "Current script should be captured")

    def test_path_traversal_blocked(self):
        with TraceSession(self.vch_path, strict=True, allow_ephemeral=True) as sess:
            dummy = os.path.join(self.test_dir, "dummy.txt")
            with open(dummy, 'w') as f:
                f.write("test")
            with self.assertRaises(ValueError):
                sess.add_artifact(dummy, arcname="../../../etc/passwd")

    def test_global_io_hook(self):
        dummy = os.path.join(self.test_dir, "io_test.txt")
        with open(dummy, 'w') as f:
            f.write("content")

        with TraceSession(self.vch_path, auto_track_io=True, allow_ephemeral=True) as sess:
            with open(dummy, 'r') as f:
                content = f.read()

        # Session closed, temp dir deleted. Read from zip.
        with zipfile.ZipFile(self.vch_path, 'r') as z:
            with z.open("audit_log.json") as f:
                # Handle NDJSON
                logs = [json.loads(line) for line in f if line.strip()]

        track_entries = [e for e in logs if e['action'] == 'call' and e['target'] == 'track_file']
        self.assertTrue(len(track_entries) > 0, "File open should be tracked")

        found = False
        for entry in track_entries:
            if entry['args_repr']:
                 if any(dummy in a for a in entry['args_repr']):
                     found = True
        self.assertTrue(found, f"File {dummy} should be in track logs")

    def test_custom_auto_audit_targets(self):
        import json
        with auto_audit(targets=["json"]):
            self.assertTrue(isinstance(sys.modules['json'], Auditor), "json module should be wrapped")
        self.assertFalse(isinstance(sys.modules['json'], Auditor), "json module should be unwrapped")

    def test_artifact_size_limit(self):
        large_file = os.path.join(self.test_dir, "large.txt")
        with open(large_file, 'w') as f:
            f.write("A" * 1024)

        with TraceSession(self.vch_path, strict=True, max_artifact_size=512, allow_ephemeral=True) as sess:
            with self.assertRaisesRegex(ValueError, "Artifact exceeds maximum size"):
                sess.add_artifact(large_file)

        vch_path2 = os.path.join(self.test_dir, "test2.vch")
        with TraceSession(vch_path2, strict=False, max_artifact_size=512) as sess:
            sess.add_artifact(large_file)

        with zipfile.ZipFile(vch_path2, 'r') as z:
            self.assertNotIn("data/large.txt", z.namelist())

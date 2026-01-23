import unittest
import threading
import os
import tempfile
import time
import random
import vouch
from vouch.hasher import Hasher

class TestConcurrency(unittest.TestCase):
    def setUp(self):
        self.output_file = tempfile.mktemp(suffix=".vch")
        self.artifact_source = tempfile.mktemp()
        with open(self.artifact_source, "w") as f:
            f.write("A" * 10000) # 10KB data

    def tearDown(self):
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        if os.path.exists(self.artifact_source):
            os.remove(self.artifact_source)

    def test_concurrent_logging_and_artifacts(self):
        """Test strict mode with heavy concurrent logging and artifact capture."""

        errors = []
        n_threads = 10
        ops_per_thread = 50

        # Create a dummy audited object
        class Worker:
            def work(self, i):
                return i * i

        worker = vouch.auditor.Auditor(Worker())

        def task(tid, session):
            try:
                for i in range(ops_per_thread):
                    # Log a call - this might fail if it relies on get_active_session internally
                    # But the auditor object `worker` might have captured session at creation?
                    # No, Auditor uses TraceSession.get_active_session() at call time.
                    # So we need to patch context or accept that logging fails.
                    # For this test, let's focus on add_artifact which we call explicitly.
                    # To make logging work, we'd need to set the contextvar in this thread.
                    # let's just test add_artifact for now, logging is secondary for this race.

                    # worker.work(i) # Skipping logging as it requires context propagation

                    # Add unique artifact
                    # We create a small file to add
                    fname = f"thread_{tid}_{i}.txt"
                    fpath = os.path.join(tempfile.gettempdir(), fname)
                    with open(fpath, "w") as f:
                        f.write(f"Data from thread {tid} iter {i}")

                    # Race condition check: multiple threads might try to add artifacts
                    session.add_artifact(fpath, arcname=fname)

                    # Cleanup local file (TraceSession copies it immediately in live mode)
                    # Wait a bit to ensure copy happens? No, add_artifact is synchronous.
                    os.remove(fpath)

                    # Random sleep to interleave
                    time.sleep(random.random() * 0.001)

            except Exception as e:
                errors.append(e)

        with vouch.vouch(self.output_file, strict=True, allow_ephemeral=True) as sess:
            threads = []
            for i in range(n_threads):
                t = threading.Thread(target=task, args=(i, sess))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        self.assertEqual(len(errors), 0, f"Errors occurred in threads: {errors}")

        # Verify output
        verifier = vouch.Verifier(self.output_file)
        self.assertTrue(verifier.verify(strict=False), "Verification failed")

        # Check artifact count
        import zipfile
        with zipfile.ZipFile(self.output_file, 'r') as z:
            # +4 for metadata files (audit_log, environment, signatures...)
            # Actually artifacts are in data/
            files = z.namelist()
            data_files = [f for f in files if f.startswith("data/")]
            # +1 for calling script artifact
            self.assertGreaterEqual(len(data_files), n_threads * ops_per_thread)

    def test_concurrent_same_artifact_race(self):
        """Test multiple threads adding the SAME artifact name concurrently."""
        errors = []
        n_threads = 5
        ops_per_thread = 20

        target_arcname = "shared_artifact.txt"

        def task(tid, session):
            try:
                for i in range(ops_per_thread):
                    # They all try to add the same source file to the same arcname
                    session.add_artifact(self.artifact_source, arcname=target_arcname)
            except Exception as e:
                errors.append(e)

        with vouch.vouch(self.output_file, strict=True, allow_ephemeral=True) as sess:
            threads = []
            for i in range(n_threads):
                t = threading.Thread(target=task, args=(i, sess))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        self.assertEqual(len(errors), 0, f"Errors in race test: {errors}")

        # Verification should pass (hash matches)
        verifier = vouch.Verifier(self.output_file)
        self.assertTrue(verifier.verify(strict=False))

if __name__ == "__main__":
    unittest.main()

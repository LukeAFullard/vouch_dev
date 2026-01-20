import multiprocessing
import time
import os
import signal
import json
import shutil
import tempfile
import sys
from unittest.mock import patch

# We need to run the worker in a way that we can control the temp dir.
# Since multiprocessing makes patching hard, we'll use a fixed temp base.

FIXED_TEMP_DIR = os.path.abspath("crash_test_temp_dir")

def crashing_worker(filename):
    if os.path.exists(FIXED_TEMP_DIR):
        shutil.rmtree(FIXED_TEMP_DIR)
    os.makedirs(FIXED_TEMP_DIR)

    # Monkeypatch tempfile.mkdtemp to return our dir
    # We can't easily monkeypatch across process boundary unless we do it inside.

    import vouch.session
    vouch.session.tempfile.mkdtemp = lambda: FIXED_TEMP_DIR

    from vouch.session import TraceSession

    session = TraceSession(filename, strict=False)
    session.__enter__()

    # Log entries
    session.logger.log_call("step1", [], {}, "result1")
    session.logger.log_call("step2", [], {}, "result2")

    # Force flush is handled by logger now
    print("Worker logged steps.")
    time.sleep(10) # Wait for kill

def test_crash_consistency():
    filename = "crash_test.vch"
    if os.path.exists(FIXED_TEMP_DIR):
        shutil.rmtree(FIXED_TEMP_DIR)

    p = multiprocessing.Process(target=crashing_worker, args=(filename,))
    p.start()

    time.sleep(2) # Wait for init and logging

    print("Killing worker...")
    os.kill(p.pid, signal.SIGKILL)
    p.join()

    # Now check if data exists in FIXED_TEMP_DIR/audit_log.json
    log_path = os.path.join(FIXED_TEMP_DIR, "audit_log.json")

    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            # It might be an incomplete JSON array (trailing comma)
            content = f.read()
            print(f"Log content length: {len(content)}")

            # Streaming logger writes "[\n", then objects.
            # It closes with "]" only on close().
            # So we expect it to be invalid JSON, but contain the data.

            if '"step1"' in content and '"step2"' in content:
                print("PASS: Data recovered from crash!")
            else:
                print("FAIL: Log file exists but data missing.")
    else:
        print("FAIL: Log file not found.")

    # Cleanup
    if os.path.exists(FIXED_TEMP_DIR):
        shutil.rmtree(FIXED_TEMP_DIR)

if __name__ == "__main__":
    test_crash_consistency()

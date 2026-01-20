import multiprocessing
import time
import os
import signal
import json
import shutil
import tempfile
import sys
from unittest.mock import patch

FIXED_TEMP_DIR = os.path.abspath("crash_test_temp_dir")

def crashing_worker(filename):
    if os.path.exists(FIXED_TEMP_DIR):
        shutil.rmtree(FIXED_TEMP_DIR)
    os.makedirs(FIXED_TEMP_DIR)

    import vouch.session
    vouch.session.tempfile.mkdtemp = lambda: FIXED_TEMP_DIR

    from vouch.session import TraceSession

    # Correct order: positional first
    session = TraceSession(filename, strict=False, allow_ephemeral=True)
    session.__enter__()

    session.logger.log_call("step1", [], {}, "result1")
    session.logger.log_call("step2", [], {}, "result2")

    print("Worker logged steps.")
    time.sleep(10)

def test_crash_consistency():
    filename = "crash_test.vch"
    if os.path.exists(FIXED_TEMP_DIR):
        shutil.rmtree(FIXED_TEMP_DIR)

    p = multiprocessing.Process(target=crashing_worker, args=(filename,))
    p.start()

    time.sleep(2)

    print("Killing worker...")
    os.kill(p.pid, signal.SIGKILL)
    p.join()

    log_path = os.path.join(FIXED_TEMP_DIR, "audit_log.json")

    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            content = f.read()
            if '"step1"' in content and '"step2"' in content:
                print("PASS: Data recovered from crash!")
            else:
                print("FAIL: Log file exists but data missing.")
    else:
        print("FAIL: Log file not found.")

    if os.path.exists(FIXED_TEMP_DIR):
        shutil.rmtree(FIXED_TEMP_DIR)

if __name__ == "__main__":
    test_crash_consistency()

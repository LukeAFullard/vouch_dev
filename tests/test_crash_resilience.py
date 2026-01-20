import multiprocessing
import time
import os
import signal
import json
import shutil
import vouch
from vouch.session import TraceSession

def crashing_worker(filename):
    """
    A worker that initializes a session, does some work, and then is killed.
    """
    # Create a session
    # Note: We can't use 'with' block easily because we want to kill it
    # BEFORE exit.

    session = TraceSession(filename, strict=False)
    session.__enter__()

    # Log some stuff
    session.logger.log_call("step1", [], {}, "result1")
    session.logger.log_call("step2", [], {}, "result2")

    # Save partial log?
    # Vouch currently only saves on __exit__.
    # So if we crash here, we expect NO log file or an empty one.

    print("Worker running...")
    time.sleep(10) # Wait to be killed

    session.__exit__(None, None, None)

def test_crash_consistency():
    filename = "crash_test.vch"
    temp_dir = "crash_test_temp" # Vouch uses mkdtemp, so we might not find it easily unless we spy on it.

    # But wait, TraceSession creates a temp dir. If the process dies,
    # the temp dir remains (OS doesn't clean /tmp immediately).
    # But the `audit_log.json` is only written in `__exit__`.

    # HYPOTHESIS: If Vouch crashes, the audit log is LOST completely because it's in memory.

    p = multiprocessing.Process(target=crashing_worker, args=(filename,))
    p.start()

    time.sleep(2) # Let it initialize

    # KILL IT
    print("Killing worker...")
    os.kill(p.pid, signal.SIGKILL)
    p.join()

    # Check artifacts
    if os.path.exists(filename):
        print(f"FAIL: {filename} exists. It shouldn't if we crashed before exit?")
        # If it exists, maybe it's valid?
    else:
        print(f"PASS: {filename} does not exist. (Data Loss Expected for now)")

    # Is this a "weakness"? Yes. For evidence, if the power plug is pulled,
    # you lose the session. A "Production Ready" forensic tool usually writes to disk incrementally.

    # Let's verify this hypothesis.

if __name__ == "__main__":
    test_crash_consistency()

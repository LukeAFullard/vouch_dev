import threading
import os
import sys
import time
import shutil
import pytest
import vouch
from vouch.session import TraceSession
from vouch.auditor import Auditor

def test_race_open():
    filename = "race_test.vch"

    # Create dummy files
    files = [f"dummy_{i}.txt" for i in range(100)]
    try:
        for f in files:
            with open(f, "w") as fh:
                fh.write("test")

        # We need to capture the session object to inspect logs later
        session = TraceSession(filename, auto_track_io=True, strict=False)

        def worker(idx):
            # Sleep a tiny bit to randomize start
            time.sleep(0.001 * (idx % 10))
            with open(files[idx], "r") as f:
                f.read()

        with session:
            threads = []
            for i in range(100):
                t = threading.Thread(target=worker, args=(i,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            # Now verify logs
            track_file_count = 0
            for entry in session.logger.log:
                if entry["target"] == "track_file":
                    track_file_count += 1

            assert track_file_count == 100, f"Expected 100 tracked files, got {track_file_count}"

    finally:
        # Cleanup
        for f in files:
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists(filename):
            os.remove(filename)

def test_race_import():
    # Setup dummy modules
    dummy_dir = "dummy_mods_race_test"
    if os.path.exists(dummy_dir):
        shutil.rmtree(dummy_dir)
    os.makedirs(dummy_dir, exist_ok=True)
    sys.path.insert(0, os.path.abspath(dummy_dir))

    count = 50
    mod_names = [f"modracetest_{i}" for i in range(count)]
    for name in mod_names:
        with open(os.path.join(dummy_dir, f"{name}.py"), "w") as f:
            f.write(f"val = {name!r}")

    filename = "race_import_test.vch"

    try:
        # Using targets=['*'] should trigger VouchFinder for everything
        # We need to run this in a way that allows us to verify results
        # Since import machinery is global, we must be careful not to break other tests
        # But pytest runs sequentially (usually)

        with vouch.start(filename=filename, targets=['*'], strict=False):

            def worker(name):
                try:
                    __import__(name)
                except Exception as e:
                    print(f"Import failed for {name}: {e}")

            threads = []
            for name in mod_names:
                t = threading.Thread(target=worker, args=(name,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            # Verify modules are wrapped
            unwrapped_count = 0
            for name in mod_names:
                if name in sys.modules:
                    mod = sys.modules[name]
                    if not isinstance(mod, Auditor):
                        unwrapped_count += 1
                else:
                    unwrapped_count += 1

            assert unwrapped_count == 0, f"{unwrapped_count}/{count} modules missed audit due to race condition."

    finally:
        # Cleanup
        shutil.rmtree(dummy_dir)
        if os.path.exists(filename):
            os.remove(filename)
        # Clean up sys.modules
        for name in mod_names:
            sys.modules.pop(name, None)

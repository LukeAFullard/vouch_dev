import threading
import os
import sys
import time
import shutil
import pytest
import vouch
import json
from vouch.session import TraceSession
from vouch.auditor import Auditor

def test_race_open():
    filename = "race_test.vch"

    files = [f"dummy_{i}.txt" for i in range(100)]
    try:
        for f in files:
            with open(f, "w") as fh:
                fh.write("test")

        # Correct order
        session = TraceSession(filename, auto_track_io=True, strict=False, allow_ephemeral=True)

        def worker(idx):
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

        import zipfile
        with zipfile.ZipFile(filename, 'r') as z:
            with z.open("audit_log.json") as f:
                content = f.read().decode('utf-8')
                log_data = [json.loads(line) for line in content.splitlines() if line.strip()]

        track_file_count = 0
        for entry in log_data:
            if entry["target"] == "track_file":
                track_file_count += 1

        assert track_file_count == 100, f"Expected 100 tracked files, got {track_file_count}"

    finally:
        for f in files:
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists(filename):
            os.remove(filename)

def test_race_import():
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
        with vouch.start(filename=filename, targets=['*'], strict=False, allow_ephemeral=True):

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
        shutil.rmtree(dummy_dir)
        if os.path.exists(filename):
            os.remove(filename)
        for name in mod_names:
            sys.modules.pop(name, None)

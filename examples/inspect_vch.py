import os
import sys
import json
import zipfile
import shutil

# Ensure we can import vouch from the parent directory if not installed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vouch import Auditor, TraceSession
from vouch.crypto import CryptoManager

def create_sample_vch(filename, key_name="example_key"):
    print(f"Generating keys: {key_name}...")
    CryptoManager.generate_keys(key_name, f"{key_name}.pub")

    print(f"Creating {filename}...")

    # Mock a library to audit
    class MathLib:
        def add(self, a, b):
            return a + b

    math_lib = MathLib()
    wrapped_math = Auditor(math_lib)

    with TraceSession(filename, private_key_path=key_name):
        result = wrapped_math.add(10, 20)
        print(f"  Executed 10 + 20 = {result}")

    # Cleanup keys
    if os.path.exists(key_name):
        os.remove(key_name)
    if os.path.exists(f"{key_name}.pub"):
        os.remove(f"{key_name}.pub")

def inspect_vch(filename):
    print(f"\nInspecting {filename}...")

    if not os.path.exists(filename):
        print(f"File {filename} does not exist.")
        return

    with zipfile.ZipFile(filename, 'r') as z:
        print("\n--- Files in Archive ---")
        for name in z.namelist():
            print(f" - {name}")

        print("\n--- Content of audit_log.json ---")
        with z.open("audit_log.json") as f:
            log_data = json.load(f)
            print(json.dumps(log_data, indent=2))

        print("\n--- Content of environment.lock ---")
        with z.open("environment.lock") as f:
            env_data = json.load(f)
            print(json.dumps(env_data, indent=2))

if __name__ == "__main__":
    vch_file = "example_audit.vch"
    try:
        create_sample_vch(vch_file)
        inspect_vch(vch_file)
    finally:
        if os.path.exists(vch_file):
            os.remove(vch_file)

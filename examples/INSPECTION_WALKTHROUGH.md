# Example: Inspecting Vouch Artifacts

## Introduction

A Vouch package (`.vch`) is simply a standard ZIP archive containing the audit logs, cryptographic signatures, and environment information. While the `vouch verify` CLI tool provides a high-level verification of these components, you may sometimes wish to inspect the raw data directly.

This example demonstrates how to programmatically access the internal components of a Vouch package—specifically `audit_log.json` and `environment.lock`—using Python's built-in `zipfile` module. This transparency ensures that you are never locked into the Vouch toolchain to read your own audit history.

## Code

The following script (`inspect_vch.py`) generates a sample Vouch package and then immediately opens it to print the contents of the log and environment files.

```python
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

        if "artifacts.json" in z.namelist():
            print("\n--- Captured Artifacts ---")
            with z.open("artifacts.json") as f:
                artifacts = json.load(f)
                print(json.dumps(artifacts, indent=2))

if __name__ == "__main__":
    vch_file = "example_audit.vch"
    try:
        create_sample_vch(vch_file)
        inspect_vch(vch_file)
    finally:
        if os.path.exists(vch_file):
            os.remove(vch_file)
```

## Results

Running the script produces the following output. Notice how `audit_log.json` captures the exact function call arguments and result, along with their hashes.

```text
Generating keys: example_key...
Creating example_audit.vch...
  Executed 10 + 20 = 30

Inspecting example_audit.vch...

--- Files in Archive ---
 - audit_log.json
 - signature.sig
 - environment.lock
 - public_key.pem

--- Content of audit_log.json ---
[
  {
    "timestamp": "2026-01-18T23:47:52.873509+00:00",
    "action": "call",
    "target": "<__main__.create_sample_vch.<locals>.MathLib object at 0x7fd2fe1ad190>.add",
    "args_repr": [
      "10",
      "20"
    ],
    "kwargs_repr": {},
    "result_repr": "30",
    "args_hash": "9dcecd78ba2613f2264b48c340f185665dea410927f46e881776d095bc88db5e",
    "kwargs_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "result_hash": "624b60c58c9d8bfb6ff1886c2fd605d2adeb6ea4da576068201b6c6958ce93f4"
  }
]

--- Content of environment.lock ---
{
  "python_version": "3.12.12 (main, Nov  7 2025, 00:07:10) [GCC 13.3.0]",
  "platform": "linux",
  "pip_freeze": "cffi==2.0.0\ncryptography==46.0.3\ngreenlet==3.2.4\nnumpy==2.4.1\npandas==2.3.3\nplaywright==1.55.0\npycparser==2.23\npyee==13.0.0\npython-dateutil==2.9.0.post0\npytz==2025.2\nsix==1.17.0\ntyping_extensions==4.15.0\ntzdata==2025.3\n-e git+https://github.com/LukeAFullard/vouch_dev@b6af0232550dd7015ea20c3f5029f4bd661eafbc#egg=vouch\n"
}
```

## Conclusion

This example confirms that Vouch artifacts are built on open standards (ZIP and JSON). You can easily audit the auditor, extract data for other tools, or manually verify the environment conditions under which the original code was executed.

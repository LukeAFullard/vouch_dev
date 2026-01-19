# Example: Capturing Artifacts

## Introduction

In many workflows, simply logging *what* happened isn't enough; you also need to preserve the exact files that were used or produced. Vouch allows you to bundle arbitrary files (artifacts) directly into the signed `.vch` package.

This ensures that the `raw_data.csv` or `final_report.pdf` you send to an auditor is byte-for-byte identical to the one present during the execution. These bundled files are hashed and verified automatically.

## Code

The following script (`capture_artifacts_example.py`) demonstrates how to use `session.add_artifact()` to include both input and output files in the audit package.

```python
import os
import sys
import shutil

# Ensure we can import vouch from the parent directory if not installed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vouch import TraceSession, Auditor
from vouch.crypto import CryptoManager

def run_artifact_capture_example():
    # 1. Setup Keys
    key_name = "capture_key"
    print(f"Generating keys: {key_name}...")
    CryptoManager.generate_keys(key_name, f"{key_name}.pub")

    # 2. Create Dummy Data
    input_file = "raw_data.txt"
    with open(input_file, "w") as f:
        f.write("Important raw data content.")
    print(f"Created {input_file}")

    output_vch = "project_audit.vch"

    # 3. Run Session with Artifact Capture
    print(f"Running audit session -> {output_vch}...")
    try:
        with TraceSession(output_vch, private_key_path=key_name) as session:
            # Mark the input file to be bundled into the package
            session.add_artifact(input_file)

            # Perform some "work" (mocked)
            print("  [Analyst] Processing data...")

            # Create an output file and bundle it too
            output_file = "results.txt"
            with open(output_file, "w") as f:
                f.write("Computed results based on raw data.")
            print(f"  [Analyst] Generated {output_file}")

            # Bundle the output
            session.add_artifact(output_file)

    except Exception as e:
        print(f"Error: {e}")
        return

    print("\nAudit package created successfully.")

    # 4. Verify using the CLI tool (simulated)
    print("\n--- Verifying Package ---")
    # We call the CLI verify function programmatically for demonstration
    from vouch.cli import verify
    import argparse

    args = argparse.Namespace(file=output_vch, data=None)
    try:
        verify(args)
    except SystemExit:
        pass # Handle exit cleanly

    # Cleanup
    print("\n--- Cleanup ---")
    for f in [input_file, output_file, output_vch, key_name, f"{key_name}.pub"]:
        if os.path.exists(f):
            os.remove(f)
            print(f"Removed {f}")

if __name__ == "__main__":
    run_artifact_capture_example()
```

## Results

When run, the script generates the package and then verifies it. Notice the "Verifying captured artifacts" section in the output.

```text
Generating keys: capture_key...
Created raw_data.txt
Running audit session -> project_audit.vch...
  [Analyst] Processing data...
  [Analyst] Generated results.txt

Audit package created successfully.

--- Verifying Package ---
Verifying project_audit.vch...
  [OK] Signature Verification: Valid
  [OK] Log Integrity: Valid
  [...] Verifying captured artifacts...
    [OK] raw_data.txt
    [OK] results.txt
  [OK] Captured Artifacts Integrity: Valid

--- Cleanup ---
Removed raw_data.txt
Removed results.txt
Removed project_audit.vch
Removed capture_key
Removed capture_key.pub
```

## Conclusion

By using `add_artifact`, you create a self-contained, verifiable unit of work. The recipient does not need to separately download data files; everything is securely packed inside the `.vch` file.

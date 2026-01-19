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

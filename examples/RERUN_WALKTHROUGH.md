# Example: Verifying by Rerunning

## Introduction

One of the strongest forms of audit is **reproducibility**: demonstrating that the same input leads to the same output when processed by the same code.

Because Vouch captures the input data, the output data, and the environment specifications, an auditor can extract these artifacts and re-execute the analysis logic to confirm the results are authentic.

## Code

The script below (`rerun_verification.py`) simulates two parties:
1.  **Analyst**: Runs the original code, bundling inputs and outputs into a `.vch` package.
2.  **Verifier**: Unzips the package, reads the `environment.lock`, and re-runs the logic using the *extracted* input data to ensure the *new* output matches the *bundled* output.

```python
import os
import sys
import shutil
import zipfile
import json
import filecmp

# Ensure we can import vouch from the parent directory if not installed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vouch import TraceSession, Auditor
from vouch.crypto import CryptoManager

# --- The Analysis Logic ---
# This represents the "Science" or "Business Logic" that needs to be verified.
def perform_analysis(input_path, output_path):
    print(f"  [Logic] Reading {input_path}...")
    with open(input_path, 'r') as f:
        data = f.read()

    # Example logic: Count words and uppercase content
    result = f"Processed: {data.upper()}\nWord Count: {len(data.split())}"

    print(f"  [Logic] Writing result to {output_path}...")
    with open(output_path, 'w') as f:
        f.write(result)

# --- Step 1: The Analyst ---
def run_analyst_session(vch_filename):
    print("\n--- Step 1: Analyst runs the original work ---")

    # Setup keys
    key_name = "analyst_key"
    CryptoManager.generate_keys(key_name, f"{key_name}.pub")

    # Create Raw Data
    raw_data = "raw_data.txt"
    with open(raw_data, "w") as f:
        f.write("traceable data analysis is critical")

    output_file = "final_report.txt"

    # Run Session
    with TraceSession(vch_filename, private_key_path=key_name) as session:
        # Capture Input
        session.add_artifact(raw_data)

        # Run Logic
        perform_analysis(raw_data, output_file)

        # Capture Output
        session.add_artifact(output_file)

    # Cleanup local files (to simulate sending only the package)
    os.remove(raw_data)
    os.remove(output_file)
    # Keep keys for now or clean up later? Let's just remove private key to simulate separation
    os.remove(key_name)
    print(f"Analyst finished. Package {vch_filename} created.")
    return key_name + ".pub"

# --- Step 2: The Auditor / Verifier ---
def run_verification_step(vch_filename, pub_key_path):
    print("\n--- Step 2: Auditor verifies by re-running ---")

    verify_dir = "verify_workspace"
    if os.path.exists(verify_dir):
        shutil.rmtree(verify_dir)
    os.makedirs(verify_dir)

    # 1. Extract the package
    print(f"Extracting {vch_filename}...")
    with zipfile.ZipFile(vch_filename, 'r') as z:
        z.extractall(verify_dir)

    # 2. Inspect Environment (Optional but recommended)
    env_lock = os.path.join(verify_dir, "environment.lock")
    with open(env_lock) as f:
        env = json.load(f)
    print(f"Recorded Python Version: {env['python_version'].split()[0]}")

    # 3. Re-run the analysis using extracted artifacts
    # We look in the 'data' folder for artifacts
    extracted_input = os.path.join(verify_dir, "data", "raw_data.txt")
    extracted_original_output = os.path.join(verify_dir, "data", "final_report.txt")

    # Define where we will put our NEW verification output
    reproduced_output = os.path.join(verify_dir, "reproduced_report.txt")

    print("Re-running analysis logic...")
    perform_analysis(extracted_input, reproduced_output)

    # 4. Compare
    print("Comparing reproduced output with original...")
    if filecmp.cmp(extracted_original_output, reproduced_output, shallow=False):
        print("  [SUCCESS] Results Match! The analysis is reproducible.")
    else:
        print("  [FAILURE] Results differ.")

    # Cleanup
    shutil.rmtree(verify_dir)
    os.remove(pub_key_path)
    os.remove(vch_filename)

if __name__ == "__main__":
    package_name = "reproducible_study.vch"
    pub_key = run_analyst_session(package_name)
    run_verification_step(package_name, pub_key)
```

## Results

```text
--- Step 1: Analyst runs the original work ---
  [Logic] Reading raw_data.txt...
  [Logic] Writing result to final_report.txt...
Analyst finished. Package reproducible_study.vch created.

--- Step 2: Auditor verifies by re-running ---
Extracting reproducible_study.vch...
Recorded Python Version: 3.12.12
Re-running analysis logic...
  [Logic] Reading verify_workspace/data/raw_data.txt...
  [Logic] Writing result to verify_workspace/reproduced_report.txt...
Comparing reproduced output with original...
  [SUCCESS] Results Match! The analysis is reproducible.
```

## Conclusion

By bundling artifacts and environment details, Vouch empowers auditors not just to trust the signature, but to empirically verify the computation itself.

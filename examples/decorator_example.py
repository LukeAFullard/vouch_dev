import vouch
import pandas as pd
import numpy as np
import os

# Create some dummy data for the example
def setup_data():
    df = pd.DataFrame({'a': range(10), 'b': range(10, 20)})
    df.to_csv("input_data.csv", index=False)
    print("Created input_data.csv")

def process_data():
    """
    Helper function using global 'pd' reference.
    Vouch will retroactively patch 'pd' to ensure this call is logged.
    """
    print("  -> executing process_data()...")
    # This read should be logged because 'pd' is patched
    df = pd.read_csv("input_data.csv")

    # Simple calculation
    df['sum'] = df['a'] + df['b']

    # Note: 'df' is a new object returned by read_csv.
    # Vouch currently proxies the library ('pd'), but does not automatically
    # wrap every returned object ('df'). So 'df.to_csv' might not be logged
    # unless deeply integrated.
    # However, the 'read_csv' call proves that the global 'pd' was audited.
    df.to_csv("output_data.csv", index=False)
    return df['sum'].mean()

@vouch.record
def main():
    print("Starting audited workflow...")

    # Call a helper function defined outside this scope
    # This proves that Vouch correctly handles functions called from the decorated entry point
    avg = process_data()

    print(f"  -> Average sum: {avg}")
    print("Workflow complete.")

if __name__ == "__main__":
    # 1. Setup
    setup_data()

    # 2. Run the audited function
    # Vouch will generate a timestamped audit file (e.g. audit_2023....vch)
    main()

    # 3. Prove it worked
    print("\n--- Verification & Proof ---")

    # Find the most recent audit file
    import glob
    list_of_files = glob.glob('audit_*.vch')
    latest_file = max(list_of_files, key=os.path.getctime)
    print(f"Generated audit file: {latest_file}")

    # Verify integrity
    if vouch.verify(latest_file):
        print("[OK] Audit package integrity verified.")
    else:
        print("[FAIL] Integrity check failed.")
        exit(1)

    # Inspect the log to prove function calls inside process_data were captured
    import zipfile, json
    print("\nInspecting logs for 'read_csv'...")

    found_read = False

    with zipfile.ZipFile(latest_file, 'r') as z:
        log = json.loads(z.read("audit_log.json"))
        for entry in log:
            target = entry.get("target", "")
            if "read_csv" in target:
                found_read = True
                print(f"  [Found] {target} (read)")

    if found_read:
        print("\n[SUCCESS] The 'read_csv' call inside the helper function was captured!")
        print("This proves that the global 'pd' variable was correctly patched.")
    else:
        print("\n[FAIL] Missing expected log entries.")
        exit(1)

    # Cleanup
    if os.path.exists("input_data.csv"): os.remove("input_data.csv")
    if os.path.exists("output_data.csv"): os.remove("output_data.csv")
    os.remove(latest_file)

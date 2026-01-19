from vouch import TraceSession, auto_audit
import os
import sys

# Ensure we have a dummy data file
if not os.path.exists("data.csv"):
    with open("data.csv", "w") as f:
        f.write("col1,col2\n1,2\n3,4")

print("Generating keys...")
if not os.path.exists("example_id"):
    # Generate keys programmatically or via CLI
    from vouch.crypto import CryptoManager
    CryptoManager.generate_keys("example_id", "example_id.pub", password="secret")

# Run session
print("Running auto-audit session...")
try:
    with TraceSession("auto_audit.vch",
                      private_key_path="example_id",
                      private_key_password="secret",
                      strict=True) as sess:
        with auto_audit():
            # Imports inside this block are intercepted
            import pandas as pd
            import numpy as np

            print("Reading CSV...")
            df = pd.read_csv("data.csv")

            print("Calculating mean...")
            mean = np.mean(df["col1"])
            print(f"Mean: {mean}")

            # Vouch automatically logged these calls

    print("Session complete. Created auto_audit.vch")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

# Verify
print("Verifying...")
# Use subprocess to call CLI
import subprocess
subprocess.run([sys.executable, "-m", "vouch.cli", "verify", "auto_audit.vch", "--data", "data.csv"])

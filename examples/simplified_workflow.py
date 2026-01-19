import vouch
import pandas as pd
import numpy as np

# This is a simplified workflow example using Vouch features:
# 1. Zero-config filename generation (timestamped)
# 2. 'with vouch.vouch():' alias
# 3. Automatic verification

print("--- Starting Simplified Audit ---")

# 1. Record the session
# Vouch will generate a file like 'audit_20240101_120000.vch'
with vouch.vouch() as sess:
    print(f"Recording to: {sess.filename}")

    # Create some dummy data
    df = pd.DataFrame(np.random.randint(0, 100, size=(10, 4)), columns=list('ABCD'))

    # Save it (Vouch captures this artifact)
    df.to_csv("random_data.csv", index=False)

    # Read it back (Vouch logs the read hash)
    df2 = pd.read_csv("random_data.csv")

    print("Analysis complete.")
    captured_filename = sess.filename

print(f"--- Audit Saved to {captured_filename} ---")

# 2. Verify it programmatically
print(f"--- Verifying {captured_filename} ---")
if vouch.verify(captured_filename):
    print("Verification SUCCESS: The audit trail is valid.")
else:
    print("Verification FAILED.")
    exit(1)

print("--- Done ---")

import vouch
import pandas as pd
import os

# This example shows how to use Vouch with zero configuration.
# It uses an ephemeral key (auto-generated) since we haven't run 'vouch gen-keys'.

print("Starting Vouch Quickstart...")

# Start the session.
# 'vouch.start' automatically wraps pandas and handles the audit log.
# We can use the simplified alias 'vouch.capture' or just 'vouch.start'
with vouch.start("quickstart.vch"):

    # Create some dummy data
    data = {
        'product': ['Apple', 'Banana', 'Cherry'],
        'price': [1.2, 0.5, 2.5],
        'quantity': [10, 20, 15]
    }
    df = pd.DataFrame(data)

    # Save to CSV.
    # Vouch will capture this file as an artifact if we added it,
    # but here we are just writing it.
    # To treat it as an input artifact for the *next* step, we read it.
    df.to_csv("products.csv", index=False)

    print("Reading data...")
    # Vouch intercepts this call and hashes 'products.csv'
    df_loaded = pd.read_csv("products.csv")

    # Perform some analysis
    revenue = (df_loaded['price'] * df_loaded['quantity']).sum()
    print(f"Total Revenue: ${revenue}")

    # You can also manually attach files to the audit package
    vouch.TraceSession.get_active_session().add_artifact("products.csv")

print("\nSuccess! Audit package 'quickstart.vch' created.")
print("You can verify it programmatically:")

if vouch.verify("quickstart.vch"):
    print("  [OK] Verification Successful")
else:
    print("  [FAIL] Verification Failed")

# Clean up the CSV file
if os.path.exists("products.csv"):
    os.remove("products.csv")

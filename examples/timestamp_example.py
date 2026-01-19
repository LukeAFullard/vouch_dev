from vouch import TraceSession, auto_audit
import pandas as pd
import os

# Ensure we have keys
if not os.path.exists("example_key.pem"):
    from vouch.crypto import CryptoManager
    CryptoManager.generate_keys("example_key.pem", "example_key.pub")

print("Running audit session with timestamping...")

# Use FreeTSA.org (No API key required)
TSA_URL = "https://freetsa.org/tsr"

with TraceSession("timestamped_audit.vch",
                  private_key_path="example_key.pem",
                  tsa_url=TSA_URL,
                  seed=12345):

    with auto_audit():
        # perform some work
        df = pd.DataFrame({'a': [1, 2, 3], 'b': [4, 5, 6]})
        print("Work done.")

print("\nVerifying the package...")
os.system("vouch verify timestamped_audit.vch")

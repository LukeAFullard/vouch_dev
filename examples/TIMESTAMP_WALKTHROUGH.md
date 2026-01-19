# Trusted Timestamping Walkthrough

This walkthrough demonstrates how to use Vouch's **Trusted Timestamping** feature (RFC 3161) to anchor your audit logs in time. This provides cryptographic proof that your data and analysis results existed at a specific point in time, which is critical for legal defensibility and intellectual property protection.

## The Code

We will use the `examples/timestamp_example.py` script. This script configures a `TraceSession` with a `tsa_url` pointing to a free Time Stamp Authority (TSA).

```python
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
# Note: In a real environment, you might need to supply the CA cert:
# vouch verify timestamped_audit.vch --tsa-ca-file /path/to/cacert.pem
os.system("vouch verify timestamped_audit.vch")
```

## Running the Example

Run the script to generate the audit package and attempt verification.

```bash
python3 examples/timestamp_example.py
```

## Verification

The `vouch verify` command checks the integrity of the timestamp token (`audit_log.tsr`) against the audit log hash.

### Handling CA Certificates

If your system's trust store does not contain the TSA's Root CA, verification will fail with a "signer certificate not found" error. You can provide the CA certificate manually.

For **FreeTSA.org**, you can download the CA certificate:
```bash
wget https://freetsa.org/files/cacert.pem
```

Then verify with the `--tsa-ca-file` flag:

```bash
vouch verify timestamped_audit.vch --tsa-ca-file cacert.pem
```

### Expected Output

```text
Verifying timestamped_audit.vch...
  [OK] Signature Verification: Valid
  [OK] Log Integrity: Valid
  [...] Verifying Timestamp...
    [OK] Timestamp Verified (Matches Log)
  [...] Verifying log chain integrity...
  [OK] Log Chain Integrity: Valid
  [OK] Environment: Python version matches (3.12.12)
  [...] Verifying captured artifacts...
    [OK] Artifact Manifest Signature: Valid
    [OK] __script__timestamp_example.py
  [OK] Captured Artifacts Integrity: Valid
```

## How It Works

1.  **Request:** When the `TraceSession` ends, Vouch calculates the SHA-256 hash of the `audit_log.json`.
2.  **Token:** It sends this hash to the configured `tsa_url`.
3.  **Response:** The TSA signs the hash and a timestamp with its private key, returning a Time Stamp Response (TSR).
4.  **Storage:** Vouch saves this token as `audit_log.tsr` inside the `.vch` package.
5.  **Verification:** `vouch verify` extracts the log and the token, validates the TSA's signature on the token, and confirms the token contains the correct hash of the log.

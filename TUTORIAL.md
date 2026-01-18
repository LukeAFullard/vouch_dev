# Tutorial: Sending an Audit Package to a Partner

This guide walks you through the workflow of using Vouch to secure a data analysis workflow and verify it at a partner organization.

## Scenario
**Analyst (Alice)** is performing a sensitive water quality analysis.
**Auditor (Bob)** needs to verify that Alice's report is accurate and based on the correct raw data.

---

## Part 1: The Analyst (Alice)

### 1. Setup Identity
First, Alice generates her unique cryptographic identity. She keeps the `private_key.pem` secure and never shares it.

```bash
vouch gen-keys --name alice_key
# Output: Generated alice_key and alice_key.pub
```

### 2. Wrap the Analysis
Alice writes her analysis script (`analysis.py`), wrapping the critical libraries with Vouch.

```python
from vouch import Auditor, TraceSession
import pandas as pd
import numpy as np

# 1. Wrap libraries
pandas = Auditor(pd)
numpy = Auditor(np)

# 2. Start a Secure Session
# Alice uses her private key to sign the session automatically
with TraceSession("water_quality_report.vch", private_key_path="alice_key"):

    # 3. Perform Analysis
    # Vouch intercepts 'read_csv' and hashes 'raw_data.csv'
    df = pandas.read_csv("raw_data.csv")

    # Vouch logs this calculation
    mean_ph = df["ph"].mean()
    print(f"Mean pH: {mean_ph}")

    # Operations are logged with their parameters
    if mean_ph < 7.0:
        print("Warning: Acidic")
```

### 3. Send the Package
Alice sends two things to Bob:
1.  The audit package: `water_quality_report.vch`
2.  The raw data: `raw_data.csv` (separately, via email/USB/cloud)

---

## Part 2: The Auditor (Bob)

### 1. Receive and Inspect
Bob receives the files. He wants to know:
*   Did Alice really generate this?
*   Did she use the `raw_data.csv` I have here, or a different version?
*   What parameters did she use?

### 2. Verify Integrity
Bob runs the verification tool.

```bash
vouch verify water_quality_report.vch --data raw_data.csv
```

**Outcome A: Success**
```text
Verifying water_quality_report.vch...
  [OK] Signature Verification: Valid
  [OK] Log Integrity: Valid
  [...] Verifying data file: raw_data.csv
        Hash: e3b0c442...
  [OK] Data Integrity: Valid
```
*Bob is confident the analysis is authentic and the data is correct.*

**Outcome B: Failure (Tampering)**
If Alice (or a hacker) changed the `raw_data.csv` before sending it, or if Bob has the wrong version:
```text
  [FAIL] Data Integrity: Mismatched/Corrupted (Hash 8d92f... not found in log)
```
*Bob rejects the report.*

### 3. Reconstruct (Optional)
If Bob wants to re-run the code, he can inspect `environment.lock` inside the `.vch` file to see exactly which Python libraries Alice used, ensuring he sets up a compatible environment.

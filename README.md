# Vouch

**Forensic logging and verification tool for data analysis workflows.**

Vouch wraps existing Python libraries (like Pandas and NumPy) to create a legally defensible, cryptographically signed audit trail of your data analysis.

## Features

*   **Non-Intrusive Proxy:** Wraps libraries without modifying their code.
*   **Tamper-Evident Logging:** SHA-256 hashing of all function inputs, outputs, and accessed files.
*   **Cryptographic Signing:** RSA-2048 signing of audit logs for non-repudiation.
*   **Environment Capture:** Records exact dependency versions (`pip freeze`) for reproducibility.
*   **Verification CLI:** Easy-to-use command line tool to validate audit packages and data provenance.

## Installation

```bash
pip install -e .
```

## Quick Start

### 1. Generate Keys

```bash
vouch gen-keys --name my_identity
```

### 2. Wrap and Run

```python
from vouch import Auditor, TraceSession
import pandas as pd

# Wrap libraries
pandas = Auditor(pd)

# Run session
with TraceSession("output.vch", private_key_path="my_identity"):
    # Vouch will hash 'data.csv' when read
    df = pandas.read_csv("data.csv")
    # Vouch logs this operation
    print(df.describe())
```

### 3. Verify

```bash
vouch verify output.vch --data data.csv
```

## Examples

### Inspecting Audit Logs and Environment

You can programmatically inspect the contents of a `.vch` file (which is a standard ZIP file) to view the `audit_log.json` and `environment.lock`.

See the [**Inspection Walkthrough**](examples/INSPECTION_WALKTHROUGH.md) for a detailed example and output.

```bash
python3 examples/inspect_vch.py
```

### Capturing Artifacts

Vouch can bundle input and output files directly into the signed package, ensuring that the exact data used in an analysis is preserved and verified.

See the [**Capture Artifacts Walkthrough**](examples/CAPTURE_WALKTHROUGH.md).

```bash
python3 examples/capture_artifacts_example.py
```

## Documentation

*   [**Tutorial: Sending an Audit Package**](TUTORIAL.md) - A step-by-step guide for Analysts and Auditors.
*   [**Legal Statement of Operations**](LEGAL.md) - Technical specifications for legal admissibility.
*   [**Background**](BACKGROUND.md) - Project goals and architecture.

## Development

Run tests:
```bash
python3 -m unittest discover tests
```

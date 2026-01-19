<p align="center"><img src="assets/vouch.png" width="95%"></p>

# Vouch

**Forensic logging and verification tool for data analysis workflows.**

Vouch wraps existing Python libraries (like Pandas and NumPy) to create a legally defensible, cryptographically signed audit trail of your data analysis.

## Features

*   **Non-Intrusive Proxy:** Wraps libraries without modifying their code.
*   **Tamper-Evident Logging:** SHA-256 hash chaining of all function inputs, outputs, and accessed files.
*   **Cryptographic Signing:** RSA-2048 signing of audit logs and artifact manifests for non-repudiation.
*   **Encrypted Identities:** Optional password-based encryption for private keys (PKCS#8).
*   **Reproducibility:** Enforces random seeds and captures exact environment dependency versions (`pip freeze`).
*   **Artifact Bundling:** Securely bundles input/output files with the audit package.
*   **Reporting:** Generates human-readable HTML and Markdown reports from audit packages.
*   **Verification CLI:** Strict validation of signatures, hash chains, and environment compatibility.

## Installation

```bash
pip install .
```

## Quick Start

### 1. Generate Keys

Generate a secure RSA key pair. You can optionally protect the private key with a password.

```bash
vouch gen-keys --name my_identity --password "super-secret"
```

### 2. Wrap and Run

```python
from vouch import Auditor, TraceSession
import pandas as pd

# Wrap libraries
pandas = Auditor(pd)

# Run session with encrypted key and enforced seed
with TraceSession("output.vch",
                  private_key_path="my_identity",
                  private_key_password="super-secret",
                  seed=42):
    # Vouch will hash 'data.csv' when read
    df = pandas.read_csv("data.csv")
    # Vouch logs this operation
    print(df.describe())
```

### 3. Verify

Verify the integrity of the package, including signatures, log chains, and environment versions.

```bash
vouch verify output.vch --data data.csv
```

### 4. Generate Report

Create a human-readable summary of the audit session.

```bash
vouch report output.vch report.html --format html
```

## ⚠️ Reproducibility Limitations

Vouch enforces seeds for `random` and `numpy.random` only. If your analysis uses:
- PyTorch: Add `torch.manual_seed(seed)`
- TensorFlow: Add `tf.random.set_seed(seed)`
- Other RNGs: Manually seed them inside your session

The `secrets` module is intentionally NOT seeded (cryptographic use).

## Examples

### Generating Audit Reports

Vouch can transform dense audit logs into clear, readable reports in HTML or Markdown format.

See the [**Reporting Walkthrough**](examples/REPORTING_WALKTHROUGH.md) for details and output previews.

```bash
python3 examples/generate_report_example.py
```

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

### Reproducing Results (Rerun)

Since Vouch captures input data and environment details, you can extract these components to re-run the analysis and verify reproducibility.

See the [**Rerun Verification Walkthrough**](examples/RERUN_WALKTHROUGH.md).

```bash
python3 examples/rerun_verification.py
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

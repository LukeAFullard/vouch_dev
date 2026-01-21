<p align="center"><img src="assets/vouch.png" width="95%"></p>

# Vouch

**Forensic logging and verification tool for data analysis workflows.**

Vouch wraps existing Python libraries (like Pandas and NumPy) to create a legally defensible, cryptographically signed audit trail of your data analysis.

## Features

*   **Non-Intrusive Proxy:** Wraps libraries without modifying their code.
*   **Tamper-Evident Logging:** SHA-256 hash chaining of all function inputs, outputs, and accessed files.
*   **Cryptographic Signing:** RSA-2048 signing of audit logs and artifact manifests for non-repudiation.
*   **Encrypted Identities:** Optional password-based encryption for private keys (PKCS#8).
*   **Timestamping:** Support for RFC 3161 Trusted Timestamping to prove existence at a point in time.
*   **Reproducibility:** Enforces random seeds (including strict checks for ML libraries) and captures exact environment dependency versions (`pip freeze`).
*   **Artifact Bundling:** Securely bundles input/output files with the audit package (with symlink protection).
*   **Reporting:** Generates human-readable HTML and Markdown reports from audit packages.
*   **Verification:** Verify logs programmatically or via CLI (Strict validation of signatures, hash chains, and environment).
*   **Diff Tool:** Compare two audit sessions to identify discrepancies in environment, logs, or artifacts.
*   **Interactive Inspector:** Explore audit packages via a TUI without manual extraction.
*   **Auto-Detection:** Automatically intercept imports, supporting both explicit targets (`pandas`, `numpy`) and wildcard "audit everything" mode.

## Installation

```bash
pip install .
```

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a detailed guide.

### 1. Write and Run

Vouch requires **Zero Configuration** to get started. Just use `with vouch.vouch():` or the `@vouch.record` decorator.

**Context Manager:**
```python
import vouch
import pandas as pd

# Automatically generates a timestamped audit file (e.g. audit_20231027_1000.vch)
with vouch.vouch():
    # Libraries imported *outside* the block are NOT automatically tracked
    # unless you re-import them or use targets=['*'] (retroactive audit).
    # For best results, import libraries inside the block or use the wildcard feature.
    import pandas as pd

    df = pd.read_csv("data.csv")
    print(df.describe())
```

**Decorator:**
```python
import vouch

# Only decorate the entry point function
@vouch.record
def analyze():
    # Import libraries inside the decorated function to ensure tracking
    import pandas as pd
    df = pd.read_csv("data.csv")
    return df.mean()

analyze()
```

### 2. Verify

Verify the integrity of the package immediately using the Python API or CLI.

```python
import vouch
# Returns True/False
is_valid = vouch.verify("audit_20231027_1000.vch")
```

```bash
vouch verify audit_20231027_1000.vch
```

## Advanced Usage

### Audit Everything (Wildcard)

You can automatically audit **all** subsequently imported third-party libraries using the wildcard target. This also attempts to wrap previously imported libraries.

```python
with vouch.start(targets=["*"]):
    import polars as pl  # Automatically audited
    import sklearn       # Automatically audited
    ...
```

### Persistent Identity

For production use, you should establish a persistent identity using `vouch gen-keys`.

### Generate Report

Create a human-readable summary of the audit session.

```bash
vouch report output.vch report.html --format html
```

### Compare Sessions (Diff)

Compare two audit packages to see what changed in the environment, code execution path, or artifacts.

```bash
vouch diff session1.vch session2.vch --show-hashes
```

### Interactive Inspection

Explore the contents of a package interactively.

```bash
vouch inspect output.vch
# (vouch) timeline
# (vouch) show 1
# (vouch) artifacts
```

## Modes of Operation

Vouch supports three modes to balance between security/completeness and performance:

### 1. Strict Mode (Default, Recommended for Production)
Ensures maximum integrity and reproducibility.
*   **Behavior:**
    *   Hashes all function inputs and outputs.
    *   Strictly enforces RNG seeding (raises error for unseeded `torch`/`tensorflow`).
    *   Strictly validates file existence (raises error if missing).
    *   Enforces security checks (e.g., rejects symlinks).
*   **Usage:** `strict=True` (default)
*   **Best for:** Final regulatory audits, model delivery, "golden" runs.

### 2. Normal Mode
A balanced mode for everyday use.
*   **Behavior:**
    *   Hashes all function inputs and outputs.
    *   Warns (instead of raising errors) for unseeded RNGs or missing optional keys.
*   **Usage:** `strict=False`
*   **Best for:** Development, debugging, non-critical logging.

### 3. Light Mode
Optimized for high-performance or high-frequency loops.
*   **Behavior:**
    *   **Skips expensive hashing** of function arguments and results (logs `"SKIPPED_LIGHT"`).
    *   **Maintains Integrity:** Still hashes File I/O (reads/writes) and bundles artifacts.
    *   **Maintains Context:** Still logs function names, call hierarchy, and string representations (`repr`) of arguments.
*   **Usage:** `light_mode=True` (can be combined with `strict=True` or `strict=False`)
*   **Best for:** Tight loops, large in-memory objects (huge DataFrames), iterative research where I/O tracking is sufficient.

```python
# Example: Light Mode for performance
with vouch.start(light_mode=True):
    # Operations here run faster as argument hashing is skipped
    ...
```

## ⚠️ Strict Mode & Security

### RNG Seeding
Vouch enforces seeds for `random` and `numpy.random`.
If **Strict Mode** (default) is enabled, Vouch will **raise an error** if it detects unseeded usage of:
- `torch`
- `tensorflow`

You must manually seed them before use:
```python
torch.manual_seed(seed)
tf.random.set_seed(seed)
```

### Symlink Protection
For security, Vouch **rejects symbolic links** when adding artifacts (`TraceSession.add_artifact`). This prevents the accidental bundling of sensitive system files or recursive loops.

### Timestamping
To add legal weight to your audit trail, provide a `tsa_url` to `TraceSession`. This requests a cryptographically verifiable timestamp token (RFC 3161) from a Trusted Timestamp Authority (TSA).
- **FreeTSA.org**: `https://freetsa.org/tsr`
- **DigiCert**: `http://timestamp.digicert.com`

The `vouch verify` command will automatically verify this timestamp if present.

### Constructor Coverage Gap
Vouch uses proxies to audit function calls. However, **Class Constructors** (e.g. `pd.DataFrame()`) are intentionally **NOT intercepted**. This is to preserve `isinstance()` compatibility, which is critical for many libraries.

**Implication:** Operations performed on objects created directly via constructors are **not audited** unless those objects are subsequently passed to a wrapped function.

**Best Practice:**
*   Use **Factory Functions** whenever possible (e.g., `pd.read_csv`, `np.array`, `torch.tensor`). These are fully audited.
*   If you must use a constructor, ensure the resulting object is used in a subsequent tracked function call to capture its state.

```python
# ❌ NOT AUDITED
df = pd.DataFrame({"a": [1, 2]})
df.mean() # DataFrame.mean is not tracked because df is not a proxy

# ✅ AUDITED (Factory Function)
df = pd.read_csv("data.csv")
df.mean() # Tracked!

# ✅ AUDITED (Wrapped Return)
df = some_audited_function()
df.mean() # Tracked!
```

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

### Trusted Timestamping (RFC 3161)

You can anchor your audit logs in time using a Trusted Timestamp Authority (TSA). This provides cryptographic proof that the data existed at a specific time.

See the [**Timestamp Walkthrough**](examples/TIMESTAMP_WALKTHROUGH.md) for a detailed guide.

```bash
python3 examples/timestamp_example.py
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

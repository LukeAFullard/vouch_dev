# Vouch Quickstart Guide

This guide is designed for first-time users who want to add an audit trail to their data analysis workflow immediately, without complex setup.

## Zero Configuration Mode

You don't need to generate keys, configure filenames, or setup proxies to get started. Vouch automatically generates a temporary secure identity and a timestamped output file.

### 1. Write Your Script

Use `with vouch.vouch():` (or the `@vouch.record` decorator) to wrap your code. This handles everything for you: it wraps common libraries like `pandas` and initializes the secure session.

**Option A: Context Manager**
```python
import vouch
import pandas as pd

# Start the audit session
# Automatically generates a file like 'audit_20231027_093000.vch'
with vouch.vouch():

    # Load your data
    # Vouch automatically records the hash of 'data.csv'
    df = pd.read_csv("data.csv")

    # Do your analysis
    result = df.describe()
    print(result)

    # Save results
    # Vouch tracks this output file as well
    result.to_csv("summary.csv")
```

**Option B: Decorator**
```python
import vouch

@vouch.record
def main():
    import pandas as pd
    df = pd.read_csv("data.csv")
    df.to_csv("summary.csv")

main()
```

> **Important:** Only use `@vouch.record` on your main entry point or top-level workflow function. Do **not** apply it to every helper function, as nested audit sessions are not supported and will raise an error.

### 2. Run It

Run your script as usual.

```bash
python3 my_script.py
```

You will see a file named `audit_YYYYMMDD_HHMMSS.vch` created in your directory. This file contains the cryptographic proof of your analysis.

### 3. Verify It

You can verify the integrity of the audit package immediately using the command line tool or Python.

**CLI:**
```bash
vouch verify audit_*.vch
```

**Python:**
```python
import vouch
import glob
import os

# Verify the most recent audit file
latest_file = max(glob.glob("audit_*.vch"), key=os.path.getctime)
if vouch.verify(latest_file):
    print("Audit trail is valid!")
```

This confirms that:
*   **Log Integrity**: The audit log has not been tampered with since creation.
*   **Artifact Integrity**: The captured files match the hashes in the log.
*   **Environment**: The Python version and library versions are recorded accurately.

## Audit Everything

If you use libraries other than `pandas` and `numpy` (e.g., `polars`, `sklearn`, `scipy`), you can tell Vouch to audit **all** imports automatically.

```python
# Audit all third-party libraries imported in this block
with vouch.start(targets=["*"]):
    import polars as pl
    import sklearn
    ...
```

Vouch intelligently excludes the Python standard library and testing tools to prevent issues.

## Next Steps: Establishing an Identity

The "Zero Configuration" mode uses an ephemeral key, which ensures integrity but doesn't prove *who* created the package.

When you are ready to share your audit packages with others (e.g., auditors, regulators) or want to sign them with your permanent identity:

1.  **Generate a Key Pair**:
    ```bash
    vouch gen-keys --name my_identity
    ```

2.  **Use Your Key**:
    ```python
    with vouch.start(private_key_path="my_identity"):
        ...
    ```

See [TUTORIAL.md](TUTORIAL.md) for more advanced workflows, including timestamping and diffing sessions.

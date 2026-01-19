# Vouch Quickstart Guide

This guide is designed for first-time users who want to add an audit trail to their data analysis workflow immediately, without complex setup.

## Zero Configuration Mode

You don't need to generate keys or configure anything to get started. Vouch automatically generates a temporary secure identity for each session if one is not found.

### 1. Write Your Script

Use `vouch.start()` to wrap your code. This handles everything for you: it wraps libraries like `pandas` and initializes the secure session.

```python
import vouch
import pandas as pd

# Start the audit session
# 'audit.vch' is the output file that will contain the full audit trail
with vouch.start("audit.vch"):

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

### 2. Run It

Run your script as usual.

```bash
python3 my_script.py
```

You will see a file named `audit.vch` created in your directory. This file contains the cryptographic proof of your analysis.

### 3. Verify It

You can verify the integrity of the audit package immediately using the command line tool.

```bash
vouch verify audit.vch
```

This confirms that:
*   **Log Integrity**: The audit log has not been tampered with since creation.
*   **Artifact Integrity**: The captured files match the hashes in the log.
*   **Environment**: The Python version and library versions are recorded accurately.

## Next Steps: Establishing an Identity

The "Zero Configuration" mode uses an ephemeral key, which ensures integrity but doesn't prove *who* created the package.

When you are ready to share your audit packages with others (e.g., auditors, regulators) or want to sign them with your permanent identity:

1.  **Generate a Key Pair**:
    ```bash
    vouch gen-keys --name my_identity
    ```

2.  **Use Your Key**:
    ```python
    with vouch.start("audit.vch", private_key_path="my_identity"):
        ...
    ```

See [TUTORIAL.md](TUTORIAL.md) for more advanced workflows, including timestamping and diffing sessions.

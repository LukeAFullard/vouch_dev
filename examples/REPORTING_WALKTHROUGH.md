# Example: Generating Audit Reports

## Introduction

Vouch not only records your analysis and captures artifacts but also allows you to generate human-readable reports from your audit packages. These reports are essential for sharing your work with stakeholders, compliance officers, or simply for your own documentation.

You can generate reports in two formats:
- **HTML**: Best for interactive viewing in a web browser.
- **Markdown**: Best for integration into documentation sites, GitHub readmes, or text-based workflows.

This example demonstrates how to run a secure Vouch session and then generate reports in both formats.

## Code

The following script (`generate_report_example.py`) sets up a complete Vouch workflow: generating keys, running a session with artifacts, and finally producing the reports.

```python
import os
import sys
import pandas as pd
import numpy as np
import shutil

# Ensure we can import vouch from the parent directory if not installed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vouch.session import TraceSession
from vouch.auditor import Auditor
from vouch.reporter import Reporter
from vouch.crypto import CryptoManager

def main():
    print("--- Vouch Reporting Example ---\n")

    # 1. Setup keys
    # To use Vouch securely, we need an RSA key pair to sign our audit logs.
    priv_key = "example_id_rsa"
    pub_key = "example_id_rsa.pub"
    print(f"1. Generating RSA keys ({priv_key}, {pub_key})...")
    CryptoManager.generate_keys(priv_key, pub_key, password="example_password")

    # 2. Run a Trace Session
    # We will simulate a data analysis task: reading a CSV, calculating a mean,
    # and tracking the input file.
    vch_file = "example_session.vch"
    data_path = "input_data.csv"

    print(f"2. Running analysis session -> {vch_file}")

    # Create dummy data
    pd.DataFrame({'A': range(5), 'B': np.random.randn(5)}).to_csv(data_path, index=False)

    # Start the session. We provide the private key and password for signing.
    # We also enforce a random seed for reproducibility.
    with TraceSession(vch_file, private_key_path=priv_key, private_key_password="example_password", seed=42) as sess:
        # Wrap the pandas library to audit calls
        pd_wrapper = Auditor(pd, name="pd")

        print("   [Action] Reading CSV file...")
        df = pd_wrapper.read_csv(data_path)

        print("   [Action] Calculating mean...")
        mean_val = df['B'].mean()

        # Manually log a significant result
        sess.logger.log_call("calculate_mean", [df], {}, mean_val)

        # Add the input file as a bundled artifact
        print("   [Action] Bundling input file as artifact...")
        sess.add_artifact(data_path)

    # 3. Generate Reports
    # Now we can generate human-readable reports from the .vch file.

    # HTML Report (Best for viewing in a browser)
    html_report = "example_report.html"
    print(f"\n3. Generating HTML report -> {html_report}")
    Reporter.generate_report(vch_file, html_report, format="html")

    # Markdown Report (Best for documentation or text-based workflows)
    md_report = "example_report.md"
    print(f"4. Generating Markdown report -> {md_report}")
    Reporter.generate_report(vch_file, md_report, format="md")

    # 4. Display Results
    print("\n--- Markdown Report Preview ---\n")
    with open(md_report, 'r') as f:
        print(f.read())
    print("-------------------------------")

    # Cleanup
    print("\nCleaning up example files...")
    for f in [priv_key, pub_key, vch_file, html_report, md_report, data_path]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    main()
```

## Results

Running the script produces the following output. The Markdown report preview shows the structured summary of the session, including the environment, captured artifacts, and the sequence of operations.

```text
--- Vouch Reporting Example ---

1. Generating RSA keys (example_id_rsa, example_id_rsa.pub)...
2. Running analysis session -> example_session.vch
   [Action] Reading CSV file...
   [Action] Calculating mean...
   [Action] Bundling input file as artifact...

3. Generating HTML report -> example_report.html
4. Generating Markdown report -> example_report.md

--- Markdown Report Preview ---

# Vouch Audit Report
**File:** `example_session.vch`

## Session Summary
- **Start Time:** 2026-01-19T01:43:39.706884+00:00
- **End Time:** 2026-01-19T01:43:39.712313+00:00
- **Total Operations:** 3

## Environment
- **Python Version:** `3.12.12 (main, Nov  7 2025, 00:07:10) [GCC 13.3.0]`
- **Platform:** `linux`

## Artifacts
- **input_data.csv**: `e5f38e40ea2309b6dd95dc8c12c1b606b93a0a94128da5bca5ccef4ed1d7f44b`

## Audit Log
### 1. TraceSession.seed_enforcement
- **Timestamp:** 2026-01-19T01:43:39.706884+00:00
- **Args:** `['42']`
- **Kwargs:** `{}`
- **Result:** `None`

### 2. pd.read_csv
- **Timestamp:** 2026-01-19T01:43:39.710162+00:00
- **Args:** `["'input_data.csv'"]`
- **Kwargs:** `{}`
- **Result:** `<DataFrame shape=(5, 2)>`

### 3. calculate_mean
- **Timestamp:** 2026-01-19T01:43:39.712313+00:00
- **Args:** `['<DataFrame shape=(5, 2)>']`
- **Kwargs:** `{}`
- **Result:** `<float64 shape=()>`

-------------------------------
```

## Conclusion

Vouch's reporting capabilities bridge the gap between secure, forensic logging and human understanding. By providing both HTML and Markdown outputs, Vouch integrates seamlessly into both visual and automated documentation workflows.

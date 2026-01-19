import os
import sys
import pandas as pd
import numpy as np
from vouch.session import TraceSession
from vouch.auditor import Auditor
from vouch.reporter import Reporter
from vouch.crypto import CryptoManager

def main():
    print("Setting up example...")

    # 1. Setup keys
    priv_key = "example_id_rsa"
    pub_key = "example_id_rsa.pub"
    if not os.path.exists(priv_key):
        print(f"Generating keys: {priv_key}, {pub_key}")
        CryptoManager.generate_keys(priv_key, pub_key, password="example_password")

    # 2. Run a Trace Session
    vch_file = "example_session.vch"
    print(f"Running session -> {vch_file}")

    # Create some dummy data file
    data_path = "input_data.csv"
    pd.DataFrame({'A': range(10), 'B': np.random.randn(10)}).to_csv(data_path, index=False)

    with TraceSession(vch_file, private_key_path=priv_key, private_key_password="example_password", seed=42) as sess:
        # Wrap pandas
        pd_wrapper = Auditor(pd, name="pd")

        # Perform operations
        print("  - Reading CSV...")
        df = pd_wrapper.read_csv(data_path)

        print("  - Calculating mean...")
        mean_val = df['B'].mean()
        sess.logger.log_call("calculate_mean", [df], {}, mean_val)

        # Add the input file as an artifact
        print("  - Adding artifact...")
        sess.add_artifact(data_path)

    # 3. Generate Report
    html_report = "example_report.html"
    print(f"Generating report -> {html_report}")
    Reporter.generate_report(vch_file, html_report)

    print("Done! Check example_report.html")

    # Clean up input file
    if os.path.exists(data_path):
        os.remove(data_path)

if __name__ == "__main__":
    main()

"""
Vouch Modes Example

This script demonstrates the three modes of operation:
1. Normal Mode: Standard logging, warnings only.
2. Strict Mode: Enforces seeds, strict checks.
3. Light Mode: Optimized performance by skipping expensive hashing.
"""

import vouch
import pandas as pd
import numpy as np
import os

def run_analysis(mode_name):
    print(f"\n--- Running Analysis in {mode_name} ---")

    # Simulate some data processing
    data = pd.DataFrame({'a': np.random.randn(100), 'b': np.random.randn(100)})
    mean_val = data.mean()
    print(f"Computed mean:\n{mean_val}")

    # Simulate IO (which should be tracked in all modes)
    fname = f"data_{mode_name.lower().replace(' ', '_')}.csv"
    data.to_csv(fname)
    print(f"Saved {fname}")
    return fname

def main():
    # 1. Normal Mode (strict=False)
    # Good for development. Won't crash if we forget to seed libraries (though we should).
    print("1. Starting Normal Mode Session...")
    with vouch.start(filename="session_normal.vch", strict=False, seed=42):
        run_analysis("Normal Mode")

    # 2. Strict Mode (strict=True - Default)
    # Good for production. Ensures reproducibility.
    print("\n2. Starting Strict Mode Session...")
    try:
        with vouch.start(filename="session_strict.vch", strict=True, seed=42):
            run_analysis("Strict Mode")
    except Exception as e:
        print(f"Strict mode caught an issue (expected if environment is perfect): {e}")

    # 3. Light Mode (light_mode=True)
    # Good for high performance.
    print("\n3. Starting Light Mode Session...")
    with vouch.start(filename="session_light.vch", light_mode=True, seed=42):
        run_analysis("Light Mode")

    print("\nAll sessions completed.")
    print("Check the generated .vch files to see the difference in logging.")

    # Clean up csvs
    for mode in ["normal_mode", "strict_mode", "light_mode"]:
        f = f"data_{mode}.csv"
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    main()

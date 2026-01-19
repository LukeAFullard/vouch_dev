# Decorator Walkthrough

This example demonstrates how to use the `@vouch.record` decorator to audit a data processing workflow.

It specifically highlights Vouch's ability to **retroactively patch global imports**. This means you can import libraries like `pandas` at the top of your script, and Vouch will still capture their usage inside your functions, even if those functions are defined outside the decorated entry point.

## The Code

See `examples/decorator_example.py` for the complete runnable script.

### Key Components

1.  **Top-Level Imports:**
    ```python
    import vouch
    import pandas as pd  # Imported BEFORE auditing starts
    ```

2.  **Helper Function:**
    This function uses the global `pd` reference. In standard Python, this reference would point to the original, unwrapped library. Vouch fixes this.
    ```python
    def process_data():
        # Vouch patches 'pd' so this read is logged
        df = pd.read_csv("input_data.csv")
        ...
    ```

3.  **Decorated Entry Point:**
    Decorate your main function. Do **not** decorate every helper function.
    ```python
    @vouch.record
    def main():
        process_data()
    ```

4.  **Execution:**
    Just call `main()`. Vouch handles session creation, global patching, logging, artifact capture, and signing automatically.
    ```python
    if __name__ == "__main__":
        main()
    ```

## Expected Output

When you run the example, Vouch generates a secure `.vch` file and logs the operations found in the helper function.

```bash
python3 examples/decorator_example.py
```

**Output:**
```text
Created input_data.csv
Starting audited workflow...
  -> executing process_data()...
  -> Average sum: 19.0
Workflow complete.

--- Verification & Proof ---
Generated audit file: audit_20231027_123456.vch
[OK] Audit package integrity verified.

Inspecting logs for 'read_csv'...
  [Found] pandas.read_csv (read)

[SUCCESS] The 'read_csv' call inside the helper function was captured!
This proves that the global 'pd' variable was correctly patched.
```

## How It Works

When `@vouch.record` starts the session:
1.  It identifies the "calling frame" (your script).
2.  It scans the global variables of that script.
3.  It finds variables (like `pd`) that point to libraries Vouch knows how to audit.
4.  It replaces those variables with the wrapped `Auditor` proxies.
5.  It executes your function.

This ensures comprehensive coverage without forcing you to change your import style.

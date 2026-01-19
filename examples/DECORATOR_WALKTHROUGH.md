# Decorator Walkthrough

This example demonstrates how to use the `@vouch.record` decorator to audit a data processing workflow.

It specifically highlights Vouch's ability to **retroactively patch global imports**. This means you can import libraries like `pandas` at the top of your script, and Vouch will still capture their usage inside your functions, even if those functions are defined outside the decorated entry point.

It also demonstrates **Deep Auditing**, where objects returned by libraries (like DataFrames) remain proxied, allowing chained operations (like `.to_csv()`) to be logged.

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

        # 'df' is automatically wrapped, so this write is also logged
        df.to_csv("output_data.csv", index=False)
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
Generated audit file: audit_20260119_113819.vch
[OK] Audit package integrity verified.

Inspecting logs for 'read_csv' and 'to_csv'...
  [Found] pandas.read_csv (read)
  [Found] pandas.read_csv().to_csv (read)
  [Found] pandas.read_csv().to_csv (write)

[SUCCESS] Both read and write operations inside the helper function were captured!
```

## How It Works

When `@vouch.record` starts the session:
1.  **Global Patching**: It identifies the "calling frame" (your script) and scans its global variables. Any variables pointing to targeted libraries (like `pd`) are replaced with wrapped `Auditor` proxies.
2.  **Deep Wrapping**: When you call `pd.read_csv(...)`, it returns a DataFrame. Vouch detects that this object belongs to the `pandas` package and automatically wraps it in a new `Auditor`.
3.  **Chained Auditing**: When you subsequently call `df.to_csv(...)`, the wrapper intercepts this call and logs it, ensuring the output artifact is captured.

This ensures comprehensive coverage without forcing you to change your import style.

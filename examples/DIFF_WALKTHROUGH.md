# Diff Tool Walkthrough

This guide demonstrates how to use the `vouch diff` command to compare two audit sessions. This is useful for identifying why a result might have changed (e.g., different environment, different data, or code changes).

## 1. Create a Baseline Session

First, run a standard analysis.

```python
# baseline.py
from vouch import TraceSession, auto_audit
import os

with open("data.csv", "w") as f:
    f.write("a,b\n1,2")

with TraceSession("baseline.vch", strict=False) as sess:
    with auto_audit():
        import pandas as pd
        df = pd.read_csv("data.csv")
        print(df.sum())
```

Run it:
```bash
python3 baseline.py
```

## 2. Create a Modified Session

Now, simulate a change. We'll modify the data file.

```python
# modified.py
from vouch import TraceSession, auto_audit
import os

# Change data!
with open("data.csv", "w") as f:
    f.write("a,b\n1,3")  # Changed 2 to 3

with TraceSession("modified.vch", strict=False) as sess:
    with auto_audit():
        import pandas as pd
        df = pd.read_csv("data.csv")
        print(df.sum())
```

Run it:
```bash
python3 modified.py
```

## 3. Compare Sessions

Use `vouch diff` to see what changed.

```bash
vouch diff baseline.vch modified.vch --show-hashes
```

**Expected Output:**

```text
Comparing baseline.vch vs modified.vch...

--- Environment Comparison ---
Environment matches.

--- Audit Log Comparison ---
Log 1 entries: 3
Log 2 entries: 3
Logs have identical structure but content differences (timestamps/hashes).

--- Artifacts Comparison ---
Artifact mismatch: data.csv
  < 96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7
  > 3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea
```

The tool correctly identifies that `data.csv` has a different hash, explaining why the results might differ.

## Other Scenarios

### Environment Changes
If you upgrade a library (e.g., `pandas`) between runs, `vouch diff` will highlight the version change in `environment.lock`.

### Code Logic Changes
If the sequence of operations changes (e.g., you added a filter step), `vouch diff` will show the divergence in the "Audit Log Comparison" section:

```text
Mismatch at entry 5:
  < call DataFrame.sum
  > call DataFrame.dropna
```

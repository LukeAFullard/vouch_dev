# Vouch

Forensic logging and verification tool for data analysis workflows.

## Installation

```bash
pip install -e .
```

## Usage

### 1. Generate Keys

```bash
vouch gen-keys --name my_identity
```

### 2. Wrap and Run

```python
from vouch import Auditor, TraceSession
import pandas as pd

# Wrap libraries
pandas = Auditor(pd)

# Run session
with TraceSession("output.vch", private_key_path="my_identity"):
    df = pandas.read_csv("data.csv")
    # ...
```

### 3. Verify

```bash
vouch verify output.vch --data data.csv
```

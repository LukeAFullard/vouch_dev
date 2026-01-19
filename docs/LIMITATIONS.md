# Known Limitations

Vouch provides powerful auditing capabilities through library proxying, but it relies on Python's dynamic nature and has specific boundaries where tracking may be lost.

## 1. Cross-Module Imports

Vouch's retroactive global patching (`_patch_caller_globals`) only updates the global variables of the **file/module where the audit session starts** (e.g., your main script).

If your script imports *other* local modules that have already imported libraries like `pandas` at their top level, those internal references will **not** be patched and operations inside those modules may not be logged.

**Example Failure Case:**

`utils.py`:
```python
import pandas as pd # Imported at load time

def load_data():
    return pd.read_csv("data.csv") # 'pd' here is the original, unwrapped module
```

`main.py`:
```python
import vouch
import utils

@vouch.record
def main():
    utils.load_data() # This call works, but the read_csv inside is NOT logged
```

**Solution:**
Ensure libraries are imported *inside* the functions in your utility modules, or pass the wrapped library object (or wrapped dataframes) to them.

## 2. Cross-Library Object Returns

Vouch's "Deep Auditing" automatically wraps objects returned by a function if they belong to the **same package**.

If a function returns an object from a *different* library (even if that library is also supported by Vouch), the wrapper chain is broken for that object.

**Example:**
```python
@vouch.record
def main():
    df = pd.DataFrame({'a': [1, 2]}) # Wrapped

    # .to_numpy() returns a numpy.ndarray
    # Since numpy != pandas, the result is NOT wrapped automatically
    arr = df.to_numpy()

    # This call is NOT logged because 'arr' is a raw numpy array
    arr.mean()
```

**Workaround:**
If `numpy` is also audited (targets include numpy), direct calls to `np.mean(arr)` *will* be logged if `np` is the wrapped module global. However, method calls on the unwrapped object (`arr.mean()`) will be missed.

## 3. Built-in Types

Vouch does not wrap standard Python types like `list`, `dict`, `int`, or `str`. If a library function converts data to a standard type (e.g. `df.to_dict()`), tracking stops for that data structure.

## 4. Operator Overloading Limits

The `Auditor` proxy implements common operators (`+`, `-`, `*`, `/`, `[]`), but it may not cover every possible magic method (e.g. `__matmul__` `@`, `__pow__`, bitwise operators). Operations using unsupported operators on wrapped objects may fail or return unwrapped results.

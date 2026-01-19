# Known Limitations

Vouch provides powerful auditing capabilities through library proxying, but it relies on Python's dynamic nature and has specific boundaries where tracking may be lost.

## 1. Class Constructors

Vouch proxies module attributes to wrap functions and objects. However, it explicitly avoids wrapping **classes** (types) to preserve `isinstance` checks.

This means that calling a class constructor directly (e.g. `pd.DataFrame(...)`) will return an **unwrapped** object.

**Workaround:**
Use factory functions where available (e.g. `pd.read_csv`, `pd.to_datetime`, `pd.concat`) which return wrapped objects. Alternatively, ensure the object is passed to a wrapped function later, which will log the interaction but not the creation.

## 2. Built-in Types

Vouch does not wrap standard Python types like `list`, `dict`, `int`, or `str`. If a library function converts data to a standard type (e.g. `df.to_dict()`), tracking stops for that data structure.

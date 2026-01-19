# Known Limitations

Vouch provides powerful auditing capabilities through library proxying, but it relies on Python's dynamic nature and has specific boundaries where tracking may be lost.

## 1. Strict Type Checking

The `Auditor` wrapper is a proxy object. While it works with most duck-typing scenarios and tries to be transparent, it will fail strict type checks:

*   `type(wrapped_obj) is TargetType` will verify as `False`.
*   C-extensions that perform strict type checking at the C level may reject wrapped objects.
*   `isinstance(wrapped_obj, TargetType)` may fail depending on how the type check is implemented (since `wrapped_obj` is an instance of `Auditor`).

## 2. Built-in Types

Vouch does not wrap standard Python types like `list`, `dict`, `int`, or `str`. If a library function converts data to a standard type (e.g. `df.to_dict()`), tracking stops for that data structure.

## 3. Standard Library (Opt-In)

By default, Vouch excludes standard library modules (e.g., `json`, `math`, `os`) to prevent stability issues. However, you can opt-in to audit specific standard library modules by listing them explicitly in the `targets` list (e.g., `targets=["json"]`).

## 4. Class Constructors (Not Intercepted)

To support Pickling and Strict Type Checking of classes, Vouch does **not** wrap class objects (types). This means calls to class constructors (e.g., `pd.DataFrame()`) are **not** intercepted in the audit log. However, the resulting instance *is* compatible with pickling and subsequent method calls on it will be audited if it is wrapped elsewhere (e.g. via return value wrapping).

*Note: Factory functions like `pd.read_csv` or `np.array` ARE intercepted because they are functions, not classes.*

## 5. Threading

Vouch uses `contextvars` to manage the active audit session. This provides automatic support for `asyncio` concurrency. However, when using `threading.Thread` manually, the audit session context is NOT automatically propagated to new threads. Operations performed in background threads will not be logged unless you manually propagate the context.

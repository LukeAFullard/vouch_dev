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

## 4. Class Constructors (Proxied)

Vouch now wraps class constructors (e.g., `pd.DataFrame()`) to return wrapped instances. However, because the class itself is wrapped in an `Auditor` proxy, using the class object in strict type checks (e.g. `isinstance(obj, pd.DataFrame)`) where `pd.DataFrame` is the wrapper might behave unexpectedly compared to using the original class.

## 5. Threading and Multiprocessing

Vouch's `TraceSession` is currently thread-local. Calls made in background threads (or subprocesses) will NOT be logged because they do not have access to the active audit session. Wrapped objects will still function correctly in threads (avoiding crashes), but their actions will be invisible to the audit log.

# Known Limitations

Vouch provides powerful auditing capabilities through library proxying, but it relies on Python's dynamic nature and has specific boundaries where tracking may be lost.

## 1. Class Constructors

Vouch proxies module attributes to wrap functions and objects. However, it explicitly avoids wrapping **classes** (types) to preserve `isinstance` checks.

This means that calling a class constructor directly (e.g. `pd.DataFrame(...)`) will return an **unwrapped** object.

**Workaround:**
Use factory functions where available (e.g. `pd.read_csv`, `pd.to_datetime`, `pd.concat`) which return wrapped objects. Alternatively, ensure the object is passed to a wrapped function later, which will log the interaction but not the creation.

## 2. Built-in Types

Vouch does not wrap standard Python types like `list`, `dict`, `int`, or `str`. If a library function converts data to a standard type (e.g. `df.to_dict()`), tracking stops for that data structure.

## 3. Async and Generators

Vouch does not automatically intercept values produced by `async` functions (coroutines) or generators.

*   **Async/Await:** The `Auditor` wraps the function call that returns the coroutine, but it does not wrap the coroutine itself to intercept the `await` result.
*   **Generators:** The `Auditor` does not wrap the generator object to intercept yielded values.

## 4. Strict Type Checking

The `Auditor` wrapper is a proxy object. While it works with most duck-typing scenarios, it will fail strict type checks:

*   `type(wrapped_obj) is TargetType` will verify as `False`.
*   C-extensions that perform strict type checking at the C level may reject wrapped objects.

## 5. Standard Library

Vouch explicitly excludes standard library modules (e.g., `json`, `math`, `os`) from automatic auditing to prevent stability issues and infinite recursion in internal tools.

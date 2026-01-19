import functools
import os
import logging
from typing import Any, Optional, Callable
from .session import TraceSession
from .hasher import Hasher

logger = logging.getLogger(__name__)

class Auditor:
    """
    A wrapper proxy that intercepts attribute access and function calls for auditing.
    """
    def __init__(self, target: Any, name: Optional[str] = None):
        """
        Initialize the Auditor.

        Args:
            target: The object to wrap.
            name: The name of the object (used in logs).
        """
        self._target = target
        self._name = name or getattr(target, "__name__", str(target))

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_target", "_name"):
            super().__setattr__(name, value)
        else:
            setattr(self._target, name, value)

    def __delattr__(self, name: str) -> None:
        if name in ("_target", "_name"):
            super().__delattr__(name)
        else:
            delattr(self._target, name)

    def __getattr__(self, name: str) -> Any:
        # Pass through dunder methods or internal attributes to avoid issues
        # (Though __getattr__ is only called if not found)
        if name.startswith("_"):
            return getattr(self._target, name)

        attr = getattr(self._target, name)

        # If it's a class/type, do NOT wrap it to preserve isinstance checks
        if isinstance(attr, type):
            return attr

        # If it's a callable (and not a class), wrap it
        if callable(attr):
            return self._wrap_callable(attr, name)

        # Recursively wrap attributes that are part of the library (heuristic)
        # Check if module starts with same prefix?
        # For now, simplistic wrapping.
        return Auditor(attr, name=f"{self._name}.{name}")

    def _wrap_callable(self, func: Callable, func_name: str) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Execute the actual function
            result = func(*args, **kwargs)

            # Log if a session is active
            session = TraceSession.get_active_session()
            if session:
                full_name = f"{self._name}.{func_name}"

                # Check for file I/O (naive implementation for read_*)
                extra_hashes = {}
                if "read" in func_name or "load" in func_name or "to_" in func_name:
                    # Check first positional arg
                    if args and isinstance(args[0], str) and os.path.exists(args[0]):
                        try:
                            file_hash = Hasher.hash_file(args[0])
                            extra_hashes["arg_0_file_hash"] = file_hash
                            extra_hashes["arg_0_path"] = args[0]
                        except (IOError, OSError) as e:
                            logger.warning(f"Failed to hash file {args[0]}: {e}")
                        except Exception as e:
                            logger.error(f"Unexpected error hashing {args[0]}: {e}")

                    # Check common kwargs for file paths
                    # specific to pandas.read_csv(filepath_or_buffer=...) or generic
                    for key, val in kwargs.items():
                         if key in ["filepath", "path", "filename", "io", "filepath_or_buffer"] and isinstance(val, str) and os.path.exists(val):
                             try:
                                file_hash = Hasher.hash_file(val)
                                extra_hashes[f"kwarg_{key}_file_hash"] = file_hash
                                extra_hashes[f"kwarg_{key}_path"] = val
                             except (IOError, OSError) as e:
                                logger.warning(f"Failed to hash file {val}: {e}")
                             except Exception as e:
                                logger.error(f"Unexpected error hashing {val}: {e}")

                session.logger.log_call(full_name, args, kwargs, result, extra_hashes)

            # --- Deep Wrapping Logic ---
            # If the result is an object from the same package as the wrapped target,
            # we should wrap it too so subsequent calls (e.g. df.to_csv) are audited.

            # Determine target package
            target_pkg = getattr(self._target, "__module__", "").split(".")[0]
            if not target_pkg and hasattr(self._target, "__package__"):
                 target_pkg = self._target.__package__

            # If we can't determine package, maybe infer from self._name?
            # e.g. "pandas.read_csv" -> "pandas"
            if not target_pkg and "." in self._name:
                target_pkg = self._name.split(".")[0]

            if target_pkg and result is not None:
                # Check if result belongs to same package
                res_mod = getattr(type(result), "__module__", "")
                if res_mod and res_mod.startswith(target_pkg):
                    # Wrap it!
                    # We assume it's a class instance (like DataFrame), so we wrap it.
                    # We assume primitives (int, str) are NOT in the package module (they are builtins).
                    return Auditor(result, name=f"{full_name}()")

            return result
        return wrapper

    # --- Proxy Dunder Methods ---
    # To allow wrapped objects (like DataFrames) to be used naturally (df['col'], len(df), etc.)
    # we must proxy dunder methods.
    # Since __getattr__ is not called for dunders, we must define them explicitly.

    def __getitem__(self, key):
        return self._target[key]

    def __setitem__(self, key, value):
        self._target[key] = value

    def __len__(self):
        return len(self._target)

    def __iter__(self):
        return iter(self._target)

    def __str__(self):
        return str(self._target)

    # Arithmetic operators (forward to target)
    # Note: If target doesn't support it, this raises TypeError, which is correct.
    # We unwrap self for the operation to work if the other operand is raw?
    # Or rely on python's dispatch.

    def __add__(self, other):
        return self._target + other

    def __sub__(self, other):
        return self._target - other

    def __mul__(self, other):
        return self._target * other

    def __truediv__(self, other):
        return self._target / other

    def __floordiv__(self, other):
        return self._target // other

    # Reverse arithmetic (if other + self)
    def __radd__(self, other):
        return other + self._target

    def __rsub__(self, other):
        return other - self._target

    def __rmul__(self, other):
        return other * self._target

    def __repr__(self):
        return f"<Auditor({self._name}) wrapping {self._target}>"

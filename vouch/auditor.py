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

    def _unwrap(self, obj: Any) -> Any:
        if isinstance(obj, Auditor):
            return obj._target
        return obj

    def _wrap_result(self, result, name_hint=""):
        """Helper to deeply wrap results if they belong to tracked packages."""
        if result is None:
            return result

        target_pkg = getattr(self._target, "__module__", "").split(".")[0]
        if not target_pkg and hasattr(self._target, "__package__"):
             target_pkg = self._target.__package__

        if not target_pkg and "." in self._name:
            target_pkg = self._name.split(".")[0]

        res_mod = getattr(type(result), "__module__", "")

        # Check active session for cross-library auditing
        should_audit = False
        session = TraceSession.get_active_session()

        if session and res_mod:
            # Check if the result module is one of the tracked targets
            pkg_name = res_mod.split(".")[0]
            if session.should_audit(pkg_name):
                should_audit = True

        if should_audit or (res_mod and res_mod.startswith(target_pkg)):
            return Auditor(result, name=name_hint)

        return result

    def __getattr__(self, name: str) -> Any:
        # Pass through dunder methods or internal attributes to avoid issues
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
        return Auditor(attr, name=f"{self._name}.{name}")

    def _hash_arguments(self, func_name, args, kwargs):
        """Helper to hash file paths found in arguments."""
        extra_hashes = {}
        # Naive implementation: check arg[0] and specific kwargs
        # This covers pandas.read_csv(filepath) and df.to_csv(filepath)

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
        return extra_hashes

    def _wrap_callable(self, func: Callable, func_name: str) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Unwrap arguments if they are Auditors
            args = tuple(self._unwrap(a) for a in args)
            kwargs = {k: self._unwrap(v) for k, v in kwargs.items()}

            # --- Pre-execution Hashing (Inputs) ---
            input_hashes = {}
            if "read" in func_name or "load" in func_name:
                 input_hashes = self._hash_arguments(func_name, args, kwargs)

            # --- Execute ---
            result = func(*args, **kwargs)

            # --- Post-execution Hashing (Outputs) ---
            output_hashes = {}
            if "to_" in func_name or "save" in func_name or "dump" in func_name or "write" in func_name:
                 output_hashes = self._hash_arguments(func_name, args, kwargs)

            # Combine hashes
            extra_hashes = {**input_hashes, **output_hashes}

            # Log if a session is active
            session = TraceSession.get_active_session()
            if session:
                full_name = f"{self._name}.{func_name}"
                session.logger.log_call(full_name, args, kwargs, result, extra_hashes)

            # --- Deep Wrapping Logic ---
            return self._wrap_result(result, name_hint=f"{full_name}()")

        return wrapper

    # --- Proxy Dunder Methods ---

    def __getitem__(self, key):
        return self._wrap_result(self._target[self._unwrap(key)])

    def __setitem__(self, key, value):
        self._target[self._unwrap(key)] = self._unwrap(value)

    def __len__(self):
        return len(self._target)

    def __iter__(self):
        return iter(self._target)

    def __str__(self):
        return str(self._target)

    # Arithmetic operators
    def __add__(self, other):
        return self._wrap_result(self._target + self._unwrap(other), f"{self._name} + {other}")

    def __sub__(self, other):
        return self._wrap_result(self._target - self._unwrap(other), f"{self._name} - {other}")

    def __mul__(self, other):
        return self._wrap_result(self._target * self._unwrap(other), f"{self._name} * {other}")

    def __truediv__(self, other):
        return self._wrap_result(self._target / self._unwrap(other), f"{self._name} / {other}")

    def __floordiv__(self, other):
        return self._wrap_result(self._target // self._unwrap(other), f"{self._name} // {other}")

    # Reverse arithmetic
    def __radd__(self, other):
        return self._wrap_result(self._unwrap(other) + self._target, f"{other} + {self._name}")

    def __rsub__(self, other):
        return self._wrap_result(self._unwrap(other) - self._target, f"{other} - {self._name}")

    def __rmul__(self, other):
        return self._wrap_result(self._unwrap(other) * self._target, f"{other} * {self._name}")

    def __repr__(self):
        return f"<Auditor({self._name}) wrapping {self._target}>"

    # Matrix multiplication
    def __matmul__(self, other):
        return self._wrap_result(self._target @ self._unwrap(other), f"{self._name} @ {other}")

    def __rmatmul__(self, other):
        return self._wrap_result(self._unwrap(other) @ self._target, f"{other} @ {self._name}")

    # Power
    def __pow__(self, other):
        return self._wrap_result(self._target ** self._unwrap(other), f"{self._name} ** {other}")

    def __rpow__(self, other):
        return self._wrap_result(self._unwrap(other) ** self._target, f"{other} ** {self._name}")

    # Bitwise operators
    def __and__(self, other):
        return self._wrap_result(self._target & self._unwrap(other), f"{self._name} & {other}")

    def __rand__(self, other):
        return self._wrap_result(self._unwrap(other) & self._target, f"{other} & {self._name}")

    def __or__(self, other):
        return self._wrap_result(self._target | self._unwrap(other), f"{self._name} | {other}")

    def __ror__(self, other):
        return self._wrap_result(self._unwrap(other) | self._target, f"{other} | {self._name}")

    def __xor__(self, other):
        return self._wrap_result(self._target ^ self._unwrap(other), f"{self._name} ^ {other}")

    def __rxor__(self, other):
        return self._wrap_result(self._unwrap(other) ^ self._target, f"{other} ^ {self._name}")

    def __invert__(self):
        return self._wrap_result(~self._target, f"~{self._name}")

    # Unary operators
    def __neg__(self):
        return self._wrap_result(-self._target, f"-{self._name}")

    def __pos__(self):
        return self._wrap_result(+self._target, f"+{self._name}")

    def __abs__(self):
        return self._wrap_result(abs(self._target), f"abs({self._name})")

    # Comparison
    def __eq__(self, other):
        return self._wrap_result(self._target == self._unwrap(other), f"{self._name} == {other}")

    def __ne__(self, other):
        return self._wrap_result(self._target != self._unwrap(other), f"{self._name} != {other}")

    def __lt__(self, other):
        return self._wrap_result(self._target < self._unwrap(other), f"{self._name} < {other}")

    def __le__(self, other):
        return self._wrap_result(self._target <= self._unwrap(other), f"{self._name} <= {other}")

    def __gt__(self, other):
        return self._wrap_result(self._target > self._unwrap(other), f"{self._name} > {other}")

    def __ge__(self, other):
        return self._wrap_result(self._target >= self._unwrap(other), f"{self._name} >= {other}")

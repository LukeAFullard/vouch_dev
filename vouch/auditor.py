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

            # --- Pre-execution Hashing (Inputs) ---
            # Capture inputs before execution (in case they change or are read)
            # Typically for read_*, the file must exist before.
            input_hashes = {}
            if "read" in func_name or "load" in func_name:
                 input_hashes = self._hash_arguments(func_name, args, kwargs)

            # --- Execute ---
            result = func(*args, **kwargs)

            # --- Post-execution Hashing (Outputs) ---
            # Capture outputs after execution (file created)
            # Typically for to_*, save_*, dump_*.
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
            target_pkg = getattr(self._target, "__module__", "").split(".")[0]
            if not target_pkg and hasattr(self._target, "__package__"):
                 target_pkg = self._target.__package__

            if not target_pkg and "." in self._name:
                target_pkg = self._name.split(".")[0]

            if target_pkg and result is not None:
                res_mod = getattr(type(result), "__module__", "")
                if res_mod and res_mod.startswith(target_pkg):
                    return Auditor(result, name=f"{full_name}()")

            return result
        return wrapper

    # --- Proxy Dunder Methods ---

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

    # Arithmetic operators
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

    # Reverse arithmetic
    def __radd__(self, other):
        return other + self._target

    def __rsub__(self, other):
        return other - self._target

    def __rmul__(self, other):
        return other * self._target

    def __repr__(self):
        return f"<Auditor({self._name}) wrapping {self._target}>"

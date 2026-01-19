import functools
import os
import logging
import inspect
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
        # Prevent nested wrapping
        if isinstance(target, Auditor):
            self._target = target._target
            # If name is not provided, inherit from existing wrapper?
            # Or keep new name? Usually outer name is more relevant or same.
            if name is None:
                self._name = target._name
            else:
                self._name = name
        else:
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

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__.update(state)

    def _unwrap(self, obj: Any) -> Any:
        if isinstance(obj, Auditor):
            return obj._target
        return obj

    def _wrap_result(self, result, name_hint=""):
        """Helper to deeply wrap results if they belong to tracked packages."""
        if result is None:
            return result

        # Optimization: If the result is the target itself (chaining), return self.
        # This preserves wrapper identity.
        if result is self._target:
            return self

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

        # If it's a class/type, do NOT wrap it.
        # Wrapping classes breaks pickling (identity check fails) and strict isinstance checks.
        # This means constructor calls (e.g. pd.DataFrame()) are not intercepted,
        # but the resulting objects are compatible with pickle and type checks.
        if isinstance(attr, type):
            return attr

        # If it's a callable (and not a class), wrap it
        if callable(attr):
            return self._wrap_callable(attr, name)

        # Recursively wrap attributes that are part of the library (heuristic)
        # Use _wrap_result logic to avoid wrapping primitives/builtins
        return self._wrap_result(attr, name_hint=f"{self._name}.{name}")

    def __call__(self, *args, **kwargs):
        """
        Support calling the wrapped object (e.g. for class constructors or functors).
        """
        func = self._target
        func_name = self._name

        # Reuse wrap_callable logic inline
        args = tuple(self._unwrap(a) for a in args)
        kwargs = {k: self._unwrap(v) for k, v in kwargs.items()}

        # Inputs hashing
        input_hashes = {}
        if "read" in func_name or "load" in func_name:
             input_hashes = self._hash_arguments(func_name, args, kwargs)

        result = func(*args, **kwargs)

        # Outputs hashing
        output_hashes = {}
        if "to_" in func_name or "save" in func_name or "dump" in func_name or "write" in func_name:
             output_hashes = self._hash_arguments(func_name, args, kwargs)

        extra_hashes = {**input_hashes, **output_hashes}

        session = TraceSession.get_active_session()
        if session:
            # If it's a class constructor, log it as such
            if isinstance(self._target, type):
                 full_name = f"{self._name}.__init__" # Approximate
            else:
                 full_name = f"{self._name}"

            session.logger.log_call(full_name, args, kwargs, result, extra_hashes)

        # Handle Async Coroutines
        if inspect.iscoroutine(result):
            return self._wrap_coroutine(result, f"{self._name}()")

        # Handle Generators
        if inspect.isgenerator(result):
            return self._wrap_generator(result, f"{self._name}()")

        return self._wrap_result(result, name_hint=f"{self._name}()")

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
            try:
                if "read" in func_name or "load" in func_name:
                     input_hashes = self._hash_arguments(func_name, args, kwargs)
            except Exception:
                pass # Don't fail audit if hashing fails

            full_name = f"{self._name}.{func_name}"
            session = TraceSession.get_active_session()

            # --- Execute ---
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                # Log exception
                if session:
                    session.logger.log_call(full_name, args, kwargs, None, extra_hashes=input_hashes, error=e)
                raise

            # --- Post-execution Hashing (Outputs) ---
            output_hashes = {}
            try:
                if "to_" in func_name or "save" in func_name or "dump" in func_name or "write" in func_name:
                     output_hashes = self._hash_arguments(func_name, args, kwargs)
            except Exception:
                pass

            # Combine hashes
            extra_hashes = {**input_hashes, **output_hashes}

            # Log success
            if session:
                session.logger.log_call(full_name, args, kwargs, result, extra_hashes)

            # --- Deep Wrapping Logic ---
            # Handle Async Coroutines
            if inspect.iscoroutine(result):
                return self._wrap_coroutine(result, full_name, args, kwargs)

            # Handle Generators
            if inspect.isgenerator(result):
                return self._wrap_generator(result, full_name, args, kwargs)

            return self._wrap_result(result, name_hint=f"{full_name}()")

        return wrapper

    async def _wrap_coroutine(self, coro, name_hint, args, kwargs):
        """Wrapper for async functions (coroutines)."""
        session = TraceSession.get_active_session()
        try:
            result = await coro
            # We could log success here too, but it might be noisy.
            # Ideally we link it to original call.
            return self._wrap_result(result, name_hint=f"{name_hint} (async)")
        except Exception as e:
            if session:
                session.logger.log_call(f"{name_hint} (async)", args, kwargs, None, error=e)
            raise

    def _wrap_generator(self, gen, name_hint, args, kwargs):
        """Wrapper for generators."""
        session = TraceSession.get_active_session()
        try:
            for item in gen:
                yield self._wrap_result(item, name_hint=f"{name_hint} (yield)")
        except Exception as e:
            if session:
                session.logger.log_call(f"{name_hint} (generator)", args, kwargs, None, error=e)
            raise

    # --- Proxy Dunder Methods ---

    def __getitem__(self, key):
        return self._wrap_result(self._target[self._unwrap(key)])

    def __setitem__(self, key, value):
        key = self._unwrap(key)
        value = self._unwrap(value)
        session = TraceSession.get_active_session()
        try:
            self._target[key] = value
            if session:
                # Log the modification
                session.logger.log_call(f"{self._name}.__setitem__", [key, value], {}, None)
        except Exception as e:
            if session:
                session.logger.log_call(f"{self._name}.__setitem__", [key, value], {}, None, error=e)
            raise

    def __delitem__(self, key):
        key = self._unwrap(key)
        session = TraceSession.get_active_session()
        try:
            del self._target[key]
            if session:
                session.logger.log_call(f"{self._name}.__delitem__", [key], {}, None)
        except Exception as e:
            if session:
                session.logger.log_call(f"{self._name}.__delitem__", [key], {}, None, error=e)
            raise

    def __len__(self):
        return len(self._target)

    def __iter__(self):
        return iter(self._target)

    def __bool__(self):
        return bool(self._target)

    def __enter__(self):
        return self._wrap_result(self._target.__enter__(), f"{self._name}.__enter__")

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._target.__exit__(exc_type, exc_val, exc_tb)

    def __await__(self):
        return self._target.__await__()

    def __aiter__(self):
        return self._wrap_result(self._target.__aiter__(), f"{self._name}.__aiter__")

    async def __anext__(self):
        return self._wrap_result(await self._target.__anext__(), f"{self._name}.__anext__")

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

    def __hash__(self):
        return hash(self._target)

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

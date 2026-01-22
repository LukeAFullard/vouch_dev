import functools
import os
import logging
import inspect
import operator
from typing import Any, Optional, Callable
from .hasher import Hasher

logger = logging.getLogger(__name__)

# Cache for dynamic class wrappers to ensure identity preservation
_class_proxy_cache = {}

class AuditorMixin:
    """
    Shared auditing logic and helpers.
    """
    _name = "Unknown"
    _target = None

    def __init__(self, *args, **kwargs):
        # Consume arguments to prevent them reaching object.__init__
        # This fixes MRO issues where wrapped classes pass args up the chain.
        super().__init__()

    def _unwrap(self, obj: Any) -> Any:
        if isinstance(obj, AuditorMixin):
            return obj._target
        return obj

    def _should_hash_inputs(self, func_name: str) -> bool:
        if "read" in func_name or "load" in func_name: return True

        from .session import TraceSession
        session = TraceSession.get_active_session()
        if session and session.custom_input_triggers:
            for trigger in session.custom_input_triggers:
                if trigger in func_name: return True
        return False

    def _should_hash_outputs(self, func_name: str) -> bool:
        if "to_" in func_name or "save" in func_name or "dump" in func_name or "write" in func_name: return True

        from .session import TraceSession
        session = TraceSession.get_active_session()
        if session and session.custom_output_triggers:
            for trigger in session.custom_output_triggers:
                if trigger in func_name: return True
        return False

    def _wrap_result(self, result, name_hint=""):
        """Helper to deeply wrap results if they belong to tracked packages."""
        if result is None:
            return result

        # Optimization: If the result is the target itself (chaining), return self.
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

        from .session import TraceSession
        session = TraceSession.get_active_session()

        if session and res_mod:
            # Check if the result module is one of the tracked targets
            pkg_name = res_mod.split(".")[0]
            if session.should_audit(pkg_name):
                should_audit = True

        if should_audit or (res_mod and res_mod.startswith(target_pkg)):
            return Auditor(result, name=name_hint)

        return result

    def _hash_arguments(self, func_name, args, kwargs):
        """Helper to hash file paths found in arguments."""
        extra_hashes = {}
        # Naive implementation: check arg[0] and specific kwargs

        if args and isinstance(args[0], str) and os.path.exists(args[0]):
            try:
                file_hash = Hasher.hash_file(args[0])
                extra_hashes["arg_0_file_hash"] = file_hash
                extra_hashes["arg_0_path"] = args[0]
            except (IOError, OSError) as e:
                from .session import TraceSession
                session = TraceSession.get_active_session()
                if session and session.strict:
                     raise
                logger.warning(f"Failed to hash file {args[0]}: {e}")
            except Exception as e:
                from .session import TraceSession
                session = TraceSession.get_active_session()
                if session and session.strict:
                     raise
                logger.error(f"Unexpected error hashing {args[0]}: {e}")

        for key, val in kwargs.items():
                if key in ["filepath", "path", "filename", "io", "filepath_or_buffer"] and isinstance(val, str) and os.path.exists(val):
                    try:
                        file_hash = Hasher.hash_file(val)
                        extra_hashes[f"kwarg_{key}_file_hash"] = file_hash
                        extra_hashes[f"kwarg_{key}_path"] = val
                    except (IOError, OSError) as e:
                        from .session import TraceSession
                        session = TraceSession.get_active_session()
                        if session and session.strict:
                            raise
                        logger.warning(f"Failed to hash file {val}: {e}")
                    except Exception as e:
                        from .session import TraceSession
                        session = TraceSession.get_active_session()
                        if session and session.strict:
                            raise
                        logger.error(f"Unexpected error hashing {val}: {e}")
        return extra_hashes

    def _wrap_callable(self, func: Callable, func_name: str) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            args = tuple(self._unwrap(a) for a in args)
            kwargs = {k: self._unwrap(v) for k, v in kwargs.items()}

            input_hashes = {}
            try:
                if self._should_hash_inputs(func_name):
                     input_hashes = self._hash_arguments(func_name, args, kwargs)
            except Exception:
                from .session import TraceSession
                session = TraceSession.get_active_session()
                if session and session.strict:
                    raise
                pass

            full_name = f"{self._name}.{func_name}"

            from .session import TraceSession
            session = TraceSession.get_active_session()

            try:
                result = func(*args, **kwargs)
            except Exception as e:
                if session:
                    session.logger.log_call(full_name, args, kwargs, None, extra_hashes=input_hashes, error=e)
                raise

            output_hashes = {}
            try:
                if self._should_hash_outputs(func_name):
                     output_hashes = self._hash_arguments(func_name, args, kwargs)
            except Exception:
                from .session import TraceSession
                session = TraceSession.get_active_session()
                if session and session.strict:
                    raise
                pass

            extra_hashes = {**input_hashes, **output_hashes}

            if inspect.iscoroutine(result):
                if session:
                    session.logger.log_call(full_name, args, kwargs, "<coroutine>", extra_hashes)
                return self._wrap_coroutine(result, full_name, args, kwargs)

            if inspect.isgenerator(result):
                if session:
                    session.logger.log_call(full_name, args, kwargs, "<generator>", extra_hashes)
                return self._wrap_generator(result, full_name, args, kwargs)

            if session:
                session.logger.log_call(full_name, args, kwargs, result, extra_hashes)

            return self._wrap_result(result, name_hint=f"{full_name}()")

        return wrapper

    async def _wrap_coroutine(self, coro, name_hint, args, kwargs):
        from .session import TraceSession
        session = TraceSession.get_active_session()
        try:
            result = await coro
            return self._wrap_result(result, name_hint=f"{name_hint} (async)")
        except Exception as e:
            if session:
                session.logger.log_call(f"{name_hint} (async)", args, kwargs, None, error=e)
            raise

    def _wrap_generator(self, gen, name_hint, args, kwargs):
        from .session import TraceSession
        session = TraceSession.get_active_session()
        try:
            for item in gen:
                yield self._wrap_result(item, name_hint=f"{name_hint} (yield)")
        except Exception as e:
            if session:
                session.logger.log_call(f"{name_hint} (generator)", args, kwargs, None, error=e)
            raise

    def _apply_inplace(self, op, op_name, other):
        other_val = self._unwrap(other)
        from .session import TraceSession
        session = TraceSession.get_active_session()

        try:
            res = op(self._target, other_val)
        except Exception as e:
            if session:
                session.logger.log_call(f"{self._name}.{op_name}", [other], {}, None, error=e)
            raise

        if res is self._target:
             if session:
                 session.logger.log_call(f"{self._name}.{op_name}", [other], {}, None)
             return self

        return self._wrap_result(res, f"{self._name} {op_name} {other}")

    def _create_class_proxy(self, target_cls):
        """
        Creates a dynamic subclass of target_cls that mixes in Auditor functionality.
        This allows objects created via the constructor to be audited while failing isinstance checks.
        """
        if target_cls in _class_proxy_cache:
            return _class_proxy_cache[target_cls]

        # Define the wrapper class
        # It inherits from target_cls (for isinstance) and AuditorMixin (for functionality)
        # Note: We do NOT inherit from Auditor to avoid __init__ MRO conflict
        class AuditedWrapper(target_cls, AuditorMixin):
            def __init__(self, *args, **kwargs):
                # Setup Auditor state
                object.__setattr__(self, "_target", self)
                object.__setattr__(self, "_name", f"{target_cls.__name__}(...)")

                # Call original init
                try:
                    target_cls.__init__(self, *args, **kwargs)
                except TypeError as e:
                    # Sometimes wrapper classes confuse MRO or __init__ logic.
                    # Fallback or re-raise
                    raise TypeError(f"Failed to initialize wrapped class {target_cls.__name__}: {e}") from e

            def __setattr__(self, name, value):
                if name in ("_target", "_name"):
                    object.__setattr__(self, name, value)
                    return

                if hasattr(target_cls, "__setattr__"):
                    target_cls.__setattr__(self, name, value)
                else:
                    object.__setattr__(self, name, value)

            def __getattribute__(self, name):
                if name.startswith("_") or name in (
                    "match", "search",
                    "_target", "_name", "_unwrap", "_wrap_result",
                    "_should_hash_inputs", "_should_hash_outputs", "_hash_arguments",
                    "_wrap_callable", "_wrap_coroutine", "_wrap_generator", "_apply_inplace",
                    "_create_class_proxy"
                ):
                    return object.__getattribute__(self, name)

                val = super().__getattribute__(name)

                if callable(val):
                    # Special handling for pandas indexers which are callable but mainly used via __getitem__
                    if name in ("iloc", "loc", "at", "iat"):
                        return val
                    return self._wrap_callable(val, name)

                # We return non-callables unwrapped to prevent breaking internal library logic (isinstance checks).
                # This means attributes (like df.columns) are not audited, but methods (df.mean()) are.
                return val

            def __getattr__(self, name):
                if hasattr(target_cls, "__getattr__"):
                    val = target_cls.__getattr__(self, name)
                    if callable(val):
                        return self._wrap_callable(val, name)
                    return val

                raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

            def __repr__(self):
                # Ensure we don't recurse if target_cls.__repr__ uses something we hook
                # Usually safely delegating to super() is fine
                return super().__repr__()

            # Note: We are missing operator overloads here.
            # Without them, operators will use target_cls implementation (unwrapped).
            # This is a limitation, but constructor audit is the main goal.
            # We could generate them dynamically here if needed.

        # Set metadata
        AuditedWrapper.__name__ = f"Audited{target_cls.__name__}"
        AuditedWrapper.__module__ = target_cls.__module__

        _class_proxy_cache[target_cls] = AuditedWrapper
        return AuditedWrapper


class Auditor(AuditorMixin):
    """
    A wrapper proxy that intercepts attribute access and function calls for auditing.
    """
    def __init__(self, target: Any, name: Optional[str] = None):
        if isinstance(target, Auditor):
            self._target = target._target
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

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return getattr(self._target, name)

        attr = getattr(self._target, name)

        if isinstance(attr, type):
            # Only wrap main data structures to avoid MRO issues with internal classes like Index
            if attr.__name__ in ("DataFrame", "Series"):
                return self._create_class_proxy(attr)
            return attr

        if callable(attr):
            return self._wrap_callable(attr, name)

        return self._wrap_result(attr, name_hint=f"{self._name}.{name}")

    def __call__(self, *args, **kwargs):
        func = self._target
        func_name = self._name

        args = tuple(self._unwrap(a) for a in args)
        kwargs = {k: self._unwrap(v) for k, v in kwargs.items()}

        input_hashes = {}
        if self._should_hash_inputs(func_name):
             input_hashes = self._hash_arguments(func_name, args, kwargs)

        result = func(*args, **kwargs)

        output_hashes = {}
        if self._should_hash_outputs(func_name):
             output_hashes = self._hash_arguments(func_name, args, kwargs)

        extra_hashes = {**input_hashes, **output_hashes}

        from .session import TraceSession
        session = TraceSession.get_active_session()
        if session:
            if isinstance(self._target, type):
                 full_name = f"{self._name}.__init__"
            else:
                 full_name = f"{self._name}"

            if inspect.iscoroutine(result):
                log_result = "<coroutine>"
            elif inspect.isgenerator(result):
                log_result = "<generator>"
            else:
                log_result = result
            session.logger.log_call(full_name, args, kwargs, log_result, extra_hashes)

        if inspect.iscoroutine(result):
            return self._wrap_coroutine(result, f"{self._name}()", args, kwargs) # Pass args for error logging

        if inspect.isgenerator(result):
            return self._wrap_generator(result, f"{self._name}()", args, kwargs)

        return self._wrap_result(result, name_hint=f"{self._name}()")

    # --- Proxy Dunder Methods ---

    def __getitem__(self, key):
        return self._wrap_result(self._target[self._unwrap(key)])

    def __setitem__(self, key, value):
        key = self._unwrap(key)
        value = self._unwrap(value)

        from .session import TraceSession
        session = TraceSession.get_active_session()
        try:
            self._target[key] = value
            if session:
                session.logger.log_call(f"{self._name}.__setitem__", [key, value], {}, None)
        except Exception as e:
            if session:
                session.logger.log_call(f"{self._name}.__setitem__", [key, value], {}, None, error=e)
            raise

    def __delitem__(self, key):
        key = self._unwrap(key)

        from .session import TraceSession
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

    def __add__(self, other):
        return self._wrap_result(self._target + self._unwrap(other), f"{self._name} + {other}")

    def __iadd__(self, other):
        return self._apply_inplace(operator.iadd, "__iadd__", other)

    def __sub__(self, other):
        return self._wrap_result(self._target - self._unwrap(other), f"{self._name} - {other}")

    def __isub__(self, other):
        return self._apply_inplace(operator.isub, "__isub__", other)

    def __mul__(self, other):
        return self._wrap_result(self._target * self._unwrap(other), f"{self._name} * {other}")

    def __imul__(self, other):
        return self._apply_inplace(operator.imul, "__imul__", other)

    def __truediv__(self, other):
        return self._wrap_result(self._target / self._unwrap(other), f"{self._name} / {other}")

    def __itruediv__(self, other):
        return self._apply_inplace(operator.itruediv, "__itruediv__", other)

    def __floordiv__(self, other):
        return self._wrap_result(self._target // self._unwrap(other), f"{self._name} // {other}")

    def __ifloordiv__(self, other):
        return self._apply_inplace(operator.ifloordiv, "__ifloordiv__", other)

    def __mod__(self, other):
        return self._wrap_result(self._target % self._unwrap(other), f"{self._name} % {other}")

    def __imod__(self, other):
        return self._apply_inplace(operator.imod, "__imod__", other)

    def __radd__(self, other):
        return self._wrap_result(self._unwrap(other) + self._target, f"{other} + {self._name}")

    def __rsub__(self, other):
        return self._wrap_result(self._unwrap(other) - self._target, f"{other} - {self._name}")

    def __rmul__(self, other):
        return self._wrap_result(self._unwrap(other) * self._target, f"{other} * {self._name}")

    def __repr__(self):
        return f"<Auditor({self._name}) wrapping {self._target}>"

    def __matmul__(self, other):
        return self._wrap_result(self._target @ self._unwrap(other), f"{self._name} @ {other}")

    def __imatmul__(self, other):
        return self._apply_inplace(operator.imatmul, "__imatmul__", other)

    def __rmatmul__(self, other):
        return self._wrap_result(self._unwrap(other) @ self._target, f"{other} @ {self._name}")

    def __pow__(self, other):
        return self._wrap_result(self._target ** self._unwrap(other), f"{self._name} ** {other}")

    def __ipow__(self, other):
        return self._apply_inplace(operator.ipow, "__ipow__", other)

    def __rpow__(self, other):
        return self._wrap_result(self._unwrap(other) ** self._target, f"{other} ** {self._name}")

    def __and__(self, other):
        return self._wrap_result(self._target & self._unwrap(other), f"{self._name} & {other}")

    def __iand__(self, other):
        return self._apply_inplace(operator.iand, "__iand__", other)

    def __rand__(self, other):
        return self._wrap_result(self._unwrap(other) & self._target, f"{other} & {self._name}")

    def __or__(self, other):
        return self._wrap_result(self._target | self._unwrap(other), f"{self._name} | {other}")

    def __ior__(self, other):
        return self._apply_inplace(operator.ior, "__ior__", other)

    def __ror__(self, other):
        return self._wrap_result(self._unwrap(other) | self._target, f"{other} | {self._name}")

    def __xor__(self, other):
        return self._wrap_result(self._target ^ self._unwrap(other), f"{self._name} ^ {other}")

    def __ixor__(self, other):
        return self._apply_inplace(operator.ixor, "__ixor__", other)

    def __rxor__(self, other):
        return self._wrap_result(self._unwrap(other) ^ self._target, f"{other} ^ {self._name}")

    def __lshift__(self, other):
        return self._wrap_result(self._target << self._unwrap(other), f"{self._name} << {other}")

    def __ilshift__(self, other):
        return self._apply_inplace(operator.ilshift, "__ilshift__", other)

    def __rshift__(self, other):
        return self._wrap_result(self._target >> self._unwrap(other), f"{self._name} >> {other}")

    def __irshift__(self, other):
        return self._apply_inplace(operator.irshift, "__irshift__", other)

    def __invert__(self):
        return self._wrap_result(~self._target, f"~{self._name}")

    def __neg__(self):
        return self._wrap_result(-self._target, f"-{self._name}")

    def __pos__(self):
        return self._wrap_result(+self._target, f"+{self._name}")

    def __abs__(self):
        return self._wrap_result(abs(self._target), f"abs({self._name})")

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

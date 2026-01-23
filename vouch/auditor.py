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

    def __init__(self, *args, **kwargs) -> None:
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
                # Avoid recursion for internal lookups
                if name.startswith("_") or name in (
                    "match", "search",
                    "_target", "_name", "_unwrap", "_wrap_result",
                    "_should_hash_inputs", "_should_hash_outputs", "_hash_arguments",
                    "_wrap_callable", "_wrap_coroutine", "_wrap_generator", "_apply_inplace",
                    "_create_class_proxy"
                ):
                    return object.__getattribute__(self, name)

                # Delegate to super class (MRO)
                val = super().__getattribute__(name)

                if callable(val):
                    # Special handling for pandas indexers which are callable but mainly used via __getitem__
                    if name in ("iloc", "loc", "at", "iat"):
                        # Wrap it so we audit __getitem__
                        wrapper_res = object.__getattribute__(self, "_wrap_result")
                        return wrapper_res(val, name_hint=f"{self._name}.{name}")

                    # Wrap callable using self._wrap_callable
                    # self._wrap_callable is inherited from AuditorMixin
                    wrapper_func = object.__getattribute__(self, "_wrap_callable")
                    return wrapper_func(val, name)

                return val

            def __repr__(self):
                # Ensure we don't recurse if target_cls.__repr__ uses something we hook
                # Usually safely delegating to super() is fine
                return super().__repr__()

        # --- Dynamic Operator Overloading ---
        # We inject operator methods into AuditedWrapper to ensure operations like
        # df + 1 are intercepted and logged.

        def make_operator(op_name, is_inplace=False):
            def wrapper(self, *args):
                from .session import TraceSession
                session = TraceSession.get_active_session()

                # Unwrap args
                unwrapped_args = tuple(self._unwrap(a) for a in args)

                try:
                    # Resolve method via MRO to ensure we get the correct implementation
                    # We start search from target_cls (skipping self/AuditedWrapper)

                    func = None
                    # Use target_cls.mro() which includes target_cls and its bases
                    for cls in target_cls.mro():
                        if op_name in cls.__dict__:
                            func = cls.__dict__[op_name]
                            break

                    if func is None:
                         # Fallback to object (common for __eq__, __ne__) if not in MRO of target_cls
                         # (though target_cls MRO usually ends in object)
                         func = getattr(object, op_name, None)

                    if func is None:
                        return NotImplemented

                    # Invoke the function
                    if hasattr(func, '__get__'):
                         # Bind to self if descriptor
                         bound_method = func.__get__(self, target_cls)
                         res = bound_method(*unwrapped_args)
                    else:
                         res = func(self, *unwrapped_args)

                except Exception as e:
                    if session:
                        session.logger.log_call(f"{self._name}.{op_name}", args, {}, None, error=e)
                    raise

                if session:
                    # Capture result representation logic
                    log_res = res
                    if is_inplace:
                        log_res = None # Avoid logging huge object if it's just self

                    session.logger.log_call(f"{self._name}.{op_name}", args, {}, log_res)

                if is_inplace:
                    return self

                # Log result
                desc = f"{self._name} {op_name} {args}"
                # Ensure we use AuditorMixin._wrap_result bound to self
                if hasattr(self, "_wrap_result"):
                     return self._wrap_result(res, name_hint=desc)
                return res
            return wrapper

        ops = [
            '__add__', '__sub__', '__mul__', '__truediv__', '__floordiv__', '__mod__',
            '__pow__', '__lshift__', '__rshift__', '__and__', '__xor__', '__or__',
            '__matmul__',
            '__radd__', '__rsub__', '__rmul__', '__rtruediv__', '__rfloordiv__', '__rmod__',
            '__rpow__', '__rlshift__', '__rrshift__', '__rand__', '__rxor__', '__ror__',
            '__rmatmul__',
            '__iadd__', '__isub__', '__imul__', '__itruediv__', '__ifloordiv__', '__imod__',
            '__ipow__', '__ilshift__', '__irshift__', '__iand__', '__ixor__', '__ior__',
            '__imatmul__',
            '__neg__', '__pos__', '__abs__', '__invert__',
            '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__',
            # Container ops
            '__getitem__', '__setitem__', '__delitem__', '__len__', '__iter__'
        ]

        for op in ops:
            # Only wrap if the target class actually supports it (or object does)
            # This prevents adding __len__ to things that don't support it, etc.
            # However, for arithmetic operators, it's safer to add them if we want to support duck typing,
            # but checking for existence in MRO is safer to avoid confusing python.

            should_wrap = False
            for cls in target_cls.mro():
                if op in cls.__dict__:
                    should_wrap = True
                    break

            if should_wrap:
                 is_inplace = op.startswith("__i")
                 setattr(AuditedWrapper, op, make_operator(op, is_inplace=is_inplace))

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

        # Sanity check
        if self._target is self:
             # This should be impossible in __init__ as self is new.
             # Unless object.__new__ returned existing object? (Singleton?)
             # Auditor inherits from object.
             raise ValueError(f"Auditor target cannot be self. Target: {target}, Self: {self}")

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_target", "_name"):
            # if name == "_target" and value is self:
            #     raise RuntimeError("Attempting to set _target to self")
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
        # Prevent recursion if _target is missing
        if name == "_target":
            raise AttributeError("_target not initialized")

        # Safely access _target
        try:
            target = object.__getattribute__(self, "_target")
        except AttributeError:
             raise AttributeError("_target not initialized")

        # Recursion Guard: If target is literally self, we are doomed
        if target is self:
             raise RuntimeError(f"Auditor _target is self (Infinite Recursion). ID: {id(self)}")

        # Double check for loop
        if isinstance(target, Auditor) and target._target is self:
             raise RuntimeError("Auditor loop detected (A->B->A)")

        if name.startswith("_"):
            return getattr(target, name)

        try:
            # If target is an Auditor itself (which shouldn't happen but checking), unwrap it
            if isinstance(target, Auditor):
                 target = target._target

            # Use object.__getattribute__ where possible to reduce recursion risk
            attr = getattr(target, name)
        except AttributeError:
            # Re-raise to avoid endless loops if attributes are missing
            raise
        except RecursionError:
             # If we hit recursion error during getattr, abort
             raise AttributeError(f"RecursionError accessing {name}")

        if isinstance(attr, type):
            # Check configured audit classes
            from .session import TraceSession
            session = TraceSession.get_active_session()
            if session and session.should_audit_class(attr.__name__):
                return self._create_class_proxy(attr)

            # Fallback: Wrap as Auditor (generic proxy)
            # This preserves attribute access (like classmethods) which _wrap_callable destroys.
            # We explicitly check for session to avoid wrapping everything if auditing is off (though Importer controls that).
            if session:
                return Auditor(attr, name=f"{self._name}.{name}")
            return attr

        if callable(attr):
            if name in ("iloc", "loc", "at", "iat"):
                 return self._wrap_result(attr, name_hint=f"{self._name}.{name}")
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

    def __str__(self):
        # Use object.__getattribute__ to avoid recursion via __getattr__
        target = object.__getattribute__(self, "_target")
        return str(target)

    def __repr__(self):
        return f"<Auditor({self._name}) wrapping {self._target}>"

    def __hash__(self):
        return hash(self._target)

    def __bool__(self):
        return bool(self._target)

    # Note: We must implement basic lifecycle methods manually or via generator
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

    # --- Dynamic Operator Generation ---
    # We dynamically generate operator methods to ensure consistent logging
    # and behavior across all proxied operations.

    def _make_operator(op_name, is_inplace=False, is_reverse=False, is_unary=False):
        def wrapper(self, *args):
            from .session import TraceSession
            session = TraceSession.get_active_session()

            unwrapped_args = tuple(self._unwrap(a) for a in args)

            # Resolve the operator function
            if hasattr(operator, op_name):
                 op_func = getattr(operator, op_name)
            elif hasattr(self._target, op_name):
                 # Fallback for things like __rshift__ if operator module doesn't match perfectly or for custom ops
                 # Actually operator module maps nicely to dunders usually.
                 # But let's rely on standard dunder invocation via getattr for non-operator module cases?
                 # Better: just use getattr on target if not in operator?
                 # No, 'operator.add(a, b)' is cleaner than 'a.__add__(b)'
                 pass

            # Manual mapping for some dunders to operator functions
            op_map = {
                '__add__': operator.add, '__sub__': operator.sub, '__mul__': operator.mul,
                '__truediv__': operator.truediv, '__floordiv__': operator.floordiv, '__mod__': operator.mod,
                '__pow__': operator.pow, '__lshift__': operator.lshift, '__rshift__': operator.rshift,
                '__and__': operator.and_, '__xor__': operator.xor, '__or__': operator.or_,
                '__matmul__': operator.matmul,
                '__iadd__': operator.iadd, '__isub__': operator.isub, '__imul__': operator.imul,
                '__itruediv__': operator.itruediv, '__ifloordiv__': operator.ifloordiv, '__imod__': operator.imod,
                '__ipow__': operator.ipow, '__ilshift__': operator.ilshift, '__irshift__': operator.irshift,
                '__iand__': operator.iand, '__ixor__': operator.ixor, '__ior__': operator.ior,
                '__imatmul__': operator.imatmul,
                '__lt__': operator.lt, '__le__': operator.le, '__eq__': operator.eq,
                '__ne__': operator.ne, '__gt__': operator.gt, '__ge__': operator.ge,
                '__neg__': operator.neg, '__pos__': operator.pos, '__abs__': operator.abs, '__invert__': operator.invert,
                '__getitem__': operator.getitem, '__setitem__': operator.setitem, '__delitem__': operator.delitem
            }

            try:
                if op_name in op_map:
                    if is_reverse:
                        # For r-ops, we swap: self is 'other' in the original expression
                        # But wait, python calls __radd__(self, other).
                        # Meaning 'other + self'.
                        # So we want operator.add(other, self._target)
                        res = op_map[op_name.replace('__r', '__')](unwrapped_args[0], self._target)
                    else:
                        res = op_map[op_name](self._target, *unwrapped_args)
                else:
                    # Fallback to direct method call
                    func = getattr(self._target, op_name)
                    res = func(*unwrapped_args)

            except Exception as e:
                if session:
                    session.logger.log_call(f"{self._name}.{op_name}", args, {}, None, error=e)
                raise

            if session:
                log_res = res
                if is_inplace:
                    log_res = None
                session.logger.log_call(f"{self._name}.{op_name}", args, {}, log_res)

            return self._wrap_result(res, f"{self._name} {op_name} {args}")
        return wrapper

    # Apply operators
    _ops_list = [
        # Arithmetic
        ('__add__', False, False, False), ('__sub__', False, False, False), ('__mul__', False, False, False),
        ('__truediv__', False, False, False), ('__floordiv__', False, False, False), ('__mod__', False, False, False),
        ('__pow__', False, False, False),
        # Bitwise
        ('__lshift__', False, False, False), ('__rshift__', False, False, False),
        ('__and__', False, False, False), ('__xor__', False, False, False), ('__or__', False, False, False),
        ('__matmul__', False, False, False),
        # Reverse Arithmetic
        ('__radd__', False, True, False), ('__rsub__', False, True, False), ('__rmul__', False, True, False),
        ('__rtruediv__', False, True, False), ('__rfloordiv__', False, True, False), ('__rmod__', False, True, False),
        ('__rpow__', False, True, False),
        # Reverse Bitwise
        ('__rlshift__', False, True, False), ('__rrshift__', False, True, False),
        ('__rand__', False, True, False), ('__rxor__', False, True, False), ('__ror__', False, True, False),
        ('__rmatmul__', False, True, False),
        # Inplace
        ('__iadd__', True, False, False), ('__isub__', True, False, False), ('__imul__', True, False, False),
        ('__itruediv__', True, False, False), ('__ifloordiv__', True, False, False), ('__imod__', True, False, False),
        ('__ipow__', True, False, False), ('__ilshift__', True, False, False), ('__irshift__', True, False, False),
        ('__iand__', True, False, False), ('__ixor__', True, False, False), ('__ior__', True, False, False),
        ('__imatmul__', True, False, False),
        # Unary
        ('__neg__', False, False, True), ('__pos__', False, False, True), ('__abs__', False, False, True), ('__invert__', False, False, True),
        # Comparison
        ('__lt__', False, False, False), ('__le__', False, False, False), ('__eq__', False, False, False),
        ('__ne__', False, False, False), ('__gt__', False, False, False), ('__ge__', False, False, False),
        # Container
        ('__getitem__', False, False, False), ('__setitem__', False, False, False), ('__delitem__', False, False, False),
        ('__len__', False, False, False), ('__iter__', False, False, False)
    ]

    for op_name, is_inplace, is_reverse, is_unary in _ops_list:
        locals()[op_name] = _make_operator(op_name, is_inplace, is_reverse, is_unary)

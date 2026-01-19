import functools
import os
from .session import TraceSession
from .hasher import Hasher

class Auditor:
    """
    A wrapper proxy that intercepts attribute access and function calls.
    """
    def __init__(self, target, name=None):
        self._target = target
        self._name = name or getattr(target, "__name__", str(target))

    def __setattr__(self, name, value):
        if name in ("_target", "_name"):
            super().__setattr__(name, value)
        else:
            setattr(self._target, name, value)

    def __delattr__(self, name):
        if name in ("_target", "_name"):
            super().__delattr__(name)
        else:
            delattr(self._target, name)

    def __getattr__(self, name):
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

        return Auditor(attr, name=f"{self._name}.{name}")

    def _wrap_callable(self, func, func_name):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Execute the actual function
            result = func(*args, **kwargs)

            # Log if a session is active
            session = TraceSession.get_active_session()
            if session:
                full_name = f"{self._name}.{func_name}"

                # Check for file I/O (naive implementation for read_*)
                extra_hashes = {}
                if "read" in func_name or "load" in func_name:
                    # Check first positional arg
                    if args and isinstance(args[0], str) and os.path.exists(args[0]):
                        try:
                            file_hash = Hasher.hash_file(args[0])
                            extra_hashes["arg_0_file_hash"] = file_hash
                            extra_hashes["arg_0_path"] = args[0]
                        except Exception:
                            pass

                    # Check common kwargs for file paths
                    # specific to pandas.read_csv(filepath_or_buffer=...) or generic
                    for key, val in kwargs.items():
                         if key in ["filepath", "path", "filename", "io", "filepath_or_buffer"] and isinstance(val, str) and os.path.exists(val):
                             try:
                                file_hash = Hasher.hash_file(val)
                                extra_hashes[f"kwarg_{key}_file_hash"] = file_hash
                                extra_hashes[f"kwarg_{key}_path"] = val
                             except Exception:
                                pass

                session.logger.log_call(full_name, args, kwargs, result, extra_hashes)

            return result
        return wrapper

    def __repr__(self):
        return f"<Auditor({self._name}) wrapping {self._target}>"

__version__ = "0.1.0"

import datetime
from functools import wraps
from contextlib import contextmanager

from .auditor import Auditor
from .session import TraceSession
from .importer import auto_audit
from .verifier import Verifier

@contextmanager
def audit(filename=None, targets=None, **kwargs):
    """
    High-level context manager for simplified auditing.
    Wraps standard libraries (pandas, numpy) and handles session creation.

    Args:
        filename: Output .vouch file path. If None, generates 'audit_YYYYMMDD_HHMMSS.vch'.
        targets: List of module names to auto-wrap (default: pandas, numpy).
        **kwargs: Arguments passed to TraceSession (e.g. strict, seed).
    """
    if filename is None:
        filename = datetime.datetime.now().strftime("audit_%Y%m%d_%H%M%S.vch")

    with TraceSession(filename, **kwargs) as sess:
        with auto_audit(targets=targets):
            yield sess

@contextmanager
def start(filename=None, targets=None, **kwargs):
    """
    Start a Vouch audit session. This is the simplest entry point.

    It automatically:
    1. Generates a temporary identity if you don't have one.
    2. Wraps common data libraries (pandas, numpy).
    3. Records your workflow to the specified file.

    Args:
        filename: Output .vouch file path. If None, generates 'audit_YYYYMMDD_HHMMSS.vch'.
        targets: List of module names to auto-wrap (default: pandas, numpy).
        **kwargs: Arguments passed to TraceSession.
    """
    with audit(filename, targets, **kwargs) as sess:
        yield sess

# Aliases for easier use
capture = start
vouch = start

def record(filename=None, targets=None, **kwargs):
    """
    Decorator to record the execution of a function.

    Usage:
        @vouch.record
        def main(): ...

        @vouch.record(filename="my_audit.vch")
        def main(): ...
    """
    def decorator(func):
        import inspect
        if inspect.iscoroutinefunction(func):
            @wraps(func)
            async def wrapper(*args, **kw):
                with start(filename, targets, **kwargs):
                    return await func(*args, **kw)
        else:
            @wraps(func)
            def wrapper(*args, **kw):
                with start(filename, targets, **kwargs):
                    return func(*args, **kw)
        return wrapper

    if callable(filename):
        # Called as @record without arguments
        func = filename
        filename = None
        return decorator(func)
    else:
        # Called as @record(...)
        return decorator

def verify(filepath: str, strict: bool = False, **kwargs) -> bool:
    """
    Verify a Vouch audit package.

    Args:
        filepath: Path to .vch file.
        strict: Fail if timestamp verification fails.
        **kwargs: Additional arguments for Verifier (e.g. data_file, auto_data).

    Returns:
        bool: True if valid.
    """
    verifier = Verifier(filepath)
    return verifier.verify(strict=strict, **kwargs)

__all__ = ["Auditor", "TraceSession", "auto_audit", "audit", "start", "capture", "vouch", "record", "verify"]

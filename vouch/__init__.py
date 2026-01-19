__version__ = "0.1.0"

from .auditor import Auditor
from .session import TraceSession
from .importer import auto_audit
from contextlib import contextmanager

@contextmanager
def audit(filename, targets=None, **kwargs):
    """
    High-level context manager for simplified auditing.
    Wraps standard libraries (pandas, numpy) and handles session creation.

    Args:
        filename: Output .vouch file path.
        targets: List of module names to auto-wrap (default: pandas, numpy).
        **kwargs: Arguments passed to TraceSession (e.g. strict, seed).
    """
    with TraceSession(filename, **kwargs) as sess:
        with auto_audit(targets=targets):
            yield sess

__all__ = ["Auditor", "TraceSession", "auto_audit", "audit"]

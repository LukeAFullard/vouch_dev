import re
import copy
from typing import Any, Union, List, Dict, Tuple

class PIIDetector:
    """
    Scans and sanitizes Personal Identifiable Information (PII) from data.
    """

    # Regex Patterns
    PATTERNS = {
        "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "IP_ADDRESS": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        "US_SSN": r'\b\d{3}-\d{2}-\d{4}\b',
        # Basic Credit Card (13-16 digits, with optional dashes/spaces)
        "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b'
    }

    def __init__(self):
        self._compiled_patterns = {
            name: re.compile(pattern) for name, pattern in self.PATTERNS.items()
        }

    def _sanitize_string(self, text: str) -> str:
        """
        Replaces PII in a string with <PII: TYPE>.
        """
        for name, pattern in self._compiled_patterns.items():
            # Special check for Credit Card to avoid false positives on simple numbers
            # (e.g. timestamps or IDs). For now, we use the regex as is but
            # rigorous implementations might use Luhn check.
            # We skip Luhn for simplicity and speed in this regex pass.

            # Use a lambda to count replacements or just sub
            text = pattern.sub(f"<PII: {name}>", text)
        return text

    def sanitize(self, obj: Any, memo: Dict[int, Any] = None) -> Any:
        """
        Recursively sanitizes PII from the object.
        Returns a new object (copy) if modification is needed,
        or the original if immutable and safe.
        """
        if memo is None:
            memo = {}

        obj_id = id(obj)
        if obj_id in memo:
            return memo[obj_id]

        if isinstance(obj, str):
            res = self._sanitize_string(obj)
            memo[obj_id] = res
            return res

        if isinstance(obj, (list, tuple, set)):
            # Handle sequences
            # For lists, we can store placeholder to handle cycles
            if isinstance(obj, list):
                res = []
                memo[obj_id] = res
                for item in obj:
                    res.append(self.sanitize(item, memo))
                return res

            # For tuples/sets, immutable, so cycle means infinite recursion usually
            # unless we detect early. But we can't build partial tuple.
            # So standard recursion limit applies, or we check if we are visiting.
            # Python's repr cycle detection uses visited IDs.
            # If we see it again, we can return a placeholder string.

            # Simple check: if already processing this ID but not finished (not in memo),
            # it is a cycle for immutable types that rely on construction.
            # Actually standard python doesn't allow tuple to contain itself directly without mutable intermediary.
            # So recursion usually goes through list/dict.

            res_list = [self.sanitize(item, memo) for item in obj]
            if isinstance(obj, tuple):
                res = tuple(res_list)
                memo[obj_id] = res
                return res
            if isinstance(obj, set):
                # Sets are unordered, so just sanitize items
                res = set(res_list)
                memo[obj_id] = res
                return res

        if isinstance(obj, dict):
            res = {}
            memo[obj_id] = res
            for key, value in obj.items():
                res[self.sanitize(key, memo)] = self.sanitize(value, memo)
            return res

        # Primitives pass through
        if isinstance(obj, (int, float, bool, type(None))):
            return obj

        # For custom objects, we can't safely modify them or deepcopy easily without issues.
        # We rely on their __repr__ or __str__.
        # Strategy: Return a string representation that IS sanitized.
        # This changes the type of the object in the args list from Object -> String.
        # This is acceptable for AUDIT LOGGING (we want safe representation),
        # but might affect HASHING if the hasher expects the object structure.
        # However, Logger.log_call calculates hash AFTER sanitization.
        # So the hash will be of the string string representation.
        # This effectively treats custom objects as their string representation for audit purposes.
        try:
            # We use str() as it's often more human readable, but repr() might be needed for details.
            # Let's try repr first as it's standard for logging.
            text_repr = repr(obj)
            return self._sanitize_string(text_repr)
        except Exception:
            return "<PII: UNABLE_TO_SANITIZE_OBJECT>"

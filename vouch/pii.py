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

    def sanitize(self, obj: Any) -> Any:
        """
        Recursively sanitizes PII from the object.
        Returns a new object (copy) if modification is needed,
        or the original if immutable and safe.
        """
        if isinstance(obj, str):
            return self._sanitize_string(obj)

        if isinstance(obj, (list, tuple, set)):
            # Handle sequences
            # Note: tuples/sets are immutable, so we must recreate them if content changes
            sanitized_items = [self.sanitize(item) for item in obj]

            if isinstance(obj, tuple):
                return tuple(sanitized_items)
            if isinstance(obj, set):
                return set(sanitized_items)
            return sanitized_items # list

        if isinstance(obj, dict):
            # Handle dictionaries
            return {
                self.sanitize(key): self.sanitize(value)
                for key, value in obj.items()
            }

        # For other objects (int, float, custom classes), return as is
        # We generally don't scan attributes of arbitrary classes to avoid
        # breaking logic or infinite recursion, relying on Logger's repr/hash
        # for them. But if __repr__ returns a string with PII, Logger handles
        # repr separately.
        # If the object ITSELF is PII (e.g. a custom EmailAddress object),
        # this detector won't catch it unless it's converted to string first.
        # But this method is called on args/kwargs before hashing.

        return obj

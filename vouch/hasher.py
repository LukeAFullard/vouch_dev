# Fix hasher.py to use lineterminator instead of line_terminator for pandas >= 1.5
import hashlib
import json
import os
import logging
from typing import Any

logger = logging.getLogger(__name__)

class Hasher:
    _registry = {}

    @classmethod
    def register(cls, type_obj, func):
        """Register a custom hash function for a specific type."""
        cls._registry[type_obj] = func

    @staticmethod
    def hash_file(filepath: str) -> str:
        """Hash a file using SHA-256."""
        if not os.path.exists(filepath):
            return "N/A"
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def hash_object(obj: Any) -> str:
        """Determine a deterministic hash for a Python object."""
        try:
            # 0. Check custom registry
            for type_obj, func in Hasher._registry.items():
                if isinstance(obj, type_obj):
                    return func(obj)

            # 1. Check protocol
            if hasattr(obj, "__vouch_hash__"):
                return obj.__vouch_hash__()

            # Special handling for pandas/numpy
            if hasattr(obj, "to_csv"):
                # Try new argument name first (pandas >= 1.5)
                try:
                    csv_str = obj.to_csv(index=True, float_format='%.17g', lineterminator='\n')
                except TypeError:
                    # Fallback for older pandas
                    csv_str = obj.to_csv(index=True, float_format='%.17g', line_terminator='\n')
                return hashlib.sha256(csv_str.encode('utf-8')).hexdigest()

            if hasattr(obj, "tobytes"):
                # NumPy arrays
                return hashlib.sha256(obj.tobytes()).hexdigest()

            if isinstance(obj, dict):
                try:
                    s = json.dumps(obj, sort_keys=True, default=str)
                    return hashlib.sha256(s.encode('utf-8')).hexdigest()
                except Exception:
                    # Fallback if json fails (e.g. keys are not strings)
                    # We create a sorted representation manually
                    # Sort by string representation of keys
                    items = []
                    for k in sorted(obj.keys(), key=str):
                        items.append(f"{repr(k)}: {repr(obj[k])}")
                    s = "{" + ", ".join(items) + "}"
                    return hashlib.sha256(s.encode('utf-8')).hexdigest()

            # Default: String representation or Pickle?
            # String repr is safer but less precise. Pickle can change across versions.
            s = str(obj)
            # Check for memory addresses in default repr (e.g., <object at 0x7f...>)
            if " at 0x" in s and ">" in s:
                 logger.warning(f"Unstable hash for {type(obj)}: Default repr contains memory address. Use light_mode or register a custom hasher.")

            hasher = hashlib.sha256()
            hasher.update(s.encode('utf-8'))
            return hasher.hexdigest()
        except Exception as e:
            logger.warning(f"Hashing failed for object type {type(obj)}: {e}")
            return "HASH_FAILED"

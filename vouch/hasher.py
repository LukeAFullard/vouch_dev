# Fix hasher.py to use lineterminator instead of line_terminator for pandas >= 1.5
import hashlib
import json
import os
import logging
from typing import Any

logger = logging.getLogger(__name__)

class Hasher:
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

            # Default: String representation or Pickle?
            # String repr is safer but less precise. Pickle can change across versions.
            hasher = hashlib.sha256()
            hasher.update(str(obj).encode('utf-8'))
            return hasher.hexdigest()
        except Exception as e:
            logger.warning(f"Hashing failed for object type {type(obj)}: {e}")
            return "HASH_FAILED"

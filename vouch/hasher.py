import hashlib
import json
import logging

try:
    import pandas as pd
    import numpy as np
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

class Hasher:
    """
    Handles hashing of various object types for the Vouch audit log.
    """

    @staticmethod
    def hash_object(obj):
        """
        Returns a SHA-256 hash of the object.
        """
        hasher = hashlib.sha256()

        if obj is None:
            hasher.update(b'None')
        elif isinstance(obj, (bool, int, float, str)):
            hasher.update(str(obj).encode('utf-8'))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                hasher.update(Hasher.hash_object(item).encode('utf-8'))
        elif isinstance(obj, dict):
            # Sort keys to ensure deterministic ordering
            for key in sorted(obj.keys()):
                hasher.update(str(key).encode('utf-8'))
                hasher.update(Hasher.hash_object(obj[key]).encode('utf-8'))
        elif HAS_PANDAS and isinstance(obj, (pd.DataFrame, pd.Series)):
             # "Smart Hashing" for pandas - using utility function or simple serialization for now
             # A more robust implementation might hash the underlying numpy array
             try:
                 # pandas.util.hash_pandas_object returns a series of hashes, one per row/index
                 # We sum them or hash the concatenation to get a single hash
                 # This is stable across some versions
                 row_hashes = pd.util.hash_pandas_object(obj, index=True)
                 hasher.update(row_hashes.values.tobytes())
             except Exception:
                 try:
                     # Fallback 1: Hash underlying values directly (if numpy backed)
                     hasher.update(obj.values.tobytes())
                 except Exception:
                     try:
                         # Fallback 2: JSON serialization (catches all data, avoids truncation)
                         # Use default_handler=str to handle non-serializable objects reasonably
                         json_str = obj.to_json(default_handler=str, date_format='iso')
                         hasher.update(json_str.encode('utf-8'))
                     except Exception:
                        # Final Fallback to string representation
                        hasher.update(str(obj).encode('utf-8'))
        elif HAS_PANDAS and isinstance(obj, np.ndarray):
            # Hash the raw bytes of the array
            # Ensure it's contiguous
            if not obj.flags['C_CONTIGUOUS']:
                obj = np.ascontiguousarray(obj)
            hasher.update(obj.tobytes())
        else:
            # Fallback for other objects
            hasher.update(str(obj).encode('utf-8'))

        return hasher.hexdigest()

    @staticmethod
    def hash_file(filepath):
        """
        Hashes a file on disk.
        """
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return None

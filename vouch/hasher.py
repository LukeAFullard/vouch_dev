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
             try:
                 # Deterministic CSV serialization
                 # float_format='%.17g' ensures full precision for floats
                 csv_str = obj.to_csv(index=True, float_format='%.17g', line_terminator='\n')
                 hasher.update(csv_str.encode('utf-8'))
             except Exception:
                 # Fallback to string representation
                 hasher.update(str(obj).encode('utf-8'))
        elif HAS_PANDAS and isinstance(obj, np.ndarray):
            # Hash the raw bytes of the array
            if obj.nbytes > 100 * 1024 * 1024:  # >100MB
                # Chunk it to avoid OOM
                # Calculate chunk size based on row size to target ~100MB per chunk
                if obj.shape[0] > 0:
                    row_bytes = obj.nbytes // obj.shape[0]
                    # Avoid division by zero if row_bytes is somehow 0 (e.g. empty dim in other axis?)
                    if row_bytes > 0:
                        chunk_size = max(1, (100 * 1024 * 1024) // row_bytes)
                    else:
                        chunk_size = 1000000 # Default fallback

                    for i in range(0, obj.shape[0], chunk_size):
                        chunk = obj[i:i+chunk_size]
                        if not chunk.flags['C_CONTIGUOUS']:
                            chunk = np.ascontiguousarray(chunk)
                        hasher.update(chunk.tobytes())
                else:
                    hasher.update(obj.tobytes())
            else:
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

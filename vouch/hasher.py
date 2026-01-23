# Fix hasher.py to use lineterminator instead of line_terminator for pandas >= 1.5
import hashlib
import json
import os
import logging
from typing import Any

logger = logging.getLogger(__name__)

class HashWriter:
    """Adapter to stream write operations to a hasher."""
    def __init__(self, hasher):
        self.hasher = hasher

    def write(self, data):
        if isinstance(data, str):
            self.hasher.update(data.encode('utf-8'))
        elif isinstance(data, bytes):
            self.hasher.update(data)

    def flush(self):
        pass

class StableJSONEncoder(json.JSONEncoder):
    """
    A custom JSON Encoder that handles unstable objects and cycles
    to ensure deterministic hashing.
    """
    def __init__(self, *args, **kwargs):
        self.raise_error = kwargs.pop("raise_error", False)
        super().__init__(*args, **kwargs)
        self._visited_ids = set()

    def default(self, obj):
        # Cycle detection for objects processed via default
        if id(obj) in self._visited_ids:
             return f"<Cycle: {type(obj).__name__}>"
        self._visited_ids.add(id(obj))

        try:
            # 1. Custom protocol
            if hasattr(obj, "__vouch_hash__"):
                 return obj.__vouch_hash__()

            # 2. Pandas / Numpy (delegate to Hasher logic)
            # Hasher.hash_object handles these and returns a hash string.
            # We return that hash string so it gets embedded in the JSON.
            if hasattr(obj, "to_csv") or hasattr(obj, "tobytes"):
                return Hasher.hash_object(obj)

            # 3. Unstable Repr
            s = str(obj)
            if " at 0x" in s and ">" in s:
                 # Try to use __dict__ (state) instead of identity
                 if hasattr(obj, "__dict__"):
                     # Return a copy to avoid json's circular reference detection
                     # if the __dict__ is being traversed (e.g. recursive object)
                     try:
                        return dict(obj.__dict__)
                     except (TypeError, ValueError):
                        # Fallback if __dict__ is not iterable
                        return str(obj.__dict__)

                 # Try to use __slots__
                 if hasattr(obj, "__slots__"):
                     try:
                         data = {}
                         for slot in obj.__slots__:
                             if hasattr(obj, slot):
                                 data[slot] = getattr(obj, slot)
                         return data
                     except Exception:
                         pass

                 msg = f"Unstable hash for {type(obj)}: Default repr contains memory address. Use light_mode or register a custom hasher."
                 if self.raise_error:
                      raise ValueError(msg)

                 return f"<Unstable: {type(obj).__name__}>"

            return s
        except Exception as e:
            if self.raise_error:
                raise e
            # Fallback for anything that fails
            return f"<Serialization Error: {type(obj).__name__}>"

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
    def hash_object(obj: Any, raise_error: bool = False) -> str:
        """Determine a deterministic hash for a Python object."""
        try:
            # 0. Check custom registry
            for type_obj, func in Hasher._registry.items():
                if isinstance(obj, type_obj):
                    return func(obj)

            # 1. Check protocol
            if hasattr(obj, "__vouch_hash__"):
                res = obj.__vouch_hash__()
                if isinstance(res, str):
                    return res
                # If it returns a state (dict/list), hash that state
                return Hasher.hash_object(res, raise_error=raise_error)

            # Special handling for pandas/numpy
            if hasattr(obj, "to_csv"):
                sha256 = hashlib.sha256()
                writer = HashWriter(sha256)
                # Try new argument name first (pandas >= 1.5)
                try:
                    obj.to_csv(writer, index=True, float_format='%.17g', lineterminator='\n')
                except TypeError as e:
                    # Fallback for older pandas only if argument is the issue
                    if "unexpected keyword argument" in str(e) and "lineterminator" in str(e):
                        obj.to_csv(writer, index=True, float_format='%.17g', line_terminator='\n')
                    else:
                        raise
                return sha256.hexdigest()

            if hasattr(obj, "tobytes"):
                # NumPy arrays
                return hashlib.sha256(obj.tobytes()).hexdigest()

            if isinstance(obj, dict):
                try:
                    sha256 = hashlib.sha256()
                    writer = HashWriter(sha256)
                    # Use StableJSONEncoder instead of default=str
                    # check_circular=False because StableJSONEncoder handles cycles for objects it processes,
                    # and standard container cycles will be caught by RecursionError (handled below).
                    json.dump(obj, writer, sort_keys=True, cls=StableJSONEncoder, check_circular=False, raise_error=raise_error)
                    return sha256.hexdigest()
                except Exception as e:
                    # Fallback if json fails (e.g. keys are not strings)
                    # We create a sorted representation manually
                    # Sort by string representation of keys
                    try:
                        items = []
                        for k in sorted(obj.keys(), key=str):
                            items.append(f"{repr(k)}: {repr(obj[k])}")
                        s = "{" + ", ".join(items) + "}"
                        return hashlib.sha256(s.encode('utf-8')).hexdigest()
                    except Exception:
                        if raise_error: raise e
                        return "HASH_FAILED_DICT"

            # Default: String representation or Pickle?
            # String repr is safer but less precise. Pickle can change across versions.
            s = str(obj)
            # Check for memory addresses in default repr (e.g., <object at 0x7f...>)
            if " at 0x" in s and ">" in s:
                 # Try to use __dict__ (state) instead of identity
                 if hasattr(obj, "__dict__"):
                     try:
                         # Recursively hash the dict
                         return Hasher.hash_object(obj.__dict__, raise_error=raise_error)
                     except Exception:
                         pass # Fallback to warning

                 # Try to use __slots__
                 if hasattr(obj, "__slots__"):
                     try:
                         data = {}
                         for slot in obj.__slots__:
                             if hasattr(obj, slot):
                                 data[slot] = getattr(obj, slot)
                         return Hasher.hash_object(data, raise_error=raise_error)
                     except Exception:
                         pass

                 msg = f"Unstable hash for {type(obj)}: Default repr contains memory address. Use light_mode or register a custom hasher."
                 if raise_error:
                     raise ValueError(msg)
                 logger.warning(msg)

                 # Return a stable string placeholder instead of the unstable repr
                 s = f"<Unstable: {type(obj).__name__}>"

            hasher = hashlib.sha256()
            hasher.update(s.encode('utf-8'))
            return hasher.hexdigest()
        except Exception as e:
            if isinstance(e, ValueError) and raise_error:
                raise
            logger.warning(f"Hashing failed for object type {type(obj)}: {e}")
            return "HASH_FAILED"

import time
import json
import datetime
from .hasher import Hasher

class Logger:
    def __init__(self):
        self.log = []
        self.sequence_number = 0
        self.previous_entry_hash = "0" * 64

    def log_call(self, target_name, args, kwargs, result, extra_hashes=None, error=None):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Hash arguments and result
        args_hash = Hasher.hash_object(args)
        kwargs_hash = Hasher.hash_object(kwargs)
        if error:
            result_hash = "ERROR"
        else:
            result_hash = Hasher.hash_object(result)

        # Create a readable representation for simple types
        # For complex types, we might just store type info
        def safe_repr(obj):
            if hasattr(obj, 'shape'): # pandas/numpy
                 return f"<{type(obj).__name__} shape={obj.shape}>"
            try:
                s = repr(obj)
                if len(s) > 1000:
                    return s[:1000] + "..."
                return s
            except:
                return f"<{type(obj).__name__}>"

        self.sequence_number += 1

        entry = {
            "timestamp": timestamp,
            "sequence_number": self.sequence_number,
            "previous_entry_hash": self.previous_entry_hash,
            "action": "call",
            "target": target_name,
            "args_repr": [safe_repr(a) for a in args],
            "kwargs_repr": {k: safe_repr(v) for k, v in kwargs.items()},
            "result_repr": safe_repr(result) if not error else "ERROR",
            "args_hash": args_hash,
            "kwargs_hash": kwargs_hash,
            "result_hash": result_hash
        }

        if error:
            entry["error"] = str(error)
            entry["error_type"] = type(error).__name__

        if extra_hashes:
            entry["extra_hashes"] = extra_hashes

        self.log.append(entry)
        self.previous_entry_hash = Hasher.hash_object(entry)

    def to_json(self):
        return json.dumps(self.log, indent=2)

    def save(self, filepath):
        with open(filepath, 'w') as f:
            json.dump(self.log, f, indent=2)

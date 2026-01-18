import time
import json
import datetime
from .hasher import Hasher

class Logger:
    def __init__(self):
        self.log = []

    def log_call(self, target_name, args, kwargs, result, extra_hashes=None):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Hash arguments and result
        args_hash = Hasher.hash_object(args)
        kwargs_hash = Hasher.hash_object(kwargs)
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

        entry = {
            "timestamp": timestamp,
            "action": "call",
            "target": target_name,
            "args_repr": [safe_repr(a) for a in args],
            "kwargs_repr": {k: safe_repr(v) for k, v in kwargs.items()},
            "result_repr": safe_repr(result),
            "args_hash": args_hash,
            "kwargs_hash": kwargs_hash,
            "result_hash": result_hash
        }

        if extra_hashes:
            entry["extra_hashes"] = extra_hashes

        self.log.append(entry)

    def to_json(self):
        return json.dumps(self.log, indent=2)

    def save(self, filepath):
        with open(filepath, 'w') as f:
            json.dump(self.log, f, indent=2)

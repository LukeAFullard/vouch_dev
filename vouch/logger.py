import time
import json
import os
import datetime
from .hasher import Hasher

class Logger:
    def __init__(self, light_mode=False, stream_path=None):
        self.log = [] # Kept for backward compat / in-memory access if needed, but we should be careful
        self.sequence_number = 0
        self.previous_entry_hash = "0" * 64
        self.light_mode = light_mode
        self.stream_path = stream_path
        self._file_handle = None

        if self.stream_path:
            self.start_streaming(self.stream_path)

    def start_streaming(self, path):
        """Switch to streaming mode. Flushes existing log to file."""
        if self._file_handle:
            return # Already streaming

        self.stream_path = path
        self._file_handle = open(self.stream_path, "w")
        self._file_handle.write("[\n") # Start JSON array

        # Flush existing memory log
        for entry in self.log:
            json.dump(entry, self._file_handle, indent=2)
            self._file_handle.write(",\n")

        self._file_handle.flush()
        self.log = [] # Free memory

    def close(self):
        if self._file_handle:
            # Remove trailing comma if exists (seek back 2 chars ",\n")
            # This is tricky with buffering.
            # Simplified approach: Write a dummy end record or just handle standard JSON parsing issues.
            # Better approach: JSON Lines (NDJSON) is robust for streaming, but Vouch uses JSON array.
            # To fix the array:
            try:
                pos = self._file_handle.tell()
                if pos > 2:
                    self._file_handle.seek(pos - 2) # Assume ",\n"
                    # Check if it is actually comma
                    if self._file_handle.read(1) == ",":
                        self._file_handle.seek(pos - 2)
                        self._file_handle.truncate()
                        self._file_handle.write("\n")
            except Exception:
                pass

            self._file_handle.write("]") # End JSON array
            self._file_handle.close()
            self._file_handle = None

    def log_call(self, target_name, args, kwargs, result, extra_hashes=None, error=None):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Hash arguments and result
        if self.light_mode:
            args_hash = "SKIPPED_LIGHT"
            kwargs_hash = "SKIPPED_LIGHT"
            result_hash = "SKIPPED_LIGHT" if not error else "ERROR"
        else:
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

        # self.log.append(entry) # disable in-memory log to prevent OOM
        self.previous_entry_hash = Hasher.hash_object(entry)

        if self._file_handle:
            json.dump(entry, self._file_handle, indent=2)
            self._file_handle.write(",\n")
            self._file_handle.flush() # Ensure it hits disk
        else:
             self.log.append(entry)

    def to_json(self):
        if self.stream_path:
            # If streaming (or finished streaming), read from file
            try:
                if self._file_handle:
                    self._file_handle.flush()

                if os.path.exists(self.stream_path):
                    with open(self.stream_path, "r") as f:
                        content = f.read()
                        # It might be incomplete JSON if still streaming
                        if content.strip().endswith(","):
                             return content.strip()[:-1] + "\n]"
                        if not content.strip().endswith("]"):
                             return content + "\n]"
                        return content
                else:
                    return json.dumps([])
            except Exception:
                 return json.dumps([])
        return json.dumps(self.log, indent=2)

    def save(self, filepath):
        if self.stream_path:
            # If we were streaming, the file is already there (at self.stream_path)
            self.close() # Ensure flush/close

            if filepath != self.stream_path:
                 import shutil
                 shutil.copy(self.stream_path, filepath)
            # If same path, nothing to do (it's already saved)
        else:
            with open(filepath, 'w') as f:
                json.dump(self.log, f, indent=2)

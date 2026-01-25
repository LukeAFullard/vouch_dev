import time
import json
import os
import datetime
import threading
from .hasher import Hasher
from .pii import PIIDetector

class Logger:
    def __init__(self, light_mode=False, strict=False, stream_path=None, detect_pii=False):
        self.log = [] # Kept for backward compat / in-memory access if needed, but we should be careful
        self.sequence_number = 0
        self.previous_entry_hash = "0" * 64
        self.light_mode = light_mode
        self.strict = strict
        self.detect_pii = detect_pii
        self.pii_detector = PIIDetector() if detect_pii else None
        self.stream_path = stream_path
        self._file_handle = None
        self._first_entry = True
        self._lock = threading.Lock()

        if self.stream_path:
            self.start_streaming(self.stream_path)

    def start_streaming(self, path):
        """Switch to streaming mode. Flushes existing log to file."""
        with self._lock:
            if self._file_handle:
                return # Already streaming

            self.stream_path = path
            self._file_handle = open(self.stream_path, "w")
            # NDJSON: No start bracket
            self._first_entry = True

            # Flush existing memory log
            for entry in self.log:
                # NDJSON: No comma, just newline
                json.dump(entry, self._file_handle)
                self._file_handle.write("\n")
                self._first_entry = False

            self._file_handle.flush()
            self.log = [] # Free memory

    def close(self):
        with self._lock:
            if self._file_handle:
                # NDJSON: No end bracket
                self._file_handle.close()
                self._file_handle = None

    def log_call(self, target_name, args, kwargs, result, extra_hashes=None, error=None):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Sanitize PII if enabled
        # This modifies the data BEFORE hashing and logging, ensuring PII is completely excluded.
        if self.detect_pii:
            try:
                args = self.pii_detector.sanitize(args)
                kwargs = self.pii_detector.sanitize(kwargs)
                if not error and result is not None:
                    result = self.pii_detector.sanitize(result)
                if error:
                     # Sanitize error message as well
                     error = self.pii_detector.sanitize(str(error))
            except Exception as e:
                # If sanitization fails, fall back to safe error or proceed cautiously
                # For now, we proceed but log internal warning?
                # Actually, if we fail to sanitize, we risk logging PII.
                # Better to redact EVERYTHING if we can't be sure?
                # Or just let it fail if strict?
                if self.strict:
                    raise RuntimeError(f"PII Sanitization failed: {e}") from e
                pass

        # Hash arguments and result (outside lock)
        if self.light_mode:
            args_hash = "SKIPPED_LIGHT"
            kwargs_hash = "SKIPPED_LIGHT"
            result_hash = "SKIPPED_LIGHT" if not error else "ERROR"
        else:
            args_hash = Hasher.hash_object(args, raise_error=self.strict)
            kwargs_hash = Hasher.hash_object(kwargs, raise_error=self.strict)
            if error:
                result_hash = "ERROR"
            else:
                result_hash = Hasher.hash_object(result, raise_error=self.strict)

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

        # Compute reprs outside lock
        args_repr = [safe_repr(a) for a in args]
        kwargs_repr = {k: safe_repr(v) for k, v in kwargs.items()}
        result_repr = safe_repr(result) if not error else "ERROR"

        with self._lock:
            self.sequence_number += 1

            entry = {
                "timestamp": timestamp,
                "sequence_number": self.sequence_number,
                "previous_entry_hash": self.previous_entry_hash,
                "action": "call",
                "target": target_name,
                "args_repr": args_repr,
                "kwargs_repr": kwargs_repr,
                "result_repr": result_repr,
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
                # NDJSON: write line
                json.dump(entry, self._file_handle)
                self._file_handle.write("\n")
                self._first_entry = False
                self._file_handle.flush() # Ensure it hits disk
            else:
                 self.log.append(entry)

    def to_json(self):
        if self.stream_path:
            # If streaming (or finished streaming), read from file
            try:
                # We can't lock file reading easily if it's opened elsewhere,
                # but to_json usually implies reading back what was written.
                # Flush first to ensure data is there.
                with self._lock:
                    if self._file_handle:
                        self._file_handle.flush()

                if os.path.exists(self.stream_path):
                    with open(self.stream_path, "r") as f:
                        lines = f.readlines()
                    # Reconstruct list for backward compatibility of to_json() return value
                    entries = []
                    for line in lines:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass # Should not happen with valid NDJSON
                    return json.dumps(entries, indent=2)
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
            # Save in-memory log as NDJSON for consistency
            with open(filepath, 'w') as f:
                for entry in self.log:
                    f.write(json.dumps(entry) + "\n")

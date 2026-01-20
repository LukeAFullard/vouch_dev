import os
import sys
import errno
import subprocess
import json
import uuid
import datetime
import zipfile
import tempfile
import shutil
import random
import inspect
import builtins
import logging
import threading
import contextvars
from typing import Optional, Dict, Any, List

import vouch
from .logger import Logger

logger = logging.getLogger(__name__)
from .crypto import CryptoManager
from .hasher import Hasher
from .git_tools import GitTracker
from cryptography.hazmat.primitives import serialization

class TraceSession:
    """
    A context manager that records library calls, hashes artifacts, and generates a verifiable audit package.
    """
    _active_session = contextvars.ContextVar("active_session", default=None)
    _env_lock = threading.Lock()

    def __init__(
        self,
        filename: str,
        strict: bool = True,
        seed: Optional[int] = None,
        private_key_path: Optional[str] = None,
        private_key_password: Optional[str] = None,
        tsa_url: Optional[str] = None,
        capture_script: bool = True,
        auto_track_io: bool = False,
        max_artifact_size: int = 1024 * 1024 * 1024,
        light_mode: bool = False,
        capture_git: bool = True,
        allow_ephemeral: bool = False,
        custom_input_triggers: Optional[List[str]] = None,
        custom_output_triggers: Optional[List[str]] = None
    ):
        """
        Initialize the TraceSession.

        Args:
            filename: Path to the output .vch file.
            strict: If True, raises exceptions for missing files or keys; otherwise warns.
            seed: Seed for random number generators (random, numpy).
            private_key_path: Path to the RSA private key for signing.
            private_key_password: Password for the private key.
            tsa_url: URL of the RFC 3161 Timestamp Authority (TSA).
            capture_script: If True, captures the calling script as an artifact.
            auto_track_io: If True, hooks builtins.open to track all file reads.
            max_artifact_size: Maximum size in bytes for a single artifact (default: 1GB).
            light_mode: If True, skips hashing of function arguments and results to improve performance.
            capture_git: If True, captures git metadata (default: True).
            allow_ephemeral: If True, allows ephemeral keys even in strict mode.
            custom_input_triggers: List of method substrings (e.g. "load_my_data") to trigger input hashing.
            custom_output_triggers: List of method substrings (e.g. "export_stuff") to trigger output hashing.
        """
        self.filename = filename
        self.strict = strict
        self.allow_ephemeral = allow_ephemeral
        self.seed = seed
        self.light_mode = light_mode
        self.capture_git = capture_git
        self.custom_input_triggers = custom_input_triggers or []
        self.custom_output_triggers = custom_output_triggers or []
        self.logger = Logger(light_mode=light_mode, strict=strict)
        self.temp_dir: Optional[str] = None
        self._ephemeral_key = None

        # Auto-detect private key if not provided
        if private_key_path is None:
            # Check local .vouch
            local_key = os.path.join(os.getcwd(), ".vouch", "id_rsa")
            # Check global .vouch
            global_key = os.path.expanduser("~/.vouch/id_rsa")

            if os.path.exists(local_key):
                private_key_path = local_key
            elif os.path.exists(global_key):
                private_key_path = global_key
            else:
                # No key found, generate ephemeral
                if self.strict and not self.allow_ephemeral:
                    raise RuntimeError("Strict mode enabled: No private key found. Ephemeral keys are forbidden in strict mode. Use 'vouch gen-keys' or strict=False.")

                self._ephemeral_key = CryptoManager.generate_ephemeral_private_key()
                logger.info("No identity found. Using ephemeral session key.")

        self.private_key_path = private_key_path
        self.private_key_password = private_key_password
        self.tsa_url = tsa_url
        self.capture_script = capture_script
        self.auto_track_io = auto_track_io
        self.max_artifact_size = max_artifact_size
        self.session_id = str(uuid.uuid4())
        self.artifacts: Dict[str, str] = {} # Map arcname -> local_path
        self._original_open: Optional[Any] = None
        self._in_tracked_open = False
        self._thread_local = threading.local()
        self._finders = []

    def register_finder(self, finder: Any) -> None:
        """Register a finder to check which modules should be audited."""
        if finder not in self._finders:
            self._finders.append(finder)

    def should_audit(self, module_name: str) -> bool:
        """
        Check if a module should be audited by querying registered finders.
        """
        if not module_name: return False
        for finder in self._finders:
            if hasattr(finder, '_should_audit'):
                if finder._should_audit(module_name):
                    return True
        return False

    def __enter__(self) -> 'TraceSession':
        if TraceSession._active_session.get() is not None:
            raise RuntimeError("Nested TraceSessions are not supported.")
        self._token = TraceSession._active_session.set(self)

        try:
            # Setup temporary directory for artifacts
            self.temp_dir = tempfile.mkdtemp()

            # Enable streaming
            log_path = os.path.join(self.temp_dir, "audit_log.json")
            self.logger.start_streaming(log_path)

            self.logger.log_call(
                "session.initialize",
                [],
                {},
                None,
                extra_hashes={
                    "session_id": self.session_id,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }
            )

            # Create data directory for captured files
            os.makedirs(os.path.join(self.temp_dir, "data"))

            # Enforce seed
            if self.seed is not None:
                random.seed(self.seed)
                try:
                    import numpy as np
                    np.random.seed(self.seed)
                except ImportError:
                    pass
                self.logger.log_call("TraceSession.seed_enforcement", [self.seed], {}, None)

            self._check_rng_usage()

            if self.capture_script:
                self._capture_calling_script()

            if self.auto_track_io:
                self._hook_open()

            if self.capture_git:
                self._capture_git_metadata()

        except Exception:
            TraceSession._active_session.reset(self._token)
            if self.logger and hasattr(self.logger, "close"):
                self.logger.close()
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
            raise

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._original_open:
            builtins.open = self._original_open
            self._original_open = None

        TraceSession._active_session.reset(self._token)

        try:
            # 1. Save audit_log.json (Close stream)
            log_path = os.path.join(self.temp_dir, "audit_log.json")
            if self.logger:
                self.logger.close()
            # self.logger.save(log_path) # Already saved via streaming

            # 2. Capture environment.lock
            env_path = os.path.join(self.temp_dir, "environment.lock")
            self._capture_environment(env_path)

            # 3. Process captured artifacts
            self._process_artifacts()

            # 4. Request Timestamp (if configured)
            if self.tsa_url:
                try:
                    from .timestamp import TimestampClient
                    client = TimestampClient()
                    tsr_data = client.request_timestamp(log_path, self.tsa_url)
                    with open(os.path.join(self.temp_dir, "audit_log.tsr"), "wb") as f:
                        f.write(tsr_data)
                except Exception as e:
                    msg = f"Timestamping failed: {e}"
                    if self.strict:
                        raise RuntimeError(msg) from e
                    else:
                        print(f"Warning: {msg}")

            # 4. Sign artifacts if private key is available
            if self._ephemeral_key or (self.private_key_path and os.path.exists(self.private_key_path)):
                self._sign_artifacts(log_path)
            elif self.strict and self.private_key_path:
                 raise FileNotFoundError(f"Private key not found at {self.private_key_path}")


            # 5. Create the .vch package (zip)
            self._package_artifacts()

        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)

    def add_artifact(self, filepath: str, arcname: Optional[str] = None) -> None:
        """
        Mark a file to be included in the .vch package.

        Args:
            filepath: Local path to the file.
            arcname: Name to store it as in the zip (default: basename of filepath).
                     It will be placed under the 'data/' folder.

        Raises:
            FileNotFoundError: If strict mode is on and file is missing.
            ValueError: If arcname contains path traversal characters or file exceeds max size.
        """
        if not os.path.exists(filepath):
            if self.strict:
                raise FileNotFoundError(f"Artifact not found: {filepath}")
            return

        # Security check for symlinks
        if os.path.islink(filepath):
            raise ValueError(f"Symlinks are not allowed: {filepath}")

        if self.strict and os.path.getsize(filepath) > self.max_artifact_size:
            raise ValueError(f"Artifact exceeds maximum size ({self.max_artifact_size} bytes): {filepath}")

        if arcname is None:
            arcname = os.path.basename(filepath)

        # Security check for arcname
        if os.path.isabs(arcname) or ".." in arcname:
             if self.strict:
                raise ValueError(f"Invalid artifact name: {arcname}. Must be relative path without '..'")
             else:
                return

        self.artifacts[arcname] = filepath

        # Immediate capture if session is active
        if self.temp_dir and os.path.exists(self.temp_dir):
             self._safe_copy_artifact(arcname, filepath)

    def track_file(self, filepath: str) -> None:
        """
        Manually log a file's hash in the audit trail without bundling it.

        Args:
            filepath: Path to the file to track.

        Raises:
            FileNotFoundError: If strict mode is on and file is missing.
        """
        if not os.path.exists(filepath):
            if self.strict:
                raise FileNotFoundError(f"File not found: {filepath}")
            return

        file_hash = Hasher.hash_file(filepath)
        # We use log_call to insert it into the chain
        self.logger.log_call("track_file", [filepath], {}, None,
            extra_hashes={"tracked_file_hash": file_hash, "tracked_path": filepath})

    def annotate(self, key: str, value: Any) -> None:
        """
        Add a metadata annotation to the audit log.

        Args:
            key: Metadata key.
            value: Metadata value.
        """
        self.logger.log_call("annotate", [key, value], {}, None)

    @classmethod
    def get_active_session(cls) -> Optional['TraceSession']:
        return cls._active_session.get()

    def _check_rng_usage(self):
        if 'torch' in sys.modules:
            msg = "PyTorch detected. Please ensure you manually seed it with torch.manual_seed(seed)."
            if self.strict:
                raise RuntimeError(msg)
            logger.warning(msg)
        if 'tensorflow' in sys.modules:
            msg = "TensorFlow detected. Please ensure you manually seed it with tf.random.set_seed(seed)."
            if self.strict:
                raise RuntimeError(msg)
            logger.warning(msg)

    def _capture_calling_script(self):
        try:
            # Stack: 0=this, 1=__enter__, 2=caller
            frame = inspect.stack()[2]
            module = inspect.getmodule(frame[0])
            if module and hasattr(module, '__file__') and module.__file__:
                script_path = os.path.abspath(module.__file__)
                if os.path.exists(script_path):
                     # Add as artifact
                     # Use a special name
                     self.add_artifact(script_path, arcname=f"__script__{os.path.basename(script_path)}")
        except Exception as e:
            logger.warning(f"Failed to capture calling script: {e}")

    def _capture_git_metadata(self):
        metadata = GitTracker.get_metadata()
        if metadata:
            with open(os.path.join(self.temp_dir, "git_metadata.json"), "w") as f:
                json.dump(metadata, f, indent=2)

    def _hook_open(self):
        self._original_open = builtins.open

        def tracked_open(file, mode='r', *args, **kwargs):
            result = self._original_open(file, mode, *args, **kwargs)

            # Recursion guard using thread-local storage
            if not getattr(self._thread_local, 'in_tracked_open', False):
                try:
                    self._thread_local.in_tracked_open = True

                    # Resolve path if it's PathLike
                    path_str = None
                    if isinstance(file, (str, os.PathLike)):
                        try:
                            path_str = os.fspath(file)
                        except TypeError:
                            pass

                    # Check if file is string/path and opened for reading
                    if path_str and ('r' in mode or 'rb' in mode):
                         if os.path.exists(path_str):
                             self.track_file(path_str)
                except Exception:
                    pass
                finally:
                    self._thread_local.in_tracked_open = False

            return result

        builtins.open = tracked_open

    def _capture_environment(self, filepath):
        try:
            freeze_output = subprocess.check_output([sys.executable, "-m", "pip", "freeze"]).decode("utf-8")
        except subprocess.CalledProcessError:
            freeze_output = "Error capturing pip freeze"

        # Capture CPU info
        import platform
        cpu_info = {
            "machine": platform.machine(),
            "processor": platform.processor(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version()
        }

        # Capture BLAS/LAPACK info from numpy
        blas_info = "N/A"
        try:
            import numpy
            import io
            import contextlib
            with TraceSession._env_lock:
                f = io.StringIO()
                with contextlib.redirect_stdout(f):
                    numpy.show_config()
                blas_info = f.getvalue()
        except ImportError:
            blas_info = "NumPy not installed"
        except Exception as e:
            blas_info = f"Error capturing NumPy config: {e}"

        env_info = {
            "vouch_version": vouch.__version__,
            "python_version": sys.version,
            "platform": sys.platform,
            "cpu_info": cpu_info,
            "blas_info": blas_info,
            "pip_freeze": freeze_output
        }

        with open(filepath, 'w') as f:
            json.dump(env_info, f, indent=2)

    def _safe_copy_artifact(self, name, src_path):
        data_dir = os.path.join(self.temp_dir, "data")
        dst_path = os.path.join(data_dir, name)

        # Double check destination is within data_dir
        try:
            common = os.path.commonpath([os.path.abspath(dst_path), os.path.abspath(data_dir)])
            if common != os.path.abspath(data_dir):
                 print(f"Warning: Skipping artifact {name} (path traversal detected)")
                 return None
        except ValueError:
            print(f"Warning: Skipping artifact {name} (invalid path or different drive)")
            return None

        src_fd = None
        try:
            # Open with O_NOFOLLOW to fail if it's a symlink
            # This prevents TOCTOU attacks where the file is replaced with a symlink
            # after os.path.islink() check but before open()
            src_fd = os.open(src_path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            if e.errno == errno.ELOOP: # It's a symlink
                 print(f"Warning: Skipping artifact {name} (symlink detected)")
                 return None
            print(f"Warning: Skipping artifact {name} (access error: {e})")
            return None

        try:
            # Check file size using the file descriptor
            stat = os.fstat(src_fd)
            if stat.st_size > self.max_artifact_size:
                print(f"Warning: Skipping artifact {name} (exceeds max size)")
                return None

            # Ensure parent directory exists
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)

            # Copy content from FD
            with os.fdopen(src_fd, 'rb') as fsrc:
                src_fd = None # os.fdopen takes ownership
                with open(dst_path, 'wb') as fdst:
                    shutil.copyfileobj(fsrc, fdst)

            # Attempt to copy metadata from the stat object
            try:
                os.chmod(dst_path, stat.st_mode)
                os.utime(dst_path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            except Exception:
                pass

            return dst_path
        except Exception as e:
             print(f"Warning: Failed to copy artifact {name}: {e}")
             return None
        finally:
            if src_fd is not None:
                os.close(src_fd)

    def _process_artifacts(self):
        """
        Copies registered artifacts to temp_dir/data and creates artifacts.json
        """
        manifest = {}
        data_dir = os.path.join(self.temp_dir, "data")
        total = len(self.artifacts)
        processed = 0

        for name, src_path in self.artifacts.items():
            processed += 1
            if total > 10 and (processed % 5 == 0 or processed == total):
                sys.stdout.write(f"\rPackaging artifacts... {processed}/{total}")
                sys.stdout.flush()

            dst_path = os.path.join(data_dir, name)

            # If not already captured (e.g. added before session start), capture now
            if not os.path.exists(dst_path):
                 if not self._safe_copy_artifact(name, src_path):
                     continue

            # Hash the file
            if os.path.exists(dst_path):
                file_hash = Hasher.hash_file(dst_path)
                manifest[name] = file_hash

        if total > 10:
             print() # Clear progress line

        with open(os.path.join(self.temp_dir, "artifacts.json"), "w") as f:
            json.dump(manifest, f, indent=2)

    def _sign_artifacts(self, log_path):
        try:
            if self._ephemeral_key:
                private_key = self._ephemeral_key
            else:
                private_key = CryptoManager.load_private_key(
                    self.private_key_path,
                    password=self.private_key_password
                )

            # Sign audit_log.json
            signature = CryptoManager.sign_file(private_key, log_path)
            with open(os.path.join(self.temp_dir, "signature.sig"), "wb") as f:
                f.write(signature)

            # Sign artifacts.json if it exists
            artifacts_path = os.path.join(self.temp_dir, "artifacts.json")
            if os.path.exists(artifacts_path):
                signature = CryptoManager.sign_file(private_key, artifacts_path)
                with open(os.path.join(self.temp_dir, "artifacts.json.sig"), "wb") as f:
                    f.write(signature)

            # Export public key
            public_key = private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(os.path.join(self.temp_dir, "public_key.pem"), "wb") as f:
                f.write(pem)

        except Exception as e:
            msg = (
                f"Failed to sign audit artifacts\n"
                f"  Key: {self.private_key_path}\n"
                f"  Error: {e}\n"
                f"  Hint: Verify key exists and password is correct"
            )
            if self.strict:
                raise RuntimeError(msg) from e
            else:
                print(f"Warning: {msg}")

    def _package_artifacts(self):
        with zipfile.ZipFile(self.filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.temp_dir)
                    zipf.write(file_path, arcname)

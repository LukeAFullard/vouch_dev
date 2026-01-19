import os
import sys
import subprocess
import json
import zipfile
import tempfile
import shutil
import random
import inspect
import builtins
import logging
import vouch
from .logger import Logger

logger = logging.getLogger(__name__)
from .crypto import CryptoManager
from .hasher import Hasher
from cryptography.hazmat.primitives import serialization

class TraceSession:
    _active_session = None

    def __init__(self, filename, strict=True, seed=None, private_key_path=None, private_key_password=None, capture_script=True, auto_track_io=False):
        self.filename = filename
        self.strict = strict
        self.seed = seed
        self.logger = Logger()
        self.temp_dir = None
        self.private_key_path = private_key_path
        self.private_key_password = private_key_password
        self.capture_script = capture_script
        self.auto_track_io = auto_track_io
        self.artifacts = {} # Map arcname -> local_path
        self._original_open = None

    def __enter__(self):
        if TraceSession._active_session is not None:
            raise RuntimeError("Nested TraceSessions are not supported.")
        TraceSession._active_session = self

        # Setup temporary directory for artifacts
        self.temp_dir = tempfile.mkdtemp()

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

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._original_open:
            builtins.open = self._original_open
            self._original_open = None

        TraceSession._active_session = None

        try:
            # 1. Save audit_log.json
            log_path = os.path.join(self.temp_dir, "audit_log.json")
            self.logger.save(log_path)

            # 2. Capture environment.lock
            env_path = os.path.join(self.temp_dir, "environment.lock")
            self._capture_environment(env_path)

            # 3. Process captured artifacts
            self._process_artifacts()

            # 4. Sign artifacts if private key is available
            if self.private_key_path and os.path.exists(self.private_key_path):
                self._sign_artifacts(log_path)
            elif self.strict and self.private_key_path:
                 raise FileNotFoundError(f"Private key not found at {self.private_key_path}")


            # 5. Create the .vch package (zip)
            self._package_artifacts()

        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)

    def add_artifact(self, filepath, arcname=None):
        """
        Mark a file to be included in the .vch package.

        :param filepath: Local path to the file.
        :param arcname: Name to store it as in the zip (default: basename of filepath).
                        It will be placed under the 'data/' folder.
        """
        if not os.path.exists(filepath):
            if self.strict:
                raise FileNotFoundError(f"Artifact not found: {filepath}")
            return

        if arcname is None:
            arcname = os.path.basename(filepath)

        # Security check for arcname
        if os.path.isabs(arcname) or ".." in arcname:
             if self.strict:
                raise ValueError(f"Invalid artifact name: {arcname}. Must be relative path without '..'")
             else:
                return

        self.artifacts[arcname] = filepath

    def track_file(self, filepath):
        """
        Manually log a file's hash in the audit trail without bundling it.
        """
        if not os.path.exists(filepath):
            if self.strict:
                raise FileNotFoundError(f"File not found: {filepath}")
            return

        file_hash = Hasher.hash_file(filepath)
        # We use log_call to insert it into the chain
        self.logger.log_call("track_file", [filepath], {}, None,
            extra_hashes={"tracked_file_hash": file_hash, "tracked_path": filepath})

    def annotate(self, key, value):
        """
        Add a metadata annotation to the audit log.
        """
        self.logger.log_call("annotate", [key, value], {}, None)

    @classmethod
    def get_active_session(cls):
        return cls._active_session

    def _check_rng_usage(self):
        if 'torch' in sys.modules:
             logger.warning("PyTorch detected. Please ensure you manually seed it with torch.manual_seed(seed).")
        if 'tensorflow' in sys.modules:
             logger.warning("TensorFlow detected. Please ensure you manually seed it with tf.random.set_seed(seed).")

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

    def _hook_open(self):
        self._original_open = builtins.open

        def tracked_open(file, mode='r', *args, **kwargs):
            result = self._original_open(file, mode, *args, **kwargs)

            # Recursion guard
            if not getattr(self, '_in_tracked_open', False):
                try:
                    self._in_tracked_open = True
                    # Check if file is string and opened for reading
                    if isinstance(file, str) and ('r' in mode or 'rb' in mode):
                         if os.path.exists(file):
                             self.track_file(file)
                except Exception:
                    pass
                finally:
                    self._in_tracked_open = False

            return result

        builtins.open = tracked_open

    def _capture_environment(self, filepath):
        try:
            freeze_output = subprocess.check_output([sys.executable, "-m", "pip", "freeze"]).decode("utf-8")
        except subprocess.CalledProcessError:
            freeze_output = "Error capturing pip freeze"

        env_info = {
            "vouch_version": vouch.__version__,
            "python_version": sys.version,
            "platform": sys.platform,
            "pip_freeze": freeze_output
        }

        with open(filepath, 'w') as f:
            json.dump(env_info, f, indent=2)

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

            # Double check destination is within data_dir
            try:
                common = os.path.commonpath([os.path.abspath(dst_path), os.path.abspath(data_dir)])
                if common != os.path.abspath(data_dir):
                     print(f"Warning: Skipping artifact {name} (path traversal detected)")
                     continue
            except ValueError:
                print(f"Warning: Skipping artifact {name} (invalid path or different drive)")
                continue

            # Ensure parent directory exists
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)

            shutil.copy2(src_path, dst_path)

            # Hash the file
            file_hash = Hasher.hash_file(dst_path)
            manifest[name] = file_hash

        if total > 10:
             print() # Clear progress line

        with open(os.path.join(self.temp_dir, "artifacts.json"), "w") as f:
            json.dump(manifest, f, indent=2)

    def _sign_artifacts(self, log_path):
        try:
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
                f"Failed to sign artifacts.\n"
                f"  Key path: {self.private_key_path}\n"
                f"  Error: {e}"
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

import os
import sys
import subprocess
import json
import zipfile
import tempfile
import shutil
from .logger import Logger
from .crypto import CryptoManager
from cryptography.hazmat.primitives import serialization

class TraceSession:
    _active_session = None

    def __init__(self, filename, strict=True, seed=None, private_key_path=None):
        self.filename = filename
        self.strict = strict
        self.seed = seed
        self.logger = Logger()
        self.temp_dir = None
        self.private_key_path = private_key_path

    def __enter__(self):
        if TraceSession._active_session is not None:
            raise RuntimeError("Nested TraceSessions are not supported.")
        TraceSession._active_session = self

        # Setup temporary directory for artifacts
        self.temp_dir = tempfile.mkdtemp()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        TraceSession._active_session = None

        try:
            # 1. Save audit_log.json
            log_path = os.path.join(self.temp_dir, "audit_log.json")
            self.logger.save(log_path)

            # 2. Capture environment.lock
            env_path = os.path.join(self.temp_dir, "environment.lock")
            self._capture_environment(env_path)

            # 3. Sign artifacts if private key is available
            if self.private_key_path and os.path.exists(self.private_key_path):
                self._sign_artifacts(log_path)
            elif self.strict and self.private_key_path:
                 raise FileNotFoundError(f"Private key not found at {self.private_key_path}")


            # 4. Create the .vch package (zip)
            self._package_artifacts()

        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)

    @classmethod
    def get_active_session(cls):
        return cls._active_session

    def _capture_environment(self, filepath):
        try:
            freeze_output = subprocess.check_output([sys.executable, "-m", "pip", "freeze"]).decode("utf-8")
        except subprocess.CalledProcessError:
            freeze_output = "Error capturing pip freeze"

        env_info = {
            "python_version": sys.version,
            "platform": sys.platform,
            "pip_freeze": freeze_output
        }

        with open(filepath, 'w') as f:
            json.dump(env_info, f, indent=2)

    def _sign_artifacts(self, log_path):
        try:
            private_key = CryptoManager.load_private_key(self.private_key_path)

            # Sign audit_log.json
            signature = CryptoManager.sign_file(private_key, log_path)
            with open(os.path.join(self.temp_dir, "signature.sig"), "wb") as f:
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
            if self.strict:
                raise RuntimeError(f"Failed to sign artifacts: {e}")
            else:
                print(f"Warning: Failed to sign artifacts: {e}")

    def _package_artifacts(self):
        with zipfile.ZipFile(self.filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.temp_dir)
                    zipf.write(file_path, arcname)

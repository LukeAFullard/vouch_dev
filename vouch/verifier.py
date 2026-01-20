import os
import sys
import zipfile
import tempfile
import json
import logging
import shutil
import ijson
from typing import Optional, List, Dict, Any, Callable

from .crypto import CryptoManager
from .hasher import Hasher
import vouch

logger = logging.getLogger(__name__)

class Verifier:
    """
    Verifies the integrity and authenticity of a Vouch audit package.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.temp_dir: Optional[str] = None
        self.status: Dict[str, Any] = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "checks": {}
        }
        # Default reporter logs to logger
        self._reporter = self._default_reporter

    def _default_reporter(self, message: str, level: str = "INFO", check_name: Optional[str] = None):
        if level == "ERROR":
            logger.error(message)
        elif level == "WARN":
            logger.warning(message)
        else:
            logger.info(message)

    def verify(self,
               data_file: Optional[str] = None,
               auto_data: bool = False,
               auto_data_dir: str = ".",
               tsa_ca_file: Optional[str] = None,
               strict: bool = False,
               reporter: Optional[Callable[[str, str, Optional[str]], None]] = None) -> bool:
        """
        Run all verification checks.

        Args:
            reporter: Optional callback(message, level, check_name) for output.
        """
        if reporter:
            self._reporter = reporter

        if not os.path.exists(self.filepath):
            self._fail("file_exists", f"Error: File {self.filepath} not found.")
            return False

        try:
            self.temp_dir = tempfile.mkdtemp()

            if not self._extract_package():
                return False

            if not self._check_components():
                return False

            if not self._verify_signature():
                return False

            # Timestamp verification (optional but checked)
            self._verify_timestamp(tsa_ca_file, strict)

            if not self._verify_log_chain():
                return False

            env_ok = self._verify_environment()
            git_ok = self._verify_git_metadata()
            art_ok = self._verify_artifacts()

            if not (env_ok and git_ok and art_ok):
                return False

            if data_file:
                if not self._verify_external_data(data_file):
                    return False

            if auto_data:
                if not self._verify_auto_data(auto_data_dir):
                    return False

            self.status["valid"] = True
            return True

        except Exception as e:
            self._fail("exception", str(e))
            return False
        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)

    def _fail(self, check_name: str, message: str):
        self.status["checks"][check_name] = {"valid": False, "message": message}
        self.status["errors"].append(message)

        # Formatting for CLI output
        display_msg = message
        if check_name == "file_exists" or (check_name == "extraction" and "Invalid Vouch file" in message):
             pass # Message already formatted as "Error: ..."
        elif check_name == "components":
             display_msg = f"Error: {message}"
        else:
             display_msg = f"  [FAIL] {message}"

        self._reporter(display_msg, level="ERROR", check_name=check_name)

    def _pass(self, check_name: str, message: str = "OK"):
        self.status["checks"][check_name] = {"valid": True, "message": message}
        self._reporter(f"  [OK] {message}", level="INFO", check_name=check_name)

    def _warn(self, message: str):
        self.status["warnings"].append(message)
        self._reporter(f"  [WARN] {message}", level="WARN", check_name=None)

    def _print(self, message: str):
        """Helper for progress messages that should go to reporter."""
        self._reporter(message, level="INFO", check_name=None)

    def _extract_package(self) -> bool:
        try:
            with zipfile.ZipFile(self.filepath, 'r') as z:
                # Safe extraction (Zip Slip protection)
                for member in z.infolist():
                    name = member.filename
                    if name.startswith('/') or '..' in name:
                        logger.warning(f"Skipping suspicious file path in package: {name}")
                        continue

                    target_path = os.path.join(self.temp_dir, name)
                    # Canonicalize
                    try:
                        if os.path.commonpath([os.path.abspath(target_path), os.path.abspath(self.temp_dir)]) != os.path.abspath(self.temp_dir):
                            logger.warning(f"Skipping artifact with path traversal: {name}")
                            continue
                    except ValueError:
                         logger.warning(f"Skipping artifact (invalid path): {name}")
                         continue

                    z.extract(member, self.temp_dir)
            # self._pass("extraction", "Package extracted successfully")
            return True
        except zipfile.BadZipFile:
            self._fail("extraction", "Invalid Vouch file (not a zip).")
            return False
        except Exception as e:
            self._fail("extraction", f"Extraction failed: {e}")
            return False

    def _check_components(self) -> bool:
        required = ["audit_log.json", "signature.sig", "public_key.pem", "environment.lock"]
        missing = []
        for f in required:
            if not os.path.exists(os.path.join(self.temp_dir, f)):
                missing.append(f)

        if missing:
            self._fail("components", f"Corrupt package. Missing {', '.join(missing)}")
            return False

        # self._pass("components", "All required components present")
        return True

    def _verify_signature(self) -> bool:
        try:
            pub_key = CryptoManager.load_public_key(os.path.join(self.temp_dir, "public_key.pem"))
            with open(os.path.join(self.temp_dir, "signature.sig"), "rb") as f:
                signature = f.read()

            CryptoManager.verify_file(pub_key, os.path.join(self.temp_dir, "audit_log.json"), signature)
            self._pass("signature", "Signature Verification: Valid")
            self._pass("log_integrity", "Log Integrity: Valid")
            return True
        except Exception as e:
            self._fail("signature", f"Signature Verification: Invalid ({e})")
            return False

    def _verify_timestamp(self, ca_file, strict) -> bool:
        tsr_path = os.path.join(self.temp_dir, "audit_log.tsr")
        if not os.path.exists(tsr_path):
            return True

        self._print("  [...] Verifying Timestamp...")
        try:
            from .timestamp import TimestampClient
            client = TimestampClient()
            if client.verify_timestamp(os.path.join(self.temp_dir, "audit_log.json"), tsr_path, ca_file):
                self._print("    [OK] Timestamp Verified (Matches Log)")
                return True
            else:
                msg = "Timestamp Verification Failed"
                self._print(f"    [FAIL] {msg}")
                if strict:
                    self._fail("timestamp", msg)
                    return False
                else:
                    return True
        except Exception as e:
            msg = f"Timestamp Error: {e}"
            self._print(f"    [FAIL] {msg}")
            if strict:
                self._fail("timestamp", msg)
                return False
            else:
                return True

    def _iterate_log(self, log_path):
        """Yields log entries, handling both NDJSON and legacy JSON array."""
        is_array = False
        try:
            with open(log_path, 'r') as f:
                # Check first char to detect array vs NDJSON
                # Only read 1 char but handle if empty
                first = f.read(1)
                if first == '[':
                    is_array = True
        except Exception:
             # If empty or error, let next block handle it
             pass

        if is_array:
            # Use ijson for array
            with open(log_path, 'r') as f:
                # ijson.items yields generator
                try:
                     yield from ijson.items(f, 'item')
                except Exception as e:
                     logger.error(f"Error parsing JSON array: {e}")
                     raise
        else:
            # Assume NDJSON
            with open(log_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        # Could be corruption or middle of crash
                        logger.warning(f"Skipping invalid JSON line: {e}")

    def _verify_log_chain(self) -> bool:
        self._print("  [...] Verifying log chain integrity...")
        try:
            prev_hash = "0" * 64
            expected_seq = 1

            for i, entry in enumerate(self._iterate_log(os.path.join(self.temp_dir, "audit_log.json"))):
                if "sequence_number" in entry:
                    if entry["sequence_number"] != expected_seq:
                        self._fail("log_chain", f"Entry {i}: Sequence mismatch (expected {expected_seq}, got {entry['sequence_number']})")
                        self._print("  [FAIL] Log Chain Integrity: Broken")
                        return False
                    expected_seq += 1

                if "previous_entry_hash" in entry:
                    if entry["previous_entry_hash"] != prev_hash:
                        self._fail("log_chain", f"Entry {i}: Previous hash mismatch")
                        self._print("  [FAIL] Log Chain Integrity: Broken")
                        return False

                prev_hash = Hasher.hash_object(entry)

            self._pass("log_chain", "Log Chain Integrity: Valid")
            return True
        except Exception as e:
            self._fail("log_chain", f"Log Chain Verification Error: {e}")
            return False

    def _verify_environment(self) -> bool:
        env_lock_path = os.path.join(self.temp_dir, "environment.lock")
        if not os.path.exists(env_lock_path):
            return True

        # Check signature
        sig_path = env_lock_path + ".sig"
        if os.path.exists(sig_path):
             try:
                pub_key = CryptoManager.load_public_key(os.path.join(self.temp_dir, "public_key.pem"))
                with open(sig_path, "rb") as f:
                    sig = f.read()
                CryptoManager.verify_file(pub_key, env_lock_path, sig)
                self._pass("environment_sig", "Environment Signature: Valid")
             except Exception as e:
                self._fail("environment_sig", f"Environment Signature: Invalid ({e})")
                return False

        elif os.path.exists(os.path.join(self.temp_dir, "signature.sig")):
             self._fail("environment_sig", "Environment Signature: Missing")
             return False

        try:
            with open(env_lock_path, "r") as f:
                env_info = json.load(f)

            if "vouch_version" in env_info:
                if env_info["vouch_version"] != vouch.__version__:
                    self._warn(f"Created with Vouch {env_info['vouch_version']}, verifying with {vouch.__version__}")

            recorded_version = env_info.get("python_version", "").split()[0]
            current_version = sys.version.split()[0]

            if recorded_version != current_version:
                self._warn(f"Environment Mismatch: Recorded Python {recorded_version}, Current {current_version}")
            else:
                self._pass("environment", f"Environment: Python version matches ({current_version})")
            return True
        except Exception as e:
            self._warn(f"Could not verify environment: {e}")
            return True

    def _verify_git_metadata(self) -> bool:
        git_path = os.path.join(self.temp_dir, "git_metadata.json")
        if not os.path.exists(git_path):
            return True

        # Check signature
        sig_path = git_path + ".sig"
        if os.path.exists(sig_path):
             try:
                pub_key = CryptoManager.load_public_key(os.path.join(self.temp_dir, "public_key.pem"))
                with open(sig_path, "rb") as f:
                    sig = f.read()
                CryptoManager.verify_file(pub_key, git_path, sig)
                self._pass("git_sig", "Git Metadata Signature: Valid")
             except Exception as e:
                self._fail("git_sig", f"Git Metadata Signature: Invalid ({e})")
                return False
        elif os.path.exists(os.path.join(self.temp_dir, "signature.sig")):
             self._fail("git_sig", "Git Metadata Signature: Missing")
             return False

        try:
            with open(git_path, "r") as f:
                data = json.load(f)

            sha = data.get("commit_sha", "Unknown")
            is_dirty = data.get("is_dirty", False)

            if is_dirty:
                self._warn(f"Git Repository was DIRTY at capture time (Commit: {sha})")
            else:
                self._pass("git", f"Git Metadata: Clean commit {sha}")
            return True
        except Exception as e:
            self._warn(f"Could not parse git metadata: {e}")
            return True

    def _verify_artifacts(self) -> bool:
        artifacts_json_path = os.path.join(self.temp_dir, "artifacts.json")
        if not os.path.exists(artifacts_json_path):
            return True

        self._print("  [...] Verifying captured artifacts...")
        # Verify Manifest Signature
        artifacts_sig_path = os.path.join(self.temp_dir, "artifacts.json.sig")
        if not os.path.exists(artifacts_sig_path):
            self._fail("artifacts_sig", "Artifact Manifest Signature: Missing (Manifest not signed)")
            return False

        try:
            pub_key = CryptoManager.load_public_key(os.path.join(self.temp_dir, "public_key.pem"))
            with open(artifacts_sig_path, "rb") as f:
                art_sig = f.read()
            CryptoManager.verify_file(pub_key, artifacts_json_path, art_sig)
            self._print("    [OK] Artifact Manifest Signature: Valid")
        except Exception as e:
            self._fail("artifacts_sig", f"Artifact Manifest Signature: Invalid ({e})")
            return False

        try:
            with open(artifacts_json_path, "r") as f:
                manifest = json.load(f)

            data_dir = os.path.join(self.temp_dir, "data")

            for name, expected_hash in manifest.items():
                if os.path.isabs(name) or ".." in name:
                    self._print(f"    [FAIL] Malformed artifact path: {name}")
                    return False

                artifact_path = os.path.join(data_dir, name)

                try:
                    common = os.path.commonpath([os.path.abspath(artifact_path), os.path.abspath(data_dir)])
                    if common != os.path.abspath(data_dir):
                         self._print(f"    [FAIL] Malformed artifact path (traversal): {name}")
                         return False
                except ValueError:
                     self._print(f"    [FAIL] Malformed artifact path (invalid/different drive): {name}")
                     return False

                if not os.path.exists(artifact_path):
                    self._print(f"    [FAIL] Missing artifact: {name}")
                    return False

                actual_hash = Hasher.hash_file(artifact_path)
                if actual_hash != expected_hash:
                    self._print(f"    [FAIL] {name} (Hash Mismatch)")
                    return False

            self._pass("artifacts", "Captured Artifacts Integrity: Valid")
            return True

        except Exception as e:
            self._fail("artifacts", f"Artifact Verification Error: {e}")
            return False

    def _verify_external_data(self, data_file: str) -> bool:
        if not os.path.exists(data_file):
            self._fail("external_data", f"Error: Data file {data_file} not found.")
            return False

        data_hash = Hasher.hash_file(data_file)
        self._print(f"  [...] Verifying external data file: {data_file}")
        self._print(f"        Hash: {data_hash}")

        found = False
        for entry in self._iterate_log(os.path.join(self.temp_dir, "audit_log.json")):
            if "extra_hashes" in entry:
                for val in entry["extra_hashes"].values():
                    if val == data_hash:
                        found = True
                        break
            if found: break

        if found:
            self._pass("external_data", "Data Integrity: Valid")
            return True
        else:
            self._fail("external_data", f"Data Integrity: Mismatched/Corrupted (Hash {data_hash} not found in log)")
            return False

    def _verify_auto_data(self, auto_data_dir: str) -> bool:
        referenced_files = {}
        for entry in self._iterate_log(os.path.join(self.temp_dir, "audit_log.json")):
            if "extra_hashes" in entry:
                extras = entry["extra_hashes"]
                for key, path in extras.items():
                    if key.endswith("_path") and isinstance(path, str):
                        hash_key = key.replace("_path", "_file_hash")
                        if hash_key in extras:
                            referenced_files[path] = extras[hash_key]

        if not referenced_files:
            self._print("    No external file references found in log.")
            return True

        self._print("  [...] Auto-verifying referenced files...")
        all_valid = True
        for path, expected_hash in referenced_files.items():
            if os.path.isabs(path):
                target_path = path
            else:
                target_path = os.path.join(auto_data_dir, path)

            if not os.path.exists(target_path):
                 # Fallback to basename
                 fallback_path = os.path.join(auto_data_dir, os.path.basename(path))
                 if os.path.exists(fallback_path):
                     target_path = fallback_path
                 else:
                    self._print(f"    [SKIP] {path} (Not found)")
                    continue

            current_hash = Hasher.hash_file(target_path)
            if current_hash != expected_hash:
                self._print(f"    [FAIL] {target_path} (Hash mismatch)")
                all_valid = False
            else:
                self._print(f"    [OK] {target_path}")

        if all_valid:
            self._pass("auto_data", "Auto-Data Verification: Valid")
            return True
        else:
            self._fail("auto_data", "Auto-Data Verification: One or more files failed verification")
            return False

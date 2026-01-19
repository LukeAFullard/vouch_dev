import subprocess
import urllib.request
import urllib.error
import shutil
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class TimestampClient:
    def __init__(self, openssl_path: str = "openssl"):
        self.openssl_path = openssl_path

    def request_timestamp(self, data_path: str, url: str) -> bytes:
        """
        Requests a timestamp token for the file at data_path using RFC 3161.
        Returns the binary timestamp response (TSR).
        """
        if not shutil.which(self.openssl_path):
             raise RuntimeError("OpenSSL not found. Cannot perform timestamping.")

        # 1. Create query
        # openssl ts -query -data <file> -sha256
        try:
             cmd = [self.openssl_path, "ts", "-query", "-data", data_path, "-sha256"]
             result = subprocess.run(cmd, check=True, capture_output=True)
             query_data = result.stdout
        except subprocess.CalledProcessError as e:
             err_msg = e.stderr.decode() if e.stderr else str(e)
             raise RuntimeError(f"Failed to create timestamp query: {err_msg}")

        # 2. Send to URL
        headers = {'Content-Type': 'application/timestamp-query'}
        req = urllib.request.Request(url, data=query_data, headers=headers, method='POST')

        try:
             with urllib.request.urlopen(req) as response:
                  if response.status != 200:
                       raise RuntimeError(f"Timestamp server returned status {response.status}")
                  tsr_data = response.read()
        except urllib.error.URLError as e:
             raise RuntimeError(f"Failed to contact timestamp server: {e}")

        return tsr_data

    def verify_timestamp(self, data_path: str, tsr_path: str, ca_file: Optional[str] = None) -> bool:
        """
        Verifies the timestamp response matches the data.
        """
        if not shutil.which(self.openssl_path):
             raise RuntimeError("OpenSSL not found.")

        # Check if tsr is valid response
        # openssl ts -verify -in <tsr> -data <file> [-CAfile <ca>]
        cmd = [self.openssl_path, "ts", "-verify", "-in", tsr_path, "-data", data_path]
        if ca_file:
             cmd.extend(["-CAfile", ca_file])
        else:
             # Try to verify with system roots or just implicit
             # Note: openssl ts -verify often fails if it can't build chain.
             # We might want to pass -untrusted tsr_path as it sometimes contains the certs.
             cmd.extend(["-untrusted", tsr_path])
             # Also, some systems (like Debian/Ubuntu) might ignore partial chain without CAfile.
             # We will try best effort.

        result = subprocess.run(cmd, capture_output=True)

        if result.returncode == 0:
             return True

        # If failed, check output
        output = result.stdout.decode() + result.stderr.decode()
        # logger.debug(f"Timestamp verification failed: {output}")

        # If strict verification failed, maybe we can at least check if the message imprint matches?
        # That proves the token corresponds to the file, even if we can't trust the signer (due to missing CA).
        # But 'verify' usually implies checking trust too.
        # For now, we return False if openssl says so.
        # Ideally we'd parse the output.
        return False

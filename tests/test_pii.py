import unittest
import os
import tempfile
import json
import shutil
from vouch.pii import PIIDetector
from vouch.session import TraceSession
import vouch

class TestPII(unittest.TestCase):
    def setUp(self):
        self.detector = PIIDetector()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_regex_detection(self):
        # Email
        self.assertEqual(
            self.detector.sanitize("Contact me at alice@example.com."),
            "Contact me at <PII: EMAIL>."
        )
        # IP
        self.assertEqual(
            self.detector.sanitize("Server is 192.168.1.1 now"),
            "Server is <PII: IP_ADDRESS> now"
        )
        # SSN
        self.assertEqual(
            self.detector.sanitize("ID: 123-45-6789"),
            "ID: <PII: US_SSN>"
        )
        # Credit Card (Simple)
        self.assertEqual(
            self.detector.sanitize("CC: 4111 1111 1111 1111"),
            "CC: <PII: CREDIT_CARD>"
        )

    def test_recursive_sanitization(self):
        data = {
            "users": [
                {"name": "Alice", "email": "alice@corp.com"},
                {"name": "Bob", "ip": "10.0.0.1"}
            ],
            "meta": ("admin@corp.com", 123)
        }

        sanitized = self.detector.sanitize(data)

        self.assertEqual(sanitized["users"][0]["email"], "<PII: EMAIL>")
        self.assertEqual(sanitized["users"][1]["ip"], "<PII: IP_ADDRESS>")
        self.assertEqual(sanitized["meta"][0], "<PII: EMAIL>")

        # Ensure originals are untouched (if we were modifying in place, which we shouldn't)
        # However, sanitize returns new objects.
        self.assertNotEqual(id(data), id(sanitized))

    def test_session_pii_redaction(self):
        vch_path = os.path.join(self.test_dir, "pii.vch")

        def sensitive_func(user_email):
            return f"Processed {user_email}"

        # 1. With PII Detection Enabled
        with TraceSession(vch_path, detect_pii=True, strict=False) as session:
            # We need to wrap the function or use auditor manually
            # But simpler to just use session.logger directly for test,
            # or use the full Vouch machinery.
            # Let's use full machinery via @vouch.record logic or auditor

            from vouch.auditor import Auditor
            wrapped = Auditor(sensitive_func, name="sensitive_func")
            wrapped("bob@example.com")

        # Read Log
        import zipfile
        with zipfile.ZipFile(vch_path, 'r') as z:
            with z.open("audit_log.json") as f:
                content = f.read().decode('utf-8')

        logs = [json.loads(line) for line in content.splitlines() if line.strip()]

        # Find the call
        call_log = next(l for l in logs if l["target"] == "sensitive_func")

        # Check args repr
        self.assertIn("<PII: EMAIL>", call_log["args_repr"][0])

        # Check result repr
        self.assertIn("<PII: EMAIL>", call_log["result_repr"])

        # Check HASHES - ensure we hashed the REDACTED value, not the original
        # If we hash original, we leak info via hash.
        # Hasher.hash_object("<PII: EMAIL>") vs Hasher.hash_object("bob@example.com")

        from vouch.hasher import Hasher
        # log_call receives args as a tuple, so we must hash a tuple to match
        expected_hash = Hasher.hash_object(("<PII: EMAIL>",))
        self.assertEqual(call_log["args_hash"], expected_hash)


    def test_session_no_pii_redaction(self):
        vch_path = os.path.join(self.test_dir, "no_pii.vch")

        def sensitive_func(user_email):
            return f"Processed {user_email}"

        # 2. With PII Detection Disabled (Default)
        with TraceSession(vch_path, detect_pii=False, strict=False) as session:
            from vouch.auditor import Auditor
            wrapped = Auditor(sensitive_func, name="sensitive_func")
            wrapped("bob@example.com")

        # Read Log
        import zipfile
        with zipfile.ZipFile(vch_path, 'r') as z:
            with z.open("audit_log.json") as f:
                content = f.read().decode('utf-8')

        logs = [json.loads(line) for line in content.splitlines() if line.strip()]
        call_log = next(l for l in logs if l["target"] == "sensitive_func")

        # Check args repr - should contain original
        self.assertIn("bob@example.com", call_log["args_repr"][0])

if __name__ == '__main__':
    unittest.main()

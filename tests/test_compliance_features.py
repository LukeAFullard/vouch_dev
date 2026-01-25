import unittest
import os
import tempfile
import json
import shutil
from cryptography import x509
from cryptography.x509.oid import NameOID
from vouch.crypto import CryptoManager
from vouch.session import TraceSession

class TestComplianceFeatures(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.priv_key = os.path.join(self.test_dir, "test_id_rsa")
        self.pub_key = os.path.join(self.test_dir, "test_id_rsa.pub")
        self.cert_path = os.path.join(self.test_dir, "test.crt")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_cert_generation_with_subject(self):
        """Test that keys can be generated with custom Common Name and Organization."""
        cn = "Test Analyst"
        org = "Test Corp"

        CryptoManager.generate_keys(
            self.priv_key,
            self.pub_key,
            cert_path=self.cert_path,
            common_name=cn,
            organization=org
        )

        # Load the cert and check subject
        with open(self.cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        subject = cert.subject
        self.assertEqual(subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, cn)
        self.assertEqual(subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, org)

    def test_session_compliance_logging(self):
        """Test that TraceSession logs compliance tags and user info."""
        # Generate keys first
        CryptoManager.generate_keys(self.priv_key, self.pub_key)

        vch_path = os.path.join(self.test_dir, "compliance.vch")
        user_info = {"name": "Jules", "id": "A123"}
        compliance_tag = "EU_AI_ART12"

        with TraceSession(
            vch_path,
            private_key_path=self.priv_key,
            compliance_usage=compliance_tag,
            user_info=user_info,
            strict=True
        ) as session:
            pass

        # Extract audit log
        import zipfile
        with zipfile.ZipFile(vch_path, 'r') as z:
            with z.open("audit_log.json") as f:
                content = f.read().decode('utf-8')

        # Parse NDJSON
        logs = [json.loads(line) for line in content.splitlines() if line.strip()]

        # Check first log entry (session.initialize)
        init_log = logs[0]
        # Target field is "target" not "function" in Logger.log_call
        self.assertEqual(init_log["target"], "session.initialize")
        config = init_log["extra_hashes"]["config"]

        self.assertEqual(config.get("compliance_usage"), compliance_tag)
        self.assertEqual(config.get("user_info"), user_info)

if __name__ == '__main__':
    unittest.main()

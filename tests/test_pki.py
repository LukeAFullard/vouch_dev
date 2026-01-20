import unittest
import os
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from vouch.timestamp import TimestampClient
from asn1crypto import x509 as asn1_x509

class TestPKI(unittest.TestCase):
    def setUp(self):
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_cert = self._generate_cert(self.ca_key, self.ca_key, "MyCA", ca=True)

        self.signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.signer_cert = self._generate_cert(self.signer_key, self.ca_key, "MySigner", ca=False, issuer_name="MyCA")

        self.ca_file = "test_ca.pem"
        with open(self.ca_file, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def tearDown(self):
        if os.path.exists(self.ca_file):
            os.remove(self.ca_file)

    def _generate_cert(self, key, signer_key, common_name, ca=False, issuer_name=None):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        if issuer_name:
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
        else:
            issuer = subject

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))

        if ca:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

        return builder.sign(signer_key, hashes.SHA256())

    def test_verify_chain(self):
        client = TimestampClient()

        # Convert cryptography cert back to asn1crypto object expected by verify_chain_of_trust
        der = self.signer_cert.public_bytes(serialization.Encoding.DER)
        asn1_cert = asn1_x509.Certificate.load(der)

        # Should pass
        try:
            client.verify_chain_of_trust(asn1_cert, self.ca_file)
        except Exception as e:
            self.fail(f"Verification failed: {e}")

    def test_verify_chain_fail(self):
        client = TimestampClient()

        # Create unrelated cert
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_cert = self._generate_cert(other_key, other_key, "OtherCA", ca=True)

        der = other_cert.public_bytes(serialization.Encoding.DER)
        asn1_cert = asn1_x509.Certificate.load(der)

        # Should fail (issuer not found)
        with self.assertRaises(ValueError):
             client.verify_chain_of_trust(asn1_cert, self.ca_file)

if __name__ == "__main__":
    unittest.main()

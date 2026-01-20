import unittest
import hashlib
import datetime
import os
from asn1crypto import tsp, cms, algos, x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509 as crypto_x509
from cryptography.x509.oid import NameOID
from vouch.timestamp import TimestampClient

class TestTimestampPure(unittest.TestCase):
    def test_verify_pure(self):
        # 1. Setup Keys
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Self-signed cert
        subject = issuer = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, u"Test TSA")])
        cert = crypto_x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(100).not_valid_before(datetime.datetime.now(datetime.timezone.utc)).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256())

        cert_der = cert.public_bytes(serialization.Encoding.DER)

        # 2. Create Data
        data = b"hello world"
        data_hash = hashlib.sha256(data).digest()
        with open("test_ts.dat", "wb") as f: f.write(data)

        # 3. Create TSTInfo
        tst_info = tsp.TSTInfo({
            'version': 1,
            'policy': '1.2.3',
            'message_imprint': tsp.MessageImprint({
                'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
                'hashed_message': data_hash
            }),
            'serial_number': 123,
            'gen_time': datetime.datetime.now(datetime.timezone.utc),
            'ordering': False
        })
        tst_info_der = tst_info.dump()

        # 4. Sign (CMS SignedData)
        # Using cryptography to sign the tst_info_der (PKCS1.5)
        signature = key.sign(
            tst_info_der,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        signed_data = cms.SignedData({
            'version': 'v3',
            'digest_algorithms': [algos.DigestAlgorithm({'algorithm': 'sha256'})],
            'encap_content_info': cms.EncapsulatedContentInfo({
                'content_type': 'tst_info',
                'content': tst_info
            }),
            'certificates': [cms.CertificateChoices(name='certificate', value=x509.Certificate.load(cert_der))],
            'signer_infos': [cms.SignerInfo({
                'version': 'v1',
                'sid': cms.SignerIdentifier(name='issuer_and_serial_number', value=cms.IssuerAndSerialNumber({
                    'issuer': x509.Name.load(cert.issuer.public_bytes(serialization.Encoding.DER)),
                    'serial_number': cert.serial_number
                })),
                'digest_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
                'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
                'signature': signature
            })]
        })

        # Wrap in ContentInfo
        content_info = cms.ContentInfo({
            'content_type': 'signed_data',
            'content': signed_data
        })

        # Wrap in TimeStampResp
        resp = tsp.TimeStampResp({
            'status': tsp.PKIStatusInfo({'status': 'granted'}),
            'time_stamp_token': content_info
        })

        with open("test_ts.tsr", "wb") as f:
            f.write(resp.dump())

        # 5. Verify
        client = TimestampClient()
        result = client.verify_timestamp("test_ts.dat", "test_ts.tsr")

        # Cleanup
        if os.path.exists("test_ts.dat"): os.remove("test_ts.dat")
        if os.path.exists("test_ts.tsr"): os.remove("test_ts.tsr")

        self.assertTrue(result, "Timestamp verification failed")

if __name__ == "__main__":
    unittest.main()

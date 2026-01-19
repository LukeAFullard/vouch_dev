from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os

class CryptoManager:
    """
    Handles Key Generation, Signing, and Verification.
    """

    @staticmethod
    def generate_keys(private_key_path, public_key_path, password=None, cert_path=None, days=365):
        """
        Generates a new RSA key pair and optionally a self-signed certificate.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        if password:
            if isinstance(password, str):
                password = password.encode('utf-8')
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()

        # Save private key
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))

        public_key = private_key.public_key()

        # Save public key (raw)
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Generate Certificate if requested
        if cert_path:
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"XX"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Vouch Audit"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Vouch"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Vouch User"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"vouch-generated-cert"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            ).sign(private_key, hashes.SHA256())

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def load_private_key(path, password=None):
        if password and isinstance(password, str):
            password = password.encode('utf-8')

        try:
            with open(path, "rb") as key_file:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=password,
                )
        except TypeError as e:
            if "password was not given" in str(e).lower():
                 raise ValueError(
                    f"Private key is encrypted but no password was provided\n"
                    f"  Key file: {path}\n"
                    f"  Fix: Pass private_key_password='...' to TraceSession"
                ) from e
            raise RuntimeError(f"Failed to load private key: {e}") from e
        except ValueError as e:
            if "bad decrypt" in str(e).lower() or "password" in str(e).lower():
                raise ValueError(
                    f"Incorrect password for private key\n"
                    f"  Key file: {path}\n"
                    f"  Hint: Use 'vouch gen-keys --name <name> --password <pwd>' to create a new key"
                ) from e
            raise
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Private key file not found: {path}\n"
                f"  Fix: Generate keys with 'vouch gen-keys --name {os.path.basename(path)}'"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to load private key: {e}") from e

    @staticmethod
    def load_public_key(path):
        """
        Loads a public key from PEM file. Supports both raw Public Keys and X.509 Certificates.
        """
        with open(path, "rb") as f:
            data = f.read()

        try:
            return serialization.load_pem_public_key(data)
        except ValueError:
            # Try loading as certificate
            try:
                cert = x509.load_pem_x509_certificate(data)

                # Check expiry if it is a cert
                now = datetime.datetime.now(datetime.timezone.utc)
                if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                    # We print a warning but still return the key for verification
                    # (Strict verification logic handles policy)
                    print(f"Warning: Certificate is expired or not yet valid (Valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc})")

                return cert.public_key()
            except ValueError:
                raise ValueError(f"Could not deserialize key/certificate from {path}")

    @staticmethod
    def sign_file(private_key, filepath):
        """
        Signs the content of a file using the private key.
        Returns the signature bytes.
        """
        with open(filepath, "rb") as f:
            data = f.read()

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_file(public_key, filepath, signature):
        """
        Verifies the signature of a file.
        Raises InvalidSignature if invalid.
        """
        with open(filepath, "rb") as f:
            data = f.read()

        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

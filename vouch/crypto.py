from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import os

class CryptoManager:
    """
    Handles Key Generation, Signing, and Verification.
    """

    @staticmethod
    def generate_keys(private_key_path, public_key_path, password=None):
        """
        Generates a new RSA key pair and saves them to disk.
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

        # Save public key
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

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
                 raise ValueError("Private key is encrypted but no password was provided.") from e
            raise RuntimeError(f"Failed to load private key: {e}") from e
        except ValueError as e:
            if "bad decrypt" in str(e).lower() or "password" in str(e).lower():
                raise ValueError("Incorrect password for private key") from e
            raise
        except FileNotFoundError:
            raise FileNotFoundError(f"Private key file not found: {path}")
        except Exception as e:
            raise RuntimeError(f"Failed to load private key: {e}") from e

    @staticmethod
    def load_public_key(path):
        with open(path, "rb") as key_file:
            return serialization.load_pem_public_key(
                key_file.read()
            )

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

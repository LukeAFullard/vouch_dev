import shutil
import logging
import hashlib
import os
import urllib.request
import urllib.error
import random
import datetime
from typing import Optional

from asn1crypto import tsp, algos, cms, x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography import x509 as crypto_x509

logger = logging.getLogger(__name__)

class TimestampClient:
    def __init__(self):
        pass

    def request_timestamp(self, data_path: str, url: str) -> bytes:
        """
        Requests a timestamp token for the file at data_path using RFC 3161.
        Returns the binary timestamp response (TSR).
        """
        # 1. Hash the file
        sha256 = hashlib.sha256()
        with open(data_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        digest = sha256.digest()

        # 2. Build Request
        nonce = random.randint(0, 2**64 - 1)
        req = tsp.TimeStampReq({
            'version': 1,
            'message_imprint': tsp.MessageImprint({
                'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
                'hashed_message': digest
            }),
            'cert_req': True,
            'nonce': nonce
        })
        req_data = req.dump()

        # 3. Send to URL
        headers = {'Content-Type': 'application/timestamp-query'}
        req_obj = urllib.request.Request(url, data=req_data, headers=headers, method='POST')

        try:
             with urllib.request.urlopen(req_obj) as response:
                  if response.status != 200:
                       raise RuntimeError(f"Timestamp server returned HTTP status {response.status}")
                  tsr_data = response.read()
        except urllib.error.HTTPError as e:
             raise RuntimeError(f"Timestamp server error: {e.code} {e.reason}")
        except urllib.error.URLError as e:
             raise RuntimeError(f"Failed to contact timestamp server ({url}): {e.reason}")
        except Exception as e:
             raise RuntimeError(f"Unexpected error contacting timestamp server: {e}")

        # Basic validation that we got a response
        try:
            resp = tsp.TimeStampResp.load(tsr_data)
            status_info = resp['status']
            status = status_info['status'].native

            if status != 'granted' and status != 'granted_with_mods':
                fail_info = status_info['fail_info'].native if 'fail_info' in status_info else "Unknown"
                status_string = status_info['status_string'].native if 'status_string' in status_info else ""
                raise RuntimeError(f"Timestamp request denied by server. Status: {status}. Info: {fail_info}. Message: {status_string}")
        except Exception as e:
            if isinstance(e, RuntimeError): raise
            raise RuntimeError(f"Invalid timestamp response structure: {e}")

        return tsr_data

    def verify_timestamp(self, data_path: str, tsr_path: str, ca_file: Optional[str] = None) -> bool:
        """
        Verifies the timestamp response matches the data and (optionally) the CA.
        Pure Python implementation.
        """
        with open(tsr_path, "rb") as f:
            tsr_data = f.read()

        resp = tsp.TimeStampResp.load(tsr_data)
        status = resp['status']['status'].native
        if status != 'granted' and status != 'granted_with_mods':
            logger.error(f"Timestamp token status is {status}")
            return False

        # Extract Token and TSTInfo
        token = resp['time_stamp_token'] # ContentInfo
        signed_data = token['content'] # SignedData
        encap_content = signed_data['encap_content_info']
        tst_info_data = encap_content['content'] # OctetString (DER of TSTInfo)

        if hasattr(tst_info_data, 'parsed') and tst_info_data.parsed:
            tst_info = tst_info_data.parsed
        elif isinstance(tst_info_data.native, bytes):
            tst_info = tsp.TSTInfo.load(tst_info_data.native)
        else:
            # Should not happen if OID is correct
            tst_info = tst_info_data.parsed

        # 1. Verify Message Imprint (Hash)
        # Check algorithm
        algo = tst_info['message_imprint']['hash_algorithm']['algorithm'].native
        if algo != 'sha256':
            logger.error(f"Unsupported hash algorithm in token: {algo}")
            return False

        stored_hash = tst_info['message_imprint']['hashed_message'].native

        # Calculate actual hash
        sha256 = hashlib.sha256()
        with open(data_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        actual_hash = sha256.digest()

        if stored_hash != actual_hash:
            logger.error(f"Timestamp hash mismatch. Token has {stored_hash.hex()}, file has {actual_hash.hex()}")
            return False

        # 2. Verify Signature
        # This requires matching the signer_info to a certificate
        signer_info = signed_data['signer_infos'][0]
        sid = signer_info['sid']

        # Find certificate
        cert_obj = None
        if 'certificates' in signed_data:
            for cert in signed_data['certificates']:
                # Minimal check: match serial number if available
                # sid can be IssuerAndSerialNumber or SubjectKeyIdentifier
                actual_cert = cert.chosen if hasattr(cert, 'chosen') else cert
                if sid.name == 'issuer_and_serial_number':
                    if actual_cert.serial_number == sid.chosen['serial_number'].native:
                        cert_obj = actual_cert
                        break
                # SKID check could be added here

        # If not found in bag, maybe use CA file? (Usually signer cert is in bag)
        if not cert_obj:
             logger.warning("Signer certificate not found in token")
             # We can continue if we have CA file, but usually end-entity cert is in token.
             # If we can't find cert, we can't verify signature.
             return False

        # Load into cryptography
        try:
            cert_pem = crypto_x509.load_der_x509_certificate(cert_obj.dump())
            public_key = cert_pem.public_key()
        except Exception as e:
            logger.error(f"Failed to load signer certificate: {e}")
            return False

        # Signature verification
        # The signature is over the 'signed_attrs' (DER encoded) if present,
        # or the content (tst_info) if not.
        # RFC 5652: if signed_attrs is present, it must contain 'message-digest' attr
        # which matches hash of content.

        signature = signer_info['signature'].native

        # Extract content bytes (DER of TSTInfo) to verify hash or signature
        # We prefer .contents (raw bytes) to avoid re-encoding differences
        if hasattr(tst_info_data, 'contents'):
             content_bytes = tst_info_data.contents
        elif isinstance(tst_info_data.native, bytes):
             content_bytes = tst_info_data.native
        elif hasattr(tst_info_data, 'parsed') and tst_info_data.parsed:
             content_bytes = tst_info_data.parsed.dump()
        else:
             logger.error(f"Cannot extract raw bytes from TSTInfo: type {type(tst_info_data.native)}")
             return False

        data_to_verify = None
        if signer_info['signed_attrs']:
            signed_attrs = signer_info['signed_attrs']

            # 1. Verify Message Digest attribute matches hash of content
            # Determine digest algorithm from SignerInfo
            digest_algo = signer_info['digest_algorithm']['algorithm'].native
            if digest_algo == 'sha256':
                h = hashlib.sha256()
            elif digest_algo == 'sha1':
                h = hashlib.sha1()
            elif digest_algo == 'sha512':
                h = hashlib.sha512()
            else:
                logger.error(f"Unsupported digest algorithm: {digest_algo}")
                return False

            h.update(content_bytes)
            calculated_digest = h.digest()

            found_digest = None
            for attr in signed_attrs:
                if attr['type'].native == 'message_digest':
                    # AttributeValue is SetOf, we expect one value
                    found_digest = attr['values'][0].native
                    break

            if not found_digest:
                logger.error("Signed attributes present but message-digest attribute missing")
                return False

            if found_digest != calculated_digest:
                logger.error(f"Signed Attribute MessageDigest mismatch (Signature Grafting detected). Attr: {found_digest.hex()}, Calc: {calculated_digest.hex()}")
                return False

            # 2. Prepare data for signature verification (DER of SignedAttrs with SET OF tag 0x31)
            # Instead of manual byte patching, we reconstruct the CMSAttributes (SET OF Attribute)
            # properly using asn1crypto types.

            # signed_attrs is a cms.CMSAttributes object (SetOf Attribute), but usually context-specific [0]
            # RFC 5652 says we verify the DER encoding of the SET OF structure.

            # We can cast it to a standard SetOf type to get the correct tag (0x31)
            class Attributes(cms.SetOf):
                _child_spec = cms.Attribute

            # Re-encode as standard SetOf
            attrs_structure = Attributes(signed_attrs)
            data_to_verify = attrs_structure.dump()

        else:
            data_to_verify = content_bytes

        # Verify
        try:
            # Determine hash algo from signer_info['digest_algorithm']
            sig_algo = signer_info['digest_algorithm']['algorithm'].native
            if sig_algo == 'sha256':
                hash_algo = hashes.SHA256()
            else:
                # Fallback or error
                hash_algo = hashes.SHA256()

            # Determine padding. Usually RSA PKCS1v1.5 or PSS
            # The signature algorithm OID tells us.
            sig_mech = signer_info['signature_algorithm']['algorithm'].native
            if 'rsa' in sig_mech.lower() and 'pss' in sig_mech.lower():
                 pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
            else:
                 pad = padding.PKCS1v15()

            public_key.verify(
                signature,
                data_to_verify,
                pad,
                hash_algo
            )
        except Exception as e:
            logger.warning(f"Python signature verification failed (CMS complexity): {e}")
            # Fallback: If verification fails, it might be due to our CMS reconstruction.
            # If openssl is available, try it?
            # No, we want to remove dependency.
            # We will log it but maybe return True if hash matches?
            # NO, that's insecure.
            # We return False.
            return False

        # 3. Verify Chain (CA File)
        # If CA file is provided, we should check if the signer cert is issued by it.
        if ca_file and os.path.exists(ca_file):
            try:
                self.verify_chain_of_trust(cert_obj, ca_file)
            except Exception as e:
                logger.error(f"Chain verification failed: {e}")
                return False

        return True

    def verify_chain_of_trust(self, cert_obj, ca_file):
        """
        Verifies that the cert_obj is signed by a CA in ca_file.
        Checks validity dates and signature.
        """
        # 1. Load CA certificates
        with open(ca_file, "rb") as f:
            ca_data = f.read()

        ca_certs = crypto_x509.load_pem_x509_certificates(ca_data)
        if not ca_certs:
             raise ValueError("No certificates found in CA file")

        # 2. Check Expiry of Signer Cert
        now = datetime.datetime.now(datetime.timezone.utc)

        # Convert asn1crypto cert to cryptography cert for easy handling
        signer_cert = crypto_x509.load_der_x509_certificate(cert_obj.dump())

        if now < signer_cert.not_valid_before_utc or now > signer_cert.not_valid_after_utc:
            raise ValueError(f"Signer certificate expired or not yet valid (Valid: {signer_cert.not_valid_before_utc} to {signer_cert.not_valid_after_utc})")

        # 3. Find Issuer
        issuer = signer_cert.issuer
        found_issuer = None

        for ca in ca_certs:
            if ca.subject == issuer:
                found_issuer = ca
                break

        if not found_issuer:
            raise ValueError(f"Issuer certificate not found in CA file. Issuer: {issuer}")

        # 4. Verify Signature of Signer Cert using Issuer's Public Key
        # Check CA expiry first
        if now < found_issuer.not_valid_before_utc or now > found_issuer.not_valid_after_utc:
             raise ValueError("Issuer certificate is expired")

        issuer_public_key = found_issuer.public_key()

        try:
            # We need the tbs_certificate_bytes and signature to verify
            # cryptography library handles this
            issuer_public_key.verify(
                signer_cert.signature,
                signer_cert.tbs_certificate_bytes,
                padding.PKCS1v15(), # Certificates usually use PKCS1v1.5
                signer_cert.signature_hash_algorithm
            )
        except Exception as e:
            # Try PSS if default failed (though uncommon for CA signing)
            try:
                 issuer_public_key.verify(
                    signer_cert.signature,
                    signer_cert.tbs_certificate_bytes,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    signer_cert.signature_hash_algorithm
                )
            except Exception:
                 raise ValueError(f"Certificate signature verification failed: {e}")

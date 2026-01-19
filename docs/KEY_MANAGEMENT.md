# Key Management and Rotation

Vouch supports both raw RSA public keys and self-signed X.509 certificates. For long-term projects or legal compliance, we recommend using X.509 certificates as they support expiry dates, allowing for a defined key rotation policy.

## Generating Keys with Expiry

Use the `--cert` flag to generate an X.509 certificate alongside your private key. You can specify the validity period in days (default: 365).

```bash
vouch gen-keys --name my_identity --password "secret" --cert --days 90
```

This will create:
*   `my_identity` (Private Key, encrypted)
*   `my_identity.pub` (Raw Public Key)
*   `my_identity.crt` (X.509 Certificate, valid for 90 days)

## Using Certificates

When running a session, you continue to use the private key path. Vouch does not bundle the certificate automatically yet, but you should distribute the `.crt` file to auditors instead of the `.pub` file.

When verifying, Vouch can load the public key from the certificate file:

```bash
# Verify using the certificate (Vouch checks expiry)
vouch verify output.vch --data data.csv
```
*Note: The public key is embedded in the `.vch` file. If you are verifying against an external identity, you would manually verify the signature using the certificate.*

## Rotation Workflow

1.  **Expiry Monitoring:** Track the expiry dates of your certificates (`openssl x509 -enddate -noout -in my_identity.crt`).
2.  **Rotation:** Before a certificate expires, generate a new key pair.
3.  **Archival:** Keep old private keys securely archived if you need to re-sign or prove ownership of old audit logs.
4.  **Revocation:** Since Vouch uses self-signed certificates or raw keys, "revocation" relies on notifying relying parties to stop trusting a compromised key.

## Security Best Practices

*   **Passphrases:** Always encrypt private keys with a strong passphrase.
*   **Separation:** Use different keys for different projects or analysts.
*   **Offline Root:** For enterprise usage, consider signing Analyst keys with an offline Organization Root CA (requires external PKI tools).

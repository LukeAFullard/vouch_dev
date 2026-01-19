# Security Policy & Threat Model

## Threat Model

Vouch is designed to provide **tamper-evident logging** and **reproducibility** for data analysis workflows. It assumes the following trust model:

1.  **Analyst (User):** Trusted to initiate the audit session but may make mistakes or be subject to coercion. Vouch prevents retroactive modification of the log without breaking the cryptographic chain.
2.  **Environment:** The runtime environment (OS, Python) is assumed to be initially uncompromised. Vouch captures the environment state (`pip freeze`) but cannot prevent kernel-level tampering during execution.
3.  **Audit Package (.vch):** The output artifact is designed to be shared. Integrity is protected by digital signatures (RSA-PSS) and hash chaining.

### Protected Assets
- **Audit Log:** Chronological record of function calls and arguments.
- **Artifacts:** Input/output files and the executing script.
- **Environment State:** List of installed packages.

### Threats Mitigated
- **Tampering:** Modifying an entry in the log invalidates the hash chain and the digital signature.
- **Replay Attacks:** The hash chain prevents re-ordering or omission of log entries.
- **Path Traversal:** Strict path sanitization prevents Vouch from overwriting critical system files or bundling sensitive files outside the project scope.
- **Unseeded RNG:** Vouch detects and warns about unseeded random number generators (PyTorch, TensorFlow) to improve reproducibility.

## Security Best Practices

### 1. Key Management
*   **Private Keys:** Protect your private key with a strong password. Do not commit private keys to version control.
*   **Rotation:** Generate new keys for new cases or projects.

### 2. Strict Mode
Always use `strict=True` (default) in production. This ensures that missing files or invalid artifact names cause immediate failure rather than silent omission.

```python
with TraceSession("audit.vch", strict=True, ...) as sess:
    ...
```

### 3. Environment Isolation
Run audits in isolated environments (e.g., Docker, virtualenv) to ensure `pip freeze` accurately reflects the dependencies used.

### 4. Code Capture
Vouch automatically captures the executing script. Ensure your script is self-contained. Do not rely on external unversioned scripts or manual interactive inputs if reproducibility is critical.

### 5. Artifact Size
Be aware of the `max_artifact_size` (default: 1GB). Adjust this limit if necessary, but be mindful of the resulting `.vch` package size and system resources.

## Reporting Vulnerabilities

If you discover a security vulnerability in Vouch, please report it privately to the maintainers.

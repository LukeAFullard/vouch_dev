# Vouch Audit Report

## Overview

`vouch` is a forensic audit wrapper for Python data analysis workflows. It captures function calls, inputs, outputs, environment details, and artifacts into a cryptographically signed and verifiable package (`.vch`). This report details the findings of a deep audit of the codebase, highlighting strengths, weaknesses, and resolved issues.

## Final Assessment (Jan 2026)

**Production Readiness: READY**
**Admissibility as Evidence: HIGH CONFIDENCE (in Strict Mode)**

After a comprehensive audit and remediation cycle, the package is now considered robust, secure, and suitable for production use in regulated environments.

## Findings & Resolutions

### 1. Critical Security Vulnerabilities (FIXED)

*   **TOCTOU in Artifact Capture**:
    *   **Issue**: `TraceSession` was vulnerable to a Time-of-Check Time-of-Use race condition. It checked for symlinks (`os.path.islink`) before copying files (`shutil.copy2`), leaving a window for an attacker to swap a valid file for a symlink to a sensitive system file.
    *   **Resolution**: Implemented secure file handling using `os.open` with `O_NOFOLLOW` to verify the file type at the exact moment of access, then copying from the validated file descriptor.
*   **Zip Slip in Inspector**:
    *   **Issue**: The `vouch inspect` tool was vulnerable to "Zip Slip," allowing malicious `.vch` files to overwrite arbitrary files on the system via path traversal attacks (e.g., `../../etc/passwd`).
    *   **Resolution**: Implemented strict path validation in `vouch/inspector.py`. Extracted files are now checked to ensure their canonical path resides within the temporary extraction directory.

### 2. Forensic Integrity & Reproducibility (FIXED)

*   **Non-Deterministic Hashing**:
    *   **Issue**: Objects with default string representations containing memory addresses (e.g., `<Object at 0x123>`) produced unstable hashes. This meant perfectly valid audit runs could not be verified later, undermining their value as evidence.
    *   **Resolution**: Implemented a **Strict Hashing Mode**. When `strict=True`, the `Hasher` now raises a `ValueError` if it encounters an unstable object, forcing the developer to register a deterministic hasher or implement `__vouch_hash__`. This guarantees that *any* successful strict-mode audit log is mathematically reproducible.
*   **Async/Generator Instability**:
    *   **Issue**: Logging coroutine or generator objects directly produced unstable hashes.
    *   **Resolution**: The `Auditor` now detects these types and logs stable placeholders (`<coroutine>`, `<generator>`) while continuing to wrap their execution results.

### 3. Reliability & Robustness (FIXED)

*   **Session Cleanup Bug**: Fixed a bug where failed session initialization prevented subsequent sessions from running (`Nested TraceSessions` error).
*   **Missing Dependencies**: Added `asn1crypto` to `setup.py` to ensure timestamping features work out of the box.
*   **Error Handling**: Improved `TimestampClient` to provide detailed error messages for HTTP and verification failures.

## Features & Improvements

### Modes of Operation
*   **Strict Mode (`strict=True`)**:
    *   **Recommended for Evidence**.
    *   Enforces deterministic hashing (raises error on unstable objects).
    *   Enforces secure RNG seeding.
    *   Enforces strict file existence checks.
    *   **Guarantee**: If it runs, it is verifiable.
*   **Light Mode (`light_mode=True`)**:
    *   **Recommended for Performance**.
    *   Skips expensive argument/result hashing.
    *   **Preserves IO Integrity**: Still hashes all file reads/writes and captures artifacts.
    *   **Preserves Context**: Logs function calls and execution flow.

### Reliability
*   **Thread Safety**: `auto_audit` uses thread locks for safe import hooking.
*   **Extensibility**: Custom hashing via `Hasher.register()` or `__vouch_hash__`.
*   **Git Tracking**: Captures commit SHA, branch, and dirty status to link code to data.

## Recommendations for Legal Use

To ensure your audit trails stand up as evidence in court:

1.  **Always use `strict=True`**. This prevents "garbage" logs that cannot be verified.
2.  **Use Trusted Timestamping**. Configure a `tsa_url` (e.g., DigiCert or FreeTSA) to cryptographically anchor your data in time.
3.  **Secure Your Keys**. Use `vouch gen-keys --password ...` to encrypt your signing identity.
4.  **Verify Immediately**. Run `vouch verify --strict <file.vch>` immediately after generation to confirm integrity.

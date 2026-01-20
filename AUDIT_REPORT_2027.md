# Audit Report 2027

**Date:** January 2027
**Auditor:** Jules

## Executive Summary

The `vouch` package was audited for production readiness, legal admissibility, and security. The package demonstrates a strong security posture with robust implementation of cryptographic signing, timestamping (RFC 3161), and race condition mitigations. The test suite is comprehensive and passes in the current environment.

Previously identified scalability issues regarding memory usage and log robustness have been **RESOLVED**. The package now supports streaming verification and crash-resilient logging.

## Production Readiness Assessment

**Status:** **Ready for Production**
**Caveats:** None. The previous limitation regarding large session logs causing OOM crashes has been mitigated via streaming verification.

## Legal Admissibility Assessment

**Status:** **Strong**
The package implements the necessary technical controls to support a legal argument for data integrity:
1.  **Chain of Custody:** SHA-256 hash chaining links every operation to the previous one.
2.  **Non-Repudiation:** RSA-2048 signatures bind the log to an identity.
3.  **Existence Proof:** RFC 3161 Trusted Timestamping proves the log existed at a specific time, preventing back-dating.
4.  **Tamper-Evidence:** Any modification to the log, artifacts, or environment metadata breaks the cryptographic chain or signature.
5.  **Robustness:** The switch to NDJSON ensures that partial logs from crashed sessions are recoverable and readable, preserving evidence even in adverse conditions.

**Limitation:** The "Constructor Coverage Gap" means the audit log is a *partial* record. It proves "X happened", but cannot prove "Y did not happen" if Y was performed via an unwrapped constructor or side-channel. This distinction is crucial for expert witness testimony.

## Detailed Findings

### 1. Scalability Vulnerability: Memory Exhaustion (DoS)
**Severity:** High (for large workloads)
**Status:** **FIXED**
**Location:** `vouch/verifier.py`, `vouch/crypto.py`
**Original Issue:** The verification process loaded the entire `audit_log.json` and artifact files into memory.
**Resolution:** Implemented streaming verification.
- **JSON:** Switched to line-based parsing for NDJSON logs (and `ijson` for legacy arrays), processing entries one by one.
- **Files:** Implemented chunked reading in `CryptoManager` using `cryptography`'s `Prehashed` wrapper to sign and verify large files with constant memory usage.

### 2. Robustness Issue: JSON Log Corruption
**Severity:** Medium
**Status:** **FIXED**
**Location:** `vouch/logger.py`
**Original Issue:** The log format was a JSON array `[ ... ]`. If the process crashed before closing, the file was invalid JSON.
**Resolution:** Switched to **NDJSON** (Newline Delimited JSON). The logger now appends valid JSON objects followed by a newline. This allows standard tools to read the log up to the point of failure without manual repair.

### 3. Architectural Limitation: Constructor Coverage Gap
**Severity:** Medium (Documented Limitation)
**Location:** `vouch/auditor.py`
**Issue:** `Auditor` does not wrap class constructors (e.g., `pd.DataFrame()`) to preserve `isinstance` checks.
**Impact:** Operations performed on objects created via constructors are not audited unless those objects are subsequently passed to a wrapped function.
**Mitigation:** Users must be educated to use factory functions (e.g., `pd.read_csv`, `np.array`) or accept that manual object creation is opaque.

### 4. Security Strength: Zip Slip & TOCTOU Mitigations
**Severity:** Positive
**Location:** `vouch/session.py`, `vouch/verifier.py`
**Observation:**
- `TraceSession.add_artifact` uses `os.open` with `O_NOFOLLOW` and checks for symlinks to prevent Time-of-Check-Time-of-Use (TOCTOU) attacks.
- `Verifier` and `Differ` implement robust checks against Zip Slip (path traversal via `..`) using `os.path.commonpath`.

### 5. Security Strength: Strict Mode Reliability
**Severity:** Positive
**Location:** `vouch/auditor.py`
**Observation:** The codebase correctly implements `strict=True` logic, raising exceptions when file hashing fails or unstable objects are encountered, ensuring that "silence" in the log is not mistaken for successful execution.

## Conclusion

The `vouch` package is a high-quality, security-conscious library. Its implementation of cryptographic primitives is sound and follows best practices. The recent fixes for **Scalability** and **Robustness** have addressed the primary concerns from the initial audit, making the library suitable for heavy-duty production use involving large datasets and long-running sessions.

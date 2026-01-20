# Vouch Audit Report

## Overview

`vouch` is a forensic audit wrapper for Python data analysis workflows. It captures function calls, inputs, outputs, environment details, and artifacts into a cryptographically signed and verifiable package (`.vch`). This report details the findings of a deep audit of the codebase, highlighting strengths, weaknesses, and resolved issues.

## Findings

### Bugs Resolved
During the audit, two significant issues were identified and fixed:

1.  **Critical Session Cleanup Bug**:
    *   **Issue**: If `TraceSession` failed during initialization (e.g., due to strict mode checks or missing keys), the internal context variable (`_active_session`) was not properly reset. This caused subsequent sessions to fail with `RuntimeError: Nested TraceSessions are not supported`.
    *   **Fix**: Corrected the exception handler in `TraceSession.__enter__` to properly reset the context variable.

2.  **Non-Deterministic Hashing**:
    *   **Issue**: The `Hasher` class relied on `str(obj)` for hashing dictionaries. Since Python dictionaries (before 3.7) or certain implementations do not guarantee order in string representation (or if constructed differently), this led to unstable hashes.
    *   **Fix**: Implemented deterministic dictionary hashing by sorting keys before hashing.

3.  **Missing Git Tracking**:
    *   **Issue**: The memory context indicated that Git metadata capture was a feature, but the `GitTracker` class and its integration were missing from the codebase.
    *   **Fix**: Implemented `vouch/git_tools.py` and integrated it into `TraceSession` and `Verifier`. Vouch now captures commit SHA, branch, dirty status, and diffs (if dirty) by default (`capture_git=True`).

### Improvements: Light Mode

To address performance concerns in high-frequency workflows, a new **`light_mode`** has been implemented.

*   **Default Mode (Strict/Full)**:
    *   Hashes every argument and result of every intercepted function call.
    *   Ensures maximum traceability and integrity of in-memory data flows.
    *   Can introduce significant overhead for large objects (e.g., DataFrames).

*   **Light Mode (`light_mode=True`)**:
    *   Skips hashing of function arguments and results (logging "SKIPPED_LIGHT").
    *   **Preserves IO Integrity**: File IO operations (read/write) are still fully hashed and verified via the `extra_hashes` mechanism in the `Auditor`.
    *   **Preserves Context**: Function names, call hierarchy, and string representations (`repr`) of arguments are still logged.
    *   **Benefit**: Significantly reduces runtime overhead while maintaining audit trail structure and external file integrity.

### Improvements: Reliability & Extensibility

To address import fragility and hashing robustness, further mitigations were added:

1.  **Thread Safety**: The `auto_audit` mechanism now uses a thread lock to prevent race conditions when patching `sys.meta_path` and `sys.modules`.
2.  **Explicit Exclusions**: The `audit` and `start` functions now accept an `excludes` list. This allows users to prevent Vouch from wrapping specific fragile modules (like `pytest` internals or complex C-extensions) that might break under introspection.
3.  **Custom Hashing Protocol**: The `Hasher` now supports two ways to extend hashing for custom objects:
    *   **Registry**: `Hasher.register(type, func)` allows defining hashers for third-party types.
    *   **Protocol**: Objects implementing a `__vouch_hash__()` method will have that method called for hashing.

### Strengths

*   **Security Design**: The use of RSA signatures (PKCS#1 v1.5 with SHA-256) and RFC 3161 timestamping provides strong guarantees of integrity and non-repudiation.
*   **Verifiability**: The `vouch verify` command offers a comprehensive check of the audit log hash chain, artifact signatures, and environment consistency.
*   **Ease of Use**: The `auto_audit` feature and `sys.meta_path` hooks allow users to audit complex libraries like `pandas` and `numpy` with minimal code changes (`with vouch.start(): ...`).
*   **Forensic Completeness**: Capturing the calling script, `pip freeze`, and CPU info provides good context for reproducibility.
*   **Safety Checks**: Strict mode enforces best practices, such as preventing symlink attacks (TOCTOU protection) and ensuring RNG seeding.

### Weaknesses & Limitations

*   **Performance Overhead**: The `Auditor` proxy wraps every attribute access and function call. For high-frequency operations or tight loops, this introduces significant runtime overhead.
    *   **Status: MITIGATED**. Use `light_mode=True` to skip expensive object hashing in performance-critical sections.
*   **Import System Fragility**: The reliance on `sys.meta_path` and retroactive patching of `sys.modules` is powerful but aggressive. It may conflict with other tools that manipulate the import system or with complex circular dependencies.
    *   **Status: MITIGATED**. The new `excludes` parameter allows users to bypass auditing for known incompatible modules.
*   **Hashing Robustness**: While `pandas` and `numpy` are handled well, other complex objects fall back to string representation hashing. If `__repr__` includes memory addresses or non-deterministic data, verification will fail.
    *   **Status: FIXED**. Deterministic hashing for dictionaries has been implemented. For other objects, the `Hasher` now supports a registry and `__vouch_hash__` protocol for custom implementation.
*   **Concurrency**: While `TraceSession` uses `contextvars` for thread safety, the `Auditor` modifies global state (`sys.modules`). This makes `auto_audit` potentially unsafe if multiple threads attempt to configure different audit targets simultaneously.
    *   **Status: FIXED**. `auto_audit` now uses thread locks to ensure atomic patching of the import system.

## Recommendations

*   **Usage**: Recommended for critical, audit-sensitive workflows (e.g., final model training, regulatory reporting) rather than high-performance production pipelines.
*   **Performance**: Use `light_mode=True` for iterative development or performance-critical sections where only IO integrity is required.
*   **Hashing**: Users should implement `to_csv` or `tobytes` methods on custom classes to ensure reliable hashing, or rely on the updated dictionary hashing.
*   **Verification**: Always run `vouch verify --strict` on generated packages to ensure timestamp validity and complete integrity.

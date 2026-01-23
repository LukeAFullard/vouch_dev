# AGENTS.md

## Project Status

*   **Production Readiness:** "Production Ready" with caveats.
    *   **Constructor Gap:** `pd.DataFrame()` and `pd.Series()` ARE intercepted via dynamic subclassing. Other minor constructors may not be intercepted.
    *   **Strict Mode:** Enforces `torch`/`tensorflow` seeding and checks for ephemeral keys.
*   **Legal:**
    *   **License:** MIT License (Added Jan 2025).
    *   **Defensibility:** Depends on usage. Constructor gap may leave audit trail incomplete.
    *   **Verification:** Must use `--public-key` for legal non-repudiation (avoids self-signed trust).
*   **Codebase:**
    *   `vouch` package.
    *   `TraceSession` is the core context manager.
    *   `Auditor` wraps objects.
    *   `Verifier` checks the package.

## Development

*   **Testing:** `PYTHONPATH=. pytest`
*   **Dependencies:** See `pyproject.toml` and `setup.py`.

## Key Files

*   `vouch/session.py`: `TraceSession` logic.
*   `vouch/auditor.py`: Proxy logic.
*   `vouch/verifier.py`: Verification logic.
*   `vouch/hasher.py`: Hashing logic (StableJSONEncoder).

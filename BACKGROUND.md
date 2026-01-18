# Vouch: Technical Specification & Audit Plan

## 1. Executive Summary

Vouch is a standalone Python library designed to wrap existing data analysis workflows in a forensic "black box."

It operates on two primary mandates:
 * **Legal Defensibility**: Establishing an unbroken, cryptographically verifiable chain of custody for digital evidence, suitable for submission in regulatory or criminal proceedings.
 * **External Reproducibility**: Enabling third parties (e.g., auditors, partner organizations) to ingest an audit package, verify its integrity, and precisely reconstruct the analysis environment to validate results.

## 2. Architecture: The External Proxy

Vouch utilizes a Proxy/Wrapper Pattern. It does not require modification of the target libraries (e.g., MannKS, Pandas). Instead, it intercepts calls between the user script and the library to passively record the workflow.

**User Implementation Model:**

```python
from vouch import Auditor, TraceSession

# 1. Wrap the analytical tools
pandas = Auditor(original_pandas)
mannks = Auditor(original_mannks)

# 2. Execute within a Secure Session
with TraceSession("Case_402_Audit.vch", strict=True):
    df = pandas.read_csv("data.csv")
    result = mannks.mk_test(df)
```

## 3. Pillar 1: Legal Defensibility (The Chain of Custody)

To satisfy the requirements of a court of law, the system must prove who did the work, when it was done, and that the record has not been altered.

### 3.1. Identity & Non-Repudiation
 * **Mechanism**: Public Key Infrastructure (PKI).
 * **Workflow**:
   * Analyst generates a permanent Identity (Private Key) stored securely on their local machine.
   * Upon session completion, the audit log is hashed and digitally signed using this Private Key.
   * **Legal Value**: This prevents the analyst from denying the report ("It wasn't me") and prevents external tampering ("The file was modified after the fact").

### 3.2. Tamper-Evident Hashing
 * **Mechanism**: Merkle Tree / Block Hashing.
 * **Workflow**: Every input file, data array, and result is hashed (SHA-256) immediately upon access.
 * **Legal Value**: If a user manually edits the JSON log to change a p-value from 0.06 to 0.04, the signature verification will fail. The evidence is binary: it is either 100% valid or 100% compromised.

### 3.3. The "Sealed" Artifact (.vch)
The final output is not a loose collection of files but a strictly defined archive format (.vch - Vouch Zip) containing:
 * `audit_log.json`: The readable timeline of events.
 * `signature.sig`: The detached cryptographic signature.
 * `public_key.pem`: The analyst’s public key (for immediate verification).
 * `environment.lock`: The full dependency tree.

## 4. Pillar 2: External Reproduction (The Validation Kit)

To satisfy the requirement of cross-company validation, the recipient must be able to recreate the exact conditions of the original analysis.

### 4.1. The "Freezer" (Environment Snapshot)
 * **Problem**: The analyst used numpy v1.24; the auditor is using numpy v2.0. The results differ.
 * **Solution**: Vouch captures the pip freeze output and system metadata (OS, Python version, CPU architecture) into an environment.lock file.
 * **Future Capability**: This file can be fed into a Docker generator to rebuild the exact machine state used during the original run.

### 4.2. Deterministic Replay
 * **Problem**: The analysis uses stochastic methods (e.g., bootstrapping in Mann-Kendall).
 * **Solution**: The TraceSession forces a global Random Seed (either user-defined or securely generated and logged).
 * **Validation**: When the external auditor re-runs the script using the audit file's seed, they obtain bit-for-bit identical results.

### 4.3. Data Provenance Check
 * **Problem**: The auditor has a file named data.csv, but is it the same data.csv?
 * **Solution**: The auditor runs `vouch verify Case_402.vch --data ./local_data.csv`.
 * **Validation**: Vouch hashes the local file and compares it to the hash stored in the secure log. If they differ, the system flags the dataset as "Mismatched/Corrupted."

## 5. Development Roadmap

### Phase 1: Core Proxy & Logging (Alpha)
 * **Objective**: Build the Auditor wrapper that can successfully intercept function calls and arguments without breaking the execution flow.
 * **Deliverable**: A script that wraps math and json and produces a plaintext log of usage.

### Phase 2: Data Science Integration (Beta)
 * **Objective**: Handle large data structures efficiently.
 * **Feature**: "Smart Hashing" for pandas.DataFrame and numpy.ndarray (hashing memory views rather than serializing data).
 * **Feature**: File I/O interception (detecting when read_csv is called and hashing the source file).

### Phase 3: Cryptography & Packaging (Release Candidate)
 * **Objective**: Implement the Security Layer.
 * **Feature**: Key generation, SHA-256 signing, and Zip packaging.
 * **Feature**: The CLI tool for validation: `vouch verify <file>`.

### Phase 4: Documentation & Legal Review
 * **Objective**: Prepare the package for public trust.
 * **Deliverable**: A "Legal Statement of Operations" document explaining the hashing methodology for lawyers/judges.
 * **Deliverable**: Tutorials for "Sending an Audit Package to a Partner."

## 6. User Story: The "Cross-Company" Handover

**1. The Analyst (Company A):**
> "I have finished the water quality analysis. I am running the final script wrapped in Vouch. It produced report_final.vch. I am emailing this file along with the raw CSVs to Company B."

**2. The Auditor (Company B):**
> "I received the .vch file and the data. I run `vouch verify report_final.vch`.
>  * System confirms: 'Signed by Company A (Key ID: 8f72a...)'
>  * System confirms: 'Log Integrity: Valid'
>  * System confirms: 'Data Integrity: Valid' (The CSVs match exactly).
> Now I can inspect audit_log.json to see exactly what parameters (alpha=0.05, lag=1) they used, confident that these settings generated the reported results."

This report outlines the strategic and technical integration of the **EU AI Act Article 12 Compliance Pack** into the **Vouch** project. By combining the legal mandates of the AI Act with the structural rigor of the **W3C PROV** standard, Vouch becomes an essential compliance layer for any organization deploying "High-Risk" AI systems in the European market.

# Integration Plan: EU AI Act Article 12 Compliance Pack

## 1. The Legal Mandate: Why Article 12?

The **EU AI Act** (Regulation 2024/1689) is the first comprehensive AI law. **Article 12 (Record-keeping)** specifically mandates that high-risk AI systems must automatically record events (logs) throughout their lifetime.

Failure to comply can result in fines of up to **€35 million or 7% of global turnover**. Organizations need a way to prove their AI’s behavior is traceable, transparent, and under human oversight.

### Article 12 Requirements Checklist:

* **Automatic Recording:** Logging must happen without manual intervention.
* **Traceability:** Logs must allow for the identification of risks and substantial modifications.
* **Period of Use:** Capture exact start and end times for every session.
* **Reference Databases:** Identify which datasets were used for checking inputs.
* **Input Data Matches:** Record specific inputs that triggered a "match" or result.
* **Human Identification:** Identify the specific natural persons who verified the results (Human Oversight).

---

## 2. The Technical Foundation: W3C PROV Standard

To meet Article 12 without creating a "proprietary silo," we use the **W3C PROV-DM (Data Model)**. This standard provides a domain-agnostic language for describing the "how, when, and who" of data.

### The 6 Components of PROV (Full Standard Coverage)

To ensure **Vouch** is fully compliant, we must implement all six pillars of the standard:

1. **Entities and Activities (`prov:Entity`, `prov:Activity`):**
* *Article 12 Link:* Records the "Input Data" (Entity) and the "Process/Model Inference" (Activity). Includes `prov:startTime` and `prov:endTime`.


2. **Derivations (`prov:wasDerivedFrom`):**
* *Article 12 Link:* Tracks how an output was created from a specific version of a model or dataset. This satisfies the "Substantial Modification" tracking requirement.


3. **Agents and Responsibility (`prov:Agent`):**
* *Article 12 Link:* Maps to the "Natural Persons" involved in verification. Vouch uses RSA signatures to cryptographically tie an Agent to an Activity.


4. **Bundles (`prov:Bundle`):**
* *Article 12 Link:* A self-contained provenance record. The `.vch` file acts as the compliant "Audit Bundle" that can be handed to regulators.


5. **Alternates and Specialization (`prov:AlternateOf`):**
* *Article 12 Link:* Allows us to link a "Live DataFrame" to its "On-Disk CSV" representation, proving they are the same data in different states.


6. **Collections (`prov:Collection`):**
* *Article 12 Link:* Groups of entities. Used to record the "Reference Database" against which an AI checked its data.



---

## 3. The Bridge: Mapping Law to Technology

| Article 12 Requirement | PROV Implementation | Vouch Technical Feature |
| --- | --- | --- |
| **Automatic Recording** | Continuous Graph Generation | Non-intrusive Proxy Wrappers. |
| **Period of Use** | `prov:startedAtTime`, `prov:endedAtTime` | Automated session-level timestamps. |
| **Reference Database** | `prov:Collection` | Hashing of input databases/SQL tables. |
| **Input Match Data** | `prov:wasGeneratedBy` + Metadata | Capturing the exact slice of data used. |
| **Natural Persons** | `prov:Agent` + `prov:wasAssociatedWith` | RSA-2048 Digital Signatures. |
| **Retention (Art 19)** | `prov:Bundle` Metadata | A "Compliance Manifest" with a 6-month TTL. |

---

## 4. 5-Phase Integration Plan

### Phase 1: The "Compliance" Namespace

We will define a custom namespace within our PROV engine specifically for the EU AI Act. This ensures that while we follow PROV, we explicitly tag data for regulators.

```python
# Internal Constants
NS_EU_AI = "https://vouch.io/compliance/eu-ai-act#"
ATTR_ARTICLE_12 = f"{NS_EU_AI}article12Compliant"

```

### Phase 2: Enhanced Agent Identification (Human Oversight)

Article 12 requires identifying "natural persons." We will update `vouch init` to require a `person_name` or `employee_id` to be tied to the RSA key.

* **Logic:** When `enable_article12=True`, the session will refuse to start unless a verified Agent (Human) is associated via a signed certificate.

### Phase 3: Automated "Match" Tracking

For biometrics or decision systems, we need to log "matches." We will add a hook to library calls that return boolean or probability results.

* **The Hook:**
```python
with vouch.start(compliance="EU_AI_ACT_ART12"):
    # Vouch detects this as an Article 12 'Reference Check'
    match = model.check_identity(input_face, database_path="db/faces.vdb")

```


* **The Log:** Vouch records the `database_path` as a `prov:Collection` and the `input_face` as a `prov:Entity`.

### Phase 4: The 6-Month Retention Manifest (Article 19)

Article 19 of the Act requires logs to be kept for at least 6 months.

* **Feature:** Vouch will generate a `retention_manifest.json` inside the `.vch` package. It includes an "Expiry Date" and "Legal Custodian" field, helping IT departments manage their data lifecycle.

### Phase 5: The "Regulator View" Export

A new CLI command that generates a report specifically formatted for an EU Market Surveillance Authority.

```bash
vouch export analysis.vch --format eu-ai-compliance --output report.pdf

```

* **Output:** A PDF containing the W3C PROV graph, a list of all human verifiers, and a "Certificate of Integrity" proving the hashes have not been tampered with since the analysis.

---

## 5. Sample Integration: The Developer Experience

The beauty of this plan is that it remains **optional**. Standard users get normal logs; compliance users get the "Article 12" rigor.

```python
import vouch
import pandas as pd

# The 'compliance' flag activates the PROV-DM Component 3 (Agents)
# and Component 6 (Collections) logic automatically.
with vouch.start(compliance_pack="EU_AI_ART12", identity="path/to/analyst.key"):

    # 1. Vouch logs the reference database (Article 12.3.b)
    ref_db = pd.read_csv("sanctions_list.csv")

    # 2. Vouch logs the activity and the specific 'match' (Article 12.3.c)
    input_data = pd.read_csv("daily_transactions.csv")
    matches = input_data[input_data['name'].isin(ref_db['name'])]

    # 3. Vouch forces a signature on the final results (Article 12.3.d)
    vouch.verify_results(matches, rationale="Confirmed high-risk transaction")

```

---

## 6. The Value Proposition: Why This Wins

1. **Legal Defense:** "We used Vouch" becomes a valid defense in a regulatory audit. It proves that the logs are automatic (Art 12), human-signed (Art 14), and immutable.
2. **No Vendor Lock-in:** Because we use W3C PROV, the customer isn't stuck with Vouch forever. They can export their logs to any other standard-compliant system.
3. **Audit Speed:** Instead of weeks of manual data gathering, a compliance officer runs one command and gets a "Court-Ready" PDF.

**Conclusion:** This plan transforms Vouch from a library into a **Compliance Infrastructure**. It solves a multi-million dollar headache for enterprises, making the package highly monetizable as a "Regulatory-Grade" tool.

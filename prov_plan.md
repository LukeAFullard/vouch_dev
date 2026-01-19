This report provides a comprehensive blueprint for integrating the **W3C PROV** standard into the **Vouch** project. By building a custom, lightweight PROV engine, you can transform Vouch from a proprietary forensic tool into a globally interoperable provenance system without sacrificing performance or introducing legacy dependencies like `ProvPy`.

# Integration Plan: W3C PROV Compliance for Vouch

## 1. Executive Summary: The "Why"

Currently, **Vouch** provides high-integrity forensic logs—it proves *that* something happened through RSA signatures and SHA-256 hash chains. However, these logs are "opaque" to external systems.

**W3C PROV** provides the "Semantic Bridge." Integrating this standard as an optional layer allows:

* **Interoperability:** Your `.vch` files can be converted to standard JSON/RDF and read by institutional audit tools.
* **Graph Logic:** It allows for "Transitive Reasoning" (e.g., "Show me every raw file that ultimately influenced this specific coefficient in a model trained 3 steps later").
* **Regulatory Compliance:** Many government and scientific bodies (NASA, EU Open Data) recognize W3C PROV as the gold standard for data lineage.

---

## 2. Background: The W3C PROV Standard

To implement this from scratch, we must adhere to the **PROV-DM (Data Model)**. The standard is structured into six core components.

### A. The Core Triad

Everything in provenance is a relationship between these three classes:

1. **Entity (`prov:Entity`):** Physical, digital, or conceptual things (e.g., a CSV file, a Pandas DataFrame).
2. **Activity (`prov:Activity`):** How entities are created or changed (e.g., a function call like `df.dropna()`).
3. **Agent (`prov:Agent`):** Something that bears responsibility for an activity (e.g., the Analyst, identified by their Vouch RSA key).

### B. Core Relationships

* **Used (`prov:used`):** An Activity utilized an Entity.
* **WasGeneratedBy (`prov:wasGeneratedBy`):** An Entity was produced by an Activity.
* **WasAssociatedWith (`prov:wasAssociatedWith`):** An Agent was responsible for an Activity.
* **WasDerivedFrom (`prov:wasDerivedFrom`):** An Entity was transformed into another Entity.

### C. The 6 Components of PROV-DM

To be fully compliant, our custom implementation must account for:

1. **Entities and Activities:** Basic state and timing.
2. **Derivations:** The "Lineage" of how data evolved.
3. **Agents and Responsibility:** Who or what performed the work.
4. **Bundles:** Groups of provenance statements (the `.vch` file itself is a "Bundle").
5. **Alternates:** Different views of the same thing (e.g., the same data as a `.csv` vs. a `pd.DataFrame`).
6. **Collections:** Groups of entities (e.g., a folder of images used for training).

---

## 3. Technical Implementation Plan

### Phase 1: Ontology Mapping

Vouch already captures most of the necessary data. We simply need to map it to the PROV schema.

| Vouch Concept | PROV-DM Mapping | Implementation Detail |
| --- | --- | --- |
| **Input Artifact** | `prov:Entity` | Identified by SHA-256 hash. |
| **Proxy Library Call** | `prov:Activity` | Identified by a unique `call_id` + Timestamp. |
| **Output Artifact** | `prov:Entity` | The "result" of the activity. |
| **Analyst RSA Key** | `prov:Agent` | The signed identity associated with the session. |
| **Session Metadata** | `prov:Bundle` | The container for the entire audit trail. |

### Phase 2: The Internal Graph Engine

Since we are avoiding external libraries, we will create a lightweight `ProvGraph` class inside `vouch/prov/core.py`.

```python
class ProvNode:
    def __init__(self, identifier, type, attributes=None):
        self.id = identifier  # e.g., "hash:sha256:abc123..."
        self.type = type      # Entity, Activity, or Agent
        self.attributes = attributes or {}

class ProvGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = [] # List of (subject, predicate, object)

    def add_relation(self, subject_id, predicate, object_id):
        # predicate: "prov:used", "prov:wasGeneratedBy", etc.
        self.edges.append((subject_id, predicate, object_id))

```

### Phase 3: Non-Intrusive Hooks

We add the PROV tracking as an optional flag in the existing `vouch.start()` context manager.

```python
# vouch/session.py
class Session:
    def __init__(self, prov_enabled=False):
        self.prov_enabled = prov_enabled
        if self.prov_enabled:
            self.graph = ProvGraph()

# When a library function is intercepted:
def handle_call(self, func_name, inputs, outputs):
    if self.session.prov_enabled:
        activity_id = f"call:{uuid4()}"
        self.graph.add_node(activity_id, "Activity", {"name": func_name})

        for inp in inputs:
            self.graph.add_relation(activity_id, "prov:used", inp.hash_id)
        for out in outputs:
            self.graph.add_relation(out.hash_id, "prov:wasGeneratedBy", activity_id)

```

### Phase 4: Custom PROV-JSON Serializer

To ensure interoperability, we will build a serializer that follows the [W3C PROV-JSON specification](https://www.w3.org/Submission/2013/SUBM-prov-json-20130424/).

**Sample PROV-JSON Output Structure:**

```json
{
  "prefix": {
    "vouch": "https://vouch.io/schema#",
    "prov": "http://www.w3.org/ns/prov#"
  },
  "entity": {
    "vouch:data_v1": { "prov:label": "raw_data.csv", "vouch:sha256": "..." }
  },
  "activity": {
    "vouch:call_1": { "prov:startTime": "2023-10-27T10:00:00Z" }
  },
  "wasGeneratedBy": {
    "_:id1": { "prov:entity": "vouch:data_v2", "prov:activity": "vouch:call_1" }
  }
}

```

---

## 4. Constraint Enforcement (Forensic Validity)

W3C PROV is not just a format; it has **semantic constraints** (PROV-CONSTRAINTS). Our integration must validate these to maintain Vouch's "Forensic" reputation:

1. **Time Ordering:** An Activity's `endTime` must be after its `startTime`.
2. **Causality:** An Entity cannot be `used` by an Activity before that Activity started.
3. **Unique Generation:** An Entity can only be `generated` by one Activity.

---

## 5. User Workflow (The Vouch Experience)

### 1. Capturing with PROV

The user simply enables the flag. This does not change their code logic.

```python
import vouch
import pandas as pd

with vouch.start(enable_prov=True):
    df = pd.read_csv("data.csv")
    result = df.groupby('type').sum()
    result.to_csv("summary.csv")

```

### 2. Exporting Standardized Provenance

The CLI is extended to allow extraction of the PROV graph from the `.vch` bundle.

```bash
# Export to standard JSON for use in other tools
vouch export my_analysis.vch --format prov-json --output lineage.json

```

### 3. Forensic Visualization

Because it is now in a standard format, users can use open-source PROV visualizers to see the lineage graph.

---

## 6. Development Roadmap

| Phase | Milestone | Deliverable |
| --- | --- | --- |
| **Phase 1** | Schema Design | Internal mapping document of Vouch-to-PROV. |
| **Phase 2** | Core Graph Engine | `vouch.prov.core` module with node/edge logic. |
| **Phase 3** | Proxy Integration | Updated library wrappers to record graph relations. |
| **Phase 4** | Serializer | Custom PROV-JSON generator (no external dependencies). |
| **Phase 5** | CLI Export | `vouch export` command. |

## 7. Conclusion: The Hybrid Advantage

By following this plan, **Vouch** becomes a hybrid powerhouse:

* **The Forensic Layer:** RSA and Hash Chains prove the audit log hasn't been tampered with.
* **The PROV Layer:** Explains the logical flow of data in a way that is globally understood.

This ensures Vouch is not just a tool for today's data scientist, but a standard-compliant platform for future-proof, legally defensible analysis.

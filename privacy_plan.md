This report outlines the integration of a **Differential Privacy (DP) Audit Layer** into **Vouch**. This optional module will allow organizations to not only claim their data is anonymous but to **mathematically prove** that individual privacy has been preserved according to strict information-theoretic bounds.

# Integration Plan: Differential Privacy (DP) Audit Layer

## 1. Executive Summary: The "Why"

In 2025, simple "anonymization" (masking names/IDs) is no longer legally sufficient. Attacks like *Database Reconstruction* can re-identify individuals from aggregate statistics.

Regulations like the **GDPR** (Europe), **CPRA** (California), and the **NZ Customer and Product Data Act** are moving towards a "Privacy by Design" standard.

* **The Problem:** Data Scientists often say, "I added noise," but have no record of *how much* or if it was sufficient.
* **The Vouch Solution:** Vouch will act as the **"Privacy Budget Accountant."** It will not perform the noise addition itself (leaving that to libraries like OpenDP) but will cryptographically log the parameters (, ) and enforce a global "Privacy Budget" to prevent reconstruction attacks.

---

## 2. Technical Background: Differential Privacy & PROV

To build this, we must map DP concepts to the **W3C PROV-DM** standard.

### A. Core DP Concepts

* ** (Epsilon):** The "Privacy Loss" parameter. Lower is more private. It quantifies how distinguishable two datasets are if they differ by one person.
* ** (Delta):** The probability that the privacy guarantee fails completely (usually set to ).
* **Sensitivity ():** The maximum amount a single individual can change the result (e.g., counting people has sensitivity 1; summing salaries has high sensitivity).
* **Privacy Budget:** The cumulative  allowed for a dataset. Once spent, the dataset is "burned" and cannot be queried again.

### B. Mapping DP to W3C PROV

We will use PROV to create a permanent record of the "Privacy Transformation."

| DP Concept | PROV-DM Concept | Implementation Detail |
| --- | --- | --- |
| **Raw (Private) Data** | `prov:Entity` | Tagged with `vouch:sensitivity="High"`. |
| **DP Mechanism (Noise)** | `prov:Activity` | The function adding noise (e.g., `laplace_mechanism`). |
| **Anonymized Output** | `prov:Entity` | Tagged with `vouch:epsilon_cost=0.1`. |
| **Privacy Officer** | `prov:Agent` | The person authorizing the budget. |
| **Budget Limit** | `prov:Plan` | The pre-defined limit (e.g., Global ). |

---

## 3. 5-Phase Integration Plan

### Phase 1: The "Privacy Budget Accountant" (Internal Engine)

We cannot rely on the user to track their own budget. Vouch must maintain a state file (`budget.lock`) that tracks cumulative  usage across sessions.

* **Logic:**
1. Load `budget.lock` (securely signed).
2. Check if `current_total_epsilon + query_epsilon > max_epsilon`.
3. If **Yes**: **HALT execution**. Raise `PrivacyBudgetExceededError`.
4. If **No**: Run query, log cost, update lockfile.



### Phase 2: Ontology & Namespace Definition

We will define a formal namespace for privacy metadata to ensure interoperability.

```python
# vouch/prov/privacy.py
NS_PRIV = "https://vouch.io/schemas/privacy#"
ATTR_EPSILON = f"{NS_PRIV}epsilon"
ATTR_DELTA = f"{NS_PRIV}delta"
ATTR_MECHANISM = f"{NS_PRIV}mechanism" # e.g., "Laplace", "Gaussian"

```

### Phase 3: "Privacy Hooks" for Standard Libraries

Rather than writing our own math, we will wrap established DP libraries like **OpenDP**, **IBM Diffprivlib**, or **Google DP**.

* **The Hook Logic:**
When the user calls a DP function, Vouch intercepts it to record the parameters.
```python
# Example of Vouch wrapping a diffprivlib function
def handle_dp_mean(self, func, args, kwargs):
    epsilon = kwargs.get('epsilon', 1.0)

    # 1. Check Budget
    self.session.budget_accountant.spend(epsilon)

    # 2. Run Function
    result = func(*args, **kwargs)

    # 3. Log to PROV
    activity_id = self.log_activity("dp_mean")
    self.log_attribute(activity_id, ATTR_EPSILON, epsilon)

    return result

```



### Phase 4: The "Safe Harbor" Output Flag

We need a way to tell the difference between "Radioactive" (raw) data and "Safe" (DP) data in the output.

* **Feature:** If an output is derived *exclusively* through DP Activities, Vouch marks the resulting artifact as `privacy_safe=True` in the manifest.
* **Why:** This allows data engineers to set up automated pipelines that *only* allow `privacy_safe` files to leave the secure enclave.

### Phase 5: The "Certificate of Anonymity" Report

A new report template that focuses solely on privacy metrics for compliance teams.

* **Content:**
* **Total Budget Consumed:** e.g., "2.4 / 5.0 Epsilon".
* **Remaining Budget:** "2.6 Epsilon".
* **Attack Vector Analysis:** "Delta set to , ensuring protection against reconstruction for populations > 100k."
* **Verification:** "All noise generated using Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)."



---

## 4. User Workflow

### 1. Defining the Budget (Admin Level)

The Privacy Officer initializes the dataset with a budget.

```bash
vouch privacy-init --dataset "customer_db.csv" --max-epsilon 5.0 --max-delta 1e-6

```

### 2. The Analyst Experience (User Level)

The analyst works as normal, but must specify their "spend."

```python
import vouch
from diffprivlib.mechanisms import Laplace

# Initialize session linked to the specific dataset budget
with vouch.start(privacy_budget="customer_db.csv"):

    # Raw data (Vouch tracks this as SENSITIVE)
    data = [100, 102, 98, 105, 99]

    # Vouch intercepts this.
    # It subtracts 0.1 from the global budget of 5.0.
    # If budget < 0.1, this raises an Error.
    mech = Laplace(epsilon=0.1, sensitivity=1)
    safe_result = mech.randomise(sum(data))

    print(f"Safe Sum: {safe_result}")

```

### 3. The Audit

The auditor verifies that the budget wasn't bypassed.

```bash
vouch audit privacy-log.vch
# Output:
# [PASS] Mechanism: Laplace
# [PASS] Epsilon: 0.1
# [PASS] Budget Remaining: 4.9
# [VERIFIED] Noise was generated after strict seeding.

```

---

## 5. Development Roadmap

| Milestone | Deliverable | Description |
| --- | --- | --- |
| **M1: Accountant** | `BudgetAccountant` Class | Persistent, cryptographically signed state file tracking cumulative . |
| **M2: Wrappers** | `vouch.privacy.wrappers` | Adapters for `diffprivlib` and `OpenDP` functions. |
| **M3: Enforcer** | `PrivacyGuard` | Runtime check that blocks code execution if budget is zero. |
| **M4: Reporting** | `vouch report --type privacy` | HTML report visualizing budget consumption over time. |

## 6. Conclusion

By integrating a **Differential Privacy Audit**, Vouch solves the "Trust" problem in modern data sharing. It moves the conversation from "I promise I anonymized it" to "Here is the cryptographically signed ledger of the exact noise added, proving it is mathematically impossible to reconstruct the original data."

This feature alone opens up sales channels to **Government Agencies** (Census Bureaus) and **Healthcare Providers** who are currently paralyzed by data sharing risks.
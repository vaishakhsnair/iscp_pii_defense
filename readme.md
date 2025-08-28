
## How to Use

### 1. Run the Detector Script

```bash
python3 detector_vaishakh_s_nair.py iscp_pii_dataset.csv
```

* **Input:** `iscp_pii_dataset.csv`
  Must have columns: `record_id`, `data_json` (JSON string of customer data).
* **Output:** `redacted_output_vaishakh_s_nair.csv`
  With columns:

  * `record_id`
  * `redacted_data_json` (PII masked)
  * `is_pii` (True/False)

### 2. Sample Input

```csv
record_id,data_json
1,"{""phone"": ""9876543210"", ""order_value"": 1299}"
2,"{""name"": ""Rajesh Kumar"", ""email"": ""rajesh.kumar@email.com""}"
```

### 3. Sample Output

```csv
record_id,redacted_data_json,is_pii
1,"{""phone"": ""98XXXXXX10"", ""order_value"": 1299}",True
2,"{""name"": ""RXXX KXXX"", ""email"": ""raXXX@email.com""}",True
```


# Deployment Strategy

## Proposed Placement

The PII Detector & Redactor will be most effective when deployed as a **multi-layer defense** integrated at both the **application ingress** and **logging layers**, with optional support for outbound traffic. This balances accuracy, scalability, and cost while minimizing latency.

---

## 1. API Gateway / Ingress Middleware

* **Why here:** This is the earliest point where customer data enters the system. By sanitizing at ingress, PII is redacted before reaching business logic, storage, or logs.
* **How it works:** The Python redactor runs as a middleware service (Express plugin or Envoy/Nginx filter). Every incoming request payload is scanned, sensitive fields masked, and the sanitized request forwarded downstream.
* **Benefits:**

  * Prevents raw PII from entering internal services.
  * Adds negligible latency (<5ms per request for regex redaction).
  * Easy to roll out gradually by enabling on specific routes.

---

## 2. Logging Layer Integration

* **Why here:** Logs are common vectors for PII leakage, especially with external monitoring or audit pipelines.
* **How it works:** The redactor hooks into `/api/logs` before log entries are persisted in SQLite or broadcast via SSE streams. All log lines are sanitized inline.
* **Benefits:**

  * Prevents silent leaks into observability stacks (ELK, dashboards).
  * Lightweight integration; redactor runs in the same pod or as a filter in Fluentd/Logstash.

---

## 3. Outbound Connector Sidecar (Optional, Phase 2)

* **Why here:** The backend communicates with third-party APIs (Gemini, GitHub, Snyk, Trufflehog). These tools don’t need raw PII.
* **How it works:** A sidecar container proxies outbound traffic, sanitizing payloads before leaving the network boundary.
* **Benefits:**

  * Enforces “no PII beyond trust boundary.”
  * Provides an audit trail of redacted fields.
  * Scales horizontally as sidecars replicate with pods.

---

## 4. Scalability & Cost Considerations

* **Scalability:** The redactor is stateless, horizontally scalable, and co-locates with existing services.
* **Latency:** Regex and rule-based redaction is deterministic and sub-5ms, safe for inline use.
* **Cost:** No need for a centralized, expensive DLP system; leverages existing API Gateway and logging stack.
* **Extensibility:** Named Entity Recognition (NER) is not required for this structured dataset but can be added later for free-text inputs if the system expands.

---

## 5. Recommendation

* **Immediate deployment:** Express/Ingress middleware + log sanitizer.
* **Medium term:** Sidecar proxy for outbound connectors.
* **Long term:** Centralized PII policy management (ConfigMap or policy controller) for consistency across all pods.

This layered approach ensures defense-in-depth with minimal latency and strong cost efficiency.

---

Would you like me to also **condense this into a shorter executive-style summary** (1–2 paragraphs, no sections), so you can paste it as the final deliverable if the evaluators expect a very brief document?

# Comparison of Self-Deployed Client-Side Log Tracking Tools

## Comparison Summary

| Tool          | API Compatibility | Primary Dependencies                   | Complexity  |
| ------------- | ----------------- | -------------------------------------- | ----------- |
| **Bugsink**   | Sentry            | **SQLite (PV)**                        | **Minimal** |
| **GlitchTip** | Sentry            | PostgreSQL, Redis, Celery              | Medium      |
| **Uptrace**   | OTel / Sentry     | ClickHouse, PostgreSQL, Redis          | High        |
| **SigNoz**    | OTel              | ClickHouse, PostgreSQL, OTel Collector | High        |

---

## 1. SigNoz

- **API Compatibility:** OpenTelemetry (OTel) native.
- **Minimum Dependencies:** - ClickHouse
- PostgreSQL
- SigNoz Query Service
- OTel Collector

## 2. Uptrace

- **API Compatibility:** OpenTelemetry (OTel) and Sentry.
- **Minimum Dependencies:**
- ClickHouse
- PostgreSQL
- Redis

## 3. GlitchTip

- **API Compatibility:** Sentry.
- **Minimum Dependencies:**
- PostgreSQL
- Redis
- Celery Worker

## 4. Bugsink

- **Compatibility:** Sentry.
- **Minimum Dependencies:**
- SQLite (Persistent Volume).

---

## Conclusion

- **Selected Tool:** Bugsink.
- **Reasoning:** Simplest deployment.
- **Infrastructure Requirement:** SQLite.

---

## Deployment

- **Endpoint:** `{AUTHGEAR_ENDPOINT}/bugsink`
- Client sends error reports to the above endpoint, which will be forwarded to the deployed Bugsink instance.

## Obtaining Logs

- **Method:** Use `kubectl cp` to obtain the SQLite database file from the persistent volume.
- **Analysis:** Restore the SQLite file into a local Bugsink instance for offline analysis.

## Data Housekeeping

- **Automated Cleanup:** Bugsink performs automatic data housekeeping based on retention settings.
- **Event Limits:** The maximum number of events and retention period are configurable.
- **Documentation:**
  - https://www.bugsink.com/docs/housekeeping/
  - https://www.bugsink.com/docs/ingestion-rate-limits-and-retention/

## Helm Chart Config Design

```yaml
bugsink:
  enabled: true
  image: bugsink/subsink:latest
  resources:
    requests:
      cpu: "100m"
      memory: "100Mi"
    limits:
      cpu: "500m"
      memory: "256Mi"
    # ... Other common k8s deployment configs
```

# Log Collection with Loki and Alloy

## Setup

- **Log Collection**: Deploy Grafana Alloy to collect logs.
  - It streams logs directly from the Kubernetes API server.
  - It also collects Kubernetes events.
- **Log Storage**: Deploy Grafana Loki to store logs.
  - Receives logs from Alloy.
  - Manages log retention automatically.

## Considerations

- **Permissions**: Requires only namespace-level permissions.
  - No cluster admin access is needed.
  - No host path access is needed.
- **Deployment**:
  - Both Alloy and Loki are deployed into the namespace.
  - No changes are needed for existing application pods.
- **Data Retention**:
  - Loki manages data retention and automatic housekeeping (e.g., deleting logs older than 90 days).

## Local Analysis Workflow

1.  **Port-Forward Remote Loki**: In a terminal, port-forward the Loki service from your Kubernetes cluster.
    -   `kubectl port-forward svc/loki-store -n authgear 3101:3100`
2.  **Export Logs**: In a *second* terminal, use `logcli` to query the remote Loki via the port-forward and save the logs.
    -   `logcli --addr=http://localhost:3101 query '{namespace="authgear"}' --since=24h --limit=10000 -o jsonl > logs/events.jsonl`
    -   `logcli --addr=http://localhost:3101 query '{job="loki.source.kubernetes.container_logs"}' --since=24h --limit=10000 -o jsonl > logs/logs.jsonl`
    OR, copy the whole loki storage
    - `kubectl cp authgear/{LOKI_POD}:/loki ./loki`
3.  **Stop Port-Forward**: Stop the `kubectl port-forward` command from the first terminal.
4.  **Start Local Stack**: Run the local analysis stack.
    -   `docker-compose up`
5.  **Analyze**: Open Grafana at `http://localhost:3000`. Promtail will automatically detect the `events.jsonl` and `logs.jsonl` files and push their contents to your local Loki, allowing you to query and visualize the logs.

## Helm Chart Config Design

```yaml
logCollector:
  enabled: true
  alloy:
    image: grafana/alloy:latest
    resources:
      requests:
        cpu: "100m"
        memory: "100Mi"
      limits:
        cpu: "500m"
        memory: "256Mi"
    # ... Other common k8s deployment configs
  loki:
    image: grafana/alloy:latest
    storage:
      persistentVolume:
        storage: 20Gi
    resources:
      requests:
        cpu: "100m"
        memory: "100Mi"
      limits:
        cpu: "500m"
        memory: "256Mi"
    # ... Other common k8s deployment configs
```

## Other Tools Explored

- **Fluent Bit**:
  - Considered as an alternative.
  - **Advantages**:
    - Low memory consumption.
    - Can output logs directly to JSON files.
  - **Disadvantages**:
    - Requires injecting a sidecar container into every application pod for container logs.
    - Needs filesystem access, which may not be available.
    - Lacks built-in data retention; requires a separate cron job to remove old logs.

## Discussion

- Support S3 compatible storage?

```yaml
  loki:
    image: grafana/alloy:latest
    storage:
      type: S3
      s3AccessKey: "..."
```

- Store logs as otel json directly?

This was the original plan, but I found Alloy `otelcol.exporter.file` component not released yet:
 https://github.com/grafana/alloy/pull/4475

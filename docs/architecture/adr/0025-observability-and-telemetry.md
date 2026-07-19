# 0025. Observability and telemetry

- **Status:** Accepted (confirmed by owner)
- **Date:** 2026-07-19

## Context

Operators use different monitoring stacks — Prometheus/Grafana (pull/scrape),
and OTLP-based backends like Grafana Cloud, New Relic, Datadog, Honeycomb (push).
The backend must integrate with all of them without code changes, while never
leaking secrets or PII into telemetry.

## Decision

Adopt a **vendor-neutral OpenTelemetry core** with a **Prometheus scrape
endpoint** alongside it:

- **Logs** — structured JSON, secret-redacted; emitted to stdout (for any
  collector) and exportable via **OTLP**.
- **Metrics** — exposed **both** as a Prometheus-compatible **`/metrics`** scrape
  endpoint **and** via **OTLP push**, so pull- and push-based backends both work.
- **Traces** — via **OpenTelemetry / OTLP**.
- **Backend-agnostic:** because the core is OpenTelemetry, Grafana, New Relic,
  Datadog, Honeycomb, etc. are supported by **configuring exporters/endpoints**
  (ADR-0022), not by code changes.
- **Health/readiness** — `/healthz` (liveness) and `/readyz` (readiness);
  readiness reflects **DB connectivity and TLS/cert readiness**.
- **Exposure & safety:** `/metrics` exposure is **deployer-configurable** (bind
  to an internal interface, require auth, or disable). Metrics/labels and spans
  must avoid **high-cardinality or sensitive values** — no key material, access
  keys, or raw handle/set values used as unbounded labels.
- Reserved routes `healthz`, `readyz`, `metrics` are already blocklisted
  (ADR-0017).

## Consequences

- Works out-of-the-box with the two dominant paradigms (scrape + OTLP) and any
  OTel-compatible vendor.
- Adds the OpenTelemetry SDK dependency and requires cardinality/redaction
  discipline.

## Open items

Exact metric/span catalog, exporter defaults and sampling, and whether
Prometheus and OTLP metrics run concurrently by default or one is opt-in.

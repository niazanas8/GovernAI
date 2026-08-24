# GovernAI Governance Benchmark

This benchmark turns the demo scenarios into a repeatable regression suite.
It exercises the real local services and produces measurable governance/security
results instead of relying on architecture claims alone.

## Coverage

- Keycloak-derived human roles and privilege escalation resistance
- OPA route/tool authorization
- Dynamic OPA policy revocation/grant/rollback
- SPIFFE/SPIRE workload kill switch
- MLflow model-stage and OPA risk-tier controls
- OpenMetadata/OPA PII masking
- Guardrails prompt-injection and output-PII checks
- Agent Governance Toolkit defense in depth
- Tamper-evident OPA audit-chain verification

## Run

Start the normal stack first and wait for the agent to become healthy:

```bash
docker compose up -d --build
curl http://localhost:8000/health
```

Then run:

```bash
docker compose exec agent python evaluation/run_governance_benchmark.py
```

The benchmark writes:

```text
evaluation/results/latest_results.json
evaluation/results/latest_report.md
```

It exits with status `1` if any governance case fails, so the same command can
later be used as a CI regression gate.

## Metrics

The report calculates:

- overall control accuracy
- attack block rate
- false-block rate
- authorization accuracy
- unauthorized-execution block rate
- PII control accuracy
- model-gate accuracy
- kill-switch compliance
- dynamic-policy accuracy
- guardrail accuracy

The benchmark is evidence for this local governance lab. It is **not** a claim
of ISO/IEC 42001 certification, EU AI Act compliance, or production readiness.

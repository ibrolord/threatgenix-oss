# Production Readiness Controls

This runbook is the v1 operating gate for a self-hosted ThreatGenix deployment.
It records the minimum controls operators must have before treating a deployment
as production-ready.

## Alerts

- scanner queue stalled
- ai provider outage
- review failure spike
- bundle storage near quota
- cross-tenant access attempt

## Runbooks

- scanner queue stalled: pause new validation requests, inspect worker health,
  and replay queued jobs after the backlog is understood.
- ai provider outage: switch the affected workspace to rules-only output or a
  configured fallback provider, then record the provider and region impact.
- bundle storage full: stop ingestion, expand or prune storage according to the
  retention policy, and verify review exports after cleanup.
- github app outage: disable repository import jobs, use manual evidence upload,
  and re-enable imports only after webhook delivery is healthy.
- rollback scanner ruleset: pin the previous approved scanner ruleset and rerun
  one known-good validation target.
- rollback prompt version: pin the previous approved prompt version and rerun the
  model regression fixture before re-enabling AI explanations.

## Kill Switches

- ai explanations
- scanner rule packs
- prompt versions
- new workers

## Backup And Recovery

- backup cadence: database and evidence metadata backups run on a documented
  schedule with owner review.
- bundle storage restore: operators can restore stored evidence bundles into a
  clean environment.
- evidence hash verification: restored bundles must match their recorded hashes
  before review packets are trusted.
- manual restore smoke test: run a restore drill and export one review packet.
- manual recovery path: document the manual path for recreating a review from
  uploaded evidence when automated integrations are unavailable.

## Customer Trust Controls

- data retention policy
- upload consent event
- scanner execution policy
- no default active external scanning
- exportable review packet
- audit log
- model/ai limitations
- storage region
- ai inference provider/region path

## Rollback Paths

- scanner ruleset rollback
- prompt version rollback
- worker image rollback

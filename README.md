# Sentinel detections

Microsoft Sentinel analytics rules, written as Sigma and deployed by GitHub Actions.

## How a rule gets to production

1. Write a Sigma rule in `rules/sigma/` and sample events in `tests/samples/<same name>.yml`.
2. Open a PR. The **PR checks** workflow:
   - lints the Sigma rule and converts it to KQL (pySigma, Kusto backend)
   - runs the KQL against production data, read-only, so a bad table or column fails the PR
   - runs the KQL against your sample events: `match` samples must fire, `nomatch` must not
   - reports how many hits the rule would have had over the last 14 days
   - deploys the rule to the test workspace with a `[TEST]` prefix
   - posts all of that, plus the generated KQL, as a comment on the PR
3. Merge. **Deploy to production** waits for an approval, then deploys.

Rules that don't fit Sigma go in `rules/kql-native/` and get the same checks.

## Layout

| Path | What's there |
|---|---|
| `rules/sigma/` | Sigma rules. Sentinel-only settings go in an `x_sentinel:` block. |
| `rules/kql-native/` | Rules kept as KQL, in Azure-Sentinel YAML format |
| `rules/exported/` | Reference copies of the current portal rules. Never deployed. |
| `tests/samples/` | Sample events per rule |
| `config.yml` | Defaults: field-mapping pipeline, schedule, noise threshold |
| `scripts/` | build, query check, deploy, export |

## Writing a rule

```yaml
title: Encoded PowerShell Command Line
id: <new uuid>
description: ...
tags: [attack.execution, attack.t1059.001]   # tactic tag is required
logsource: { category: process_creation, product: windows }
detection: ...
level: high
x_sentinel:              # all optional
  pipeline: sentinel_asim  # or azure_monitor, microsoft_xdr
  frequency: PT1H
  period: PT1H
  entities:
    - { type: Host, identifier: HostName, column: DvcHostname }
```

The pipeline decides which tables and column names the KQL uses:
`sentinel_asim` targets ASIM parsers (`imProcessCreate`, ...), `azure_monitor`
targets `SecurityEvent` and similar, `microsoft_xdr` targets Defender tables
(`DeviceProcessEvents`, ...).

## Running locally

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/build.py                     # convert + static checks
az login
python scripts/query_check.py --workspace-id <prod workspace GUID>
```

First-time Azure and GitHub setup: [docs/setup.md](docs/setup.md).

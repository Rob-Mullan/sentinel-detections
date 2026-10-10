#!/usr/bin/env bash
# Export the existing analytics rules from a Sentinel workspace into rules/exported/.
# These are the reference copies we convert to Sigma; they are never deployed.
# Usage: scripts/export_rules.sh <subscription-id> <resource-group> <workspace-name>
set -euo pipefail
sub="$1"; rg="$2"; ws="$3"
out=rules/exported
mkdir -p "$out"
url="https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01"
az rest --method get --url "$url" -o json > "$out/_all.json"
# One file per rule, named after its display name, for readable diffs.
python3 - "$out" <<'PY'
import json, re, sys
from pathlib import Path
out = Path(sys.argv[1])
rules = json.loads((out / "_all.json").read_text())["value"]
for r in rules:
    name = r["properties"].get("displayName") or r["name"]
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:80]
    (out / f"{slug}.json").write_text(json.dumps(r, indent=2) + "\n")
(out / "_all.json").unlink()
kinds = {}
for r in rules:
    kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
print(f"Exported {len(rules)} rules: " + ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())))
PY

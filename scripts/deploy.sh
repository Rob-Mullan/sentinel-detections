#!/usr/bin/env bash
# Deploy every built rule (build/arm/*.json) to a Sentinel workspace.
# Usage: scripts/deploy.sh <resource-group> <workspace-name> [display-name-prefix]
# Rules are named by their Sigma id, so re-running updates rules in place.
set -euo pipefail
rg="$1"; ws="$2"; prefix="${3:-}"
failed=0
for t in build/arm/*.json; do
  name="$(basename "$t" .json)"
  echo "::group::$name"
  if az deployment group create \
      --resource-group "$rg" \
      --name "rule-${name:0:58}" \
      --template-file "$t" \
      --parameters workspace="$ws" displayNamePrefix="$prefix" \
      --only-show-errors -o none; then
    echo "deployed $name"
  else
    echo "::error title=Deploy failed::$name"
    failed=1
  fi
  echo "::endgroup::"
done
exit $failed

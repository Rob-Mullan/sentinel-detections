#!/usr/bin/env python3
"""Check built rules against a Log Analytics workspace (read-only).

For every rule in build/rules.json:
  1. Validation  - run the query over real data; a syntax error, unknown table
                   or unknown column fails the check.
  2. Sample tests - if tests/samples/<name>.yml exists, run the query against
                   each sample event (swapped in for the real table with
                   datatable()). "match" samples must return a row, "nomatch"
                   samples must return none.
  3. Noise       - report how many rows the query returned over the lookback
                   window in config.yml, and flag it if over noise_threshold.

Needs only read access (Log Analytics Reader) and an `az login` session.
Writes a Markdown report to --report. Exit code is 1 if any rule fails 1 or 2;
noise is reported but never fails the run.
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.loganalytics.io"


def token():
    out = subprocess.run(
        ["az", "account", "get-access-token", "--resource", API, "--query", "accessToken", "-o", "tsv"],
        check=True, capture_output=True, text=True)
    return out.stdout.strip()


def run_query(workspace_id, tok, query, timespan):
    req = urllib.request.Request(
        f"{API}/v1/workspaces/{workspace_id}/query",
        data=json.dumps({"query": query, "timespan": timespan}).encode(),
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        detail = json.loads(e.read() or b"{}").get("error", {})
        inner = detail.get("innererror", {})
        while inner.get("innererror"):
            inner = inner["innererror"]
        raise RuntimeError(inner.get("message") or detail.get("message") or str(e)) from None
    return body["tables"][0]["rows"]


def kql_value(v, typ):
    if v is None:
        return f"{typ}(null)"
    if typ == "string":
        return json.dumps(str(v))
    if typ == "dynamic":
        return f"dynamic({json.dumps(v)})"
    if typ == "bool":
        return "true" if v else "false"
    return str(v)


def kql_type(values):
    vals = [v for v in values if v is not None]
    if vals and all(isinstance(v, bool) for v in vals):
        return "bool"
    if vals and all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
        return "long"
    if vals and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
        return "real"
    if any(isinstance(v, (dict, list)) for v in vals):
        return "dynamic"
    return "string"


def with_sample(query, table, row, types):
    cols = list(row)
    schema = ", ".join(f"{c}:{types.get(c) or kql_type([row[c]])}" for c in cols)
    values = ", ".join(kql_value(row[c], types.get(c) or kql_type([row[c]])) for c in cols)
    return f"let {table} = datatable({schema}) [{values}];\n{query}"


def source_table(query):
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", query)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace-id", required=True, help="Log Analytics workspace ID (GUID) to query")
    ap.add_argument("--report", default="build/query-report.md")
    ap.add_argument("--only", nargs="*", help="rule names to check (default: all)")
    args = ap.parse_args()

    config = yaml.safe_load((ROOT / "config.yml").read_text())
    rules = json.loads((ROOT / "build" / "rules.json").read_text())
    if args.only:
        rules = [r for r in rules if r["name"] in args.only]
    tok = token()

    lines = ["## Detection checks", "",
             f"Queried the production workspace read-only. Noise window: {config['noise_lookback']}, "
             f"flag above {config['noise_threshold']} hits.", "",
             "| Rule | Query valid | Sample tests | Hits | |", "|---|---|---|---|---|"]
    failed = False
    for r in rules:
        status, valid, samples, hits = "✅", "✅", "–", "–"
        notes = []

        try:
            count = run_query(args.workspace_id, tok, f"{r['query']}\n| count", config["noise_lookback"])[0][0]
            hits = str(count)
            if count > config["noise_threshold"]:
                status = "⚠️"
                notes.append(f"noisy: {count} hits")
        except RuntimeError as e:
            valid, status, failed = "❌", "❌", True
            notes.append(f"query error: {e}")

        sample_file = ROOT / "tests" / "samples" / f"{r['name']}.yml"
        if sample_file.exists() and valid == "✅":
            spec = yaml.safe_load(sample_file.read_text())
            table = spec.get("table") or source_table(r["query"])
            types = spec.get("types", {})
            cases = [(True, s) for s in spec.get("match", [])] + [(False, s) for s in spec.get("nomatch", [])]
            passed = 0
            for i, (should_match, row) in enumerate(cases, 1):
                label = f"{'match' if should_match else 'nomatch'} #{i}"
                try:
                    rows = run_query(args.workspace_id, tok, with_sample(r["query"], table, row, types), "PT1H")
                except RuntimeError as e:
                    notes.append(f"{label}: {e}")
                    continue
                if bool(rows) == should_match:
                    passed += 1
                else:
                    notes.append(f"{label}: {'did not fire' if should_match else 'fired but should not'}")
            samples = f"{passed}/{len(cases)}"
            if passed != len(cases):
                status, failed = "❌", True
        elif not sample_file.exists():
            notes.append("no samples")

        lines.append(f"| `{r['name']}` | {valid} | {samples} | {hits} | {status} {'; '.join(notes)} |")
        print(f"{status} {r['name']}: valid={valid} samples={samples} hits={hits} {'; '.join(notes)}")

    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text("\n".join(lines) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

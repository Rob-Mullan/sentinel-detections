#!/usr/bin/env python3
"""Build Sentinel analytics rules from the rules/ folder.

Sigma rules (rules/sigma/**.yml) are converted to KQL with pySigma.
Native KQL rules (rules/kql-native/**.yml, Azure-Sentinel YAML format) are taken as-is.
Every rule is checked for required metadata and written to:

  build/kql/<name>.kql      the query, for review and for query_check.py
  build/arm/<name>.json     an ARM template that deploys the rule
  build/rules.json          a manifest the other scripts read

Exit code is 1 if any rule has an error (missing metadata, failed conversion).
"""
import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"

SEVERITY = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",
}

TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "ResourceDevelopment",
    "initial_access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "PrivilegeEscalation",
    "defense_evasion": "DefenseEvasion",
    "credential_access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral_movement": "LateralMovement",
    "collection": "Collection",
    "command_and_control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def load_config():
    return yaml.safe_load((ROOT / "config.yml").read_text())


def parent_technique(t):
    return t.upper().split(".")[0]


def sigma_rules(config, errors):
    plugins = InstalledSigmaPlugins.autodiscover()
    pipelines = plugins.pipelines
    backends = {}
    out = []
    for path in sorted((ROOT / "rules" / "sigma").rglob("*.yml")):
        rel = path.relative_to(ROOT)
        try:
            collection = SigmaCollection.from_yaml(path.read_text())
        except Exception as e:  # pySigma raises many error types on bad YAML
            errors.append(f"{rel}: not a valid Sigma rule: {e}")
            continue
        for rule in collection.rules:
            x = rule.custom_attributes.get("x_sentinel") or {}
            problems = []
            if not rule.id:
                problems.append("missing id")
            if not rule.description:
                problems.append("missing description")
            if not rule.level:
                problems.append("missing level")
            tactics = sorted({TACTICS[t.name] for t in rule.tags if t.namespace == "attack" and t.name in TACTICS})
            techniques = sorted({parent_technique(t.name) for t in rule.tags
                                 if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", t.name)})
            if not tactics:
                problems.append("needs at least one attack.<tactic> tag")
            if rule.status and rule.status.name.lower() == "deprecated":
                continue
            if problems:
                errors.append(f"{rel}: " + ", ".join(problems))
                continue

            pipeline_name = x.get("pipeline", config["pipeline"])
            if pipeline_name not in pipelines:
                errors.append(f"{rel}: unknown pipeline '{pipeline_name}'")
                continue
            if pipeline_name not in backends:
                backends[pipeline_name] = KustoBackend(processing_pipeline=pipelines[pipeline_name]())
            try:
                queries = backends[pipeline_name].convert_rule(rule)
            except Exception as e:
                errors.append(f"{rel}: conversion failed: {e}")
                continue
            if len(queries) != 1:
                errors.append(f"{rel}: expected one query, got {len(queries)}")
                continue

            out.append({
                "id": str(rule.id),
                "name": path.stem,
                "source": str(rel),
                "kind": "sigma",
                "pipeline": pipeline_name,
                "title": rule.title,
                "description": rule.description.strip(),
                "severity": SEVERITY[rule.level.name.lower()],
                "query": queries[0],
                "frequency": x.get("frequency", config["frequency"]),
                "period": x.get("period", config["period"]),
                "trigger_threshold": x.get("trigger_threshold", config["trigger_threshold"]),
                "suppression": x.get("suppression", config["suppression"]),
                "tactics": tactics,
                "techniques": techniques,
                "entities": x.get("entities", []),
            })
    return out


def native_rules(config, errors):
    """Rules kept as KQL because they don't fit Sigma (joins, complex aggregation)."""
    out = []
    for path in sorted((ROOT / "rules" / "kql-native").rglob("*.yml")):
        rel = path.relative_to(ROOT)
        r = yaml.safe_load(path.read_text())
        missing = [k for k in ("id", "name", "description", "severity", "query", "tactics") if not r.get(k)]
        if missing:
            errors.append(f"{rel}: missing {', '.join(missing)}")
            continue
        entities = []
        for m in r.get("entityMappings", []):
            for f in m.get("fieldMappings", []):
                entities.append({"type": m["entityType"], "identifier": f["identifier"], "column": f["columnName"]})
        out.append({
            "id": r["id"],
            "name": path.stem,
            "source": str(rel),
            "kind": "kql-native",
            "pipeline": None,
            "title": r["name"],
            "description": r["description"].strip(),
            "severity": r["severity"],
            "query": r["query"].strip(),
            "frequency": r.get("queryFrequency", config["frequency"]),
            "period": r.get("queryPeriod", config["period"]),
            "trigger_threshold": r.get("triggerThreshold", config["trigger_threshold"]),
            "suppression": r.get("suppressionDuration", config["suppression"]),
            "tactics": r["tactics"],
            "techniques": sorted({parent_technique(t) for t in r.get("relevantTechniques", [])}),
            "entities": entities,
        })
    return out


def iso_duration(v):
    """Accept ISO 8601 (PT1H) or Azure-Sentinel shorthand (1h, 5m, 1d)."""
    v = str(v)
    m = re.fullmatch(r"(\d+)([mhd])", v)
    if not m:
        return v
    n, unit = m.groups()
    return f"P{n}D" if unit == "d" else f"PT{n}{unit.upper()}"


def arm_literal(s):
    """ARM evaluates strings that start with '[' as expressions; '[[' escapes that."""
    return "[" + s if s.startswith("[") else s


def arm_template(rule):
    entity_mappings = {}
    for e in rule["entities"]:
        entity_mappings.setdefault(e["type"], []).append(
            {"identifier": e["identifier"], "columnName": e["column"]})
    title = rule["title"].replace("'", "''")
    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {"type": "string"},
            "displayNamePrefix": {"type": "string", "defaultValue": ""},
        },
        "resources": [{
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{rule['id']}')]",
            "apiVersion": "2023-02-01",
            "kind": "Scheduled",
            "properties": {
                "displayName": f"[concat(parameters('displayNamePrefix'), '{title}')]",
                "description": arm_literal(rule["description"]),
                "severity": rule["severity"],
                "enabled": True,
                "query": arm_literal(rule["query"]),
                "queryFrequency": iso_duration(rule["frequency"]),
                "queryPeriod": iso_duration(rule["period"]),
                "triggerOperator": "GreaterThan",
                "triggerThreshold": rule["trigger_threshold"],
                "suppressionDuration": iso_duration(rule["suppression"]),
                "suppressionEnabled": False,
                "tactics": rule["tactics"],
                "techniques": rule["techniques"],
            },
        }],
    }
    if entity_mappings:
        template["resources"][0]["properties"]["entityMappings"] = [
            {"entityType": t, "fieldMappings": f} for t, f in entity_mappings.items()
        ]
    return template


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    config = load_config()
    errors = []
    rules = sigma_rules(config, errors) + native_rules(config, errors)

    ids = {}
    for r in rules:
        if r["id"] in ids:
            errors.append(f"{r['source']}: id {r['id']} already used by {ids[r['id']]}")
        ids[r["id"]] = r["source"]

    (BUILD / "kql").mkdir(parents=True, exist_ok=True)
    (BUILD / "arm").mkdir(parents=True, exist_ok=True)
    for r in rules:
        (BUILD / "kql" / f"{r['name']}.kql").write_text(r["query"] + "\n")
        (BUILD / "arm" / f"{r['name']}.json").write_text(json.dumps(arm_template(r), indent=2) + "\n")
    (BUILD / "rules.json").write_text(json.dumps(rules, indent=2) + "\n")

    print(f"Built {len(rules)} rule(s) into {BUILD.relative_to(ROOT)}/")
    for e in errors:
        print(f"ERROR {e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

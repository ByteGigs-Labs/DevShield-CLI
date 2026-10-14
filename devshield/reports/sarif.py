from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from devshield.core.baseline import fingerprint
from devshield.core.models import Finding, ScanResult, Severity
from devshield.core.registry import RuleRegistry

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/ByteGigs-Labs/DevShield-CLI"
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
FALLBACK_FILES = ("package.json", "composer.json", "Dockerfile", "README.md")


def _fallback_file(root: str) -> str:
    return next((f for f in FALLBACK_FILES if (Path(root) / f).exists()), FALLBACK_FILES[-1])


def _rule_entry(rule_id: str, registry: RuleRegistry, finding: Finding | None) -> dict[str, Any]:
    rule = registry.get(rule_id)
    title = rule.title if rule else (finding.title if finding else rule_id)
    severity = rule.severity if rule else (finding.severity if finding else Severity.MEDIUM)
    description = rule.description if rule else ""
    remediation = (rule.remediation if rule else None) or (finding.remediation if finding else "")
    entry: dict[str, Any] = {
        "id": rule_id,
        "name": title,
        "shortDescription": {"text": title},
        "fullDescription": {"text": description or title},
        "help": {
            "text": f"{description}\n\nFix: {remediation}".strip(),
            "markdown": f"**Why it matters:** {description}\n\n**How to fix:** {remediation}",
        },
        "defaultConfiguration": {"level": LEVELS[severity]},
        "properties": {
            "tags": [rule.category.value] if rule else [],
            "security-severity": SECURITY_SEVERITY[severity],
        },
    }
    if rule:
        entry["helpUri"] = f"{INFORMATION_URI}/blob/main/docs/rules/{rule_id}.md"
    return entry


def _location(finding: Finding, fallback: str) -> dict[str, Any]:
    location = finding.location
    physical: dict[str, Any] = {
        "artifactLocation": {
            "uri": quote(location.file if location else fallback),
            "uriBaseId": "%SRCROOT%",
        }
    }
    if location and location.line:
        physical["region"] = {"startLine": location.line}
    return {"physicalLocation": physical}


def build_sarif(result: ScanResult, registry: RuleRegistry) -> dict[str, Any]:
    first_finding = {f.rule_id: f for f in reversed(result.findings)}
    rule_ids = sorted({rule.id for rule in registry.all()} | set(first_finding))
    index = {rule_id: i for i, rule_id in enumerate(rule_ids)}
    fallback = _fallback_file(result.root)
    notifications = [
        {"level": "error", "message": {"text": f"Rule {e.rule_id} failed: {e.message}"}}
        for e in result.errors
    ] + [{"level": "warning", "message": {"text": w}} for w in result.warnings]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DevShield",
                        "version": result.devshield_version,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule_entry(r, registry, first_finding.get(r)) for r in rule_ids],
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": Path(result.root).as_uri() + "/"}},
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "endTimeUtc": result.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "ruleIndex": index[f.rule_id],
                        "level": LEVELS[f.severity],
                        "message": {"text": f.message},
                        "locations": [_location(f, fallback)],
                        "partialFingerprints": {"devshield/v1": fingerprint(f)},
                    }
                    for f in result.findings
                ],
            }
        ],
    }


def render_sarif(result: ScanResult, registry: RuleRegistry) -> str:
    return json.dumps(build_sarif(result, registry), indent=2) + "\n"

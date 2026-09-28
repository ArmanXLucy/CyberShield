from __future__ import annotations

from pathlib import Path
from typing import Any
import os


def analyze_yara(path: str, rules_path: str) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        import yara  # type: ignore
    except Exception as exc:
        return [{
            "severity": "informational",
            "category": "yara",
            "title": "YARA engine unavailable",
            "description": "The optional yara-python dependency is not installed, so YARA rules were not evaluated.",
            "evidence": type(exc).__name__,
            "confidence": "medium",
        }], []

    rule_files = list(Path(rules_path).glob("*.yar"))
    if not rule_files:
        return [{
            "severity": "informational",
            "category": "yara",
            "title": "No YARA rules configured",
            "description": "The scanner did not find any local YARA rule files.",
            "evidence": str(rules_path),
            "confidence": "high",
        }], []

    sources = {f"r{i}": str(f) for i, f in enumerate(rule_files)}
    rules = yara.compile(filepaths=sources)
    matches = rules.match(path, timeout=10)
    findings = []
    names = []
    for match in matches:
        names.append(match.rule)
        findings.append({
            "severity": "high",
            "category": "yara",
            "title": f"YARA rule matched: {match.rule}",
            "description": "A local CyberShield YARA rule matched static content in the file.",
            "evidence": match.rule,
            "confidence": "high",
        })
    return findings, names


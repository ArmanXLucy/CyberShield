from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITIES = ("safe", "informational", "low", "medium", "high", "critical")
CONFIDENCE = ("low", "medium", "high")


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: str
    detector: str
    confidence: str = "medium"
    recommendation: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            self.severity = "informational"
        if self.confidence not in CONFIDENCE:
            self.confidence = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:500],
            "detector": self.detector,
            "confidence": self.confidence,
            "recommendation": self.recommendation[:500],
        }


@dataclass
class ScanContext:
    path: str
    original_name: str
    extension: str
    detected_type: str = "unknown"
    mime_type: str = "application/octet-stream"
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding | dict[str, Any]) -> None:
        self.findings.append(finding if isinstance(finding, Finding) else Finding(
            severity=finding.get("severity", "informational"),
            category=finding.get("category", "generic"),
            title=finding.get("title", "Static indicator"),
            description=finding.get("description", ""),
            evidence=finding.get("evidence", ""),
            detector=finding.get("detector", "unknown"),
            confidence=finding.get("confidence", "medium"),
            recommendation=finding.get("recommendation", ""),
        ))


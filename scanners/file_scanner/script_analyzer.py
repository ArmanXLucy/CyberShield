from __future__ import annotations

from pathlib import Path
from typing import Any
import re


PATTERNS = [
    (r"\b(?:powershell|pwsh)\b", "PowerShell command reference", "medium", "The script references PowerShell."),
    (r"\b(?:Invoke-WebRequest|DownloadString|Start-BitsTransfer)\b", "Download primitive", "medium", "The script references a network download primitive."),
    (r"\b(?:FromBase64String|base64)\b", "Base64 decoding reference", "low", "The script contains a Base64 decoding reference."),
    (r"\b(?:eval|exec)\s*\(", "Dynamic code execution", "medium", "The script contains dynamic code execution."),
    (r"\b(?:child_process|os\.system|subprocess)\b", "Process execution primitive", "medium", "The script references an OS process execution API."),
    (r"\b(?:chmod\s+\+x|/bin/sh|/bin/bash)\b", "Shell execution reference", "medium", "The script references a shell execution path."),
    (r"\b(?:curl|wget)\b", "Network command reference", "low", "The script references a command-line network utility."),
    (r"https?://[^\s'\"`]+", "External URL", "informational", "The script contains an external URL."),
]


def analyze_script(path: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    suffix = Path(path).suffix.lower()
    data = Path(path).read_bytes()[:2 * 1024 * 1024]
    text = data.decode("utf-8", "ignore")
    meta = {"lines": text.count("\n") + 1, "encoding": "utf-8-or-lossy"}

    if suffix in {".vbs", ".vbe", ".wsf", ".ps1", ".bat", ".cmd", ".sh", ".py", ".js", ".jsx", ".ts"}:
        findings = []
        for pattern, title, severity, desc in PATTERNS:
            match = re.search(pattern, text, re.I)
            if match:
                findings.append({
                    "severity": severity,
                    "category": "script_behavior",
                    "title": title,
                    "description": desc,
                    "evidence": match.group(0)[:160],
                    "confidence": "medium",
                })
        return findings, meta
    return [], meta


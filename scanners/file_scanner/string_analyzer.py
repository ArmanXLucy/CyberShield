from __future__ import annotations

import re
from pathlib import Path

SUSPICIOUS_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"\bpowershell(?:\.exe)?\b", re.I), "Suspicious PowerShell reference", "Executable/script content references PowerShell.", "medium"),
    (re.compile(r"\b(?:cmd|command)\.exe\b", re.I), "Command shell reference", "Content references the Windows command shell.", "low"),
    (re.compile(r"\b(?:wscript|cscript|mshta)\.exe\b", re.I), "Windows script host reference", "Content references a Windows script execution host.", "medium"),
    (re.compile(r"\b(?:rundll32|regsvr32)\.exe\b", re.I), "LOLBin reference", "Content references a Windows signed utility commonly used by malware, but the string alone is not proof of malicious behavior.", "medium"),
    (re.compile(r"\b(?:downloadstring|invoke-webrequest|bitsadmin|certutil)\b", re.I), "Network/download utility reference", "Content contains a string associated with system download or transfer utilities.", "medium"),
    (re.compile(r"\b(?:eval|exec)\s*\(", re.I), "Dynamic code execution reference", "Content contains a dynamic execution pattern.", "low"),
    (re.compile(r"(?:http://|https://)[^\s\"']{1,180}", re.I), "Embedded URL", "Content contains one or more embedded URLs.", "informational"),
]


def _extract_strings(data: bytes) -> list[str]:
    ascii_strings = re.findall(rb"[\x20-\x7e]{5,}", data)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){5,}", data)
    result = [x.decode("utf-8", "ignore") for x in ascii_strings]
    result.extend(x.decode("utf-16le", "ignore") for x in utf16_strings)
    return result


def analyze_strings(path: str, max_bytes: int = 8 * 1024 * 1024) -> list[dict[str, str]]:
    data = Path(path).read_bytes()[:max_bytes]
    strings = _extract_strings(data)
    findings: list[dict[str, str]] = []
    combined = "\n".join(strings)
    for pattern, title, desc, severity in SUSPICIOUS_PATTERNS:
        m = pattern.search(combined)
        if not m:
            continue
        evidence = m.group(0)
        findings.append({
            "title": title,
            "description": desc,
            "severity": severity,
            "evidence": evidence[:160],
        })
    return findings


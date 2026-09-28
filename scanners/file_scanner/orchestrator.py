from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os
import time

from .base import ScanContext
from .hash_analyzer import analyze_hashes
from .entropy_analyzer import analyze_entropy
from .mime_analyzer import detect_type
from .string_analyzer import analyze_strings
from .archive_analyzer import analyze_archive
from .pe_analyzer import analyze_pe
from .pdf_analyzer import analyze_pdf
from .office_analyzer import analyze_office
from .script_analyzer import analyze_script
from .yara_analyzer import analyze_yara

SUPPORTED = {
    ".exe", ".dll", ".sys", ".scr", ".ocx",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".js", ".jsx", ".ts", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".py", ".sh",
}


def _risk(findings: list[dict[str, Any]], entropy: float) -> tuple[str, str]:
    # Combine duplicate evidence from overlapping detectors so a single behavior
    # does not become high risk merely because two analyzers observed it.
    unique = {}
    for f in findings:
        key = (f.get("category"), f.get("title"))
        unique[key] = f
    values = list(unique.values())

    critical = [f for f in values if f.get("severity") == "critical"]
    high = [f for f in values if f.get("severity") == "high"]
    medium = [f for f in values if f.get("severity") == "medium"]
    low = [f for f in values if f.get("severity") == "low"]

    if critical:
        return "critical", "high"
    if high or len(medium) >= 3:
        return "high", "high" if any(f.get("confidence") == "high" for f in high) else "medium"
    if len(medium) >= 1:
        return "medium", "medium"
    if low or entropy >= 7.6:
        return "low", "low"
    return "informational", "low"


def scan_file(path: str, original_name: str, yara_rules_path: str) -> dict[str, Any]:
    started = time.time()
    p = Path(path)
    suffix = p.suffix.lower()
    detected_type, mime = detect_type(path)
    ctx = ScanContext(path=path, original_name=original_name, extension=suffix, detected_type=detected_type, mime_type=mime)

    if suffix not in SUPPORTED:
        ctx.add({
            "severity": "informational",
            "category": "limited_analysis",
            "title": "Unsupported extension",
            "description": "The file extension is outside the enhanced format-specific scanner list.",
            "evidence": suffix or "(none)",
            "confidence": "high",
        })  # type: ignore[arg-type]

    size = p.stat().st_size
    hashes = analyze_hashes(path)
    entropy = analyze_entropy(path)
    ctx.metadata["file_size"] = size
    ctx.metadata["extension"] = suffix
    ctx.metadata["detected_type"] = detected_type
    ctx.metadata["mime_type"] = mime
    ctx.metadata["hashes"] = hashes
    ctx.metadata["entropy"] = round(entropy, 3)

    string_findings = analyze_strings(path)
    for f in string_findings:
        ctx.add({
            "severity": f["severity"],
            "category": "strings",
            "title": f["title"],
            "description": f["description"],
            "evidence": f["evidence"],
            "detector": "generic string analyzer",
            "confidence": "medium" if f["severity"] != "informational" else "high",
            "recommendation": "Review the detected reference in the context of the file; a string alone does not establish maliciousness.",
        })  # type: ignore[arg-type]

    # Format-specific analysis based on actual type and suffix.
    if detected_type.startswith("Windows PE") or suffix in {".exe", ".dll", ".sys", ".scr", ".ocx"}:
        fs, meta = analyze_pe(path)
        ctx.metadata["pe"] = meta
        for f in fs:
            ctx.add({
                **f,
                "detector": "PE analyzer",
                "recommendation": "Review the finding alongside other static indicators; do not treat one weak signal as proof of malware.",
            })  # type: ignore[arg-type]

    if detected_type.startswith("PDF") or suffix == ".pdf":
        fs, meta = analyze_pdf(path)
        ctx.metadata["pdf"] = meta
        for f in fs:
            ctx.add({
                **f,
                "detector": "PDF analyzer",
                "recommendation": "Review active-content or external-link findings before opening the document in a permissive viewer.",
            })  # type: ignore[arg-type]

    if suffix in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}:
        fs, meta = analyze_office(path, detected_type)
        ctx.metadata["office"] = meta
        for f in fs:
            ctx.add({
                **f,
                "detector": "Office analyzer",
                "recommendation": "Review macros and embedded objects; keep macros disabled unless the source is trusted and the content is expected.",
            })  # type: ignore[arg-type]

    if suffix in {".zip", ".rar", ".7z", ".tar", ".gz"} or "archive" in detected_type.lower() or "ZIP" in detected_type:
        fs, meta = analyze_archive(path, detected_type)
        ctx.metadata["archive"] = meta
        for f in fs:
            ctx.add({
                **f,
                "detector": "archive analyzer",
                "recommendation": "Do not extract or execute archive contents until the archive has been reviewed.",
            })  # type: ignore[arg-type]

    if suffix in {".js", ".jsx", ".ts", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".py", ".sh"}:
        fs, meta = analyze_script(path)
        ctx.metadata["script"] = meta
        for f in fs:
            ctx.add({
                **f,
                "detector": "script analyzer",
                "recommendation": "Review the script manually in a safe editor; do not execute it just to test the finding.",
            })  # type: ignore[arg-type]

    yara_findings, yara_names = analyze_yara(path, yara_rules_path)
    ctx.metadata["yara_matches"] = yara_names
    for f in yara_findings:
        ctx.add({
            **f,
            "detector": "local YARA rule",
            "recommendation": "Review the matching rule name and supporting evidence before making a final determination.",
        })  # type: ignore[arg-type]

    # MIME/signature mismatch.
    ext_label = suffix.lstrip(".").lower()
    if ext_label == "pdf" and not detected_type.lower().startswith("pdf"):
        ctx.add({
            "severity": "high",
            "category": "type_mismatch",
            "title": "Extension does not match detected type",
            "description": "The filename extension suggests PDF, but the file signature/type did not identify it as a PDF.",
            "evidence": f"extension=.pdf; detected={detected_type}",
            "detector": "type/signature analyzer",
            "confidence": "high",
            "recommendation": "Do not open the file as a trusted PDF until its origin and true file type are confirmed.",
        })
    if ext_label in {"exe", "dll", "sys", "scr", "ocx"} and not detected_type.lower().startswith("windows pe"):
        ctx.add({
            "severity": "high",
            "category": "type_mismatch",
            "title": "Executable extension but non-PE signature",
            "description": "The filename suggests a Windows executable, but the file signature did not identify a PE image.",
            "evidence": f"extension=.{ext_label}; detected={detected_type}",
            "detector": "type/signature analyzer",
            "confidence": "high",
            "recommendation": "Treat renamed or malformed executable files cautiously and verify their source.",
        })

    serialized_findings = [f.to_dict() for f in ctx.findings]
    severity, confidence = _risk(serialized_findings, entropy)
    limited = any(
        f.get("category") in {"limited_analysis", "yara"} and f.get("title") in {
            "YARA engine unavailable",
            "PE parser unavailable",
            "PDF parser unavailable",
            "Legacy Office macro parser unavailable",
            "7z archive requires optional parser",
            "RAR archive requires optional parser",
            "Unsupported extension",
            "No YARA rules configured",
        }
        for f in serialized_findings
    )
    if limited and severity in {"informational", "low"}:
        assessment = "Unable to fully analyze"
        overall = "informational"
    elif not ctx.findings:
        assessment = "No suspicious indicators found"
        overall = "informational"
    elif severity == "critical":
        assessment = "CRITICAL RISK"
        overall = "critical"
    elif severity == "high":
        assessment = "HIGH RISK"
        overall = "high"
    elif severity == "medium":
        assessment = "MEDIUM RISK"
        overall = "medium"
    else:
        assessment = "LOW RISK"
        overall = "low"

    if not any(f.category == "yara" and f.severity == "high" for f in ctx.findings) and not ctx.findings:
        ctx.metadata["assessment_note"] = "No known suspicious indicators were detected by the local static-analysis rules; this does not guarantee the file is safe."
    else:
        ctx.metadata["assessment_note"] = "Static analysis provides indicators, not a guarantee of safety."

    result = {
        "version": 1,
        "scan_type": "file",
        "filename": original_name[:160],
        "file_size": size,
        "detected_type": detected_type,
        "mime_type": mime,
        "extension": suffix,
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "entropy": round(entropy, 3),
        "assessment": assessment,
        "severity": overall,
        "confidence": confidence,
        "findings": serialized_findings,
        "metadata": ctx.metadata,
        "duration_ms": int((time.time() - started) * 1000),
    }
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--name", required=True)
    parser.add_argument("--rules", required=True)
    args = parser.parse_args()
    print(json.dumps(scan_file(args.path, args.name, args.rules), ensure_ascii=False))


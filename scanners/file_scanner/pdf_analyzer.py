from __future__ import annotations

from pathlib import Path
from typing import Any
import re


def analyze_pdf(path: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    try:
        import fitz  # PyMuPDF
    except Exception as exc:
        return [{
            "severity": "informational",
            "category": "limited_analysis",
            "title": "PDF parser unavailable",
            "description": "PyMuPDF is not installed, so only generic static checks are available.",
            "evidence": type(exc).__name__,
            "confidence": "medium",
        }], meta

    try:
        doc = fitz.open(path)
        meta["pages"] = doc.page_count
        meta["metadata"] = {k: str(v)[:200] for k, v in (doc.metadata or {}).items() if v}
        text_sample = ""
        for idx, page in enumerate(doc):
            if idx >= min(doc.page_count, 20):
                break
            text_sample += page.get_text("text")[:10000] + "\n"

        raw = Path(path).read_bytes()[:12 * 1024 * 1024]
        for marker, title, severity, desc in [
            (b"/JavaScript", "Embedded JavaScript", "medium", "The PDF contains JavaScript-related objects."),
            (b"/JS", "JavaScript object reference", "medium", "The PDF references JavaScript execution."),
            (b"/OpenAction", "Automatic document action", "medium", "The PDF contains an automatic action that can execute when opened."),
            (b"/AA", "Additional actions", "low", "The PDF contains additional action entries."),
            (b"/Launch", "Launch action", "high", "The PDF contains a launch action capable of invoking another resource."),
            (b"/URI", "Embedded URI action", "informational", "The PDF contains a URI action."),
        ]:
            if marker in raw:
                findings.append({
                    "severity": severity,
                    "category": "pdf_active_content",
                    "title": title,
                    "description": desc,
                    "evidence": marker.decode("ascii"),
                    "confidence": "medium",
                })

        urls = re.findall(rb"https?://[^\s<>()\x00]{3,200}", raw, re.I)
        if urls:
            findings.append({
                "severity": "informational",
                "category": "external_links",
                "title": "External links present",
                "description": "The PDF contains one or more embedded HTTP(S) URLs.",
                "evidence": f"{len(urls)} URL-like references",
                "confidence": "high",
            })
        doc.close()
        return findings, meta
    except Exception as exc:
        return [{
            "severity": "medium",
            "category": "malformed_pdf",
            "title": "PDF structure could not be fully parsed",
            "description": "The PDF parser could not safely open the document.",
            "evidence": type(exc).__name__,
            "confidence": "high",
        }], meta


from __future__ import annotations

from pathlib import Path
from typing import Any
import zipfile


def analyze_office(path: str, detected_type: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    suffix = Path(path).suffix.lower()

    if suffix in {".docx", ".xlsx", ".pptx"} or "OpenXML" in detected_type:
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                meta["member_count"] = len(names)
                for name in names:
                    lower = name.lower()
                    if "vbaProject.bin".lower() in lower:
                        findings.append({
                            "severity": "high",
                            "category": "macro",
                            "title": "VBA macro project embedded",
                            "description": "The OpenXML package contains a VBA project.",
                            "evidence": name,
                            "confidence": "high",
                        })
                    if "embeddings/" in lower:
                        findings.append({
                            "severity": "medium",
                            "category": "embedded_object",
                            "title": "Embedded object present",
                            "description": "The document package contains embedded objects.",
                            "evidence": name,
                            "confidence": "medium",
                        })
                    if "externalLinks/" in lower:
                        findings.append({
                            "severity": "medium",
                            "category": "external_link",
                            "title": "External link relationship present",
                            "description": "The document package contains external link relationships.",
                            "evidence": name,
                            "confidence": "medium",
                        })
        except Exception as exc:
            findings.append({
                "severity": "medium",
                "category": "malformed_office",
                "title": "OpenXML package could not be fully inspected",
                "description": "The package could not be parsed as a valid Office OpenXML container.",
                "evidence": type(exc).__name__,
                "confidence": "high",
            })

    if suffix in {".doc", ".xls", ".ppt"} or detected_type.startswith("OLE"):
        try:
            from oletools.olevba import VBA_Parser  # type: ignore
            vba = VBA_Parser(path)
            has_macros = vba.detect_vba_macros()
            if has_macros:
                findings.append({
                    "severity": "high",
                    "category": "macro",
                    "title": "VBA macros detected",
                    "description": "The Office compound document contains VBA macro streams.",
                    "evidence": "olevba reported VBA macros",
                    "confidence": "high",
                })
                meta["macro_modules"] = []
                for filename, stream_path, vba_filename, code in vba.extract_macros() or []:
                    meta["macro_modules"].append(str(stream_path))
                    text = code or ""
                    for token in ("AutoOpen", "Workbook_Open", "Document_Open", "Shell(", "CreateObject"):
                        if token.lower() in text.lower():
                            findings.append({
                                "severity": "high" if token in {"AutoOpen", "Workbook_Open", "Document_Open"} else "medium",
                                "category": "macro_behavior",
                                "title": f"Macro references {token}",
                                "description": "The macro code contains a potentially active execution or auto-run reference.",
                                "evidence": token,
                                "confidence": "medium",
                            })
            vba.close()
        except Exception:
            findings.append({
                "severity": "informational",
                "category": "limited_analysis",
                "title": "Legacy Office macro parser unavailable",
                "description": "Legacy Office macro analysis requires oletools; generic static checks remain available.",
                "evidence": "oletools not available",
                "confidence": "medium",
            })
    return findings, meta


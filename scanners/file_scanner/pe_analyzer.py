from __future__ import annotations

from pathlib import Path
from typing import Any
import math


def analyze_pe(path: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {"sections": [], "imports": [], "signed": False}

    try:
        import pefile  # type: ignore
    except Exception as exc:
        return [{
            "severity": "informational",
            "category": "limited_analysis",
            "title": "PE parser unavailable",
            "description": "The file is a Windows PE candidate, but the optional pefile dependency is unavailable.",
            "evidence": type(exc).__name__,
            "confidence": "medium",
        }], meta

    try:
        pe = pefile.PE(path, fast_load=False)
        meta["machine"] = hex(pe.FILE_HEADER.Machine)
        meta["timestamp"] = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
        meta["entry_point"] = hex(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
        meta["image_base"] = hex(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0))

        cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        meta["signed"] = bool(getattr(cert_dir, "Size", 0))

        if not meta["signed"]:
            findings.append({
                "severity": "low",
                "category": "signature",
                "title": "Unsigned executable",
                "description": "No Authenticode certificate table was found in the PE security directory.",
                "evidence": "IMAGE_DIRECTORY_ENTRY_SECURITY size = 0",
                "confidence": "medium",
            })

        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", "ignore")
            entropy = sec.get_entropy()
            meta["sections"].append({"name": name, "entropy": round(entropy, 3), "size": int(sec.SizeOfRawData)})
            if entropy >= 7.2 and sec.SizeOfRawData >= 4096:
                findings.append({
                    "severity": "medium",
                    "category": "entropy",
                    "title": "High entropy PE section",
                    "description": "A section has unusually high entropy, which can be associated with packing or encryption.",
                    "evidence": f"{name}: entropy {entropy:.2f}",
                    "confidence": "medium",
                })

        try:
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                dll = entry.dll.decode("utf-8", "ignore").lower()
                meta["imports"].append(dll)
                for imp in entry.imports[:50]:
                    name = (imp.name or b"").decode("ascii", "ignore").lower()
                    if name in {"createprocessa", "createprocessw", "winexec", "shellexecutea", "shellexecutew"}:
                        findings.append({
                            "severity": "medium",
                            "category": "suspicious_behavior",
                            "title": "Process execution API import",
                            "description": "The executable imports a Windows API commonly used to launch another process.",
                            "evidence": f"{dll}!{name}",
                            "confidence": "medium",
                        })
        except AttributeError:
            pass

        if any(x in " ".join(meta["imports"]) for x in {"wininet.dll", "urlmon.dll", "winhttp.dll"}):
            findings.append({
                "severity": "low",
                "category": "network_capability",
                "title": "Network-capable PE imports",
                "description": "The executable imports Windows networking libraries.",
                "evidence": ", ".join(sorted(set(meta["imports"]))[:8]),
                "confidence": "low",
            })

        return findings, meta
    except Exception as exc:
        return [{
            "severity": "medium",
            "category": "malformed_pe",
            "title": "PE structure could not be fully parsed",
            "description": "The file has a PE signature but the parser could not safely interpret all structures.",
            "evidence": type(exc).__name__,
            "confidence": "high",
        }], meta


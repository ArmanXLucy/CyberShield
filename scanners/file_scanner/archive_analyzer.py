from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any
import io
import os
import tarfile
import zipfile


MAX_ARCHIVE_FILES = int(os.getenv("MAX_ARCHIVE_FILES", "1000"))
MAX_ARCHIVE_EXTRACTED_MB = int(os.getenv("MAX_ARCHIVE_EXTRACTED_MB", "100"))
MAX_ARCHIVE_DEPTH = int(os.getenv("MAX_ARCHIVE_RECURSION", "3"))

EXEC_EXTS = {".exe", ".dll", ".sys", ".scr", ".ocx", ".com"}
SCRIPT_EXTS = {".js", ".jsx", ".ts", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".py", ".sh"}
SUSPICIOUS_NAMES = {"invoice.exe", "update.exe", "setup.exe", "crack.exe", "keygen.exe", "patch.exe"}


def _unsafe_name(name: str) -> bool:
    p = PurePosixPath(name.replace("\\", "/"))
    return p.is_absolute() or ".." in p.parts


def _member_finding(name: str, size: int) -> list[dict[str, str]]:
    suffix = Path(name).suffix.lower()
    findings: list[dict[str, str]] = []
    if suffix in EXEC_EXTS:
        findings.append({
            "severity": "medium",
            "category": "archive_payload",
            "title": "Executable inside archive",
            "description": "The archive contains a Windows executable or system binary.",
            "evidence": name,
            "confidence": "medium",
        })
    elif suffix in SCRIPT_EXTS:
        findings.append({
            "severity": "medium",
            "category": "archive_payload",
            "title": "Script inside archive",
            "description": "The archive contains a script file that can carry active code.",
            "evidence": name,
            "confidence": "medium",
        })
    if suffix in EXEC_EXTS and name.lower().split("/")[-1] in SUSPICIOUS_NAMES:
        findings.append({
            "severity": "low",
            "category": "suspicious_filename",
            "title": "Suspicious executable filename",
            "description": "The archive contains an executable using a commonly abused filename.",
            "evidence": name,
            "confidence": "low",
        })
    return findings


def _analyze_zip_bytes(data: bytes, depth: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    meta = {"files": 0, "unpacked_bytes": 0, "depth": depth, "path_traversal": False, "bomb_suspected": False}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            meta["files"] = len(infos)
            if len(infos) > MAX_ARCHIVE_FILES:
                findings.append({
                    "severity": "high",
                    "category": "archive_bomb",
                    "title": "Archive file-count limit exceeded",
                    "description": "The archive contains more members than the configured safety limit.",
                    "evidence": f"{len(infos)} members",
                    "confidence": "high",
                })
                return findings, meta

            for info in infos:
                name = info.filename
                if _unsafe_name(name):
                    meta["path_traversal"] = True
                    findings.append({
                        "severity": "high",
                        "category": "path_traversal",
                        "title": "Path traversal entry detected",
                        "description": "The archive contains an absolute or parent-directory path that could escape an extraction root.",
                        "evidence": name,
                        "confidence": "high",
                    })
                size = int(getattr(info, "file_size", 0) or 0)
                compressed = max(int(getattr(info, "compress_size", 0) or 0), 1)
                meta["unpacked_bytes"] += size
                findings.extend(_member_finding(name, size))

                if size / compressed > 1000 and size > 10 * 1024 * 1024:
                    meta["bomb_suspected"] = True
                    findings.append({
                        "severity": "high",
                        "category": "archive_bomb",
                        "title": "High compression ratio",
                        "description": "A member has an unusually high compression ratio and could cause excessive resource use when decompressed.",
                        "evidence": f"{name}: {size / compressed:.0f}x",
                        "confidence": "high",
                    })

                if meta["unpacked_bytes"] > MAX_ARCHIVE_EXTRACTED_MB * 1024 * 1024:
                    meta["bomb_suspected"] = True
                    findings.append({
                        "severity": "high",
                        "category": "archive_bomb",
                        "title": "Archive expansion limit exceeded",
                        "description": "The declared uncompressed size exceeds the configured safety limit.",
                        "evidence": f"{meta['unpacked_bytes'] / 1024 / 1024:.1f} MB",
                        "confidence": "high",
                    })
                    break

            # Safely inspect a limited number of nested ZIP members in-memory.
            if depth < MAX_ARCHIVE_DEPTH:
                nested = 0
                for info in infos:
                    if nested >= 25:
                        break
                    if Path(info.filename).suffix.lower() not in {".zip"}:
                        continue
                    if info.file_size > 10 * 1024 * 1024:
                        continue
                    try:
                        nested_data = zf.read(info)
                        child_findings, child_meta = _analyze_zip_bytes(nested_data, depth + 1)
                        findings.extend(child_findings)
                        meta["unpacked_bytes"] += child_meta.get("unpacked_bytes", 0)
                        nested += 1
                    except Exception:
                        continue
    except zipfile.BadZipFile:
        findings.append({
            "severity": "medium",
            "category": "malformed_archive",
            "title": "Malformed ZIP structure",
            "description": "The file has a ZIP signature but could not be parsed as a valid ZIP archive.",
            "evidence": "ZIP parser error",
            "confidence": "high",
        })
    return findings, meta


def _analyze_tar(path: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    meta = {"files": 0, "unpacked_bytes": 0, "depth": 0, "path_traversal": False}
    try:
        with tarfile.open(path, "r:*") as tf:
            members = tf.getmembers()
            meta["files"] = len(members)
            for member in members[:MAX_ARCHIVE_FILES]:
                meta["unpacked_bytes"] += int(member.size or 0)
                if _unsafe_name(member.name):
                    meta["path_traversal"] = True
                    findings.append({
                        "severity": "high",
                        "category": "path_traversal",
                        "title": "Path traversal entry detected",
                        "description": "The archive contains a path that escapes a safe extraction root.",
                        "evidence": member.name,
                        "confidence": "high",
                    })
                findings.extend(_member_finding(member.name, int(member.size or 0)))
            if len(members) > MAX_ARCHIVE_FILES:
                findings.append({
                    "severity": "high",
                    "category": "archive_bomb",
                    "title": "Archive file-count limit exceeded",
                    "description": "The archive contains more members than the configured safety limit.",
                    "evidence": f"{len(members)} members",
                    "confidence": "high",
                })
            if meta["unpacked_bytes"] > MAX_ARCHIVE_EXTRACTED_MB * 1024 * 1024:
                findings.append({
                    "severity": "high",
                    "category": "archive_bomb",
                    "title": "Archive expansion limit exceeded",
                    "description": "The declared uncompressed size exceeds the configured safety limit.",
                    "evidence": f"{meta['unpacked_bytes'] / 1024 / 1024:.1f} MB",
                    "confidence": "high",
                })
    except (tarfile.TarError, EOFError):
        findings.append({
            "severity": "medium",
            "category": "malformed_archive",
            "title": "Malformed TAR/GZIP structure",
            "description": "The file could not be parsed as a valid TAR-based archive.",
            "evidence": "TAR parser error",
            "confidence": "high",
        })
    return findings, meta


def analyze_archive(path: str, detected_type: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    suffix = Path(path).suffix.lower()
    if suffix == ".zip" or "ZIP" in detected_type:
        return _analyze_zip_bytes(Path(path).read_bytes(), 0)
    if suffix in {".tar", ".gz", ".tgz"}:
        return _analyze_tar(path)
    if suffix == ".7z":
        try:
            import py7zr  # type: ignore
            with py7zr.SevenZipFile(path, mode="r") as zf:
                infos = zf.list()
                findings: list[dict[str, Any]] = []
                total = 0
                for info in infos[:MAX_ARCHIVE_FILES]:
                    name = str(getattr(info, "filename", ""))
                    size = int(getattr(info, "uncompressed", 0) or 0)
                    total += size
                    findings.extend(_member_finding(name, size))
                    if _unsafe_name(name):
                        findings.append({
                            "severity": "high",
                            "category": "path_traversal",
                            "title": "Path traversal entry detected",
                            "description": "The archive contains a potentially unsafe member path.",
                            "evidence": name,
                            "confidence": "high",
                        })
                if len(infos) > MAX_ARCHIVE_FILES or total > MAX_ARCHIVE_EXTRACTED_MB * 1024 * 1024:
                    findings.append({
                        "severity": "high",
                        "category": "archive_bomb",
                        "title": "7z resource limit exceeded",
                        "description": "The archive exceeds the configured member or expansion safety limits.",
                        "evidence": f"{len(infos)} members; {total / 1024 / 1024:.1f} MB expanded",
                        "confidence": "high",
                    })
                return findings, {"files": len(infos), "unpacked_bytes": total, "depth": 0}
        except Exception as exc:
            return [{
                "severity": "informational",
                "category": "limited_analysis",
                "title": "7z archive requires optional parser",
                "description": "The 7z container was not fully parsed because the optional py7zr dependency is unavailable or the archive is malformed.",
                "evidence": type(exc).__name__,
                "confidence": "medium",
            }], {"files": None, "unpacked_bytes": None, "depth": 0}
    if suffix == ".rar":
        try:
            import rarfile  # type: ignore
            with rarfile.RarFile(path) as rf:
                infos = rf.infolist()
                findings = []
                total = 0
                for info in infos[:MAX_ARCHIVE_FILES]:
                    name = str(info.filename)
                    size = int(getattr(info, "file_size", 0) or 0)
                    total += size
                    findings.extend(_member_finding(name, size))
                    if _unsafe_name(name):
                        findings.append({
                            "severity": "high",
                            "category": "path_traversal",
                            "title": "Path traversal entry detected",
                            "description": "The archive contains a potentially unsafe member path.",
                            "evidence": name,
                            "confidence": "high",
                        })
                if len(infos) > MAX_ARCHIVE_FILES or total > MAX_ARCHIVE_EXTRACTED_MB * 1024 * 1024:
                    findings.append({
                        "severity": "high",
                        "category": "archive_bomb",
                        "title": "RAR resource limit exceeded",
                        "description": "The archive exceeds the configured member or expansion safety limits.",
                        "evidence": f"{len(infos)} members; {total / 1024 / 1024:.1f} MB expanded",
                        "confidence": "high",
                    })
                return findings, {"files": len(infos), "unpacked_bytes": total, "depth": 0}
        except Exception as exc:
            return [{
                "severity": "informational",
                "category": "limited_analysis",
                "title": "RAR archive requires optional parser",
                "description": "The RAR container was not fully parsed because the optional rarfile dependency is unavailable or the archive is malformed.",
                "evidence": type(exc).__name__,
                "confidence": "medium",
            }], {"files": None, "unpacked_bytes": None, "depth": 0}
    return [], {}


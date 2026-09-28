from __future__ import annotations

import mimetypes
from pathlib import Path


SIGNATURES = [
    (b"%PDF-", "PDF document", "application/pdf"),
    (b"MZ", "Windows PE executable", "application/vnd.microsoft.portable-executable"),
    (b"PK\x03\x04", "ZIP/container", "application/zip"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE compound document", "application/x-ole-storage"),
    (b"{\\rtf", "RTF document", "application/rtf"),
    (b"\x1F\x8B", "GZIP archive", "application/gzip"),
]


def detect_type(path: str) -> tuple[str, str]:
    suffix = Path(path).suffix.lower()
    try:
        head = Path(path).read_bytes()[:4096]
    except OSError:
        head = b""

    for sig, label, mime in SIGNATURES:
        if head.startswith(sig):
            if label == "ZIP/container":
                if b"[Content_Types].xml" in head:
                    if b"word/" in head:
                        return "DOCX/OpenXML document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    if b"xl/" in head:
                        return "XLSX/OpenXML spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    if b"ppt/" in head:
                        return "PPTX/OpenXML presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                return label, mime
            return label, mime

    try:
        import magic  # type: ignore
        return str(magic.from_file(path)), str(magic.from_file(path, mime=True))
    except Exception:
        guessed = mimetypes.guess_type("file" + suffix)[0] or "application/octet-stream"
        return "Generic file", guessed


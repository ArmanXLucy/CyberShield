import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from server.scanners.file_scanner.hash_analyzer import analyze_hashes
from server.scanners.file_scanner.entropy_analyzer import analyze_entropy
from server.scanners.file_scanner.archive_analyzer import analyze_archive
from server.scanners.file_scanner.orchestrator import scan_file


RULES = str(Path(__file__).resolve().parents[1] / "yara_rules")


class FileScannerTest(unittest.TestCase):
    def test_hashes_are_deterministic(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"CyberShield test")
            path = fh.name
        try:
            hashes = analyze_hashes(path)
            self.assertEqual(hashes["sha256"], "b12211729a3f53ede672ac07ef97884f2987dc48711858ea72c7f81cd3a7ddcd")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_entropy_range(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(bytes(range(256)) * 4)
            path = fh.name
        try:
            value = analyze_entropy(path)
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 8.0)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_zip_path_traversal_is_detected(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as fh:
            with zipfile.ZipFile(fh, "w") as zf:
                zf.writestr("../../escape.txt", b"no extraction")
            path = fh.name
        try:
            findings, meta = analyze_archive(path, "ZIP/container")
            self.assertTrue(meta["path_traversal"])
            self.assertTrue(any(f["category"] == "path_traversal" for f in findings))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_benign_text_is_not_claimed_safe(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8") as fh:
            fh.write("benign test data")
            path = fh.name
        try:
            report = scan_file(path, "benign.txt", RULES)
            self.assertEqual(report["assessment"], "Unable to fully analyze")
            self.assertEqual(report["scan_type"], "file")
            self.assertTrue(report["sha256"])
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()


"""Recursive digital-forensics scanner for image and APK evidence.

The scanner is intentionally conservative: it records hashes and observable metadata,
never modifies evidence files, and reports parsing errors as findings instead of
terminating the complete scan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

try:
    import exifread
except ImportError:  # pragma: no cover - exercised by an installation error in CLI use
    exifread = None

try:
    from PIL import Image
except ImportError:  # pragma: no cover - exercised by an installation error in CLI use
    Image = None

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp", ".gif"}
APK_EXTENSION = ".apk"
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _json_safe(value: Any) -> Any:
    """Convert library-specific values into JSON-compatible values."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


class ContinuousForensicAgent:
    """Recursively scan an evidence directory without changing its contents."""

    def __init__(self, target_directory: str | os.PathLike[str] = "evidence", output_path: str | os.PathLike[str] = "manus_report.json"):
        self.target_directory = Path(target_directory)
        self.output_path = Path(output_path)

    @staticmethod
    def _hash_file(path: Path) -> dict[str, str]:
        digests = {"md5": hashlib.md5(usedforsecurity=False), "sha256": hashlib.sha256()}
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                for digest in digests.values():
                    digest.update(chunk)
        return {name: digest.hexdigest() for name, digest in digests.items()}

    def _base_finding(self, path: Path, relative_path: str) -> dict[str, Any]:
        finding: dict[str, Any] = {
            "path": relative_path,
            "filename": path.name,
            "extension": path.suffix.lower(),
            "mime_type": mimetypes.guess_type(path.name)[0],
            "size_bytes": None,
            "hashes": {},
            "analysis": {},
            "flags": [],
            "errors": [],
        }
        try:
            finding["size_bytes"] = path.stat().st_size
            finding["hashes"] = self._hash_file(path)
        except (OSError, ValueError) as exc:
            finding["errors"].append(f"HASH_ERROR: {exc}")
        return finding

    def _analyze_image(self, path: Path, finding: dict[str, Any]) -> None:
        analysis: dict[str, Any] = {"format": None, "width": None, "height": None, "mode": None, "exif": {}}
        if Image is not None:
            try:
                with Image.open(path) as image:
                    analysis.update({"format": image.format, "width": image.width, "height": image.height, "mode": image.mode})
                    image.verify()
            except Exception as exc:
                finding["errors"].append(f"IMAGE_READ_ERROR: {exc}")
        else:
            finding["errors"].append("IMAGE_READ_ERROR: Pillow is not installed")

        if exifread is not None:
            try:
                with path.open("rb") as stream:
                    tags = exifread.process_file(stream, details=False)
                analysis["exif"] = {str(key): str(value) for key, value in tags.items()}
                software = analysis["exif"].get("Image Software", "").lower()
                if any(tool in software for tool in ("photoshop", "gimp", "canva")):
                    finding["flags"].append("MANIPULATION_SOFTWARE_DETECTED")
            except Exception as exc:
                finding["errors"].append(f"EXIF_READ_ERROR: {exc}")
        else:
            finding["errors"].append("EXIF_READ_ERROR: ExifRead is not installed")
        finding["analysis"] = analysis

    @staticmethod
    def _android_attribute(element: ET.Element, name: str) -> str | None:
        return element.attrib.get(f"{{{ANDROID_NS}}}{name}") or element.attrib.get(name)

    def _analyze_apk_manifest(self, manifest_bytes: bytes) -> dict[str, Any]:
        """Extract common package metadata from text XML manifests.

        Android release APKs commonly use binary AXML. The scanner detects that form
        and records a clear limitation rather than guessing at package or permission data.
        """
        if manifest_bytes[:4] != b"<?xm" and b"<manifest" not in manifest_bytes[:256]:
            return {"format": "binary_or_unknown", "parse_status": "unsupported_binary_xml", "permissions": []}
        root = ET.fromstring(manifest_bytes)
        package = root.attrib.get("package")
        application = root.find("application")
        activities = []
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] in {"activity", "activity-alias", "service", "receiver", "provider"}:
                name = self._android_attribute(element, "name")
                if name:
                    activities.append({"type": element.tag.rsplit("}", 1)[-1], "name": name})
        permissions = []
        for element in root:
            if element.tag.rsplit("}", 1)[-1] in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
                name = self._android_attribute(element, "name")
                if name:
                    permissions.append(name)
        return {
            "format": "text_xml",
            "parse_status": "parsed",
            "package": package,
            "version_name": self._android_attribute(root, "versionName"),
            "version_code": self._android_attribute(root, "versionCode"),
            "permissions": sorted(set(permissions)),
            "components": activities,
            "application_label": self._android_attribute(application, "label") if application is not None else None,
        }

    def _analyze_apk(self, path: Path, finding: dict[str, Any]) -> None:
        analysis: dict[str, Any] = {"is_zip_archive": False, "entries": [], "manifest": None}
        try:
            if not zipfile.is_zipfile(path):
                finding["flags"].append("INVALID_APK_ARCHIVE")
                finding["errors"].append("APK is not a valid ZIP archive")
                finding["analysis"] = analysis
                return
            with zipfile.ZipFile(path, "r") as archive:
                analysis["is_zip_archive"] = True
                analysis["entries"] = sorted(archive.namelist())
                if "AndroidManifest.xml" not in archive.namelist():
                    finding["flags"].append("MISSING_ANDROID_MANIFEST")
                    finding["errors"].append("AndroidManifest.xml is missing")
                else:
                    try:
                        analysis["manifest"] = self._analyze_apk_manifest(archive.read("AndroidManifest.xml"))
                    except (ET.ParseError, UnicodeDecodeError, ValueError) as exc:
                        finding["flags"].append("MANIFEST_PARSE_ERROR")
                        finding["errors"].append(f"MANIFEST_PARSE_ERROR: {exc}")
                        analysis["manifest"] = {"format": "unknown", "parse_status": "error", "permissions": []}
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            finding["flags"].append("APK_PARSE_ERROR")
            finding["errors"].append(f"APK_PARSE_ERROR: {exc}")
        finding["analysis"] = analysis

    def scan_directory(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "schema_version": "1.0",
            "metadata": {
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "target_directory": str(self.target_directory),
                "status": "completed",
                "finding_count": 0,
            },
            "findings": [],
            "errors": [],
        }
        if not self.target_directory.exists():
            report["metadata"]["status"] = "completed_with_warnings"
            report["errors"].append(f"Evidence directory not found: {self.target_directory}")
        elif not self.target_directory.is_dir():
            report["metadata"]["status"] = "completed_with_warnings"
            report["errors"].append(f"Evidence path is not a directory: {self.target_directory}")
        else:
            for path in sorted(self.target_directory.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                relative = path.relative_to(self.target_directory).as_posix()
                finding = self._base_finding(path, relative)
                if path.suffix.lower() in IMAGE_EXTENSIONS:
                    finding["type"] = "image"
                    self._analyze_image(path, finding)
                elif path.suffix.lower() == APK_EXTENSION:
                    finding["type"] = "apk"
                    self._analyze_apk(path, finding)
                else:
                    finding["type"] = "file"
                report["findings"].append(finding)
        report["metadata"]["finding_count"] = len(report["findings"])
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(json.dumps(_json_safe(report), indent=2, sort_keys=False) + "\n", encoding="utf-8")
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Recursively scan image and APK evidence.")
    parser.add_argument("--evidence", default="evidence", help="Evidence directory to scan (default: evidence)")
    parser.add_argument("--output", default="manus_report.json", help="JSON report path (default: manus_report.json)")
    args = parser.parse_args()
    report = ContinuousForensicAgent(args.evidence, args.output).scan_directory()
    print(f"Scan completed: {report['metadata']['finding_count']} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

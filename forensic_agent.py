"""Recursive, raw digital-forensics scanner for image and APK evidence.

The scanner is read-only. It records every available metadata tag and manifest
attribute returned by the installed parsers, together with file-system attributes,
cryptographic hashes, archive entries, and non-fatal parsing errors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

try:
    import exifread
except ImportError:  # pragma: no cover
    exifread = None

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp", ".gif"}
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def _xml_name(tag: str | None) -> str | None:
    if tag is None:
        return None
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return {"namespace": namespace, "local_name": local}
    return {"namespace": None, "local_name": tag}


def _raw_xml_element(element: ET.Element) -> dict[str, Any]:
    """Serialize an XML element without filtering tags, attributes, or children."""
    return {
        "tag": _xml_name(element.tag),
        "attributes": {str(key): str(value) for key, value in element.attrib.items()},
        "text": element.text,
        "tail": element.tail,
        "children": [_raw_xml_element(child) for child in list(element)],
    }


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

    @staticmethod
    def _file_attributes(path: Path) -> dict[str, Any]:
        metadata: dict[str, Any] = {}
        try:
            info = path.stat()
            metadata = {
                "size_bytes": info.st_size,
                "mode_octal": oct(stat.S_IMODE(info.st_mode)),
                "mode_type": stat.filemode(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "inode": info.st_ino,
                "device": info.st_dev,
                "hard_link_count": info.st_nlink,
                "access_time_ns": info.st_atime_ns,
                "modify_time_ns": info.st_mtime_ns,
                "change_time_ns": info.st_ctime_ns,
            }
        except OSError as exc:
            metadata["stat_error"] = str(exc)
        return metadata

    def _base_finding(self, path: Path, relative_path: str) -> dict[str, Any]:
        file_attributes = self._file_attributes(path)
        finding: dict[str, Any] = {
            "path": relative_path,
            "filename": path.name,
            "extension": path.suffix.lower(),
            "mime_type": mimetypes.guess_type(path.name)[0],
            "size_bytes": file_attributes.get("size_bytes"),
            "file_attributes": file_attributes,
            "hashes": {},
            "analysis": {},
            "flags": [],
            "errors": [],
        }
        try:
            finding["hashes"] = self._hash_file(path)
        except (OSError, ValueError) as exc:
            finding["errors"].append(f"HASH_ERROR: {exc}")
        return finding

    def _analyze_image(self, path: Path, finding: dict[str, Any]) -> None:
        analysis: dict[str, Any] = {
            "format": None,
            "width": None,
            "height": None,
            "mode": None,
            "image_info": {},
            "exif": {},
        }
        if Image is not None:
            try:
                with Image.open(path) as image:
                    analysis.update({
                        "format": image.format,
                        "width": image.width,
                        "height": image.height,
                        "mode": image.mode,
                        "image_info": _json_safe(dict(image.info)),
                    })
                    exif = image.getexif()
                    analysis["pil_exif"] = {str(key): _json_safe(value) for key, value in exif.items()}
                with Image.open(path) as verification_image:
                    verification_image.verify()
            except Exception as exc:
                finding["errors"].append(f"IMAGE_READ_ERROR: {exc}")
        else:
            finding["errors"].append("IMAGE_READ_ERROR: Pillow is not installed")

        if exifread is not None:
            try:
                with path.open("rb") as stream:
                    tags = exifread.process_file(stream, details=True, extract_thumbnail=True)
                analysis["exifread_tags"] = {str(key): _json_safe(value) for key, value in tags.items()}
            except Exception as exc:
                finding["errors"].append(f"EXIF_READ_ERROR: {exc}")
        else:
            finding["errors"].append("EXIF_READ_ERROR: ExifRead is not installed")
        finding["analysis"] = analysis

    def _analyze_apk_manifest(self, manifest_bytes: bytes) -> dict[str, Any]:
        """Return all parseable text-XML manifest structure without whitelisting fields."""
        try:
            root = ET.fromstring(manifest_bytes)
        except (ET.ParseError, UnicodeDecodeError) as exc:
            return {
                "format": "binary_or_invalid_xml",
                "parse_status": "error",
                "raw_size_bytes": len(manifest_bytes),
                "raw_hex": manifest_bytes.hex(),
                "parse_error": str(exc),
            }
        elements = list(root.iter())
        permissions = []
        components = []
        for element in elements:
            local_name = _xml_name(element.tag)["local_name"]
            attributes = {str(key): str(value) for key, value in element.attrib.items()}
            android_name = attributes.get(f"{{{ANDROID_NS}}}name") or attributes.get("name")
            if local_name and local_name.startswith("uses-permission") and android_name:
                permissions.append(android_name)
            if local_name in {"activity", "activity-alias", "service", "receiver", "provider"} and android_name:
                components.append({"type": local_name, "name": android_name})
        return {
            "format": "text_xml",
            "parse_status": "parsed",
            "raw_size_bytes": len(manifest_bytes),
            "raw_xml": manifest_bytes.decode("utf-8", errors="replace"),
            "document": _raw_xml_element(root),
            "package": root.attrib.get("package"),
            "version_name": root.attrib.get(f"{{{ANDROID_NS}}}versionName") or root.attrib.get("versionName"),
            "version_code": root.attrib.get(f"{{{ANDROID_NS}}}versionCode") or root.attrib.get("versionCode"),
            "permissions": sorted(permissions),
            "components": components,
        }

    def _analyze_apk(self, path: Path, finding: dict[str, Any]) -> None:
        analysis: dict[str, Any] = {"is_zip_archive": False, "entries": [], "entry_details": [], "manifest": None}
        try:
            if not zipfile.is_zipfile(path):
                finding["flags"].append("INVALID_APK_ARCHIVE")
                finding["errors"].append("APK is not a valid ZIP archive")
                finding["analysis"] = analysis
                return
            with zipfile.ZipFile(path, "r") as archive:
                analysis["is_zip_archive"] = True
                analysis["entries"] = sorted(archive.namelist())
                analysis["entry_details"] = [
                    {
                        "filename": info.filename,
                        "date_time": list(info.date_time),
                        "compress_type": info.compress_type,
                        "compress_size": info.compress_size,
                        "file_size": info.file_size,
                        "CRC": info.CRC,
                        "flag_bits": info.flag_bits,
                        "external_attr": info.external_attr,
                        "internal_attr": info.internal_attr,
                        "create_system": info.create_system,
                        "create_version": info.create_version,
                        "extract_version": info.extract_version,
                        "header_offset": info.header_offset,
                        "comment": info.comment.decode("utf-8", errors="replace"),
                        "extra_hex": info.extra.hex(),
                    }
                    for info in archive.infolist()
                ]
                if "AndroidManifest.xml" in archive.namelist():
                    manifest = self._analyze_apk_manifest(archive.read("AndroidManifest.xml"))
                    analysis["manifest"] = manifest
                    if manifest.get("parse_status") != "parsed":
                        finding["flags"].append("MANIFEST_PARSE_ERROR")
                        finding["errors"].append(f"MANIFEST_PARSE_ERROR: {manifest.get('parse_error', 'manifest could not be parsed')}")
                else:
                    finding["flags"].append("MISSING_ANDROID_MANIFEST")
                    finding["errors"].append("AndroidManifest.xml is missing")
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            finding["flags"].append("APK_PARSE_ERROR")
            finding["errors"].append(f"APK_PARSE_ERROR: {exc}")
        finding["analysis"] = analysis

    def scan_directory(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "schema_version": "2.0-raw",
            "metadata": {
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "target_directory": str(self.target_directory),
                "status": "completed",
                "finding_count": 0,
                "filtering": "none",
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
                elif path.suffix.lower() == ".apk":
                    finding["type"] = "apk"
                    self._analyze_apk(path, finding)
                else:
                    finding["type"] = "file"
                report["findings"].append(finding)
        report["metadata"]["finding_count"] = len(report["findings"])
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(json.dumps(_json_safe(report), indent=2) + "\n", encoding="utf-8")
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Recursively scan all image and APK evidence without metadata filtering.")
    parser.add_argument("--evidence", default="evidence", help="Evidence directory to scan (default: evidence)")
    parser.add_argument("--output", default="manus_report.json", help="JSON report path (default: manus_report.json)")
    args = parser.parse_args()
    report = ContinuousForensicAgent(args.evidence, args.output).scan_directory()
    print(f"Scan completed: {report['metadata']['finding_count']} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

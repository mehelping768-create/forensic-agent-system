"""Deep, read-only digital-forensics scanner for evidence payloads.

The scanner records raw observable data without suppressing metadata. It never executes
APK or other evidence content. Indicator matches are additive findings only; they do
not filter, discard, or alter any raw data.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import re
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
try:
    from androguard.core.apk import APK
except ImportError:  # pragma: no cover
    APK = None

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp", ".gif"}
TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".properties", ".md", ".dump", ".list", ".bak"}
ANDROID_NS = "http://schemas.android.com/apk/res/android"
URL_RE = re.compile(r"(?i)\b(?:https?|ftp|ws|wss)://[^\s\"'<>]+")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w.])")
PRINTABLE_RE = re.compile(rb"[ -~]{4,}")
INDICATOR_RULES = {
    "POTENTIAL_REMOTE_ACCESS_TOOL": re.compile(r"(?i)\b(anydesk|teamviewer|supremo|rustdesk|quicksupport|airmirror|airdroid|vysor|scrcpy|droidcam|remote.?desktop|remote.?admin|rat)\b"),
    "POTENTIAL_COMMAND_AND_CONTROL": re.compile(r"(?i)\b(c2|c&c|command.?and.?control|beacon|reverse.?shell|botnet|dropper|payload|callback|webhook)\b"),
    "POTENTIAL_EXFILTRATION_HOOK": re.compile(r"(?i)\b(upload|exfil|sendfile|file.?upload|telegram|discord|slack|pastebin|transfer\.sh|ngrok|gofile|megaupload)\b"),
    "POTENTIAL_CREDENTIAL_OR_CONTACT_ACCESS": re.compile(r"(?i)\b(contacts?|address.?book|call.?log|sms|messages?|accounts?|credentials?|password|token|cookie|clipboard|location|gps)\b"),
    "POTENTIAL_CLONE_OR_IMPERSONATION": re.compile(r"(?i)\b(mod(?:ified)?|clone|cracked|patched|repack(?:ed)?|pirate|fake|unofficial|imposter)\b"),
}


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def _xml_name(tag: str | None) -> dict[str, Any] | None:
    if tag is None:
        return None
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return {"namespace": namespace, "local_name": local}
    return {"namespace": None, "local_name": tag}


def _raw_xml_element(element: ET.Element) -> dict[str, Any]:
    return {
        "tag": _xml_name(element.tag),
        "attributes": {str(key): str(value) for key, value in element.attrib.items()},
        "text": element.text,
        "tail": element.tail,
        "children": [_raw_xml_element(child) for child in list(element)],
    }


def _extract_strings(data: bytes) -> list[str]:
    return [match.decode("utf-8", errors="replace") for match in PRINTABLE_RE.findall(data)]


def _indicator_matches(values: list[str]) -> list[dict[str, str]]:
    matches = []
    for value in values:
        for indicator, pattern in INDICATOR_RULES.items():
            if pattern.search(value):
                matches.append({"indicator": indicator, "evidence": value})
    return matches


class ContinuousForensicAgent:
    def __init__(self, target_directory: str | os.PathLike[str] = "evidence", output_path: str | os.PathLike[str] = "manus_report.json"):
        self.target_directory = Path(target_directory)
        self.output_path = Path(output_path)

    @staticmethod
    def _hash_bytes(data: bytes) -> dict[str, str]:
        return {"md5": hashlib.md5(data, usedforsecurity=False).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}

    @staticmethod
    def _hash_file(path: Path) -> dict[str, str]:
        md5 = hashlib.md5(usedforsecurity=False)
        sha256 = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}

    @staticmethod
    def _file_attributes(path: Path) -> dict[str, Any]:
        try:
            info = path.stat()
            return {
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
            return {"stat_error": str(exc)}

    @staticmethod
    def _raw_payload(data: bytes) -> dict[str, Any]:
        strings = _extract_strings(data)
        text = None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            pass
        return {
            "byte_length": len(data),
            "hashes": ContinuousForensicAgent._hash_bytes(data),
            "printable_strings": strings,
            "urls": URL_RE.findall(text if text is not None else "\n".join(strings)),
            "ip_addresses": IP_RE.findall(text if text is not None else "\n".join(strings)),
            "text_utf8": text,
            "raw_base64": base64.b64encode(data).decode("ascii"),
        }

    def _base_finding(self, path: Path, relative_path: str) -> dict[str, Any]:
        attrs = self._file_attributes(path)
        finding: dict[str, Any] = {
            "path": relative_path,
            "filename": path.name,
            "extension": path.suffix.lower(),
            "mime_type": mimetypes.guess_type(path.name)[0],
            "size_bytes": attrs.get("size_bytes"),
            "file_attributes": attrs,
            "hashes": {},
            "analysis": {},
            "indicators": [],
            "flags": [],
            "errors": [],
        }
        try:
            finding["hashes"] = self._hash_file(path)
        except (OSError, ValueError) as exc:
            finding["errors"].append(f"HASH_ERROR: {exc}")
        return finding

    def _analyze_image(self, path: Path, finding: dict[str, Any]) -> None:
        analysis: dict[str, Any] = {"format": None, "width": None, "height": None, "mode": None, "image_info": {}, "pil_exif": {}, "exifread_tags": {}}
        if Image is not None:
            try:
                with Image.open(path) as image:
                    analysis.update({"format": image.format, "width": image.width, "height": image.height, "mode": image.mode, "image_info": _json_safe(dict(image.info))})
                    analysis["pil_exif"] = {str(key): _json_safe(value) for key, value in image.getexif().items()}
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
        all_values = list(analysis["exifread_tags"].values()) + list(analysis["image_info"].values())
        finding["indicators"] = _indicator_matches([str(value) for value in all_values])
        finding["analysis"] = analysis

    def _manifest_from_xml(self, manifest_bytes: bytes) -> dict[str, Any]:
        try:
            root = ET.fromstring(manifest_bytes)
        except (ET.ParseError, UnicodeDecodeError) as exc:
            return {"format": "binary_or_invalid_xml", "parse_status": "error", "raw_size_bytes": len(manifest_bytes), "raw_hex": manifest_bytes.hex(), "parse_error": str(exc)}
        permissions, intent_filters, components, component_details, strings = [], [], [], [], []
        for element in root.iter():
            name = _xml_name(element.tag)
            local = name["local_name"] if name else None
            attrs = {str(key): str(value) for key, value in element.attrib.items()}
            android_name = attrs.get(f"{{{ANDROID_NS}}}name") or attrs.get("name")
            if local and local.startswith("uses-permission"):
                permissions.append(android_name or attrs)
            if local == "intent-filter":
                intent_filters.append(_raw_xml_element(element))
            if local in {"activity", "activity-alias", "service", "receiver", "provider"}:
                components.append({"type": local, "name": android_name})
                component_details.append({"type": local, "name": android_name, "attributes": attrs})
            if local in {"string", "string-array", "plurals"}:
                strings.append(_raw_xml_element(element))
        raw_xml = manifest_bytes.decode("utf-8", errors="replace")
        values = [raw_xml] + [json.dumps(item, ensure_ascii=False) for item in strings]
        return {
            "format": "text_xml",
            "parse_status": "parsed",
            "raw_size_bytes": len(manifest_bytes),
            "raw_xml": raw_xml,
            "document": _raw_xml_element(root),
            "package": root.attrib.get("package"),
            "version_name": root.attrib.get(f"{{{ANDROID_NS}}}versionName") or root.attrib.get("versionName"),
            "version_code": root.attrib.get(f"{{{ANDROID_NS}}}versionCode") or root.attrib.get("versionCode"),
            "permissions": sorted(permissions),
            "intent_filters": intent_filters,
            "components": components,
            "component_details": component_details,
            "string_resources": strings,
            "urls": URL_RE.findall(raw_xml),
            "ip_addresses": IP_RE.findall(raw_xml),
            "printable_strings": _extract_strings(manifest_bytes),
            "indicator_matches": _indicator_matches(values),
        }

    def _androguard_manifest(self, path: Path) -> dict[str, Any] | None:
        if APK is None:
            return None
        try:
            apk = APK(str(path))
            xml = apk.get_android_manifest_xml()
            if xml is None:
                return None
            raw = ET.tostring(xml, encoding="utf-8")
            parsed = self._manifest_from_xml(raw)
            parsed["parser"] = "androguard"
            parsed["androguard_permissions"] = apk.get_permissions()
            parsed["androguard_activities"] = apk.get_activities()
            parsed["androguard_services"] = apk.get_services()
            parsed["androguard_receivers"] = apk.get_receivers()
            parsed["androguard_providers"] = apk.get_providers()
            return parsed
        except Exception as exc:
            return {"format": "binary_or_invalid_xml", "parse_status": "error", "parser": "androguard", "parse_error": str(exc)}

    def _analyze_apk(self, path: Path, finding: dict[str, Any]) -> None:
        analysis: dict[str, Any] = {"is_zip_archive": False, "entries": [], "entry_details": [], "entry_payloads": [], "manifest": None, "resources": []}
        try:
            if not zipfile.is_zipfile(path):
                finding["flags"].append("INVALID_APK_ARCHIVE")
                finding["errors"].append("APK is not a valid ZIP archive")
                finding["analysis"] = analysis
                return
            with zipfile.ZipFile(path, "r") as archive:
                analysis["is_zip_archive"] = True
                all_strings: list[str] = []
                all_urls: list[str] = []
                all_ips: list[str] = []
                for info in archive.infolist():
                    data = archive.read(info.filename)
                    payload = self._raw_payload(data)
                    all_strings.extend(payload["printable_strings"])
                    all_urls.extend(payload["urls"])
                    all_ips.extend(payload["ip_addresses"])
                    analysis["entries"].append(info.filename)
                    analysis["entry_details"].append({"filename": info.filename, "date_time": list(info.date_time), "compress_type": info.compress_type, "compress_size": info.compress_size, "file_size": info.file_size, "CRC": info.CRC, "flag_bits": info.flag_bits, "external_attr": info.external_attr, "internal_attr": info.internal_attr, "create_system": info.create_system, "create_version": info.create_version, "extract_version": info.extract_version, "header_offset": info.header_offset, "comment": info.comment.decode("utf-8", errors="replace"), "extra_hex": info.extra.hex()})
                    analysis["entry_payloads"].append({"filename": info.filename, "payload": payload})
                    if info.filename == "AndroidManifest.xml":
                        analysis["manifest"] = self._manifest_from_xml(data)
                        if analysis["manifest"].get("parse_status") != "parsed":
                            finding["flags"].append("MANIFEST_PARSE_ERROR")
                            finding["errors"].append(f"MANIFEST_PARSE_ERROR: {analysis['manifest'].get('parse_error', 'manifest could not be parsed')}")
                    if info.filename.lower().endswith("strings.xml") or info.filename == "resources.arsc":
                        analysis["resources"].append({"filename": info.filename, "payload": payload})
                if analysis["manifest"] is None and "AndroidManifest.xml" in archive.namelist():
                    analysis["manifest"] = self._androguard_manifest(path)
                if analysis["manifest"] is None:
                    finding["flags"].append("MISSING_ANDROID_MANIFEST")
                    finding["errors"].append("AndroidManifest.xml is missing")
                analysis["entries"] = sorted(analysis["entries"])
                analysis["all_printable_strings"] = all_strings
                analysis["all_urls"] = all_urls
                analysis["all_ip_addresses"] = all_ips
                analysis["all_indicator_matches"] = _indicator_matches(all_strings + all_urls + all_ips)
                finding["indicators"] = analysis["all_indicator_matches"] + ((analysis["manifest"] or {}).get("indicator_matches", []))
                if not analysis["manifest"]:
                    finding["flags"].append("MISSING_OR_UNPARSED_ANDROID_MANIFEST")
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            finding["flags"].append("APK_PARSE_ERROR")
            finding["errors"].append(f"APK_PARSE_ERROR: {exc}")
        finding["analysis"] = analysis

    def _analyze_generic(self, path: Path, finding: dict[str, Any]) -> None:
        try:
            data = path.read_bytes()
            payload = self._raw_payload(data)
            finding["analysis"] = {"payload": payload}
            finding["indicators"] = _indicator_matches(payload["printable_strings"] + payload["urls"] + payload["ip_addresses"])
        except (OSError, ValueError) as exc:
            finding["errors"].append(f"PAYLOAD_READ_ERROR: {exc}")

    def scan_directory(self) -> dict[str, Any]:
        report: dict[str, Any] = {"schema_version": "2.0-raw", "metadata": {"scan_time": datetime.now(timezone.utc).isoformat(), "target_directory": str(self.target_directory), "status": "completed", "finding_count": 0, "filtering": "none", "analysis_mode": "deep"}, "findings": [], "errors": []}
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
                finding = self._base_finding(path, path.relative_to(self.target_directory).as_posix())
                if path.suffix.lower() in IMAGE_EXTENSIONS:
                    finding["type"] = "image"
                    self._analyze_image(path, finding)
                elif path.suffix.lower() == ".apk":
                    finding["type"] = "apk"
                    self._analyze_apk(path, finding)
                else:
                    finding["type"] = "file"
                    self._analyze_generic(path, finding)
                report["findings"].append(finding)
        report["metadata"]["finding_count"] = len(report["findings"])
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(json.dumps(_json_safe(report), indent=2) + "\n", encoding="utf-8")
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Deeply scan all evidence payloads without metadata filtering.")
    parser.add_argument("--evidence", default="evidence")
    parser.add_argument("--output", default="manus_report.json")
    args = parser.parse_args()
    report = ContinuousForensicAgent(args.evidence, args.output).scan_directory()
    print(f"Scan completed: {report['metadata']['finding_count']} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

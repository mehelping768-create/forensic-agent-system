from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import stat
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import exifread
from PIL import Image

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp", ".gif"}
REPORT_SCHEMA = "forensic-detailed-summary-1.0"
TIMELINE_GAP_HOURS = 24


def safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [safe(x) for x in value]
    if isinstance(value, dict):
        return {str(k): safe(v) for k, v in value.items()}
    return str(value)


def hashes(path: Path) -> dict[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def filesystem(path: Path) -> dict[str, Any]:
    s = path.stat()
    return {
        "size_bytes": s.st_size,
        "mode_octal": oct(stat.S_IMODE(s.st_mode)),
        "mode_type": stat.filemode(s.st_mode),
        "uid": s.st_uid,
        "gid": s.st_gid,
        "inode": s.st_ino,
        "device": s.st_dev,
        "hard_link_count": s.st_nlink,
        "access_time_ns": s.st_atime_ns,
        "modify_time_ns": s.st_mtime_ns,
        "change_time_ns": s.st_ctime_ns,
        "modify_time_utc": datetime.fromtimestamp(s.st_mtime, tz=timezone.utc).isoformat(),
    }


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y:%m:%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def analyze_image(path: Path, root: Path) -> dict[str, Any]:
    errors: list[str] = []
    record: dict[str, Any] = {
        "path": path.relative_to(root).as_posix(),
        "filename": path.name,
        "extension": path.suffix.lower(),
        "mime_type": mimetypes.guess_type(path.name)[0],
        "file_attributes": filesystem(path),
        "hashes": hashes(path),
        "image": {},
        "exif": {},
        "anomalies": [],
        "errors": errors,
    }
    try:
        with Image.open(path) as image:
            record["image"] = {
                "format": image.format,
                "width": image.width,
                "height": image.height,
                "mode": image.mode,
                "info": safe(dict(image.info)),
                "pil_exif": {str(k): safe(v) for k, v in image.getexif().items()},
            }
        with Image.open(path) as verification:
            verification.verify()
    except Exception as exc:
        errors.append(f"IMAGE_READ_ERROR: {exc}")
        record["anomalies"].append("IMAGE_PARSE_ERROR")
    try:
        with path.open("rb") as stream:
            tags = exifread.process_file(stream, details=True, extract_thumbnail=True)
        record["exif"] = {str(k): safe(v) for k, v in tags.items()}
    except Exception as exc:
        errors.append(f"EXIF_READ_ERROR: {exc}")
        record["anomalies"].append("EXIF_PARSE_ERROR")
    capture_value = record["exif"].get("EXIF DateTimeOriginal") or record["exif"].get("Image DateTime")
    record["capture_time_utc"] = parse_datetime(str(capture_value) if capture_value else None).isoformat() if parse_datetime(str(capture_value) if capture_value else None) else None
    record["device_signature"] = {
        "make": record["exif"].get("Image Make"),
        "model": record["exif"].get("Image Model"),
        "software": record["exif"].get("Image Software"),
        "unique_id": record["exif"].get("EXIF ImageUniqueID"),
    }
    if record["capture_time_utc"] and record["capture_time_utc"] > record["file_attributes"]["modify_time_utc"]:
        record["anomalies"].append("CAPTURE_TIME_AFTER_FILESYSTEM_MODIFY_TIME")
    return record


def main() -> None:
    root = Path(__file__).resolve().parent
    evidence = root / "evidence"
    output = root / "forensic_detailed_summary.json"
    files = sorted(p for p in evidence.rglob("*") if p.is_file() and not p.is_symlink() and p.suffix.lower() in IMAGE_EXTENSIONS)
    findings = [analyze_image(path, evidence) for path in files]
    by_hash = defaultdict(list)
    for item in findings:
        by_hash[item["hashes"]["sha256"]].append(item["path"])
    duplicate_groups = [paths for paths in by_hash.values() if len(paths) > 1]
    device_counts = Counter(json.dumps(item["device_signature"], sort_keys=True) for item in findings)
    dimensions = Counter(f"{item['image'].get('width')}x{item['image'].get('height')}" for item in findings)
    capture_items = sorted((item["capture_time_utc"], item["path"]) for item in findings if item["capture_time_utc"])
    timeline_gaps = []
    for (previous_time, previous_path), (current_time, current_path) in zip(capture_items, capture_items[1:]):
        previous = datetime.fromisoformat(previous_time)
        current = datetime.fromisoformat(current_time)
        hours = (current - previous).total_seconds() / 3600
        if hours > TIMELINE_GAP_HOURS:
            timeline_gaps.append({"from": previous_time, "to": current_time, "gap_hours": round(hours, 3), "from_file": previous_path, "to_file": current_path})
    all_anomalies = [{"path": f["path"], "anomalies": f["anomalies"], "errors": f["errors"]} for f in findings if f["anomalies"] or f["errors"]]
    total_size = sum(f["file_attributes"]["size_bytes"] for f in findings)
    report = {
        "schema_version": REPORT_SCHEMA,
        "scan_metadata": {
            "scan_time_utc": datetime.now(timezone.utc).isoformat(),
            "repository_relative_evidence_root": "evidence/",
            "image_extensions_scanned": sorted(IMAGE_EXTENSIONS),
            "timeline_gap_threshold_hours": TIMELINE_GAP_HOURS,
            "requested_file_count": 18,
            "actual_photo_file_count": len(findings),
            "total_size_bytes": total_size,
        },
        "summary": {
            "photo_count": len(findings),
            "total_size_bytes": total_size,
            "formats": dict(Counter(f["image"].get("format") for f in findings)),
            "dimensions": dict(dimensions),
            "device_signatures": [{"signature": json.loads(signature), "count": count} for signature, count in device_counts.items()],
            "duplicate_sha256_groups": duplicate_groups,
            "capture_time_range": {"earliest_utc": capture_items[0][0] if capture_items else None, "latest_utc": capture_items[-1][0] if capture_items else None},
            "timeline_gaps_over_threshold": timeline_gaps,
            "anomaly_count": len(all_anomalies),
            "anomalies": all_anomalies,
        },
        "findings": findings,
    }
    output.write_text(json.dumps(safe(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "photo_count": len(findings), "total_size_bytes": total_size, "anomaly_count": len(all_anomalies)}, indent=2))


if __name__ == "__main__":
    main()

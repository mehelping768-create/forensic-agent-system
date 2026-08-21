"""Fetch designated evidence files from a public Google Drive folder.

The script downloads to a temporary directory, copies only configured evidence file
extensions into the destination, and writes a provenance manifest. It never deletes
existing evidence and never executes downloaded content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import gdown

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".tiff", ".bmp"}
OTHER_EXTENSIONS = {".apk", ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".properties", ".dump", ".list", ".bak", ".vcf", ".zip"}
DEFAULT_EXTENSIONS = IMAGE_EXTENSIONS | OTHER_EXTENSIONS


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_extensions(value: str | None) -> set[str]:
    if not value:
        return DEFAULT_EXTENSIONS.copy()
    return {item.strip().lower() if item.strip().startswith(".") else "." + item.strip().lower() for item in value.split(",") if item.strip()}


def copy_selected_files(download_root: Path, destination: Path, extensions: set[str]) -> list[dict[str, Any]]:
    copied: list[dict[str, Any]] = []
    for source in sorted(download_root.rglob("*")):
        if not source.is_file() or source.is_symlink() or source.suffix.lower() not in extensions:
            continue
        relative = source.relative_to(download_root)
        category = "photos/raw" if source.suffix.lower() in IMAGE_EXTENSIONS else "other"
        target = destination / category / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target = target.with_name(f"{target.stem}__gdrive{target.suffix}")
        shutil.copy2(source, target)
        copied.append({"source_relative_path": relative.as_posix(), "destination_relative_path": target.relative_to(destination).as_posix(), "size_bytes": target.stat().st_size, "sha256": sha256(target), "extension": target.suffix.lower()})
    return copied


def fetch(folder_url: str | None, destination: Path, manifest_path: Path, extensions: set[str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "gdrive-ingestion-1.0",
        "ingestion_time_utc": datetime.now(timezone.utc).isoformat(),
        "source_type": "public_google_drive_folder",
        "source_configured": bool(folder_url),
        "destination": str(destination),
        "allowed_extensions": sorted(extensions),
        "files": [],
        "errors": [],
    }
    if not folder_url:
        result["status"] = "skipped_no_folder_url"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="gdrive-evidence-") as temporary:
            download_root = Path(temporary) / "download"
            downloaded = gdown.download_folder(url=folder_url, output=str(download_root), quiet=False)
            if downloaded is None:
                result["errors"].append("Google Drive folder download returned no files")
            result["files"] = copy_selected_files(download_root, destination, extensions)
        result["status"] = "completed"
    except Exception as exc:
        result["status"] = "completed_with_errors"
        result["errors"].append(f"GDRIVE_DOWNLOAD_ERROR: {exc}")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest images, APKs, contacts, archives, and configuration payloads from a public Google Drive folder.")
    parser.add_argument("--folder-url", default=os.environ.get("GDRIVE_FOLDER_URL"), help="Public Google Drive folder URL; defaults to GDRIVE_FOLDER_URL")
    parser.add_argument("--destination", default=os.environ.get("GDRIVE_DESTINATION", "evidence"), help="Evidence root; images route to photos/raw and other payloads to other")
    parser.add_argument("--manifest", default=os.environ.get("GDRIVE_MANIFEST", "evidence/gdrive_ingestion_manifest.json"))
    parser.add_argument("--extensions", default=os.environ.get("GDRIVE_EXTENSIONS"), help="Comma-separated extensions; default is images and APK")
    args = parser.parse_args()
    result = fetch(args.folder_url, Path(args.destination), Path(args.manifest), parse_extensions(args.extensions))
    print(json.dumps({"status": result["status"], "files_copied": len(result["files"]), "errors": result["errors"]}, indent=2))
    return 0 if result["status"] in {"completed", "skipped_no_folder_url"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

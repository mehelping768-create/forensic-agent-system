import hashlib
import json
import zipfile
from pathlib import Path

from PIL import Image

from forensic_agent import ContinuousForensicAgent


def run_scan(tmp_path: Path, evidence: Path):
    output = tmp_path / "manus_report.json"
    report = ContinuousForensicAgent(evidence, output).scan_directory()
    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == report
    return report


def test_missing_evidence_directory_is_reported_without_crashing(tmp_path):
    report = run_scan(tmp_path, tmp_path / "missing")
    assert report["metadata"]["status"] == "completed_with_warnings"
    assert report["metadata"]["finding_count"] == 0
    assert "not found" in report["errors"][0]


def test_empty_evidence_directory_produces_empty_report(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    report = run_scan(tmp_path, evidence)
    assert report["metadata"]["status"] == "completed"
    assert report["findings"] == []
    assert report["errors"] == []


def test_image_metadata_and_hashes_are_recorded_recursively(tmp_path):
    evidence = tmp_path / "evidence" / "nested"
    evidence.mkdir(parents=True)
    image_path = evidence / "sample.png"
    Image.new("RGB", (17, 23), (20, 40, 60)).save(image_path)

    report = run_scan(tmp_path, tmp_path / "evidence")
    finding = report["findings"][0]
    raw = image_path.read_bytes()
    assert finding["path"] == "nested/sample.png"
    assert finding["type"] == "image"
    assert finding["size_bytes"] == len(raw)
    assert finding["hashes"]["md5"] == hashlib.md5(raw, usedforsecurity=False).hexdigest()
    assert finding["hashes"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert finding["analysis"]["format"] == "PNG"
    assert finding["analysis"]["width"] == 17
    assert finding["analysis"]["height"] == 23
    assert finding["errors"] == []


def test_valid_xml_manifest_apk_extracts_package_and_permissions(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app" android:versionName="1.2.3" android:versionCode="7">
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.CAMERA" />
  <application android:label="Example">
    <activity android:name=".MainActivity" />
  </application>
</manifest>'''
    apk_path = evidence / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex placeholder")

    finding = run_scan(tmp_path, evidence)["findings"][0]
    assert finding["type"] == "apk"
    assert finding["flags"] == []
    apk = finding["analysis"]
    assert apk["is_zip_archive"] is True
    assert "classes.dex" in apk["entries"]
    assert apk["manifest"]["package"] == "com.example.app"
    assert apk["manifest"]["version_name"] == "1.2.3"
    assert apk["manifest"]["version_code"] == "7"
    assert apk["manifest"]["permissions"] == ["android.permission.CAMERA", "android.permission.INTERNET"]
    assert apk["manifest"]["components"] == [{"type": "activity", "name": ".MainActivity"}]


def test_invalid_apk_is_flagged_and_scan_continues(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "broken.apk").write_bytes(b"not a zip archive")
    (evidence / "ordinary.txt").write_text("keep scanning", encoding="utf-8")

    report = run_scan(tmp_path, evidence)
    by_name = {item["filename"]: item for item in report["findings"]}
    assert "INVALID_APK_ARCHIVE" in by_name["broken.apk"]["flags"]
    assert by_name["ordinary.txt"]["type"] == "file"
    assert len(report["findings"]) == 2


def test_apk_without_manifest_is_flagged(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with zipfile.ZipFile(evidence / "no-manifest.apk", "w") as archive:
        archive.writestr("classes.dex", b"placeholder")
    finding = run_scan(tmp_path, evidence)["findings"][0]
    assert finding["analysis"]["is_zip_archive"] is True
    assert "MISSING_ANDROID_MANIFEST" in finding["flags"]
    assert finding["analysis"]["manifest"] is None


def test_malformed_manifest_is_reported_without_crashing(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with zipfile.ZipFile(evidence / "malformed.apk", "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest><broken>")
    finding = run_scan(tmp_path, evidence)["findings"][0]
    assert "MANIFEST_PARSE_ERROR" in finding["flags"]
    assert finding["analysis"]["manifest"]["parse_status"] == "error"


def test_corrupted_image_is_reported_and_does_not_stop_scan(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "corrupt.jpg").write_bytes(b"invalid image bytes")
    (evidence / "note.txt").write_text("still scanned", encoding="utf-8")
    report = run_scan(tmp_path, evidence)
    by_name = {item["filename"]: item for item in report["findings"]}
    assert by_name["corrupt.jpg"]["type"] == "image"
    assert any(error.startswith("IMAGE_READ_ERROR:") for error in by_name["corrupt.jpg"]["errors"])
    assert by_name["note.txt"]["type"] == "file"


def test_generic_payload_extracts_urls_ips_strings_and_indicators(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    payload = evidence / "app-dump.txt"
    payload.write_text("user=alice callback https://c2.example.test/upload from 192.0.2.10 token contacts", encoding="utf-8")
    finding = run_scan(tmp_path, evidence)["findings"][0]
    raw = finding["analysis"]["payload"]
    assert "https://c2.example.test/upload" in raw["urls"]
    assert "192.0.2.10" in raw["ip_addresses"]
    assert any(item["indicator"] == "POTENTIAL_COMMAND_AND_CONTROL" for item in finding["indicators"])
    assert any(item["indicator"] == "POTENTIAL_CREDENTIAL_OR_CONTACT_ACCESS" for item in finding["indicators"])
    assert raw["text_utf8"].startswith("user=alice")


def test_manifest_preserves_intent_filters_services_and_string_resources(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.deep">
      <uses-permission android:name="android.permission.INTERNET" />
      <application android:label="Clone">
        <activity android:name=".MainActivity"><intent-filter><action android:name="android.intent.action.VIEW" /><category android:name="android.intent.category.DEFAULT" /></intent-filter></activity>
        <service android:name=".UploadService" />
      </application>
    </manifest>'''
    strings = b'''<resources><string name="endpoint">https://c2.example.test/api</string><string name="operator">alice</string></resources>'''
    with zipfile.ZipFile(evidence / "deep.apk", "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("res/values/strings.xml", strings)
        archive.writestr("classes.dex", b"callback https://c2.example.test/api 198.51.100.7")
    finding = run_scan(tmp_path, evidence)["findings"][0]
    apk = finding["analysis"]
    assert apk["manifest"]["permissions"] == ["android.permission.INTERNET"]
    assert len(apk["manifest"]["intent_filters"]) == 1
    assert {item["type"] for item in apk["manifest"]["components"]} == {"activity", "service"}
    assert len(apk["manifest"]["string_resources"]) == 0
    assert any(item["filename"] == "res/values/strings.xml" for item in apk["resources"])
    assert "https://c2.example.test/api" in apk["all_urls"]
    assert "198.51.100.7" in apk["all_ip_addresses"]


def test_gdrive_ingestion_skips_cleanly_without_configured_url(tmp_path):
    from scripts.fetch_gdrive import fetch, parse_extensions

    destination = tmp_path / "evidence"
    manifest_path = tmp_path / "manifest.json"
    result = fetch(None, destination, manifest_path, parse_extensions(None))
    assert result["status"] == "skipped_no_folder_url"
    assert result["files"] == []
    assert json.loads(manifest_path.read_text()) ["status"] == "skipped_no_folder_url"


def test_gdrive_ingestion_copies_only_allowed_files_with_provenance(tmp_path):
    from scripts.fetch_gdrive import copy_selected_files

    download_root = tmp_path / "download"
    source_dir = download_root / "folder"
    source_dir.mkdir(parents=True)
    (source_dir / "photo.JPG").write_bytes(b"image")
    (source_dir / "app.apk").write_bytes(b"apk")
    (source_dir / "notes.txt").write_text("not copied", encoding="utf-8")
    destination = tmp_path / "evidence"
    copied = copy_selected_files(download_root, destination, {".jpg", ".apk"})
    assert {item["destination_relative_path"] for item in copied} == {"photos/raw/folder/photo.JPG", "other/folder/app.apk"}
    assert not (destination / "folder/notes.txt").exists()
    assert all(item["sha256"] for item in copied)

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

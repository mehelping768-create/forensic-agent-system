# forensic-agent-system

`forensic-agent-system` is a read-only, recursive digital-forensics scanner for image files, Android APK archives, and text/configuration evidence payloads. It computes MD5 and SHA-256 hashes for every encountered file, records all image metadata and EXIF tags returned by the installed parsers, captures complete ZIP entry details, preserves readable manifest XML and every parsed XML attribute/element, extracts strings, URLs, IP addresses, permissions, intent filters, components, and string resources, and writes a raw structured JSON report to `manus_report.json` without metadata filtering.

> This project records observable file properties and parsing results. It is not a substitute for a formal chain-of-custody process, malware sandbox, decompiler, or legal forensic methodology.

## Requirements

The project supports Python 3.10 or newer. Install dependencies into a virtual environment before running the scanner:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Evidence layout

Place evidence below the repository’s `evidence/` directory. Nested directories are supported, and the scanner does not modify files.

```text
evidence/
├── case-001/
│   ├── photograph.jpg
│   └── application.apk
└── notes.txt
```

Supported image extensions are `.jpg`, `.jpeg`, `.png`, `.tif`, `.tiff`, `.webp`, `.bmp`, and `.gif`. Files with the `.apk` extension are treated as Android application archives. Other files are still recorded with their size, MIME guess, and hashes, but receive no format-specific analysis.

## Running the scanner

From the repository root, run:

```bash
python forensic_agent.py
```

The default command recursively scans `evidence/` and writes `manus_report.json`. Custom paths can be supplied for local testing or scheduled execution:

```bash
python forensic_agent.py --evidence /path/to/evidence --output /path/to/manus_report.json
```

Missing or empty evidence directories are handled gracefully. A missing directory produces a report with `completed_with_warnings` status and a top-level error; an empty directory produces a completed report with zero findings. Individual corrupted files produce per-finding errors and flags without stopping the rest of the scan.

## Report schema

The report is a JSON object with the following top-level fields. Raw reports use schema version `2.0-raw`, set `metadata.filtering` to `none`, and set `metadata.analysis_mode` to `deep`.

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Report schema version, currently `2.0-raw`. |
| `metadata` | object | Scan timestamp, target path, status, and finding count. |
| `findings` | array | One object per regular file recursively found under the evidence directory. |
| `errors` | array | Scan-level errors, such as a missing evidence directory. |

Each finding also includes `file_attributes`, containing available filesystem stat values such as size, mode, UID, GID, inode, device, link count, and nanosecond timestamps. No permission, EXIF, ZIP-entry, XML-attribute, URL, IP, or string whitelist is used. Image findings preserve Pillow image information, Pillow EXIF values, and all ExifRead tags. APK findings preserve every ZIP entry and entry-payload detail, readable manifest XML plus a recursive raw element tree, all printable strings, URLs, IP addresses, permissions, intent filters, components, and resource payloads. Generic text/configuration payloads preserve UTF-8 text, printable strings, URLs, IP addresses, and base64 raw bytes. Binary Android XML is preserved as raw hexadecimal bytes with an explicit parse error rather than silently discarded.

Each finding contains common path, type, size, hash, analysis, flags, and errors fields. The raw report preserves all parser-returned image and EXIF data, every APK archive entry detail, and all parseable manifest XML content. Release APKs commonly use Android binary XML; those files are preserved as raw hexadecimal bytes with an explicit parse error rather than being silently discarded. Invalid archives and missing manifests are represented through flags and errors. Indicator matches are additive and include potential remote-access tools, command-and-control references, exfiltration hooks, credential/contact access, and clone or repackaging terms; they never suppress raw data and are not proof of malicious behavior.

A representative report fragment is:

```json
{
  "schema_version": "1.0",
  "metadata": {"status": "completed", "finding_count": 1},
  "findings": [{
    "path": "case-001/photograph.jpg",
    "type": "image",
    "hashes": {"md5": "...", "sha256": "..."},
    "analysis": {"format": "JPEG", "width": 800, "height": 600, "mode": "RGB", "exif": {}},
    "flags": [],
    "errors": []
  }],
  "errors": []
}
```

## Google Drive ingestion

The workflow ingests files from the configured public Google Drive folder `https://drive.google.com/drive/folders/1UOmnVMArcB0tp94fIP71HYv1oTc5PuCu` before running the raw scan. A repository Actions secret named `GDRIVE_FOLDER_URL` may override this default URL. The ingestion step downloads the folder into a temporary workspace, routes raw images into `evidence/photos/raw/`, routes APKs, contact cards, archives, lists, and configuration payloads into `evidence/other/`, avoids overwriting existing files by adding a `__gdrive` suffix, and writes `evidence/gdrive_ingestion_manifest.json` with source paths, destination paths, sizes, and SHA-256 hashes. It never deletes existing evidence and never executes downloaded content.

The same operation can be run locally:

```bash
export GDRIVE_FOLDER_URL="https://drive.google.com/drive/folders/1UOmnVMArcB0tp94fIP71HYv1oTc5PuCu"
python scripts/fetch_gdrive.py --destination evidence --manifest evidence/gdrive_ingestion_manifest.json
```

If `GDRIVE_FOLDER_URL` is not configured, the script exits successfully with `skipped_no_folder_url`, allowing the workflow to scan repository evidence without requiring a Drive source. The folder must be publicly accessible to the downloader; authenticated private Drive ingestion should use a separately managed service account or API credential rather than committing credentials to the repository.

## Historical timeline and call-log analysis

Run `python scripts/generate_historical_timeline.py` to create `historical_timeline_summary.json` and extend `forensic_detailed_summary.json`. The analyzer safely inspects archive members, JSON/XML/text exports, database candidates, image metadata already present in the detailed report, filesystem timestamps, and archive-member timestamps. It does not execute archives or contact discovered endpoints. Call-log records are reported with direction, timestamps, and durations when a supported database or export is present; absent records are reported explicitly rather than inferred.

## Account security audit

Run `python scripts/generate_account_security_audit.py` after ingestion to create `account_security_audit.json`. The audit extracts observed usernames, phone numbers, email addresses, contact-change phrases, URLs, IP addresses, and additive network/account/contact indicators from text, VCF, HTML, and ZIP payloads. It is read-only and treats pattern matches as observations rather than proof of compromise.

## Tests

Run the complete test suite with:

```bash
pytest -q
```

The tests cover missing and empty evidence directories, recursive scanning, valid and malformed APK archives, XML manifest permissions and package details, image dimensions and hashes, corrupted images, and JSON serialization. The default workflow generates the raw report with `python forensic_agent.py --evidence evidence --output manus_report.json`.

## Security and evidence handling

Keep sensitive evidence outside public repositories and restrict access to generated reports. The scanner reads files but does not alter them; nevertheless, running it on untrusted inputs consumes local resources. Review report retention, access permissions, and chain-of-custody requirements before using it in an operational investigation.

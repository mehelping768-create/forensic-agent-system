# forensic-agent-system

`forensic-agent-system` is a read-only, recursive digital-forensics scanner for image files and Android APK archives. It computes MD5 and SHA-256 hashes for every encountered file, records image metadata and EXIF tags, and inspects APK ZIP contents and readable XML manifests. The scanner writes a structured JSON report to `manus_report.json`.

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

The report is a JSON object with the following top-level fields:

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Report schema version, currently `1.0`. |
| `metadata` | object | Scan timestamp, target path, status, and finding count. |
| `findings` | array | One object per regular file recursively found under the evidence directory. |
| `errors` | array | Scan-level errors, such as a missing evidence directory. |

Each finding contains common path, type, size, hash, analysis, flags, and errors fields. Image analysis includes `format`, `width`, `height`, `mode`, and an `exif` object. APK analysis includes archive entries and manifest details such as package name, version values, permissions, application label, and component names. Release APKs commonly use Android binary XML; those files are identified as unsupported rather than being misinterpreted. Invalid archives and missing manifests are represented through flags and errors.

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

## Tests

Run the complete test suite with:

```bash
pytest -q
```

The tests cover missing and empty evidence directories, recursive scanning, valid and malformed APK archives, XML manifest permissions and package details, image dimensions and hashes, corrupted images, and JSON serialization.

## Security and evidence handling

Keep sensitive evidence outside public repositories and restrict access to generated reports. The scanner reads files but does not alter them; nevertheless, running it on untrusted inputs consumes local resources. Review report retention, access permissions, and chain-of-custody requirements before using it in an operational investigation.

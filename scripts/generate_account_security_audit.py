"""Generate a structured account and contact security audit from evidence payloads.

This is a read-only extractor. It does not contact discovered endpoints or execute
archives. Sensitive values remain in the JSON report for repository-controlled review.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

URL_RE = re.compile(r"(?i)\b(?:https?|ftp|ws|wss)://[^\s\"'<>]+")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w.])")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{6,}\d)(?!\w)")
USERNAME_RE = re.compile(r"(?im)\b(?:username|user[_ -]?name|user|login|handle|screen[_ -]?name|account)\s*[:=]\s*([^\r\n<]{1,160})")
CHANGE_RE = re.compile(r"(?im)([^\r\n]{0,80}(?:created|updated|changed|added|removed|deleted|modified|joined|left|last active|last login|set time|upload time)[^\r\n]{0,180})")
INDICATOR_RULES = {
    "NETWORK_ENDPOINT": re.compile(r"(?i)\b(?:https?|ftp|ws|wss)://|\b(?:c2|c&c|callback|webhook|beacon|reverse.?shell)\b"),
    "CONTACT_ACCESS": re.compile(r"(?i)\b(?:contact|address.?book|phone number|call log|sms|vcard|vcf)\b"),
    "ACCOUNT_ACCESS": re.compile(r"(?i)\b(?:username|email|password|credential|token|cookie|account|login|session)\b"),
    "EXFILTRATION_REFERENCE": re.compile(r"(?i)\b(?:upload|exfil|send|transfer|telegram|discord|pastebin|ngrok|gofile)\b"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def clean(value: str) -> str:
    return html.unescape(value).strip(" \t\r\n\"'<>;,.")


def extract_from_text(text: str) -> dict[str, list[str]]:
    text = html.unescape(text)
    usernames = [clean(m) for m in USERNAME_RE.findall(text)]
    phones = sorted({clean(m) for m in PHONE_RE.findall(text) if len(re.sub(r"\D", "", m)) >= 7})
    emails = sorted(set(EMAIL_RE.findall(text)))
    urls = sorted(set(clean(m) for m in URL_RE.findall(text)))
    ips = sorted(set(IP_RE.findall(text)))
    changes = sorted(set(clean(m) for m in CHANGE_RE.findall(text)))
    indicators = sorted({name for name, pattern in INDICATOR_RULES.items() if pattern.search(text)})
    return {"usernames": usernames, "phone_numbers": phones, "email_addresses": emails, "urls": urls, "ip_addresses": ips, "contact_changes": changes, "network_indicators": indicators}


def merge(target: dict[str, list[str]], source: dict[str, list[str]]) -> None:
    for key, values in source.items():
        target.setdefault(key, []).extend(values)


def analyze_payload(path: Path, relative: str) -> dict[str, Any]:
    data = path.read_bytes()
    text = printable_text(data)
    extracted = extract_from_text(text)
    record = {"path": relative, "size_bytes": len(data), "sha256": sha256(data), "sources": [{"path": relative, "kind": "file"}], **extracted}
    if path.suffix.lower() == ".vcf":
        record["contact_records"] = text.count("BEGIN:VCARD")
    if path.suffix.lower() == ".zip" or data[:2] == b"PK":
        record["archive_entries"] = []
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    entry_data = archive.read(info.filename)
                    entry_text = printable_text(entry_data)
                    entry_extracted = extract_from_text(entry_text)
                    merge(record, entry_extracted)
                    record["archive_entries"].append({"name": info.filename, "size_bytes": info.file_size, "sha256": sha256(entry_data), **entry_extracted})
        except zipfile.BadZipFile as exc:
            record["archive_error"] = str(exc)
    for key in ("usernames", "phone_numbers", "email_addresses", "urls", "ip_addresses", "contact_changes", "network_indicators"):
        record[key] = sorted(set(record[key]))
    return record


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    evidence = root / "evidence"
    output = root / "account_security_audit.json"
    findings = []
    for path in sorted(evidence.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.name != "gdrive_ingestion_manifest.json":
            findings.append(analyze_payload(path, path.relative_to(evidence).as_posix()))
    totals = {key: sorted({value for finding in findings for value in finding[key]}) for key in ("usernames", "phone_numbers", "email_addresses", "urls", "ip_addresses", "contact_changes", "network_indicators")}
    report = {
        "schema_version": "account-security-audit-1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_root": "evidence/",
        "read_only": True,
        "scope": "Extracted account, contact, change-history, and network indicators from available evidence payloads. Values are observations, not proof of compromise.",
        "summary": {"files_analyzed": len(findings), "total_bytes": sum(item["size_bytes"] for item in findings), "indicator_type_counts": dict(Counter(value for finding in findings for value in finding["network_indicators"])), "contact_record_count": sum(item.get("contact_records", 0) for item in findings)},
        "aggregates": totals,
        "findings": findings,
    }
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "files_analyzed": len(findings), "usernames": len(totals["usernames"]), "phone_numbers": len(totals["phone_numbers"]), "contact_changes": len(totals["contact_changes"]), "network_indicators": len(totals["network_indicators"])}, indent=2))


if __name__ == "__main__":
    main()

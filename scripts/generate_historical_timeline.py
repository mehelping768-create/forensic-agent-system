"""Generate historical timeline and call-log analysis from evidence without executing content."""
from __future__ import annotations
import hashlib, json, re, sqlite3, tempfile, zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATE_RE = re.compile(r"\b(?:19|20)\d{2}[-/:]\d{1,2}[-/:]\d{1,2}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?\b")
CALL_TERMS = re.compile(r"(?i)call|duration|incoming|outgoing|missed|dialed|phone|number")
CALL_DB_NAMES = re.compile(r"(?i)(call.?log|calls?|telephony|phone).*(?:db|sqlite|sqlite3)$|(?:db|sqlite|sqlite3)$")


def iso(value: Any) -> str | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Android/Unix timestamps can be seconds or milliseconds.
        seconds = value / 1000 if value > 10_000_000_000 else value
        if 315532800 <= seconds < 4_000_000_000:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    if isinstance(value, str):
        match = DATE_RE.search(value)
        if match:
            raw = match.group(0).replace('/', '-').replace(' ', 'T')
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
                try: return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc).isoformat()
                except ValueError: pass
    return None


def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()


def walk_json(value: Any, path: str = '$') -> list[dict[str, str]]:
    events=[]
    if isinstance(value, dict):
        for key, item in value.items():
            timestamp=iso(item)
            if timestamp: events.append({'timestamp_utc':timestamp,'source_key':f'{path}.{key}','raw_value':str(item)[:500]})
            events.extend(walk_json(item, f'{path}.{key}'))
    elif isinstance(value, list):
        for i,item in enumerate(value): events.extend(walk_json(item, f'{path}[{i}]'))
    elif isinstance(value, str):
        timestamp=iso(value)
        if timestamp: events.append({'timestamp_utc':timestamp,'source_key':path,'raw_value':value[:500]})
    return events


def parse_call_db(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    records=[]
    try:
        con=sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        tables=[row[0] for row in con.execute("select name from sqlite_master where type='table'")]
        for table in tables:
            cols=[row[1] for row in con.execute(f'pragma table_info("{table}")')]
            if not any(re.search(r'(?i)call|number|duration|date|type', c) for c in cols): continue
            rows=con.execute(f'select * from "{table}"').fetchall()
            for row in rows:
                record=dict(zip(cols,row))
                if any(CALL_TERMS.search(f'{k} {v}') for k,v in record.items()): records.append({'table':table,'fields':record})
        con.close(); return records, None
    except Exception as exc: return [], str(exc)


def normalize_call_type(value: Any) -> str:
    mapping = {1: 'incoming', 2: 'outgoing', 3: 'missed', '1': 'incoming', '2': 'outgoing', '3': 'missed'}
    return mapping.get(value, str(value).lower() if value is not None else 'unknown')


def json_call_records(obj: Any, source: str) -> list[dict[str, Any]]:
    items = obj.get('items', []) if isinstance(obj, dict) else obj if isinstance(obj, list) else []
    if not isinstance(items, list): return []
    records=[]
    for item in items:
        if not isinstance(item, dict) or not any(k in item for k in ('number','duration','type','date')): continue
        raw_date=item.get('date')
        timestamp=iso(raw_date)
        records.append({'source':source,'direction':normalize_call_type(item.get('type')),'timestamp_utc':timestamp,'duration_seconds':item.get('duration'),'number':item.get('number'),'name':item.get('name'),'raw_fields':item})
    return records


def inspect_bytes(data: bytes, source: str) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    timeline=[]; call_candidates=[]
    text=data.decode('utf-8', errors='replace')
    for match in DATE_RE.finditer(text): timeline.append({'timestamp_utc':iso(match.group(0)),'source':source,'context':text[max(0,match.start()-100):match.end()+100]})
    try:
        obj=json.loads(text)
        timeline.extend({'timestamp_utc':e['timestamp_utc'],'source':source,'context':e['raw_value']} for e in walk_json(obj))
        records=json_call_records(obj, source)
        if records: call_candidates.append({'source':source,'reason':'structured JSON call export','record_count':len(records),'records':records})
    except Exception: pass
    if CALL_TERMS.search(text) and not call_candidates: call_candidates.append({'source':source,'reason':'call-related terms present','record_count':0,'records':[]})
    return timeline, call_candidates


def main() -> None:
    root=Path(__file__).resolve().parents[1]; evidence=root/'evidence'; output=root/'historical_timeline_summary.json'
    timeline=[]; call_logs=[]; archive_members=[]; db_candidates=[]; file_timestamps=[]
    for path in sorted(evidence.rglob('*')):
        if not path.is_file() or path.name in {'manus_report.json', 'gdrive_ingestion_manifest.json'}: continue
        stat=path.stat(); file_timestamps.append({'path':path.relative_to(evidence).as_posix(),'modify_time_utc':datetime.fromtimestamp(stat.st_mtime,tz=timezone.utc).isoformat(),'change_time_utc':datetime.fromtimestamp(stat.st_ctime,tz=timezone.utc).isoformat(),'size_bytes':stat.st_size})
        data=path.read_bytes(); ts,candidates=inspect_bytes(data,path.relative_to(evidence).as_posix()); timeline.extend(ts); call_logs.extend(candidates)
        if CALL_DB_NAMES.search(path.name):
            records,error=parse_call_db(path); db_candidates.append({'path':path.relative_to(evidence).as_posix(),'records':records,'error':error}); call_logs.append({'source':path.relative_to(evidence).as_posix(),'reason':'database filename candidate','record_count':len(records),'records':records})
        if path.suffix.lower()=='.zip':
            try:
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        archive_members.append({'archive':path.relative_to(evidence).as_posix(),'member':info.filename,'archive_datetime_utc':datetime(*info.date_time,tzinfo=timezone.utc).isoformat(),'size_bytes':info.file_size})
                        member=archive.read(info.filename); m_ts,m_calls=inspect_bytes(member,f'{path.relative_to(evidence).as_posix()}::{info.filename}'); timeline.extend(m_ts); call_logs.extend(m_calls)
                        if CALL_DB_NAMES.search(info.filename): call_logs.append({'source':f'{path.name}::{info.filename}','reason':'database filename candidate inside archive','record_count':0,'records':[]})
            except zipfile.BadZipFile as exc: call_logs.append({'source':path.relative_to(evidence).as_posix(),'reason':f'bad zip: {exc}','record_count':0,'records':[]})
    unique={json.dumps(x,sort_keys=True):x for x in timeline if x.get('timestamp_utc')}; timeline=sorted(unique.values(),key=lambda x:x['timestamp_utc'] or '')
    call_records=[r for c in call_logs for r in c.get('records',[])]
    direction_counts=Counter(r.get('direction','unknown') for r in call_records)
    duration_total=sum(float(r.get('duration_seconds') or 0) for r in call_records if str(r.get('duration_seconds') or '').replace('.','',1).isdigit())
    result={'schema_version':'historical-timeline-1.0','generated_at_utc':datetime.now(timezone.utc).isoformat(),'scope':'Observed timestamps and call-log candidates from available evidence; gaps are not proof of missing evidence.','summary':{'files_scanned':len(file_timestamps),'timeline_event_count':len(timeline),'earliest_observed_timestamp_utc':timeline[0]['timestamp_utc'] if timeline else None,'latest_observed_timestamp_utc':timeline[-1]['timestamp_utc'] if timeline else None,'call_log_sources':len(call_logs),'call_record_count':len(call_records),'incoming_count':direction_counts.get('incoming',0),'outgoing_count':direction_counts.get('outgoing',0),'missed_count':direction_counts.get('missed',0),'duration_seconds_total':duration_total},'call_log_analysis':{'database_candidates':db_candidates,'sources':call_logs,'records':call_records},'timeline_events':timeline,'filesystem_timestamps':file_timestamps,'archive_members':archive_members}
    output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    # Extend the existing detailed report without replacing its raw findings.
    detail_path=root/'forensic_detailed_summary.json'
    if detail_path.exists():
        detail=json.loads(detail_path.read_text()); detail['historical_timeline']=result; detail_path.write_text(json.dumps(detail,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(result['summary'],indent=2))

if __name__=='__main__': main()

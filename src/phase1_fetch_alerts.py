"""
Phase 1: Elastic Alert Fetcher
"""
import json
import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from elasticsearch import Elasticsearch, exceptions as es_exceptions

load_dotenv()

ES_HOST = os.getenv("ES_HOST", "localhost")
ES_PORT = int(os.getenv("ES_PORT", 9200))
ES_USER = os.getenv("ES_USER", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")

EVENT_PROFILE = {
    4625: {"name": "An account failed to log on", "mitre_technique": "T1110", "mitre_name": "Brute Force", "initial_severity": "Medium", "category": "credential_attack"},
    4740: {"name": "A user account was locked out", "mitre_technique": "T1110", "mitre_name": "Brute Force", "initial_severity": "High", "category": "credential_attack"},
    4720: {"name": "A user account was created", "mitre_technique": "T1136", "mitre_name": "Create Account", "initial_severity": "High", "category": "persistence"},
    4732: {"name": "A member was added to a security-enabled local group", "mitre_technique": "T1078", "mitre_name": "Valid Accounts / Privilege Escalation", "initial_severity": "High", "category": "privilege_escalation"}
}

TARGET_EVENT_IDS = list(EVENT_PROFILE.keys())

def create_es_client():
    connection_config = {"hosts": [{"host": ES_HOST, "port": ES_PORT, "scheme": "http"}]}
    if ES_USER and ES_PASSWORD:
        connection_config["basic_auth"] = (ES_USER, ES_PASSWORD)
    client = Elasticsearch(**connection_config)
    try:
        info = client.info()
        print(f"[OK] 連線成功 Elasticsearch {info['version']['number']}")
    except es_exceptions.ConnectionError as e:
        print(f"[ERROR] 無法連線: {e}")
        raise
    return client

def build_alert_query(hours_back=24):
    now = datetime.now(timezone.utc)
    time_from = now - timedelta(hours=hours_back)
    return {
        "query": {"bool": {"must": [
            {"terms": {"winlog.event_id": TARGET_EVENT_IDS}},
            {"range": {"@timestamp": {"gte": time_from.isoformat(), "lte": now.isoformat()}}}
        ]}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 100
    }

def format_alert(raw_hit):
    source = raw_hit.get("_source", {})
    winlog = source.get("winlog", {})
    event_data = winlog.get("event_data", {})
    host_info = source.get("host", {})
    event_id = winlog.get("event_id")
    profile = EVENT_PROFILE.get(int(event_id), {}) if event_id else {}
    return {
        "alert_id": raw_hit.get("_id", "unknown"),
        "timestamp": source.get("@timestamp", "unknown"),
        "event_id": event_id,
        "event_name": profile.get("name", "Unknown Event"),
        "target_account": {"username": event_data.get("TargetUserName", "unknown"), "domain": event_data.get("TargetDomainName", "unknown")},
        "source_ip": event_data.get("IpAddress", "unknown"),
        "host": {"name": host_info.get("name", "unknown"), "ip": host_info.get("ip", ["unknown"])[0] if isinstance(host_info.get("ip"), list) else "unknown"},
        "mitre": {"technique_id": profile.get("mitre_technique", "Unknown"), "technique_name": profile.get("mitre_name", "Unknown"), "category": profile.get("category", "unknown")},
        "initial_severity": profile.get("initial_severity", "Medium"),
        "raw_event_data": event_data
    }

def fetch_alerts(es_client, index_pattern="winlogbeat-*", hours_back=168):
    query = build_alert_query(hours_back=hours_back)
    print(f"\n[INFO] 查詢 index: {index_pattern}，時間範圍: 最近 {hours_back} 小時")
    try:
        response = es_client.search(index=index_pattern, body=query)
    except es_exceptions.NotFoundError:
        print(f"[WARN] Index 不存在，嘗試 logs-*...")
        try:
            response = es_client.search(index="logs-*", body=query)
        except es_exceptions.NotFoundError:
            print("[ERROR] 找不到任何 index")
            return []
    hits = response.get("hits", {}).get("hits", [])
    total = response.get("hits", {}).get("total", {}).get("value", 0)
    print(f"[RESULT] 找到 {total} 筆 alerts（取回 {len(hits)} 筆）")
    formatted_alerts = []
    for hit in hits:
        try:
            formatted_alerts.append(format_alert(hit))
        except Exception as e:
            print(f"[WARN] 格式化失敗: {e}")
    return formatted_alerts

def main():
    print("=" * 50)
    print(" Phase 1: Elastic Alert Fetcher")
    print("=" * 50)
    es = create_es_client()
    alerts = fetch_alerts(es_client=es, index_pattern="winlogbeat-*", hours_back=168)
    if not alerts:
        print("\n[WARN] 沒有找到 alerts，使用測試資料...")
        alerts = [
            {"alert_id": "test-001", "timestamp": "2025-06-20T02:30:00Z", "event_id": 4625, "event_name": "An account failed to log on", "target_account": {"username": "Administrator", "domain": "WORKSTATION"}, "source_ip": "192.168.56.102", "host": {"name": "WIN-TARGET", "ip": "192.168.56.101"}, "mitre": {"technique_id": "T1110", "technique_name": "Brute Force", "category": "credential_attack"}, "initial_severity": "Medium", "raw_event_data": {"LogonType": "3"}},
            {"alert_id": "test-002", "timestamp": "2025-06-20T02:31:00Z", "event_id": 4740, "event_name": "A user account was locked out", "target_account": {"username": "Administrator", "domain": "WORKSTATION"}, "source_ip": "192.168.56.102", "host": {"name": "WIN-TARGET", "ip": "192.168.56.101"}, "mitre": {"technique_id": "T1110", "technique_name": "Brute Force", "category": "credential_attack"}, "initial_severity": "High", "raw_event_data": {}},
            {"alert_id": "test-003", "timestamp": "2025-06-20T14:00:00Z", "event_id": 4720, "event_name": "A user account was created", "target_account": {"username": "backdoor_svc", "domain": "WORKSTATION"}, "source_ip": "192.168.56.102", "host": {"name": "WIN-TARGET", "ip": "192.168.56.101"}, "mitre": {"technique_id": "T1136", "technique_name": "Create Account", "category": "persistence"}, "initial_severity": "High", "raw_event_data": {"SubjectUserName": "Administrator"}}
        ]
        print(f"[INFO] 使用 {len(alerts)} 筆測試資料")

    output = {"phase": 1, "description": "Formatted alerts from Elastic SIEM", "summary": {"total_alerts": len(alerts)}, "alerts": alerts}
    with open("phase1_alerts.json", "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n[OK] 已儲存至 phase1_alerts.json，共 {len(alerts)} 筆")
    print("[NEXT] 執行 phase2_triage_engine.py")

if __name__ == "__main__":
    main()

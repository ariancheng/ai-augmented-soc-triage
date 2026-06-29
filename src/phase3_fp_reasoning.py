"""
Phase 3: False Positive Reasoning Engine
"""
import json
import os
import time
from datetime import datetime, timezone
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
MODEL = "claude-sonnet-4-6"

BASELINE_CONTEXT = {
    "organization": "Home Lab SOC Exercise Environment",
    "business_hours": {"start": "00:00", "end": "23:59", "timezone": "UTC", "note": "Lab environment, all hours considered business hours"},
    "known_admin_ips": ["192.168.56.1", "192.168.56.100", "172.16.10.1"],
    "service_accounts": ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "winlogbeat_svc"],
    "authorized_account_creators": ["Administrator", "admin"],
    "authorized_group_managers": ["Administrator", "admin"],
    "sensitive_accounts": ["Administrator", "Domain Admin", "krbtgt"]
}

FEW_SHOT_EXAMPLES = """
EXAMPLE 1 - FALSE POSITIVE (FP Likelihood: High):
Alert: Event ID 4625, target: helpdesk_svc, source IP: 192.168.56.1, time: 09:15 UTC
Context: Source IP is known admin workstation. Target is a service account. Single failure.
Analysis: Service accounts occasionally fail authentication during scheduled tasks. Single failure from trusted IP.
Result: {"fp_likelihood": "High", "fp_category": "Service Account Operational Noise", "is_likely_fp": true}

EXAMPLE 2 - TRUE POSITIVE (FP Likelihood: Low):
Alert: Event ID 4625 x47 attempts, target: Administrator, source IP: 10.0.0.99, time: 02:30 UTC
Context: 47 failed attempts in 3 minutes. Source IP not in known-good list. Target is high-privilege account.
Analysis: Rapid sequential failures against Administrator from unknown IP is textbook brute force.
Result: {"fp_likelihood": "Low", "fp_category": "Active Brute Force Attack", "is_likely_fp": false}

EXAMPLE 3 - AMBIGUOUS (FP Likelihood: Medium):
Alert: Event ID 4720, target created: temp_user_01, creator: Administrator, time: 14:00 UTC
Context: Administrator is authorized to create accounts. Generic account name raises suspicion.
Analysis: Could be legitimate IT activity or persistence mechanism. Needs verification.
Result: {"fp_likelihood": "Medium", "fp_category": "Possibly Legitimate IT Activity", "is_likely_fp": null}
"""

FP_SYSTEM_PROMPT = """You are a senior SOC analyst specializing in alert tuning and false positive reduction.
Assess whether a security alert is likely a FALSE POSITIVE (normal business activity) or TRUE POSITIVE (real threat).
Output ONLY valid JSON. No other text."""

def build_fp_prompt(alert, triage_report):
    return f"""Analyze this alert for false positive likelihood.

ENVIRONMENT BASELINE:
{json.dumps(BASELINE_CONTEXT, indent=2)}

LEARNING EXAMPLES:
{FEW_SHOT_EXAMPLES}

ALERT TO ANALYZE:
{json.dumps(alert, indent=2, ensure_ascii=False, default=str)}

PHASE 2 AI TRIAGE CONTEXT:
{json.dumps({
    "ai_severity": triage_report.get("severity_assessment", {}).get("level"),
    "ai_technique": triage_report.get("mitre_attack", {}).get("technique_id"),
    "ai_escalated": triage_report.get("escalation", {}).get("escalate_to_l2")
}, indent=2)}

Return ONLY a JSON object:
{{
  "alert_id": "<same as input>",
  "fp_analysis_timestamp": "<ISO 8601 UTC>",
  "fp_assessment": {{
    "fp_likelihood": "<High | Medium | Low>",
    "is_likely_fp": <true | false | null>,
    "confidence": "<High | Medium | Low>"
  }},
  "fp_reasoning": {{
    "primary_reason": "<main reason, 1-2 sentences>",
    "supporting_evidence": ["<evidence 1>", "<evidence 2>"],
    "contra_evidence": ["<evidence against FP or null>"],
    "fp_category": "<Service Account Noise | Admin Activity | Legitimate IT Operations | Active Attack | Unknown>",
    "baseline_match": "<how does this compare to known baseline?>"
  }},
  "recommended_action": {{
    "action": "<CLOSE_FP | VERIFY_WITH_OWNER | ESCALATE | MONITOR>",
    "action_detail": "<specific next step for L1 analyst>",
    "auto_close_eligible": <true | false>
  }},
  "tuning_suggestion": {{
    "suggest_rule_tuning": <true | false>,
    "tuning_note": "<suggest how to tune the detection rule if this is a known FP pattern>"
  }}
}}"""

def analyze_false_positive(alert, triage_report):
    prompt = build_fp_prompt(alert, triage_report)
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=1000,
            temperature=0.1,
            system=FP_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
        raw_output = response.content[0].text.strip()
        if "```" in raw_output:
            raw_output = raw_output.split("```")[1]
            if raw_output.startswith("json"):
                raw_output = raw_output[4:]
        return json.loads(raw_output)
    except Exception as e:
        return {
            "alert_id": alert.get("alert_id"),
            "error": str(e),
            "fp_assessment": {"fp_likelihood": "Low", "is_likely_fp": False, "confidence": "Low"},
            "recommended_action": {"action": "ESCALATE", "action_detail": "FP analysis failed. Manual review required."}
        }

def merge_and_prioritize(alerts, triage_reports, fp_reports):
    triage_by_id = {r.get("alert_id"): r for r in triage_reports}
    fp_by_id = {r.get("alert_id"): r for r in fp_reports}
    merged = []
    for alert in alerts:
        aid = alert.get("alert_id")
        triage = triage_by_id.get(aid, {})
        fp = fp_by_id.get(aid, {})
        fp_likelihood = fp.get("fp_assessment", {}).get("fp_likelihood", "Low")
        ai_severity = triage.get("severity_assessment", {}).get("level", "Medium")
        escalate = triage.get("escalation", {}).get("escalate_to_l2", False)
        if fp_likelihood == "High":
            final_disposition = "LIKELY_FP"
            final_priority = "P4"
        elif fp_likelihood == "Medium":
            final_disposition = "NEEDS_VERIFICATION"
            final_priority = "P3"
        elif ai_severity == "High" and escalate:
            final_disposition = "ESCALATE_L2"
            final_priority = "P1"
        else:
            final_disposition = "L1_MONITOR"
            final_priority = "P2"
        merged.append({
            "alert_id": aid,
            "event_id": alert.get("event_id"),
            "timestamp": alert.get("timestamp"),
            "target_account": alert.get("target_account", {}).get("username"),
            "source_ip": alert.get("source_ip"),
            "ai_severity": ai_severity,
            "fp_likelihood": fp_likelihood,
            "final_disposition": final_disposition,
            "final_priority": final_priority,
            "triage_report": triage,
            "fp_report": fp
        })
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    merged.sort(key=lambda x: priority_order.get(x.get("final_priority", "P3"), 3))
    return merged

def main():
    print("=" * 50)
    print(" Phase 3: False Positive Reasoning Engine")
    print("=" * 50)

    with open("phase1_alerts.json", "r", encoding="utf-8") as f:
        phase1_data = json.load(f)
    with open("phase2_triage_reports.json", "r", encoding="utf-8") as f:
        phase2_data = json.load(f)

    alerts = phase1_data.get("alerts", [])
    triage_reports = phase2_data.get("triage_reports", [])
    triage_by_id = {r.get("alert_id"): r for r in triage_reports}

    print(f"\n[INFO] Starting FP analysis on {len(triage_reports)} alerts")

    fp_reports = []
    for i, alert in enumerate(alerts[:len(triage_reports)], 1):
        aid = alert.get("alert_id")
        triage = triage_by_id.get(aid, {})
        print(f"[{i:02d}/{len(triage_reports)}] FP analysis Event {alert.get('event_id')} | Target: {alert.get('target_account', {}).get('username', '?')}")
        fp_report = analyze_false_positive(alert, triage)
        fp_likelihood = fp_report.get("fp_assessment", {}).get("fp_likelihood", "?")
        action = fp_report.get("recommended_action", {}).get("action", "?")
        print(f"       → FP Likelihood: {fp_likelihood} | Action: {action}")
        fp_reports.append(fp_report)
        time.sleep(1.5)

    final_alert_queue = merge_and_prioritize(alerts, triage_reports, fp_reports)
    disposition_counts = {}
    for item in final_alert_queue:
        d = item.get("final_disposition", "UNKNOWN")
        disposition_counts[d] = disposition_counts.get(d, 0) + 1

    total = len(final_alert_queue)
    fp_count = disposition_counts.get("LIKELY_FP", 0)
    fp_rate = f"{(fp_count / total * 100):.1f}%" if total > 0 else "0%"

    output = {
        "phase": 3,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "statistics": {
            "total_processed": total,
            "disposition_breakdown": disposition_counts,
            "fp_reduction_rate": f"{fp_rate} alerts identified as likely FP"
        },
        "prioritized_alert_queue": final_alert_queue
    }

    with open("phase3_fp_analysis.json", "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, default=str)

    print(f"\n[OK] Saved to phase3_fp_analysis.json")
    print(f"     Disposition breakdown: {disposition_counts}")
    print(f"     FP reduction rate: {fp_rate}")
    print("[NEXT] Set up GitHub repository (Phase 4)")

if __name__ == "__main__":
    main()

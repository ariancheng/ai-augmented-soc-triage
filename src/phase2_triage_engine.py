"""
Phase 2: Claude Triage Engine
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

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with 10+ years of experience.
Your role is to perform L1 triage analysis on Windows Security Event Log alerts.

CRITICAL RULES:
1. You MUST output ONLY valid JSON. No preamble, no explanation, no markdown code blocks.
2. Follow the exact JSON schema provided in each request.
3. Be concise but thorough.
4. Base your analysis strictly on the evidence provided.

KNOWLEDGE CONTEXT:
- Windows Event ID 4625: Failed logon attempt
- Windows Event ID 4740: Account lockout
- Windows Event ID 4720: New user account created
- Windows Event ID 4732: Member added to security-enabled local group
- MITRE ATT&CK T1110: Brute Force
- MITRE ATT&CK T1136: Create Account (Persistence)
- MITRE ATT&CK T1078: Valid Accounts (Privilege Escalation)"""

def build_user_prompt(alert):
    return f"""Analyze the following Windows Security Event alert and return a triage report.

ALERT DATA:
{json.dumps(alert, indent=2, ensure_ascii=False, default=str)}

Return ONLY a JSON object matching this exact schema:
{{
  "alert_id": "<same as input alert_id>",
  "triage_timestamp": "<ISO 8601 UTC timestamp>",
  "severity_assessment": {{
    "level": "<High | Medium | Low>",
    "confidence": "<High | Medium | Low>",
    "reasoning": "<2-3 sentences explaining why>"
  }},
  "mitre_attack": {{
    "technique_id": "<e.g. T1110.001>",
    "technique_name": "<full technique name>",
    "tactic": "<e.g. Credential Access>",
    "mapping_reasoning": "<why this alert maps to this technique>"
  }},
  "threat_narrative": {{
    "what_happened": "<explain in plain English>",
    "attack_stage": "<Reconnaissance | Initial Access | Persistence | Privilege Escalation | Credential Access>",
    "potential_impact": "<what could happen if this is a true positive>"
  }},
  "l1_immediate_actions": [
    "<action 1>",
    "<action 2>",
    "<action 3>"
  ],
  "escalation": {{
    "escalate_to_l2": <true | false>,
    "priority": "<P1 | P2 | P3>",
    "reasoning": "<explain why>"
  }},
  "ioc_summary": {{
    "source_ip": "<source IP or null>",
    "target_account": "<target username>",
    "host": "<affected hostname>",
    "additional_indicators": []
  }}
}}"""

def analyze_alert(alert, retry_count=3):
    user_prompt = build_user_prompt(alert)
    for attempt in range(retry_count):
        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=1500,
                temperature=0.2,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}]
            )
            raw_output = response.content[0].text.strip()
            if raw_output.startswith("```"):
                raw_output = raw_output.split("```")[1]
                if raw_output.startswith("json"):
                    raw_output = raw_output[4:]
            triage_report = json.loads(raw_output)
            triage_report["_metadata"] = {"model": MODEL, "attempt": attempt + 1}
            return triage_report
        except json.JSONDecodeError as e:
            print(f"  [WARN] JSON parse failed (attempt {attempt+1}): {e}")
            if attempt < retry_count - 1:
                time.sleep(2)
            else:
                return create_error_report(alert, f"JSON parse error: {e}")
        except anthropic.RateLimitError:
            print(f"  [WARN] Rate limit, waiting 30s...")
            time.sleep(30)
        except anthropic.APIError as e:
            print(f"  [ERROR] API error: {e}")
            return create_error_report(alert, str(e))
    return create_error_report(alert, "Max retries exceeded")

def create_error_report(alert, error):
    return {
        "alert_id": alert.get("alert_id", "unknown"),
        "triage_timestamp": datetime.now(timezone.utc).isoformat(),
        "error": error,
        "severity_assessment": {"level": "High", "confidence": "Low", "reasoning": "Automated analysis failed. Manual review required."},
        "escalation": {"escalate_to_l2": True, "priority": "P2", "reasoning": "AI analysis failed. Escalating for manual review."},
        "_metadata": {"error": error, "model": MODEL}
    }

def main():
    print("=" * 50)
    print(" Phase 2: Claude Triage Engine")
    print("=" * 50)

    try:
        with open("phase1_alerts.json", "r", encoding="utf-8") as f:
            phase1_data = json.load(f)
    except FileNotFoundError:
        print("[ERROR] phase1_alerts.json not found. Run phase1 first.")
        return

    alerts = phase1_data.get("alerts", [])
    print(f"\n[INFO] Loaded {len(alerts)} alerts")

    triage_reports = []
    total = len(alerts)

    for i, alert in enumerate(alerts, 1):
        print(f"[{i:02d}/{total}] Analyzing Event {alert.get('event_id')} | Target: {alert.get('target_account', {}).get('username', '?')} | Severity: {alert.get('initial_severity')}")
        report = analyze_alert(alert)
        ai_severity = report.get("severity_assessment", {}).get("level", "?")
        escalate = report.get("escalation", {}).get("escalate_to_l2", "?")
        print(f"       → AI Assessment: {ai_severity} | Escalate L2: {escalate}")
        triage_reports.append(report)
        if i < total:
            time.sleep(1.5)

    output = {
        "phase": 2,
        "model": MODEL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "statistics": {
            "total_analyzed": len(triage_reports),
            "escalated_to_l2": sum(1 for r in triage_reports if r.get("escalation", {}).get("escalate_to_l2") == True),
            "severity_distribution": {
                "High": sum(1 for r in triage_reports if r.get("severity_assessment", {}).get("level") == "High"),
                "Medium": sum(1 for r in triage_reports if r.get("severity_assessment", {}).get("level") == "Medium"),
                "Low": sum(1 for r in triage_reports if r.get("severity_assessment", {}).get("level") == "Low")
            }
        },
        "triage_reports": triage_reports
    }

    with open("phase2_triage_reports.json", "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, default=str)

    print(f"\n[OK] Saved to phase2_triage_reports.json")
    print(f"     Total: {output['statistics']['total_analyzed']} | Escalated: {output['statistics']['escalated_to_l2']}")
    print(f"     Severity: {output['statistics']['severity_distribution']}")
    print("[NEXT] Run phase3_fp_reasoning.py")

if __name__ == "__main__":
    main()

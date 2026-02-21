import os
import json
import time
import asyncio
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load .env so GEMINI_API_KEY is available when running via uvicorn
load_dotenv()

from google import genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# gemini-2.5-flash: confirmed working on free tier
GEMINI_MODEL = "models/gemini-2.5-flash"

_client: Optional[genai.Client] = None

# ─── Rate-Limit Guard ─────────────────────────────────────────────────────────
# Tracks recent Gemini call timestamps to avoid hammering the free-tier quota.
# Free tier allows 20 requests per minute (RPM). We stay safe at 15.
_call_timestamps: list = []
_MAX_CALLS_PER_MINUTE = 15

# ─── Command-Level Cache ──────────────────────────────────────────────────────
# Maps command string → analysis result dict to avoid re-calling Gemini for
# the same command (very common in honeypot simulations).
_analysis_cache: Dict[str, Dict[str, Any]] = {}


def _get_client() -> Optional[genai.Client]:
    global _client
    if _client is None and GEMINI_API_KEY:
        _client = genai.Client(api_key=GEMINI_API_KEY)
    return _client


def _is_quota_available() -> bool:
    """Return True if we have remaining quota for a Gemini call right now."""
    now = time.monotonic()
    # Keep only timestamps from the last 60 seconds
    recent = [t for t in _call_timestamps if now - t < 60]
    _call_timestamps.clear()
    _call_timestamps.extend(recent)
    return len(recent) < _MAX_CALLS_PER_MINUTE


def _record_call():
    """Record that a Gemini API call was just made."""
    _call_timestamps.append(time.monotonic())


def _call_gemini(prompt: str, retries: int = 1) -> Optional[str]:
    """
    Call Gemini with automatic retry on 429 quota errors.
    Uses a rate-limit guard to avoid wasting retries when quota is exhausted.
    Returns the response text, or None if all retries fail.
    NOTE: This is a synchronous function — call via asyncio.to_thread() from
    async contexts to avoid blocking the event loop.
    """
    client = _get_client()
    if not client:
        print("[Gemini] No API key configured.")
        return None

    # Check local rate-limit guard before even trying
    if not _is_quota_available():
        print("[Gemini] Local rate-limit guard: quota near limit, using rule-based fallback.")
        return None

    for attempt in range(retries + 1):
        try:
            _record_call()
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            return response.text
        except Exception as e:
            err = str(e)
            if "429" in err and attempt < retries:
                wait = 30  # Wait for quota reset
                print(f"[Gemini] Rate limited. Waiting {wait}s before retry {attempt+1}/{retries}...")
                time.sleep(wait)
            else:
                print(f"[Gemini] Failed after {attempt+1} attempt(s): {type(e).__name__}: {e}")
                return None
    return None


def analyze_command(command: str) -> Dict[str, Any]:
    """
    Analyze a shell command for threat level using Gemini.
    - Checks the command cache first to avoid redundant API calls.
    - Falls back to rule-based analysis if Gemini is unavailable or rate-limited.
    NOTE: This is synchronous — in async contexts call via asyncio.to_thread().
    """
    # 1. Cache hit — return immediately, no API call needed
    if command in _analysis_cache:
        return _analysis_cache[command]

    # 2. No API key — use rule-based fallback instantly
    if not GEMINI_API_KEY:
        result = _rule_based_analysis(command)
        _analysis_cache[command] = result
        return result

    # 3. Quota guard — fall back without waiting if we're near the limit
    if not _is_quota_available():
        result = _rule_based_analysis(command)
        _analysis_cache[command] = result
        return result

    prompt = (
        "You are a cybersecurity expert analyzing a command entered by an attacker inside an SSH honeypot.\n"
        f"Command: {command}\n\n"
        "Respond ONLY with a valid JSON object (no markdown, no code blocks) with these exact keys:\n"
        '- "severity": one of "LOW", "MEDIUM", "HIGH", "CRITICAL"\n'
        '- "description": short one-line description of what this command does\n'
        '- "action": recommended SOC action (e.g. "Monitor", "Block IP", "Escalate")\n'
        '- "score": integer threat score from 0 to 100\n'
        '- "ttp": MITRE ATT&CK technique name (e.g. "T1059 - Command and Scripting Interpreter")'
    )
    try:
        text = _call_gemini(prompt)
        if not text:
            result = _rule_based_analysis(command)
            _analysis_cache[command] = result
            return result
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)
        _analysis_cache[command] = result
        return result
    except Exception as e:
        print(f"Gemini analysis failed: {e}")
        result = _rule_based_analysis(command)
        _analysis_cache[command] = result
        return result


def generate_attacker_profile(attacker_data: Dict[str, Any]) -> str:
    """
    Generate a detailed attacker profile with TTP mapping using Gemini.
    """
    if not GEMINI_API_KEY:
        return _rule_based_profile(attacker_data)

    commands = attacker_data.get("commands", [])
    credentials = attacker_data.get("credentials", [])
    web_attacks = attacker_data.get("web_attacks", [])

    prompt = (
        "You are a cyber threat intelligence analyst. Based on the following attacker activity from a honeypot, "
        "generate a structured attacker profile.\n\n"
        f"Attacker IP: {attacker_data.get('ip_address', 'Unknown')}\n"
        f"Location: {attacker_data.get('city', '?')}, {attacker_data.get('country', '?')}\n"
        f"Risk Score: {attacker_data.get('risk_score', 0)}/100\n"
        f"SSH Commands Executed: {commands}\n"
        f"Credentials Tried: {credentials}\n"
        f"Web Attack Payloads: {web_attacks}\n\n"
        "Generate a profile with these sections:\n"
        "1. **Threat Actor Classification** (Opportunistic/APT/Script Kiddie/etc.)\n"
        "2. **TTPs Identified** (map to MITRE ATT&CK where possible)\n"
        "3. **Attack Pattern Summary**\n"
        "4. **Estimated Skill Level**\n"
        "5. **Recommended Defensive Actions**\n"
        "Keep it concise but professional. Use markdown formatting."
    )
    text = _call_gemini(prompt)
    if text:
        return text
    return _rule_based_profile(attacker_data)


def generate_threat_report(attacker_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a full structured threat intelligence report.
    Uses Gemini for the narrative; falls back to rule-based analysis when
    Gemini is unavailable (no key, rate-limited, or transient error).
    """
    commands = attacker_data.get("commands", [])
    credentials = attacker_data.get("credentials", [])
    web_attacks = attacker_data.get("web_attacks", [])
    services_hit = attacker_data.get("services_hit", [])

    # Always build a solid rule-based report first; Gemini may enrich it.
    rule_report = _rule_based_report(attacker_data)

    if not GEMINI_API_KEY:
        rule_report["summary"] = (
            "AI report unavailable (no API key). "
            "The following analysis is fully rule-based."
        )
        return rule_report

    prompt = (
        "You are a SOC analyst generating a threat intelligence export report.\n\n"
        f"Attacker IP: {attacker_data.get('ip_address', 'Unknown')}\n"
        f"Location: {attacker_data.get('city', '?')}, {attacker_data.get('country', '?')}\n"
        f"Risk Score: {attacker_data.get('risk_score', 0)}/100\n"
        f"First Seen: {attacker_data.get('first_seen', 'N/A')}\n"
        f"Last Seen: {attacker_data.get('last_seen', 'N/A')}\n"
        f"SSH Commands: {commands}\n"
        f"Credentials Attempted: {credentials}\n"
        f"Web Payloads: {web_attacks}\n"
        f"Honeypot Services Probed: {services_hit}\n\n"
        "Respond ONLY with a valid JSON object (no markdown, no code blocks) with these exact keys:\n"
        '- "summary": multi-sentence executive summary of the attack\n'
        '- "risk_level": one of "LOW", "MEDIUM", "HIGH", "CRITICAL"\n'
        '- "ttps": list of strings, each being a MITRE ATT&CK technique (e.g. "T1110 - Brute Force")\n'
        '- "attacker_type": string classification (e.g. "Opportunistic Bot", "Manual Attacker")\n'
        '- "timeline": list of strings describing attack stages chronologically\n'
        '- "recommendations": list of 3-5 defensive recommendation strings\n'
        '- "ioc": list of indicators of compromise (IPs, usernames, payloads)'
    )
    try:
        text = _call_gemini(prompt)
        if not text:
            # Gemini unavailable — return fully-populated rule-based report
            rule_report["summary"] = (
                "Gemini is temporarily unavailable (rate-limit or quota). "
                "The following analysis is fully rule-based using MITRE ATT&CK mappings."
            )
            return rule_report
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as e:
        print(f"Gemini threat report generation failed: {e}")
        rule_report["summary"] = (
            f"Gemini report generation failed ({type(e).__name__}). "
            "The following analysis is fully rule-based."
        )
        return rule_report


def detect_ttps(commands: list, web_attacks: list, credentials: list, services_hit: list) -> list:
    """
    Rule-based TTP detection mapped to MITRE ATT&CK.
    Returns a list of TTP tag strings.
    """
    ttps = set()

    all_cmds = " ".join(commands).lower()
    all_web = " ".join(web_attacks).lower()

    # Recon
    if any(x in all_cmds for x in ["whoami", "id", "uname", "hostname", "ifconfig", "ip addr"]):
        ttps.add("T1082 - System Information Discovery")
    if any(x in all_cmds for x in ["ps", "netstat", "ss "]):
        ttps.add("T1057 - Process Discovery")

    # Credential Access
    if credentials:
        ttps.add("T1110 - Brute Force")
    if any(x in all_cmds for x in ["cat /etc/passwd", "cat /etc/shadow"]):
        ttps.add("T1003 - OS Credential Dumping")

    # Execution
    if any(x in all_cmds for x in ["bash -i", "python -c", "perl -e", "ruby -e", "php -r"]):
        ttps.add("T1059 - Command and Scripting Interpreter")

    # Persistence
    if any(x in all_cmds for x in ["crontab", ".bashrc", ".profile", "~/.ssh/authorized_keys"]):
        ttps.add("T1053 - Scheduled Task/Job")

    # Defense Evasion
    if any(x in all_cmds for x in ["history -c", "unset HISTFILE", "rm -rf /var/log"]):
        ttps.add("T1070 - Indicator Removal")

    # C2 / Exfiltration
    if any(x in all_cmds for x in ["wget", "curl", "nc ", "ncat", "socat"]):
        ttps.add("T1105 - Ingress Tool Transfer")

    # Web Attacks
    if any(x in all_web for x in ["select", "union", "' or", "1=1", "--"]):
        ttps.add("T1190 - Exploit Public-Facing Application (SQLi)")
    if "<script" in all_web:
        ttps.add("T1059.007 - Cross-Site Scripting")

    # Service Probing
    if "mysql" in services_hit:
        ttps.add("T1046 - Network Service Scanning (MySQL)")
    if "ftp" in services_hit:
        ttps.add("T1046 - Network Service Scanning (FTP)")

    return list(ttps)


def classify_command(command: str) -> Dict[str, Any]:
    """Public, Gemini-free command classifier for real-time SSH logging."""
    return _rule_based_analysis(command)


def _rule_based_analysis(command: str) -> Dict[str, Any]:
    """Fallback rule-based analysis."""
    cmd = command.lower()

    if any(x in cmd for x in ["wget", "curl", "nc ", "ncat", "bash -i", "python -c", "php -r"]):
        return {
            "severity": "CRITICAL",
            "description": "Attempted reverse shell or malware download.",
            "action": "Immediate IP Block",
            "score": 95,
            "ttp": "T1059 - Command and Scripting Interpreter"
        }

    if any(x in cmd for x in ["sudo", "rm -rf", "chmod 777", "chown", "dd ", "mkfs"]):
        return {
            "severity": "HIGH",
            "description": "Destructive or privileged command attempt.",
            "action": "Monitor Closely",
            "score": 75,
            "ttp": "T1548 - Abuse Elevation Control Mechanism"
        }

    if any(x in cmd for x in ["whoami", "id", "pwd", "ls", "uname", "cat /etc/passwd"]):
        return {
            "severity": "MEDIUM",
            "description": "System enumeration and reconnaissance.",
            "action": "Log Activity",
            "score": 45,
            "ttp": "T1082 - System Information Discovery"
        }

    return {
        "severity": "LOW",
        "description": "General shell interaction.",
        "action": "None",
        "score": 10,
        "ttp": "T1059 - Command and Scripting Interpreter"
    }


def _rule_based_report(attacker_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a complete threat report using pure rule-based logic.
    This is the authoritative fallback whenever Gemini is unavailable.
    """
    commands   = attacker_data.get("commands", [])
    credentials = attacker_data.get("credentials", [])
    web_attacks = attacker_data.get("web_attacks", [])
    services_hit = attacker_data.get("services_hit", [])
    ip         = attacker_data.get("ip_address", "Unknown")
    risk_score = attacker_data.get("risk_score", 0)

    ttps = detect_ttps(commands, web_attacks, credentials, services_hit)

    # ── Risk Level ────────────────────────────────────────────────────────────
    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ── Attacker Type ─────────────────────────────────────────────────────────
    all_cmds = " ".join(commands).lower()
    if any(x in all_cmds for x in ["bash -i", "wget", "curl", "nc ", "python -c"]):
        attacker_type = "Advanced Manual Attacker"
    elif credentials and not commands:
        attacker_type = "Credential Brute-Force Bot"
    elif web_attacks:
        attacker_type = "Web Application Attacker"
    elif commands:
        attacker_type = "Script Kiddie / Opportunistic Attacker"
    else:
        attacker_type = "Automated Scanner"

    # ── Timeline ──────────────────────────────────────────────────────────────
    timeline = []
    if credentials:
        timeline.append(f"[Credential Phase] {len(credentials)} login attempt(s) observed (e.g. {credentials[0]!r}).")
    if commands:
        timeline.append(f"[Execution Phase] {len(commands)} SSH command(s) executed after gaining access.")
    if web_attacks:
        timeline.append(f"[Web Attack Phase] {len(web_attacks)} web payload(s) detected.")
    if services_hit:
        timeline.append(f"[Service Probing] Honeypot services probed: {', '.join(services_hit)}.")
    if not timeline:
        timeline.append("No detailed activity timeline available.")

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = []
    if credentials:
        recs.append("Enforce strong password policies and enable MFA on all SSH endpoints.")
        recs.append(f"Block or rate-limit IP {ip} at the firewall level.")
    if any(x in all_cmds for x in ["wget", "curl", "nc ", "bash -i"]):
        recs.append("Isolate affected systems immediately and perform forensic triage.")
    if web_attacks:
        recs.append("Review and harden web application input validation; deploy a WAF.")
    if "T1082 - System Information Discovery" in ttps:
        recs.append("Audit exposed system information and restrict command execution where possible.")
    if not recs:
        recs.append("Monitor the source IP for further suspicious activity.")
        recs.append("Review honeypot logs for additional attack indicators.")

    # ── IOCs ──────────────────────────────────────────────────────────────────
    ioc = []
    if ip and ip != "Unknown":
        ioc.append(f"IP: {ip}")
    for cred in credentials[:5]:  # cap at 5
        ioc.append(f"Credential: {cred}")
    for payload in web_attacks[:3]:
        ioc.append(f"Web payload: {payload[:80]}")

    return {
        "summary": "",  # caller sets this
        "risk_level": risk_level,
        "ttps": ttps,
        "attacker_type": attacker_type,
        "timeline": timeline,
        "recommendations": recs,
        "ioc": ioc,
    }


def _rule_based_profile(attacker_data: Dict[str, Any]) -> str:
    ip = attacker_data.get("ip_address", "Unknown")
    score = attacker_data.get("risk_score", 0)
    report = _rule_based_report(attacker_data)
    ttps_bullet = "\n".join(f"- {t}" for t in report["ttps"]) or "- None detected"
    return (
        f"## Attacker Profile: {ip}\n\n"
        f"**Risk Score:** {score}/100\n"
        f"**Risk Level:** {report['risk_level']}\n"
        f"**Threat Actor Classification:** {report['attacker_type']}\n\n"
        f"**TTPs Identified (MITRE ATT&CK):**\n{ttps_bullet}\n\n"
        f"**Recommended Actions:**\n" + "\n".join(f"- {r}" for r in report["recommendations"])
    )

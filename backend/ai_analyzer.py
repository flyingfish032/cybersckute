import os
import openai
from typing import Dict, Any

# Configure OpenAI (load from env or defaults)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

def analyze_command(command: str) -> Dict[str, Any]:
    """
    Analyze a shell command for threat level.
    """
    if not OPENAI_API_KEY:
        return _rule_based_analysis(command)

    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Analyze the following shell command executed by an attacker in a honeypot. Determine the threat level (LOW, MEDIUM, HIGH, CRITICAL) and provide a short summary and recommended SOC action. Return JSON only with keys: severity, description, action, score (0-100)."},
                {"role": "user", "content": command}
            ],
            max_tokens=150
        )
        # In a real app, we'd parse the JSON properly. For now, let's assume valid JSON or fallback.
        # This is a simplified implementation.
        content = response.choices[0].message.content
        import json
        try:
            return json.loads(content)
        except:
             return _rule_based_analysis(command)
    except Exception as e:
        print(f"AI Analysis failed: {e}")
        return _rule_based_analysis(command)

def _rule_based_analysis(command: str) -> Dict[str, Any]:
    """
    Fallback rule-based analysis.
    """
    cmd = command.lower()
    
    if any(x in cmd for x in ["wget", "curl", "nc", "ncat", "bash -i", "python -c", "php -r"]):
        return {
            "severity": "CRITICAL",
            "description": "Attempted reverse shell or malware download.",
            "action": "Immediate IP Block",
            "score": 95
        }
    
    if any(x in cmd for x in ["sudo", "rm -rf", "chmod", "chown", "mv", "dd"]):
        return {
            "severity": "HIGH",
            "description": "Destructive or privileged command attempt.",
            "action": "Monitor Closely",
            "score": 75
        }
        
    if any(x in cmd for x in ["whoami", "id", "pwd", "ls", "uname", "cat /etc/passwd"]):
        return {
            "severity": "MEDIUM",
            "description": "System enumeration.",
            "action": "Log Activity",
            "score": 45
        }

    return {
        "severity": "LOW",
        "description": "General shell interaction.",
        "action": "None",
        "score": 10
    }

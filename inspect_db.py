from backend.database import SessionLocal
from backend.models import Attacker, HoneypotCommand, WebAttack, Credential, ThreatReport

def inspect_db():
    db = SessionLocal()
    output_lines = []
    try:
        attackers = db.query(Attacker).all()
        output_lines.append(f"\n--- Attackers ({len(attackers)}) ---")
        for a in attackers:
            output_lines.append(f"ID: {a.id}, IP: {a.ip_address}, Risk Score: {a.risk_score}, Last Seen: {a.last_seen}")

        commands = db.query(HoneypotCommand).all()
        output_lines.append(f"\n--- Commands ({len(commands)}) ---")
        for c in commands:
            output_lines.append(f"Attacker ID: {c.attacker_id}, Command: {c.command}, Time: {c.timestamp}")

        creds = db.query(Credential).all()
        output_lines.append(f"\n--- Stolen Credentials ({len(creds)}) ---")
        for c in creds:
             output_lines.append(f"Attacker ID: {c.attacker_id}, User: {c.username}, Pass: {c.password}, Source: {c.source}")

        report_content = "\n".join(output_lines)
        print(report_content)
        
        with open("honeypot_report.txt", "w", encoding="utf-8") as f:
            f.write(report_content)
        print("\nReport saved to honeypot_report.txt")

    finally:
        db.close()

if __name__ == "__main__":
    inspect_db()

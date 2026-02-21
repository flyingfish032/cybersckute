from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .database import engine, Base, SessionLocal
from .models import (
    Attacker, HoneypotCommand, WebAttack, Credential,
    ThreatReport, DynamicService, ServiceInteraction
)
from . import ssh_honeypot, web_honeypot
from .websocket_manager import manager
from .dynamic_services import service_manager, SERVICE_CONFIGS
from .ai_analyzer import generate_attacker_profile, generate_threat_report, detect_ttps
import asyncio
import json
from sqlalchemy.orm import Session
from .database import get_db
from datetime import datetime

# Create Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI-Enhanced Honeypot & Deception System")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Web Honeypot Router
app.include_router(web_honeypot.router)


@app.on_event("startup")
async def startup_event():
    # Start SSH Honeypot
    app.state.ssh_server = await ssh_honeypot.start_ssh_server()

    # Auto-start dynamic services
    for service_name in ["mysql", "ftp", "http_alt"]:
        await service_manager.spawn_service(service_name)


@app.on_event("shutdown")
async def shutdown_event():
    await service_manager.shutdown_all()


@app.get("/")
def read_root():
    return {
        "status": "Honeypot Active",
        "ssh_port": 2222,
        "web_honeypot": "/admin",
        "active_services": service_manager.list_running()
    }


# ─── Stats ────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total_attackers = db.query(Attacker).count()
    total_commands = db.query(HoneypotCommand).count()
    total_web_attacks = db.query(WebAttack).count()
    total_creds = db.query(Credential).count()
    total_service_probes = db.query(ServiceInteraction).count()

    return {
        "attackers": total_attackers,
        "commands": total_commands,
        "web_attacks": total_web_attacks,
        "credentials": total_creds,
        "service_probes": total_service_probes
    }


# ─── Attackers ────────────────────────────────────────────────────────────────

@app.get("/api/attackers")
def get_attackers(db: Session = Depends(get_db)):
    attackers = db.query(Attacker).order_by(Attacker.last_seen.desc()).limit(50).all()
    return [
        {
            "id": a.id,
            "ip_address": a.ip_address,
            "city": a.city,
            "country": a.country,
            "latitude": a.latitude,
            "longitude": a.longitude,
            "risk_score": a.risk_score,
            "ttp_tags": a.ttp_tags or "",
            "attacker_profile": a.attacker_profile or "",
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
        }
        for a in attackers
    ]


@app.get("/api/attacker/{ip}/profile")
async def get_attacker_profile(ip: str, db: Session = Depends(get_db)):
    """Get or generate an AI attacker profile."""
    attacker = db.query(Attacker).filter(Attacker.ip_address == ip).first()
    if not attacker:
        return JSONResponse({"error": "Attacker not found"}, status_code=404)

    return {
        "ip_address": attacker.ip_address,
        "city": attacker.city,
        "country": attacker.country,
        "risk_score": attacker.risk_score,
        "ttp_tags": attacker.ttp_tags or "",
        "profile": attacker.attacker_profile or "No profile generated yet. Use /generate-report.",
        "first_seen": attacker.first_seen,
        "last_seen": attacker.last_seen,
    }


@app.post("/api/attacker/{ip}/generate-report")
async def generate_report_for_attacker(ip: str, db: Session = Depends(get_db)):
    """Trigger Gemini to generate a full threat report for an attacker."""
    attacker = db.query(Attacker).filter(Attacker.ip_address == ip).first()
    if not attacker:
        return JSONResponse({"error": "Attacker not found"}, status_code=404)

    commands = [c.command for c in attacker.commands]
    credentials = [f"{c.username}:{c.password}" for c in attacker.credentials]
    web_attacks = [w.payload for w in attacker.web_attacks if w.payload]
    service_interactions = [s.attacker_ip for s in attacker.service_interactions]

    # Detect TTPs
    services_hit = list(set(
        si.service.name for si in attacker.service_interactions if si.service
    ))
    ttps = detect_ttps(commands, web_attacks, credentials, services_hit)

    # Combine existing and new TTPs
    existing = set(filter(None, (attacker.ttp_tags or "").split(",")))
    merged_ttps = sorted(existing.union(set(ttps)))
    attacker.ttp_tags = ",".join(merged_ttps)

    # Generate full Gemini threat report
    attacker_data = {
        "ip_address": attacker.ip_address,
        "city": attacker.city,
        "country": attacker.country,
        "risk_score": attacker.risk_score,
        "first_seen": str(attacker.first_seen),
        "last_seen": str(attacker.last_seen),
        "commands": commands,
        "credentials": credentials,
        "web_attacks": web_attacks,
        "services_hit": services_hit,
    }

    threat_report = generate_threat_report(attacker_data)
    profile_md = generate_attacker_profile(attacker_data)

    attacker.attacker_profile = profile_md

    # Save ThreatReport to DB
    report = ThreatReport(
        attacker_id=attacker.id,
        severity=threat_report.get("risk_level", "MEDIUM"),
        description=threat_report.get("summary", ""),
        recommended_action=", ".join(threat_report.get("recommendations", [])),
        service_type="full_report",
        full_report_json=json.dumps(threat_report)
    )
    db.add(report)
    db.commit()

    return {
        "ip_address": ip,
        "ttp_tags": attacker.ttp_tags,
        "profile_markdown": profile_md,
        "threat_report": threat_report
    }


# ─── Recent Activity ──────────────────────────────────────────────────────────

@app.get("/api/recent_activity")
def get_activity(db: Session = Depends(get_db)):
    commands = db.query(HoneypotCommand).order_by(HoneypotCommand.timestamp.desc()).limit(20).all()
    return [
        {
            "type": "command",
            "attacker_ip": c.attacker.ip_address,
            "command": c.command,
            "severity": c.severity,
            "ttp": c.ttp,
            "timestamp": c.timestamp
        }
        for c in commands
    ]


# ─── Credentials ──────────────────────────────────────────────────────────────

@app.get("/api/credentials")
def get_credentials(db: Session = Depends(get_db)):
    creds = db.query(Credential).order_by(Credential.timestamp.desc()).all()
    return [
        {
            "id": c.id,
            "timestamp": c.timestamp,
            "source": c.source,
            "username": c.username,
            "password": c.password,
            "attacker_ip": c.attacker.ip_address if c.attacker else "Unknown"
        }
        for c in creds
    ]


# ─── Dynamic Services ─────────────────────────────────────────────────────────

@app.get("/api/services")
def get_services(db: Session = Depends(get_db)):
    """List all known fake honeypot services and their status."""
    db_services = db.query(DynamicService).all()
    db_map = {s.name: s for s in db_services}

    result = []
    for name, config in SERVICE_CONFIGS.items():
        svc = db_map.get(name)
        result.append({
            "name": name,
            "port": config["port"],
            "description": config["description"],
            "is_running": service_manager.is_running(name),
            "interaction_count": svc.interaction_count if svc else 0,
            "started_at": svc.started_at if svc else None,
        })
    return result


@app.post("/api/services/{name}/spawn")
async def spawn_service(name: str):
    """Dynamically start a new fake honeypot service."""
    if name not in SERVICE_CONFIGS:
        return JSONResponse({"error": f"Unknown service: {name}. Options: {list(SERVICE_CONFIGS.keys())}"}, status_code=400)
    success = await service_manager.spawn_service(name)
    if success:
        return {"status": "started", "service": name, "port": SERVICE_CONFIGS[name]["port"]}
    return JSONResponse({"error": f"Could not start {name}. Already running or port in use."}, status_code=409)


@app.delete("/api/services/{name}/stop")
async def stop_service(name: str):
    """Stop a running fake honeypot service."""
    success = await service_manager.stop_service(name)
    if success:
        return {"status": "stopped", "service": name}
    return JSONResponse({"error": f"{name} is not running."}, status_code=404)


@app.get("/api/services/{name}/interactions")
def get_service_interactions(name: str, db: Session = Depends(get_db)):
    """Get all interactions logged for a given fake service."""
    svc = db.query(DynamicService).filter(DynamicService.name == name).first()
    if not svc:
        return []
    return [
        {
            "id": i.id,
            "attacker_ip": i.attacker_ip,
            "raw_data": i.raw_data,
            "timestamp": i.timestamp
        }
        for i in svc.interactions
    ]


# ─── Threat Intel Export ─────────────────────────────────────────────────────

@app.get("/api/threat-intel/export")
def export_threat_intel(db: Session = Depends(get_db)):
    """Export all threat intelligence as a structured JSON download."""
    attackers = db.query(Attacker).all()
    reports = db.query(ThreatReport).order_by(ThreatReport.timestamp.desc()).all()
    service_interactions = db.query(ServiceInteraction).order_by(ServiceInteraction.timestamp.desc()).all()

    export_data = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_attackers": len(attackers),
            "total_reports": len(reports),
            "total_service_probes": len(service_interactions)
        },
        "attackers": [
            {
                "ip_address": a.ip_address,
                "location": f"{a.city}, {a.country}",
                "risk_score": a.risk_score,
                "ttp_tags": (a.ttp_tags or "").split(","),
                "attacker_profile": a.attacker_profile or "",
                "first_seen": str(a.first_seen),
                "last_seen": str(a.last_seen),
                "commands": [c.command for c in a.commands],
                "credentials": [
                    {"username": c.username, "password": c.password, "source": c.source}
                    for c in a.credentials
                ],
                "web_attacks": [
                    {"endpoint": w.endpoint, "payload": w.payload}
                    for w in a.web_attacks
                ],
            }
            for a in attackers
        ],
        "threat_reports": [
            {
                "id": r.id,
                "attacker_id": r.attacker_id,
                "severity": r.severity,
                "description": r.description,
                "recommended_action": r.recommended_action,
                "service_type": r.service_type,
                "full_report": json.loads(r.full_report_json or "{}"),
                "timestamp": str(r.timestamp)
            }
            for r in reports
        ],
        "service_interactions": [
            {
                "service": si.service.name if si.service else "unknown",
                "attacker_ip": si.attacker_ip,
                "raw_data": si.raw_data,
                "timestamp": str(si.timestamp)
            }
            for si in service_interactions
        ]
    }

    from fastapi.responses import Response
    content = json.dumps(export_data, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=threat_intel_export.json"}
    )


# ─── Data Reset ───────────────────────────────────────────────────────────────

@app.delete("/api/reset")
def reset_data(db: Session = Depends(get_db)):
    db.query(ServiceInteraction).delete()
    db.query(HoneypotCommand).delete()
    db.query(WebAttack).delete()
    db.query(Credential).delete()
    db.query(ThreatReport).delete()
    db.query(DynamicService).delete()
    db.query(Attacker).delete()
    db.commit()
    return {"status": "Data Reset Successful"}


# ─── WebSocket Live Feed ──────────────────────────────────────────────────────

@app.websocket("/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

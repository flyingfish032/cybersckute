from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base, SessionLocal
from .models import Attacker, HoneypotCommand, WebAttack, Credential, ThreatReport
from . import ssh_honeypot, web_honeypot
from .websocket_manager import manager
import asyncio
from sqlalchemy.orm import Session
from .database import get_db
from typing import List

# Create Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI-Enhanced Honeypot System")

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
    # Start SSH Honeypot (Port 2222)
    # Run in background task but keep reference
    app.state.ssh_server = await ssh_honeypot.start_ssh_server()

@app.get("/")
def read_root():
    return {"status": "Honeypot Active", "ssh_port": 2222}

# API Endpoints for Dashboard

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total_attackers = db.query(Attacker).count()
    total_commands = db.query(HoneypotCommand).count()
    total_web_attacks = db.query(WebAttack).count()
    total_creds = db.query(Credential).count()
    
    return {
        "attackers": total_attackers,
        "commands": total_commands,
        "web_attacks": total_web_attacks,
        "credentials": total_creds
    }

@app.get("/api/attackers")
def get_attackers(db: Session = Depends(get_db)):
    return db.query(Attacker).order_by(Attacker.last_seen.desc()).limit(50).all()

@app.get("/api/recent_activity")
def get_activity(db: Session = Depends(get_db)):
    # Combine commands and web attacks
    commands = db.query(HoneypotCommand).order_by(HoneypotCommand.timestamp.desc()).limit(20).all()
    # Serialize for frontend
    return [
        {"type": "command", "attacker_ip": c.attacker.ip_address, "command": c.command, "timestamp": c.timestamp} 
        for c in commands
    ]

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

@app.delete("/api/reset")
def reset_data(db: Session = Depends(get_db)):
    db.query(HoneypotCommand).delete()
    db.query(WebAttack).delete()
    db.query(Credential).delete()
    db.query(ThreatReport).delete()
    db.query(Attacker).delete()
    db.commit()
    return {"status": "Data Reset Successful"}

@app.websocket("/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

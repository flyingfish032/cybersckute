"""
dynamic_services.py — Adaptive Honeypot Service Manager

Runs fake TCP services (MySQL, FTP) that respond with realistic banners and
capture all attacker interactions. Services can be started/stopped at runtime.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Optional

from .database import SessionLocal
from .models import Attacker, DynamicService, ServiceInteraction, ThreatReport
from .websocket_manager import manager

import random

SAMPLE_LOCATIONS = [
    {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
    {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    {"country": "Brazil", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333},
    {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890},
    {"country": "USA", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    {"country": "Germany", "city": "Berlin", "lat": 52.5200, "lon": 13.4050},
    {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234},
]


def _get_geoip(ip: str) -> dict:
    random.seed(ip)
    loc = random.choice(SAMPLE_LOCATIONS)
    random.seed()
    return loc


# ─────────────────────────────────────────────────────────────────────────────
# Service definitions: name → (port, banner bytes)
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_CONFIGS = {
    "mysql": {
        "port": 3307,  # 3306 often taken by real MySQL on Windows; use 3307
        "banner": (
            # Realistic MySQL 5.7 handshake packet (enough to fool scanners)
            b"\x4a\x00\x00\x00\x0a"
            b"5.7.42-log\x00"
            b"\x08\x00\x00\x00"
            b"\x3f\x46\x21\x41\x3b\x31\x26\x29\x00"
            b"\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x43\x6f\x6b\x4a\x48\x43\x51\x4e\x59\x4d\x4c\x00"
            b"mysql_native_password\x00"
        ),
        "description": "MySQL 5.7 Database Server"
    },
    "ftp": {
        "port": 2121,  # 21 requires admin on Windows; 2121 is unprivileged
        "banner": b"220 ProFTPD 1.3.5 Server (Debian) [::ffff:192.168.1.100]\r\n",
        "description": "ProFTPD FTP Server"
    },
    "http_alt": {
        "port": 8888,  # 8080 often taken by dev tools on Windows; use 8888
        "banner": (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.41 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body><h1>It works!</h1></body></html>\r\n"
        ),
        "description": "Apache HTTP Server (Alt Port)"
    }
}


class FakeServiceProtocol(asyncio.Protocol):
    """Generic fake service protocol — sends a banner and logs all received data."""

    def __init__(self, service_name: str, service_port: int, banner: bytes):
        self.service_name = service_name
        self.service_port = service_port
        self.banner = banner
        self.peer_ip: Optional[str] = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        self.peer_ip = peername[0] if peername else "Unknown"
        print(f"[{self.service_name.upper()}] Connection from {self.peer_ip}")
        # Send the realistic service banner
        transport.write(self.banner)

    def data_received(self, data: bytes):
        self.buffer += data
        asyncio.create_task(self._log_interaction(data))

    def connection_lost(self, exc):
        print(f"[{self.service_name.upper()}] {self.peer_ip} disconnected")

    async def _log_interaction(self, raw_data: bytes):
        db = SessionLocal()
        try:
            ip = self.peer_ip

            # Upsert attacker
            attacker = db.query(Attacker).filter(Attacker.ip_address == ip).first()
            if not attacker:
                geo = _get_geoip(ip)
                attacker = Attacker(
                    ip_address=ip,
                    city=geo["city"],
                    country=geo["country"],
                    latitude=geo["lat"],
                    longitude=geo["lon"],
                    risk_score=30  # Base score for probing
                )
                db.add(attacker)
                db.commit()
                db.refresh(attacker)

            # Find service record
            svc = db.query(DynamicService).filter(DynamicService.name == self.service_name).first()
            svc_id = svc.id if svc else None

            # Log interaction
            interaction = ServiceInteraction(
                service_id=svc_id,
                attacker_id=attacker.id,
                attacker_ip=ip,
                raw_data=raw_data.decode("utf-8", errors="replace")[:500]
            )
            db.add(interaction)

            # Update service interaction count
            if svc:
                svc.interaction_count = (svc.interaction_count or 0) + 1

            # Update attacker last seen
            attacker.last_seen = datetime.utcnow()

            # Append TTP for network scanning
            existing_ttps = set((attacker.ttp_tags or "").split(","))
            existing_ttps.add(f"T1046-{self.service_name.upper()}")
            attacker.ttp_tags = ",".join(filter(None, existing_ttps))

            # Create threat report for service probe
            report = ThreatReport(
                attacker_id=attacker.id,
                severity="MEDIUM",
                description=f"Attacker probed fake {self.service_name.upper()} service on port {self.service_port}",
                recommended_action="Monitor and correlate with other activity",
                service_type=self.service_name
            )
            db.add(report)
            db.commit()

            # Broadcast via WebSocket
            await manager.broadcast_json({
                "type": "service_probe",
                "service": self.service_name,
                "port": self.service_port,
                "ip": ip,
                "data_preview": raw_data.decode("utf-8", errors="replace")[:80] if raw_data else "(no data sent)"
            })

        except Exception as e:
            print(f"[{self.service_name.upper()}] Error logging: {e}")
        finally:
            db.close()


class ServiceManager:
    """
    Manages a pool of dynamic fake honeypot services.
    Services can be started/stopped at runtime via API calls.
    """

    def __init__(self):
        self._servers: Dict[str, asyncio.AbstractServer] = {}

    async def spawn_service(self, name: str) -> bool:
        """Start a fake service by name. Returns True on success."""
        if name in self._servers:
            print(f"[ServiceManager] {name} is already running.")
            return False

        config = SERVICE_CONFIGS.get(name)
        if not config:
            print(f"[ServiceManager] Unknown service: {name}")
            return False

        port = config["port"]
        banner = config["banner"]
        description = config["description"]

        loop = asyncio.get_event_loop()
        try:
            server = await loop.create_server(
                lambda: FakeServiceProtocol(name, port, banner),
                host="0.0.0.0",
                port=port
            )
            self._servers[name] = server
            print(f"[ServiceManager] Started fake {name.upper()} on port {port}")

            # Persist to DB
            db = SessionLocal()
            try:
                svc = db.query(DynamicService).filter(DynamicService.name == name).first()
                if svc:
                    svc.is_active = 1
                    svc.started_at = datetime.utcnow()
                    svc.interaction_count = 0
                else:
                    svc = DynamicService(name=name, port=port, banner=description)
                    db.add(svc)
                db.commit()
            finally:
                db.close()

            return True

        except OSError as e:
            print(f"[ServiceManager] Failed to start {name} on port {port}: {e}")
            return False

    async def stop_service(self, name: str) -> bool:
        """Stop a running fake service."""
        server = self._servers.pop(name, None)
        if not server:
            return False
        server.close()
        await server.wait_closed()
        print(f"[ServiceManager] Stopped fake {name.upper()}")

        db = SessionLocal()
        try:
            svc = db.query(DynamicService).filter(DynamicService.name == name).first()
            if svc:
                svc.is_active = 0
            db.commit()
        finally:
            db.close()

        return True

    def is_running(self, name: str) -> bool:
        return name in self._servers

    def list_running(self):
        return list(self._servers.keys())

    async def shutdown_all(self):
        for name in list(self._servers.keys()):
            await self.stop_service(name)


# Singleton
service_manager = ServiceManager()

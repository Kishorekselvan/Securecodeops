import os
import sqlite3
import pickle
import base64
import traceback
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import jwt

app = FastAPI(title="Demo Vulnerable E-Commerce API", version="1.0.0")

# SECURITY ISSUE: Hardcoded JWT Secret Key (CWE-798)
JWT_SECRET = "supersecretjwtkey12345"
DATABASE_PATH = "demo_users.db"

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, role) VALUES (1, 'admin', 'admin123', 'admin')")
    conn.commit()
    conn.close()

init_db()

@app.get("/")
def read_root():
    return {"message": "Demo Application API Running"}

# SECURITY ISSUE: SQL Injection via Dynamic String Formatting (CWE-89 / A03:2021)
@app.post("/api/login")
async def login(request: Request):
    try:
        data = await request.json()
        username = data.get("username", "")
        password = data.get("password", "")

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE: Direct SQL string interpolation allows ' OR '1'='1 injection
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            # Generate JWT token using hardcoded key
            token = jwt.encode({"user_id": user[0], "role": user[2]}, JWT_SECRET, algorithm="HS256")
            return {"status": "success", "token": token, "user": {"id": user[0], "username": user[1], "role": user[2]}}
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        # SECURITY ISSUE: Raw Exception Stack Trace Leakage (CWE-209)
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e), "trace": traceback.format_exc()})

# SECURITY ISSUE: Command Injection via os.system / Shell (CWE-78 / A03:2021)
@app.get("/api/tools/ping")
def ping_host(host: str):
    # VULNERABLE: Executing shell command with unvalidated user input
    command = f"ping -c 1 {host}"
    status = os.system(command)
    return {"host": host, "status_code": status}

# SECURITY ISSUE: Insecure Deserialization via Python pickle (CWE-502 / A08:2021)
@app.post("/api/profile/restore")
async def restore_profile(request: Request):
    data = await request.json()
    encoded_payload = data.get("state_payload", "")
    try:
        raw_bytes = base64.b64decode(encoded_payload)
        # VULNERABLE: Untrusted pickle deserialization executes arbitrary payload
        profile = pickle.loads(raw_bytes)
        return {"status": "restored", "profile": str(profile)}
    except Exception as e:
        return {"error": "Failed to deserialize state", "details": str(e)}

# SECURITY ISSUE: SSRF via Unvalidated URL Request (CWE-918 / A10:2021)
@app.get("/api/fetch-remote")
def fetch_remote_resource(target_url: str):
    import urllib.request
    # VULNERABLE: Fetching unvalidated user-supplied internal URLs
    with urllib.request.urlopen(target_url) as response:
        html = response.read()
    return {"url": target_url, "size": len(html)}

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import mysql.connector
import bcrypt
import base64
import re
import os

load_dotenv()

SECRET_KEY           = os.getenv("SECRET_KEY")
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
DB_PASSWORD          = os.getenv("DB_PASSWORD")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(SessionMiddleware, secret_key="session_secret_123", same_site="lax", https_only=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    client_kwargs={"scope": "openid email profile"}
)

def get_db(use_db=True):
    return mysql.connector.connect(
        host=os.getenv("MYSQLHOST", "localhost"),
        user=os.getenv("MYSQLUSER", "root"),
        password=os.getenv("MYSQLPASSWORD", os.getenv("DB_PASSWORD")),
        port=int(os.getenv("MYSQLPORT", 3306)),
        database=os.getenv("MYSQLDATABASE", "encode_project") if use_db else None
    )

def init_db():
    conn = get_db(use_db=False)
    cur = conn.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS encode_project")
    conn.commit()
    cur.close()
    conn.close()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) DEFAULT NULL,
            auth_type VARCHAR(20) DEFAULT 'manual',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            original_text TEXT NOT NULL,
            converted_text TEXT NOT NULL,
            action VARCHAR(10) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

init_db()

class SignupData(BaseModel):
    username: str
    email: str
    password: str

class LoginData(BaseModel):
    email: str
    password: str

class TextData(BaseModel):
    text: str

def make_token(user_id, username, email):
    return jwt.encode(
        {"user_id": user_id, "username": username, "email": email,
         "exp": datetime.utcnow() + timedelta(hours=24)},
        SECRET_KEY, algorithm="HS256"
    )

def get_user(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def is_base64(text: str) -> bool:
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    if not re.match(pattern, text):
        return False
    try:
        base64.b64decode(text).decode('utf-8')
        return True
    except:
        return False

def get_or_create_user(email, username):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    if not user:
        cur.execute(
            "INSERT INTO users (username, email, auth_type) VALUES (%s, %s, 'google')",
            (username, email)
        )
        conn.commit()
        user_id = cur.lastrowid
    else:
        user_id = user[0]
        username = user[1]
    cur.close()
    conn.close()
    return user_id, username

@app.post("/signup")
def signup(data: SignupData):
    conn = get_db()
    cur = conn.cursor()
    try:
        hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users (username, email, password, auth_type) VALUES (%s, %s, %s, 'manual')",
            (data.username, data.email, hashed)
        )
        conn.commit()
        user_id = cur.lastrowid
    except mysql.connector.IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")
    finally:
        cur.close()
        conn.close()
    return {"token": make_token(user_id, data.username, data.email), "username": data.username}

@app.post("/login")
def login(data: LoginData):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password FROM users WHERE email = %s", (data.email,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user or not user[2] or not bcrypt.checkpw(data.password.encode(), user[2].encode()):
        raise HTTPException(status_code=401, detail="Wrong email or password")
    return {"token": make_token(user[0], user[1], data.email), "username": user[1]}

@app.get("/dashboard")
def dashboard(user=Depends(get_user)):
    return {"username": user["username"]}

@app.get("/auth/google")
async def google_login(request: Request):
    redirect_uri = "https://oauth-encode-project.onrender.com/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")
        if not user_info:
            resp = await oauth.google.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                token=token
            )
            user_info = resp.json()
        email    = user_info.get("email")
        username = user_info.get("name") or email.split("@")[0]
        user_id, username = get_or_create_user(email, username)
        jwt_token = make_token(user_id, username, email)
        return RedirectResponse(
            url=f"http://127.0.0.1:5500/index.html?token={jwt_token}&username={username}"
        )
    except Exception as e:
        print("OAuth Error:", e)
        return RedirectResponse(url=f"http://127.0.0.1:5500/index.html?error=oauth_failed")

@app.post("/encode")
def encode(data: TextData, user=Depends(get_user)):
    if is_base64(data.text):
        return {"result": "already_encoded"}
    encoded = base64.b64encode(data.text.encode('utf-8')).decode('utf-8')
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO history (user_id, original_text, converted_text, action) VALUES (%s, %s, %s, %s)",
        (user["user_id"], data.text, encoded, "encode")
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"result": encoded}

@app.post("/decode")
def decode(data: TextData, user=Depends(get_user)):
    if not is_base64(data.text):
        return {"result": "not_encoded"}
    decoded = base64.b64decode(data.text.encode('utf-8')).decode('utf-8')
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO history (user_id, original_text, converted_text, action) VALUES (%s, %s, %s, %s)",
        (user["user_id"], data.text, decoded, "decode")
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"result": decoded}

@app.get("/history")
def get_history(user=Depends(get_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, original_text, converted_text, action, created_at FROM history WHERE user_id = %s ORDER BY created_at DESC",
        (user["user_id"],)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"id": r[0], "original": r[1], "converted": r[2], "action": r[3], "time": str(r[4])} for r in rows]

@app.delete("/history/{id}")
def delete_one(id: int, user=Depends(get_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM history WHERE id = %s AND user_id = %s", (id, user["user_id"]))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Deleted!"}

@app.delete("/history")
def delete_all(user=Depends(get_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM history WHERE user_id = %s", (user["user_id"],))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "All deleted!"}
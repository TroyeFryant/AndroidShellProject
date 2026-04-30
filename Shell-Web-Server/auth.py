"""
认证模块 — JWT + bcrypt + MySQL
"""

import os
import secrets
import time
from datetime import datetime

import bcrypt
import jwt
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import get_db

JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECONDS = 24 * 3600

_bearer = HTTPBearer(auto_error=False)


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="登录已过期，请重新登录")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="无效的认证令牌")


def authenticate(username: str, password: str) -> dict | None:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            return None
        cur.execute("UPDATE users SET last_login = %s WHERE id = %s", (datetime.now(), user["id"]))
        conn.commit()
        return {"username": user["username"], "role": user["role"]}


async def require_auth(cred: HTTPAuthorizationCredentials = Depends(_bearer)):
    if not cred:
        raise HTTPException(status_code=401, detail="未提供认证令牌")
    return decode_token(cred.credentials)

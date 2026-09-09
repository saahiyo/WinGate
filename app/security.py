from datetime import timedelta
from hashlib import sha256
from uuid import uuid4
from jose import jwt, JWTError, ExpiredSignatureError
from pwdlib import PasswordHash
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .core import settings, utcnow, get_db, User, AuthSession

password_hash = PasswordHash.recommended()
oauth2 = OAuth2PasswordBearer(tokenUrl='/auth/login')

def new_id() -> str: return uuid4().hex

def api_error(status_code: int, code: str, message: str, extra: dict | None = None) -> HTTPException:
    payload = {'code': code, 'message': message, 'trace_id': new_id()}
    if extra: payload.update(extra)
    return HTTPException(status_code=status_code, detail=payload)

def hash_secret(value: str) -> str: return sha256(value.encode()).hexdigest()
def hash_password(value: str) -> str: return password_hash.hash(value)
def verify_password(value: str, hashed: str) -> bool: return password_hash.verify(value, hashed)

def create_access_token(user_id: int, session_id: str):
    now = utcnow()
    exp = now + timedelta(minutes=settings.access_token_minutes)
    return jwt.encode({'sub': str(user_id), 'sid': session_id, 'iat': now, 'exp': exp, 'typ': 'access'}, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

def decode_access_token(token: str):
    try:
        p = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        if p.get('typ') != 'access': raise ValueError('Invalid token type')
        return int(p['sub']), p['sid']
    except ExpiredSignatureError:
        raise api_error(status.HTTP_401_UNAUTHORIZED, 'AUTH_EXPIRED', 'Access token has expired')
    except (JWTError, KeyError, ValueError, TypeError):
        raise api_error(status.HTTP_401_UNAUTHORIZED, 'AUTH_REQUIRED', 'Valid authentication is required')

def require_context(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    user_id, session_id = decode_access_token(token)
    session = db.get(AuthSession, session_id)
    user = db.get(User, user_id)
    if not user:
        raise api_error(status.HTTP_401_UNAUTHORIZED, 'AUTH_REQUIRED', 'User not found')
    if user.status != 'active':
        raise api_error(status.HTTP_403_FORBIDDEN, 'ACCOUNT_DISABLED', 'Account is disabled or inactive')
    if not session or session.user_id != user_id or session.revoked_at or session.expires_at <= utcnow():
        raise api_error(status.HTTP_401_UNAUTHORIZED, 'AUTH_REVOKED', 'Session is invalid or expired')
    if (utcnow() - session.last_seen_at).total_seconds() > 60:
        session.last_seen_at = utcnow()
        db.commit()
    return user, session

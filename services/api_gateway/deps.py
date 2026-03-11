"""
RBAC dependencies and JWT helpers for FastAPI route protection.
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from models import User

JWT_SECRET    = os.getenv("JWT_SECRET", "REPLACE_WITH_STRONG_SECRET_IN_DOTENV")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE    = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            print(f"DEBUG AUTH: Token missing 'sub' claim: {payload}")
            raise credentials_exc
    except JWTError as e:
        print(f"DEBUG AUTH: JWT decode error: {e}")
        raise credentials_exc

    result = await db.execute(select(User).where(User.username == user_id))
    user = result.scalar_one_or_none()
    if not user:
        print(f"DEBUG AUTH: User '{user_id}' not found in DB")
        raise credentials_exc
    if not user.is_active:
        print(f"DEBUG AUTH: User '{user_id}' is inactive")
        raise credentials_exc
    return user


def require_role(*roles: str):
    """FastAPI dependency factory — enforce RBAC."""
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' not permitted. Required: {roles}",
            )
        return current_user
    return _check

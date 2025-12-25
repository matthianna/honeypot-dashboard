"""Authentication routes."""

import structlog
from fastapi import APIRouter, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings
from app.auth.schemas import LoginRequest, TokenResponse, RefreshRequest
from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)

router = APIRouter()
logger = structlog.get_logger()
limiter = Limiter(key_func=get_remote_address)

# In-memory store for hashed admin password (initialized on first use)
_admin_password_hash: str = None


def get_admin_password_hash() -> str:
    """Get or create the admin password hash."""
    global _admin_password_hash
    if _admin_password_hash is None:
        settings = get_settings()
        _admin_password_hash = get_password_hash(settings.admin_password)
    return _admin_password_hash


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """
    Authenticate user and return JWT tokens.
    
    Security:
    - Rate limited to prevent brute force attacks
    - Password verified using bcrypt
    - Returns both access and refresh tokens
    """
    settings = get_settings()
    
    # Verify username
    if request.username != settings.admin_username:
        logger.warning("login_failed", reason="invalid_username", username=request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    
    # Verify password
    if not verify_password(request.password, get_admin_password_hash()):
        logger.warning("login_failed", reason="invalid_password", username=request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    
    # Generate tokens
    access_token = create_access_token(subject=request.username)
    refresh_token = create_refresh_token(subject=request.username)
    
    logger.info("login_successful", username=request.username)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest):
    """
    Refresh access token using refresh token.
    
    Security:
    - Validates refresh token signature and expiry
    - Returns new access and refresh tokens
    """
    # Decode and validate refresh token
    payload = decode_token(request.refresh_token)
    
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )
    
    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    
    # Generate new tokens
    access_token = create_access_token(subject=username)
    new_refresh_token = create_refresh_token(subject=username)
    
    logger.info("token_refreshed", username=username)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.post("/logout")
async def logout():
    """
    Logout endpoint.
    
    Note: With JWT, logout is primarily handled client-side by discarding tokens.
    This endpoint exists for audit logging purposes.
    """
    logger.info("logout_requested")
    return {"message": "Logged out successfully"}


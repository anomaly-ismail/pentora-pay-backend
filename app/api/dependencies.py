import asyncio
import hashlib
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.dependencies import get_db
from app.models.user_session import UserSession
from app.models.user import User
from app.core.logging import get_logger
from app.core.config import get_settings

logger = get_logger(__name__)
security = HTTPBearer()
optional_security = HTTPBearer(auto_error=False)


# ─────────────────────────────────────────────────────────────────────────────
# UserDTO — cache'e giren hafif veri nesnesi.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(slots=True, frozen=True)
class UserDTO:
    id: uuid.UUID
    is_active: bool
    nfc_verified: bool
    tckn_hash: str


# ─────────────────────────────────────────────────────────────────────────────
# Token → UserDTO in-memory cache
# M-7: threading.Lock → asyncio.Lock (async context uyumlu)
# ─────────────────────────────────────────────────────────────────────────────
_SESSION_CACHE_TTL = 60  # saniye

_CacheEntry = tuple[UserDTO, float, datetime]


class _SessionCache:
    """
    asyncio.Lock ile TTL-tabanlı token hash → UserDTO cache.
    M-7: threading.Lock yerine asyncio.Lock kullanılır — event loop bloklaması önlenir.
    """

    __slots__ = ("_store", "_lock")

    def __init__(self) -> None:
        self._store: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, token_hash: str) -> Optional[tuple[UserDTO, datetime]]:
        async with self._lock:
            entry = self._store.get(token_hash)
            if entry is None:
                return None
            dto, cached_at, expires_at = entry
            if time.monotonic() - cached_at > _SESSION_CACHE_TTL:
                del self._store[token_hash]
                return None
            return dto, expires_at

    async def set(self, token_hash: str, dto: UserDTO, expires_at: datetime) -> None:
        async with self._lock:
            self._store[token_hash] = (dto, time.monotonic(), expires_at)

    async def invalidate(self, token_hash: str) -> None:
        async with self._lock:
            self._store.pop(token_hash, None)

    async def evict_expired(self) -> None:
        now = time.monotonic()
        async with self._lock:
            expired = [k for k, v in self._store.items() if now - v[1] > _SESSION_CACHE_TTL]
            for k in expired:
                del self._store[k]


_session_cache = _SessionCache()


def _compute_token_hash(token_str: str, pepper: str) -> str:
    """
    M-6: session_pepper kullanılır (tckn_pepper'dan ayrı).
    grauth_token_hash = SHA3-256(token || session_pepper)
    """
    return hashlib.sha3_256(
        token_str.encode("utf-8") + pepper.encode("utf-8")
    ).hexdigest()


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> UserDTO:
    """
    GRAuth token doğrulaması.
    Cache hit'te DB'ye hiç dokunulmaz; dönen tip UserDTO (ORM nesnesi değil).
    """
    token_str = credentials.credentials
    settings = get_settings()
    # M-6: session_pepper kullan
    token_hash = _compute_token_hash(token_str, settings.session_pepper)

    # ── Cache hit ────────────────────────────────────────────────────────────
    cached = await _session_cache.get(token_hash)
    if cached is not None:
        dto, expires_at = cached
        now = datetime.now(timezone.utc)
        if now > expires_at:
            await _session_cache.invalidate(token_hash)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Oturumunuz sonlandırılmış.")
        if not dto.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Kullanıcı hesabı aktif değil.")
        return dto

    # ── Cache miss → DB sorgusu ───────────────────────────────────────────────
    stmt = (
        select(
            UserSession.expires_at,
            UserSession.is_revoked,
            User.id,
            User.is_active,
            User.nfc_verified,
            User.tckn_hash,
        )
        .join(User, UserSession.user_id == User.id)
        .where(
            UserSession.grauth_token_hash == token_hash,
            UserSession.is_revoked.is_(False),
        )
    )
    row = (await db.execute(stmt)).first()

    if row is None:
        logger.warning("auth.dependency.invalid_token", ip=request.client.host if request.client else "unknown")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Geçersiz veya süresi dolmuş oturum.")

    now = datetime.now(timezone.utc)
    if row.is_revoked or now > row.expires_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Oturumunuz sonlandırılmış.")

    if not row.is_active:
        logger.warning("auth.dependency.inactive_user", uid=row.id)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Kullanıcı hesabı aktif değil.")

    dto = UserDTO(
        id=row.id,
        is_active=row.is_active,
        nfc_verified=row.nfc_verified,
        tckn_hash=row.tckn_hash,
    )
    await _session_cache.set(token_hash, dto, row.expires_at)
    return dto


async def get_current_user_optional(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_security),
    db: AsyncSession = Depends(get_db),
) -> Optional[UserDTO]:
    if credentials is None:
        return None
    try:
        return await get_current_user(request=request, credentials=credentials, db=db)
    except HTTPException:
        return None

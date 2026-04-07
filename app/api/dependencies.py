import hashlib
from datetime import datetime, timezone
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.dependencies import get_db
from app.models.user import User
from app.models.user_session import UserSession
from app.core.logging import get_logger
from app.core.config import get_settings

logger = get_logger(__name__)
security = HTTPBearer()

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Geçerli bir GRAuth Token ve Session Korelasyonu gerektirir.
    Token'in şifrelenmiş içeriği açılmadan sadece doğrulanmış oturum hash'i üzerinden işlem yapar.
    """
    token_str = credentials.credentials
    settings = get_settings()

    # user_sessions.grauth_token_hash alanı: SHA3-256(token || pepper)
    token_hash = hashlib.sha3_256(
        token_str.encode("utf-8") + settings.tckn_pepper.encode("utf-8")
    ).hexdigest()

    # DB session ara
    stmt = (
        select(UserSession)
        .options(selectinload(UserSession.user))
        .where(UserSession.grauth_token_hash == token_hash)
    )
    result = await db.execute(stmt)
    user_session = result.scalars().first()

    if not user_session:
        logger.warning("auth.dependency.invalid_token", ip=request.client.host)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz veya süresi dolmuş oturum."
        )

    # Süre ve Revoke kontrolü
    now = datetime.now(timezone.utc)
    if user_session.is_revoked or now > user_session.expires_at:
        logger.warning("auth.dependency.expired_or_revoked_session", sid=user_session.session_uuid)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Oturumunuz sonlandırılmış."
        )

    if not user_session.user.is_active:
        logger.warning("auth.dependency.inactive_user", uid=user_session.user.id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Kullanıcı hesabı aktif değil."
        )

    return user_session.user

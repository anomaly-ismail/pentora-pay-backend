"""FastAPI dependency — her istek için DB oturumu sağlar."""
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Her HTTP isteği için bağımsız bir DB oturumu açar.
    Commit sorumluluğu endpoint'e aittir; hata durumunda rollback yapılır.
    Seçenek A: auto-commit kaldırıldı — her endpoint kendi commit'ini açıkça yapar.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise

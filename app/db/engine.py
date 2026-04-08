"""
Async PostgreSQL engine ve session factory.
SQLAlchemy 2.0 + asyncpg kullanır.
Tüm sorgular ORM üzerinden geçer → sıfır ham SQL → SQL enjeksiyon imkânsız.
"""
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            pool_size=settings.postgres_pool_size,
            max_overflow=settings.postgres_max_overflow,
            pool_pre_ping=True,          # bağlantı canlılık kontrolü
            pool_recycle=3600,           # 1 saatte bir bağlantı yenile
            echo=settings.debug,         # SQL'i yalnızca debug'da logla
            connect_args={
                "server_settings": {
                    # ISO 27001 A.12.4 — her bağlantıda uygulama adı loglanır
                    "application_name": settings.app_name,
                    # Performans + güvenlik
                    "statement_timeout": "30000",    # 30sn sorgu zaman aşımı
                    "lock_timeout": "10000",         # 10sn kilit zaman aşımı
                }
            },
        )
        logger.info(
            "db.engine.created",
            host=settings.postgres_host,
            db=settings.postgres_db,
            pool_size=settings.postgres_pool_size,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,   # commit sonrası nesneleri canlı tut
            autoflush=False,
            autocommit=False,
        )
    return _session_factory


async def create_all_tables() -> None:
    """Geliştirme için tüm tabloları oluşturur. Üretimde Alembic kullanın."""
    from app.db.base import Base
    # Modelleri import et (Base.metadata'ya kayıt olsunlar)
    import app.models.user          # noqa: F401
    import app.models.user_session  # noqa: F401
    import app.models.audit_event   # noqa: F401
    import app.models.corporate_application  # noqa: F401
    import app.models.notification  # noqa: F401
    import app.models.user_device  # noqa: F401

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Geriye dönük uyumluluk: mevcut tabloda yeni kolonlar eksikse ekle
        await conn.exec_driver_sql(
            "ALTER TABLE corporate_applications "
            "ADD COLUMN IF NOT EXISTS applicant_tckn VARCHAR(11)"
        )
    logger.info("db.tables.created")


async def dispose_engine() -> None:
    """Uygulama kapanırken bağlantı havuzunu temizle."""
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None
        logger.info("db.engine.disposed")

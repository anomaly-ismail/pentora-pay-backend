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
            pool_recycle=1800,           # 30 dakikada bir bağlantı yenile
            pool_timeout=10,             # bağlantı bekleme zaman aşımı
            echo=settings.debug,         # SQL'i yalnızca debug'da logla
            connect_args={
                # asyncpg prepared statement cache — tekrar eden sorgular plan cache'den gelir
                "prepared_statement_cache_size": 256,
                "server_settings": {
                    # ISO 27001 A.12.4 — her bağlantıda uygulama adı loglanır
                    "application_name": settings.app_name,
                    # Performans + güvenlik
                    "statement_timeout": "30000",    # 30sn sorgu zaman aşımı
                    "lock_timeout": "10000",         # 10sn kilit zaman aşımı
                    # Sorgu planlayıcı istatistiklerini güncel tut
                    "jit": "off",                    # OLTP için JIT kapalı (küçük sorgular)
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


async def run_migrations() -> None:
    """
    Uygulama başlarken Alembic migration'larını otomatik uygular.
    alembic upgrade head ile eşdeğer — manuel komut gerekmez.
    Idempotent: zaten güncel ise hiçbir şey yapmaz.

    env.py'deki run_async_migrations mantığını doğrudan uygular;
    asyncio.run() çakışması yoktur.
    """
    from pathlib import Path
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from sqlalchemy import pool
    from sqlalchemy.ext.asyncio import async_engine_from_config

    project_root = Path(__file__).parent.parent.parent
    cfg = Config(str(project_root / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)

    # Tüm modelleri yükle — target_metadata için
    from app.db.base import Base
    import app.models.user                       # noqa: F401
    import app.models.user_session               # noqa: F401
    import app.models.audit_event                # noqa: F401
    import app.models.accounting                 # noqa: F401
    import app.models.notification               # noqa: F401
    import app.models.user_device                # noqa: F401
    import app.models.corporate_application      # noqa: F401
    import app.models.web_corporate_application  # noqa: F401
    target_metadata = Base.metadata

    from alembic import context as alembic_ctx

    def _do_upgrade(connection):
        alembic_ctx.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with alembic_ctx.begin_transaction():
            alembic_ctx.run_migrations()

    connectable = async_engine_from_config(
        cfg.get_section(cfg.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as conn:
        await conn.run_sync(_do_upgrade)
    await connectable.dispose()

    logger.info("db.migrations.applied")


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
    import app.models.web_corporate_application  # noqa: F401

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Geriye dönük uyumluluk: mevcut tabloda yeni kolonlar eksikse ekle
        await conn.exec_driver_sql(
            "ALTER TABLE corporate_applications "
            "ADD COLUMN IF NOT EXISTS applicant_tckn VARCHAR(11)"
        )
        await conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS web_corporate_applications ("
            "id UUID PRIMARY KEY DEFAULT gen_random_uuid(),"
            "first_name VARCHAR(80) NOT NULL,"
            "last_name VARCHAR(80) NOT NULL,"
            "city VARCHAR(80) NOT NULL,"
            "phone VARCHAR(20) NOT NULL,"
            "kvkk_approved BOOLEAN NOT NULL DEFAULT FALSE,"
            "submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        )
    logger.info("db.tables.created")


async def dispose_engine() -> None:
    """Uygulama kapanırken bağlantı havuzunu temizle."""
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None
        logger.info("db.engine.disposed")

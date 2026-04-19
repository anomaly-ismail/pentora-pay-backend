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

    Resmi Alembic "Programmatic API with Asyncio" pattern'i kullanır:
    cfg.attributes["connection"] ile bağlantı env.py'ye geçirilir,
    asyncio.run() çakışması yoktur.
    """
    from pathlib import Path
    from alembic.config import Config
    from alembic import command

    project_root = Path(__file__).parent.parent.parent
    cfg = Config(str(project_root / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)

    def _run_upgrade(connection, cfg):
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")

    engine = create_async_engine(get_settings().database_url)
    async with engine.begin() as conn:
        await conn.run_sync(_run_upgrade, cfg)
    await engine.dispose()

    logger.info("db.migrations.applied")


def _reconcile_schema_sync(sync_conn) -> None:
    """
    Self-healing şema uyumlayıcısı.

    SQLAlchemy model metadata'sını canlı DB şemasıyla karşılaştırır; eksik
    kolonları `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` ile, eksik indeksleri
    `CREATE INDEX IF NOT EXISTS` ile otomatik ekler.

    Idempotent ve üretim-güvenli:
      • Mevcut veriye dokunmaz — yalnızca eksik olanları ekler.
      • Kolon tipleri, NULL/NOT NULL ve server_default PostgreSQL dialect'i ile
        SQLAlchemy DDL compiler'ından üretilir (manuel string hatası riski yok).
      • `NOT NULL` + `server_default` yoksa kolon güvenli şekilde nullable eklenir
        (mevcut satırlarda veri yok → NOT NULL constraint violation önlenir).
      • Foreign key / enum değişiklikleri bu reconciler'ın kapsamında değildir;
        o tür migration'lar için Alembic kullanılır.
    """
    from sqlalchemy import inspect as sa_inspect

    from app.db.base import Base

    inspector = sa_inspect(sync_conn)
    dialect = sync_conn.dialect
    ddl_compiler = dialect.ddl_compiler(dialect, None)

    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            # create_all çağrıldıktan sonra tablo hâlâ yoksa, bir FK sorunu
            # vardır — bunu susmadan logla ve bu tabloyu atla.
            logger.warning("db.schema.reconcile.table_missing", table=table.name)
            continue

        # ── Eksik kolonlar ─────────────────────────────────────────────────
        existing_cols = {c["name"] for c in inspector.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing_cols:
                continue

            col_spec = ddl_compiler.get_column_specification(col)
            needs_null_fallback = (
                not col.nullable and col.server_default is None
            )

            if needs_null_fallback:
                # NOT NULL + default yoksa mevcut satırları bozmadan
                # güvenli bir şekilde NULL kolon olarak ekle.
                safe_spec = col_spec.replace(" NOT NULL", "")
                sync_conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" '
                    f'ADD COLUMN IF NOT EXISTS {safe_spec}'
                )
                logger.warning(
                    "db.schema.column_added_nullable",
                    table=table.name,
                    column=col.name,
                    hint=(
                        "NOT NULL + default olmadan kolon eklendi; "
                        "mevcut satırlar için backfill gerekebilir."
                    ),
                )
            else:
                sync_conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" '
                    f'ADD COLUMN IF NOT EXISTS {col_spec}'
                )
                logger.info(
                    "db.schema.column_added",
                    table=table.name,
                    column=col.name,
                )

        # ── Eksik indeksler ────────────────────────────────────────────────
        existing_idx = {i["name"] for i in inspector.get_indexes(table.name)}
        for index in table.indexes:
            if not index.name or index.name in existing_idx:
                continue
            cols_sql = ", ".join(f'"{c.name}"' for c in index.columns)
            unique_sql = "UNIQUE " if index.unique else ""
            sync_conn.exec_driver_sql(
                f'CREATE {unique_sql}INDEX IF NOT EXISTS "{index.name}" '
                f'ON "{table.name}" ({cols_sql})'
            )
            logger.info(
                "db.schema.index_added",
                table=table.name,
                index=index.name,
            )


async def create_all_tables() -> None:
    """
    Tüm ortamlarda çalışan idempotent şema bootstrap'i:
      1. `CREATE TABLE IF NOT EXISTS` — eksik tablolar
      2. Self-healing reconciler — eksik kolonlar + indeksler
      3. Geriye dönük manuel SQL fix'leri (applicant_tckn tip yükseltme vb.)

    Mevcut veriye ve yapılara dokunmaz. Üretimde ayrıca Alembic migration'ları
    çalıştırmanız önerilir (FK, enum, constraint değişiklikleri için).
    """
    from app.db.base import Base  # noqa: F401 — metadata.create_all için
    # Modelleri import et (Base.metadata'ya kayıt olsunlar)
    import app.models.user          # noqa: F401
    import app.models.user_session  # noqa: F401
    import app.models.audit_event   # noqa: F401
    import app.models.corporate_application  # noqa: F401
    import app.models.notification  # noqa: F401
    import app.models.user_device  # noqa: F401
    import app.models.web_corporate_application  # noqa: F401
    import app.models.corporate_payment  # noqa: F401
    import app.models.corporate_receive_request  # noqa: F401
    import app.models.mrtd_session  # noqa: F401
    import app.models.revoked_admin_token  # noqa: F401  # H-2: kalıcı admin JWT blacklist
    import app.models.employee  # noqa: F401  # Çalışan kayıtları (PII şifreli)

    async with get_engine().begin() as conn:
        # 1) Eksik tabloları oluştur (create_all zaten IF NOT EXISTS kullanır)
        from app.db.base import Base as _Base
        await conn.run_sync(_Base.metadata.create_all)

        # 2) Self-healing: eksik kolon ve indeksleri otomatik ekle
        await conn.run_sync(_reconcile_schema_sync)

        # 3) Eski özel migration'lar — kolon tip yükseltmeleri vb.
        # L-5: applicant_tckn artık HMAC-SHA3-512 hash saklar (128 hex)
        await conn.exec_driver_sql(
            "ALTER TABLE corporate_applications "
            "ADD COLUMN IF NOT EXISTS applicant_tckn VARCHAR(128)"
        )
        await conn.exec_driver_sql(
            "ALTER TABLE corporate_applications "
            "ALTER COLUMN applicant_tckn TYPE VARCHAR(128)"
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

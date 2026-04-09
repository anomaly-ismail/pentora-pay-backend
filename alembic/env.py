import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app.core.config import get_settings
settings = get_settings()

config.set_main_option("sqlalchemy.url", str(settings.database_url))

from app.db.base import Base
import app.models.user
import app.models.user_session
import app.models.audit_event
import app.models.accounting

target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """In this scenario we need to create an Engine
    and associate a connection with the context.
    Bu fonksiyon engine.py'den de doğrudan çağrılabilir.

    override_url: engine.py'den çağrılırken settings'ten URL geçilebilir.
    """
    connectable = config.attributes.get("connection", None)

    if connectable is None:
        # CLI'dan çağrıldı — kendi engine'ini oluştur
        engine = async_engine_from_config(
            config.get_section(config.config_ini_section, {}),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
        async with engine.connect() as connection:
            await connection.run_sync(do_run_migrations)
        await engine.dispose()
    else:
        # Programmatic: dışarıdan bağlantı verildi (engine.py startup)
        await connectable.run_sync(do_run_migrations)


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    CLI'dan çağrıldığında asyncio.run kullanır.
    Programmatic kullanımda (engine.py startup) cfg.attributes["connection"]
    set edilmiş olur; bu durumda do_run_migrations doğrudan çağrılır.
    """
    connectable = config.attributes.get("connection", None)

    if connectable is not None:
        # Programmatic: zaten sync bağlantı içindeyiz (conn.run_sync tarafından çağrıldık)
        do_run_migrations(connectable)
    else:
        # CLI: kendi async engine'ini oluştur
        asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

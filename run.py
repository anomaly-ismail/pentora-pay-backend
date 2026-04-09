import asyncio
import uvicorn
from app.core.config import get_settings


async def _run_migrations_once() -> None:
    """
    Uvicorn başlamadan önce migration'ları tek seferlik çalıştır.
    Reloader process'ten izole — sadece bu entry point'ten tetiklenir.
    """
    from app.db.engine import run_migrations, dispose_engine
    await run_migrations()
    await dispose_engine()   # migration engine'ini kapat; uygulama kendi pool'unu açar


if __name__ == "__main__":
    settings = get_settings()

    # Migration'ı uvicorn başlamadan önce çalıştır.
    # reload=True olsa bile bu blok sadece ana process'te çalışır —
    # WatchFiles reloader child process'leri bu __main__ bloğunu tekrar exec etmez.
    asyncio.run(_run_migrations_once())

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True if settings.app_env == "development" else False,
        workers=settings.workers,
        # uvloop: asyncio'dan ~2x daha hızlı event loop (Linux/Mac)
        loop="uvloop" if settings.app_env != "development" else "auto",
        # httptools: http11'den daha hızlı HTTP parser
        http="httptools" if settings.app_env != "development" else "auto",
        # Bağlantı backlog — yüksek yük altında kuyruk kapasitesi
        backlog=2048,
        # Keep-alive timeout — bağlantı yeniden kullanımı
        timeout_keep_alive=30,
    )

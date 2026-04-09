import uvicorn
from app.core.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
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

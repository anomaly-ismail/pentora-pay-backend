import uvicorn
from app.core.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    
    # Tüm IP'lerden (0.0.0.0) gelen istekleri kabul etmek için ayarlandı.
    # Bu sayede Android Emulator (10.0.2.2) sorunsuz bağlanabilir.
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True if settings.app_env == "development" else False,
        workers=settings.workers,
    )

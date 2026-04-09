"""
FastAPI Ana Uygulama — Tüm middleware'ların ve route'ların merkezi noktası.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.core.gr_auth import assert_crypto_environment
from app.middleware.audit_log import AuditLogMiddleware
from app.middleware.rate_limiter import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.client_auth import ClientAuthMiddleware
from app.api.v1.router import router as v1_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlatma ve kapatma yaşam döngüsü."""
    configure_logging()
    logger = get_logger("startup")

    # Kriptografik ortam öz-testi — hata varsa başlatmayı durdur
    assert_crypto_environment()

    # Alembic migration'larını otomatik uygula (upgrade head — idempotent)
    from app.db.engine import create_all_tables, run_migrations
    await run_migrations()

    # Tüm ortamlarda eksik tabloları oluştur (CREATE TABLE IF NOT EXISTS — idempotent, güvenli)
    # Var olan tablolara ve veriye dokunmaz; yalnızca eksik olanları ekler.
    await create_all_tables()

    logger.info(
        "app.started",
        name=settings.app_name,
        version=settings.app_version,
        env=settings.app_env,
        debug=settings.debug,
    )
    yield
    logger.info("app.shutdown")
    
    from app.db.engine import dispose_engine
    await dispose_engine()


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Uygulaması
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Güvenli Ödeme Sistemi Backend API\n\n"
        "OWASP Top 10 ve ISO 27001 uyumlu güvenlik mimarisi."
    ),
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# ─────────────────────────────────────────────────────────────────────────────
# Middleware Yığını
# NOT: FastAPI/Starlette middleware'ı LIFO sırasında çalıştırır.
#      Son eklenen → ilk çalışır.
#
# Çalışma sırası (ilk → son):
#   1. TrustedHost   — sahte Host header'larını blokla
#   2. CORS          — cross-origin politikası
#   3. RequestID     — benzersiz istek kimliği
#   4. AuditLog      — tüm istekleri logla
#   5. RateLimit     — hız sınırlama
#   6. SecurityHeaders → tüm güvenlik + Pentora header'ları
# ─────────────────────────────────────────────────────────────────────────────

# 7. Client Auth Middleware (Yalnızca yetkili Flutter uygulaması)
app.add_middleware(ClientAuthMiddleware)

# 6. SecurityHeaders (son eklenen = ilk çalışan = ilk eklenecek burada)
app.add_middleware(SecurityHeadersMiddleware)

# 5. Rate Limiting
app.add_middleware(RateLimitMiddleware)

# 4. Audit Log
app.add_middleware(AuditLogMiddleware)

# 3. Request ID
app.add_middleware(RequestIDMiddleware)

# 2. CORS (ISO 27001 A.13 — Network Controls)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Request-ID",
        "X-Pentora-Signature",
        "X-Pentora-GRAuth",
    ],
    expose_headers=[
        "X-Request-ID",
        "X-Response-Time",
        "X-Pentora-Signature",
        "X-Pentora-SQL",
        "X-Pentora-GRAuth",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
    ],
    max_age=600,
)

# 1. Trusted Host — her ortamda aktif (OWASP A05: Security Misconfiguration)
# Güvenlik hiçbir zaman APP_ENV flag'ine bağımlı olmamalı
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
        "api.pentorasec.com.tr",
        "pay.pentorasec.com.tr",
    ],
)

# ─────────────────────────────────────────────────────────────────────────────
# Route'lar
# ─────────────────────────────────────────────────────────────────────────────
app.include_router(v1_router, prefix="/api/v1")


# ─────────────────────────────────────────────────────────────────────────────
# Health Check (publick, rate limit dışı)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"], include_in_schema=False)
async def health():
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "env": settings.app_env,
    }

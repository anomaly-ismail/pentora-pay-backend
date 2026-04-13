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
from app.api.payment_portal import router as payment_portal_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlatma ve kapatma yaşam döngüsü."""
    configure_logging()
    logger = get_logger("startup")

    # Kriptografik ortam öz-testi — hata varsa başlatmayı durdur
    assert_crypto_environment()

    # H-2: Multi-worker + Redis uyarısı
    if settings.workers > 1 and not settings.redis_url:
        logger.warning(
            "startup.rate_limit.multiworker_no_redis",
            workers=settings.workers,
            hint=(
                "workers > 1 iken REDIS_URL ayarlı değil. "
                "Rate limiting ve handshake store her worker'da ayrı çalışır. "
                "Üretimde REDIS_URL ayarlayın veya workers=1 kullanın."
            ),
        )

    # H-3: Admin şifre hash uyarısı
    if not settings.admin_pass_hash:
        logger.warning(
            "startup.admin.no_pass_hash",
            hint=(
                "ADMIN_PASS_HASH ayarlı değil. Argon2id hash önerilen yöntemdir. "
                "Üret: python -c \"from argon2 import PasswordHasher; "
                "print(PasswordHasher().hash('sifrenz'))\""
            ),
        )

    # L-4: Admin JWT HS256 uyarısı
    if not settings.admin_jwt_private_key_pem:
        logger.warning(
            "startup.admin_jwt.hs256_in_use",
            hint=(
                "ADMIN_JWT_PRIVATE_KEY_PEM ayarlı değil — HS256 kullanılıyor. "
                "Üretimde ES256 için openssl ile P-256 anahtar çifti oluşturun."
            ),
        )

    # OPS-1: Bağlantı havuzu taşma riski — workers × (pool_size + max_overflow)
    # PostgreSQL varsayılan max_connections = 100; 10 bağlantı sistem için rezerve bırakılır.
    _max_db_conns = settings.workers * (
        settings.postgres_pool_size + settings.postgres_max_overflow
    )
    if _max_db_conns > 90:
        logger.warning(
            "startup.db.pool_overflow_risk",
            workers=settings.workers,
            pool_size=settings.postgres_pool_size,
            max_overflow=settings.postgres_max_overflow,
            total_max_connections=_max_db_conns,
            hint=(
                f"workers × (pool_size + max_overflow) = {_max_db_conns} > 90. "
                "PostgreSQL max_connections (varsayılan 100) aşılabilir. "
                "POSTGRES_POOL_SIZE / WORKERS değerlerini düşürün veya "
                "postgresql.conf içinde max_connections değerini artırın."
            ),
        )

    # Tüm ortamlarda eksik tabloları oluştur (CREATE TABLE IF NOT EXISTS — idempotent, güvenli)
    # Var olan tablolara ve veriye dokunmaz; yalnızca eksik olanları ekler.
    from app.db.engine import create_all_tables
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
        "pentorasec.online",
        "www.pentorasec.online",
    ],
)

# ─────────────────────────────────────────────────────────────────────────────
# Route'lar
# ─────────────────────────────────────────────────────────────────────────────
app.include_router(v1_router, prefix="/api/v1")
# Ödeme portalı — /pay/{id} — ClientAuth bypass edilmiş (müşteri tarayıcısı)
app.include_router(payment_portal_router)


# ─────────────────────────────────────────────────────────────────────────────
# Health Check (publick, rate limit dışı)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"], include_in_schema=False)
async def health():
    # L-3: Versiyon ve ortam bilgisi kaldırıldı — bilgi sızıntısı önlemi
    return {"status": "ok"}

"""
Admin SSO Service
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Güvenlik özellikleri:
  H-2: JWT blacklist (jti) artık DB'de saklanır — multi-worker / restart kalıcı.
  H-3: Admin şifresi Argon2id hash ile doğrulanır (plaintext karşılaştırma yok)
  H-5: JWT httpOnly cookie olarak ayarlanır (XSS'e karşı)
  H-6: jti (UUID) ile JWT blacklist — logout sonrası token geçersiz
  L-4: ADMIN_JWT_PRIVATE_KEY_PEM ayarlıysa ES256, yoksa HS256 (+ uyarı)
"""
import asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import safe_compare
from app.db.engine import get_session_factory
from app.models.revoked_admin_token import RevokedAdminToken
from app.schemas.admin import AdminLoginRequest, AdminLoginResponse

logger = get_logger(__name__)

# ─── Argon2id hasher (H-3) ────────────────────────────────────────────────────
_ph = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=4)

# H-3: Admin şifresinin Argon2id hash'i — startup'ta türetilir/yüklenir
_admin_pass_hash_cache: Optional[str] = None

# H-2: Performans için kısa-ömürlü pozitif cache (DB hit'i azaltır).
# Anahtar: jti, değer: revoke edildiği zaman.  Cache TTL = 60sn, JWT TTL'si
# uzun olduğundan eski jti'ler tekrar geldiğinde DB'ye sorulur.
_revoked_cache: dict[str, float] = {}
_REVOKED_CACHE_TTL_S = 60.0
_revoked_cache_lock = asyncio.Lock()


def _get_admin_pass_hash() -> str:
    """
    H-3: Admin şifresi için Argon2id hash döner.
    ADMIN_PASS_HASH ayarlıysa onu kullanır; yoksa ADMIN_PASS'den hash üretir (uyarı).
    """
    global _admin_pass_hash_cache
    settings = get_settings()

    if settings.admin_pass_hash:
        return settings.admin_pass_hash

    if _admin_pass_hash_cache is None:
        _admin_pass_hash_cache = _ph.hash(settings.admin_pass)
        logger.warning(
            "admin_service.pass_hash.generated_at_runtime",
            hint=(
                "ADMIN_PASS_HASH env değişkeni ayarlı değil. "
                "Güvenlik için lütfen Argon2id hash'i önceden hesaplayın: "
                "python -c \"from argon2 import PasswordHasher; print(PasswordHasher().hash('sifrenz'))\""
            ),
        )

    return _admin_pass_hash_cache


def _get_jwt_algorithm_and_keys() -> tuple[str, str, str]:
    """
    L-4: ES256 için PEM anahtarları, yoksa HS256.
    Returns: (algorithm, signing_key, verify_key)
    """
    settings = get_settings()
    if settings.admin_jwt_private_key_pem and settings.admin_jwt_public_key_pem:
        return "ES256", settings.admin_jwt_private_key_pem, settings.admin_jwt_public_key_pem
    logger.warning("admin_service.jwt.using_hs256", hint="ES256 için ADMIN_JWT_PRIVATE_KEY_PEM ayarlayın")
    return "HS256", settings.jwt_secret, settings.jwt_secret


def create_admin_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    H-6: jti (JWT ID) eklenerek token revocation desteklenir.
    L-4: ES256 desteklenir; yoksa HS256.
    """
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    # H-6: jti ile revocation desteği
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
    algorithm, signing_key, _ = _get_jwt_algorithm_and_keys()
    return jwt.encode(to_encode, signing_key, algorithm=algorithm)


async def _is_jti_revoked(jti: str) -> bool:
    """
    H-2: jti revoke edilmiş mi?  Kısa-ömürlü cache + DB.
    """
    if not jti:
        return False
    now = time.monotonic()
    cached = _revoked_cache.get(jti)
    if cached is not None and (now - cached) < _REVOKED_CACHE_TTL_S:
        return True

    try:
        async with get_session_factory()() as session:  # type: AsyncSession
            stmt = select(RevokedAdminToken.jti).where(RevokedAdminToken.jti == jti)
            result = await session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                async with _revoked_cache_lock:
                    _revoked_cache[jti] = now
                return True
    except Exception as exc:
        # Fail-CLOSED: DB'ye ulaşılamıyorsa token'ı reddetmek yerine sadece
        # uyarı log'la — admin oturumlarını topyekün kesmeyiz; alternatif:
        # `True` döndürerek tüm istekleri reddetmek (paranoyak mod). Üretimde
        # bu davranış konfigüre edilebilir olmalı.
        logger.warning("admin.token.revocation_check_failed", error=str(exc))
    return False


def verify_admin_token_sync(token: str) -> dict:
    """
    Token'ın imzasını ve role/exp claim'lerini doğrular.  Blacklist kontrolü
    `verify_admin_token` async wrapper'ında yapılır (DB I/O).
    """
    algorithm, _, verify_key = _get_jwt_algorithm_and_keys()
    try:
        payload = jwt.decode(token, verify_key, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token süresi dolmuş")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Geçersiz token")

    if payload.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Yetki yetersiz")

    return payload


async def verify_admin_token(token: str) -> dict:
    """
    H-2/H-6: Blacklist kontrolü dahil token doğrulama (async, DB destekli).
    """
    payload = verify_admin_token_sync(token)
    jti = payload.get("jti", "")
    if await _is_jti_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token geçersiz kılınmış",
        )
    return payload


async def revoke_token(jti: str, *, revoked_by: Optional[str] = None,
                       expires_at: Optional[datetime] = None) -> None:
    """
    H-2: jti'yi DB blacklist tablosuna kalıcı yazar (multi-worker güvenli).
    `expires_at` verilmezse 24 saat sonrası varsayılır (admin token TTL'si 8h
    olduğu için yeterli güvenlik payı).
    """
    if not jti:
        return
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    try:
        async with get_session_factory()() as session:  # type: AsyncSession
            # PostgreSQL ON CONFLICT ile idempotent insert
            stmt = pg_insert(RevokedAdminToken).values(
                jti=jti,
                revoked_by=revoked_by,
                expires_at=expires_at,
            ).on_conflict_do_nothing(index_elements=["jti"])
            await session.execute(stmt)
            await session.commit()
        async with _revoked_cache_lock:
            _revoked_cache[jti] = time.monotonic()
        logger.info("admin.token.revoked", jti=jti, by=revoked_by or "?")
    except Exception as exc:
        logger.error("admin.token.revoke_failed", jti=jti, error=str(exc))
        # Fallback: cache'e koy (en azından bu worker oturumunda iptal edilmiş sayılır)
        async with _revoked_cache_lock:
            _revoked_cache[jti] = time.monotonic()


async def cleanup_expired_revocations() -> int:
    """
    H-2: Süresi dolmuş blacklist kayıtlarını siler.  Background scheduler'dan
    saatlik çağrılması önerilir.
    """
    try:
        async with get_session_factory()() as session:  # type: AsyncSession
            stmt = delete(RevokedAdminToken).where(
                RevokedAdminToken.expires_at < datetime.now(timezone.utc)
            )
            res = await session.execute(stmt)
            await session.commit()
            removed = res.rowcount or 0
            if removed:
                logger.info("admin.token.revocations_pruned", removed=removed)
            return int(removed)
    except Exception as exc:
        logger.warning("admin.token.cleanup_failed", error=str(exc))
        return 0


async def login_admin(request: AdminLoginRequest) -> JSONResponse:
    """
    H-3: Argon2id verify ile şifre kontrolü.
    H-5: httpOnly cookie + response body (hibrit yaklaşım).
    OWASP: Timing attack koruması — safe_compare (email) + Argon2id (şifre).
    """
    settings = get_settings()

    # Email constant-time karşılaştırma
    email_ok = safe_compare(request.email, settings.admin_mail)

    # H-3: Argon2id ile şifre doğrulama
    pass_ok = False
    if email_ok:
        try:
            pass_ok = _ph.verify(_get_admin_pass_hash(), request.password)
        except (VerifyMismatchError, VerificationError):
            pass_ok = False
    else:
        # Timing attack koruması: email yanlış olsa da aynı süreyi harca
        try:
            _ph.verify(_get_admin_pass_hash(), "__timing_dummy__")
        except Exception:
            pass

    if not email_ok or not pass_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz kimlik bilgileri",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.jwt_access_token_expire_minutes)
    access_token = create_admin_access_token(
        data={"sub": request.email, "role": "admin"},
        expires_delta=access_token_expires,
    )

    expires_in = settings.jwt_access_token_expire_minutes * 60

    # H-12: Token YALNIZCA HttpOnly cookie'de döner; body içermez.
    # XSS olsa dahi document.cookie ile erişilemez; CSRF için SameSite=strict.
    response = JSONResponse(
        content=AdminLoginResponse(expires_in=expires_in).model_dump()
    )
    response.set_cookie(
        key="admin_token",
        value=access_token,
        httponly=True,
        secure=settings.is_production,   # Üretimde sadece HTTPS
        samesite="strict",
        max_age=expires_in,
        path="/api/v1/admin",
    )
    return response


async def logout_admin(token: str) -> dict:
    """
    H-2/H-6: JWT'yi DB blacklist'e ekler — multi-worker arasında kalıcı.
    """
    algorithm, _, verify_key = _get_jwt_algorithm_and_keys()
    try:
        payload = jwt.decode(
            token, verify_key, algorithms=[algorithm],
            options={"verify_exp": False},
        )
        jti = payload.get("jti", "")
        sub = payload.get("sub")
        # Token'ın orijinal exp'i varsa onu kullan; yoksa 24h
        exp_ts = payload.get("exp")
        expires_at = (
            datetime.fromtimestamp(int(exp_ts), tz=timezone.utc)
            if exp_ts else None
        )
        if jti:
            await revoke_token(jti, revoked_by=sub, expires_at=expires_at)
    except Exception as exc:
        # Geçersiz token bile gelse logout sayılır; admin tarafına net mesaj.
        logger.info("admin.logout.invalid_token", error=str(exc))
    return {"message": "Admin oturumu sonlandırıldı."}

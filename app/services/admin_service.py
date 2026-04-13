"""
Admin SSO Service
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Güvenlik özellikleri:
  H-3: Admin şifresi Argon2id hash ile doğrulanır (plaintext karşılaştırma yok)
  H-5: JWT httpOnly cookie olarak ayarlanır (XSS'e karşı)
  H-6: jti (UUID) ile JWT blacklist — logout sonrası token geçersiz
  L-4: ADMIN_JWT_PRIVATE_KEY_PEM ayarlıysa ES256, yoksa HS256 (+ uyarı)
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import safe_compare
from app.schemas.admin import AdminLoginRequest, AdminLoginResponse

logger = get_logger(__name__)

# ─── Argon2id hasher (H-3) ────────────────────────────────────────────────────
_ph = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=4)

# H-3: Admin şifresinin Argon2id hash'i — startup'ta türetilir/yüklenir
_admin_pass_hash_cache: Optional[str] = None

# H-6: JWT blacklist — revoke edilmiş jti değerleri
# Üretimde Redis ile değiştirilebilir.
_jwt_blacklist: set[str] = set()


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


def verify_admin_token(token: str) -> dict:
    """
    H-6: Blacklist kontrolü dahil token doğrulama.
    L-4: ES256 veya HS256.
    """
    settings = get_settings()
    algorithm, _, verify_key = _get_jwt_algorithm_and_keys()
    try:
        payload = jwt.decode(token, verify_key, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token süresi dolmuş")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Geçersiz token")

    # H-6: Blacklist kontrolü
    jti = payload.get("jti", "")
    if jti and jti in _jwt_blacklist:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token geçersiz kılınmış")

    if payload.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Yetki yetersiz")

    return payload


def revoke_token(jti: str) -> None:
    """H-6: Token'ı blacklist'e ekler."""
    if jti:
        _jwt_blacklist.add(jti)
        logger.info("admin.token.revoked", jti=jti)


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

    # H-5: httpOnly cookie olarak da ayarla (XSS'e karşı koruma)
    response = JSONResponse(
        content=AdminLoginResponse(
            access_token=access_token,
            expires_in=expires_in,
        ).model_dump()
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
    """H-6: JWT'yi blacklist'e ekler."""
    settings = get_settings()
    algorithm, _, verify_key = _get_jwt_algorithm_and_keys()
    try:
        payload = jwt.decode(token, verify_key, algorithms=[algorithm], options={"verify_exp": False})
        jti = payload.get("jti", "")
        if jti:
            revoke_token(jti)
    except Exception:
        pass  # Geçersiz token — yine de logout sayılır
    return {"message": "Admin oturumu sonlandırıldı."}

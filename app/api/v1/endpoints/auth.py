"""Auth Endpoint'leri — Handshake, Kayıt, Giriş, Çıkış."""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update

from app.core.handshake import HandshakeError, perform_handshake
from app.core.logging import get_logger
from app.core.config import get_settings
from app.db.dependencies import get_db
from app.models.user_session import UserSession
from app.schemas.auth import (
    HandshakeRequest,
    HandshakeResponse,
    RegisterRequest,
    RegisterResponse,
    LoginRequest,
    LoginResponse,
)
from app.services.auth_service import register_user, login_user
from app.api.dependencies import UserDTO, _compute_token_hash, _session_cache, get_current_user

router = APIRouter(prefix="/auth", tags=["Auth"])
logger = get_logger(__name__)
_bearer = HTTPBearer()


@router.post(
    "/handshake",
    response_model=HandshakeResponse,
    status_code=status.HTTP_200_OK,
    summary="ECDH Key Exchange — Dinamik Session Key",
    description=(
        "Flutter uygulaması her oturum başında bu endpoint'i çağırarak "
        "ephemeral ECDH P-256 anahtar değişimi yapar. "
        "Dönen server_public_key ile session_key türetilir (sadece RAM'de). "
        "Bu endpoint ClientAuthMiddleware bypass'ındadır."
    ),
)
async def handshake(body: HandshakeRequest, request: Request) -> HandshakeResponse:
    """
    ECDH P-256 handshake — sunucu ephemeral keypair üretir,
    shared secret'tan HKDF-SHA256 ile session_key türetir.
    Session key RAM'de TTL ile saklanır.
    """
    # Bundle ID doğrulama (middleware bypass'ında olduğu için manuel kontrol)
    bundle_id = request.headers.get("X-Pentora-Bundle-ID", "")

    try:
        result = await perform_handshake(
            client_public_key_b64=body.client_public_key_b64,
            client_nonce_b64=body.client_nonce_b64,
            bundle_id=bundle_id,
        )
    except HandshakeError as exc:
        logger.warning("handshake.failed", reason=str(exc),
                       ip=request.client.host if request.client else "?")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "handshake_failed", "message": str(exc)},
        )

    return HandshakeResponse(
        handshake_id=result.handshake_id,
        server_public_key_b64=result.server_public_key_b64,
        server_nonce_b64=result.server_nonce_b64,
        expires_in=result.expires_in,
    )


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Yeni Müşteri Kaydı (TCKN + PIN + NFC)",
    description=(
        "Üç faktörlü kimlik doğrulamayla yeni müşteri kaydı oluşturur. "
        "Başarı durumunda GRAuth token döner (AES-256-GCM + HMAC-SHA3-512 şifreli). "
        "DB'de hiçbir PII plaintext saklanmaz."
    ),
)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RegisterResponse:
    """
    Kayıt akışı:
      TCKN checksum (sunucu) → çakışma kontrolü (hash) → GRAuth token üretimi
      → DB kayıt (sıfır plaintext PII) → denetim logu → token dön
    """
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    user_agent = request.headers.get("user-agent", "")[:200]

    grauth_result = await register_user(
        request=body,
        db=db,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    await db.commit()

    return RegisterResponse(
        grauth_token=grauth_result.token,
        session_id=grauth_result.session_id,
        expires_in=grauth_result.expires_at - grauth_result.issued_at,
        nfc_verified=body.nfc_verified,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Müşteri Girişi (TCKN + PIN)",
    description=(
        "TCKN ve PIN bilgilerini doğrulayarak giriş yapar. "
        "Başarı durumunda GRAuth token döner (AES-256-GCM + HMAC-SHA3-512 şifreli). "
        "Zamanlama saldırılarına (timing attacks) karşı korumalıdır."
    ),
)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    user_agent = request.headers.get("user-agent", "")[:200]

    grauth_result = await login_user(
        request=body,
        db=db,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    await db.commit()

    return LoginResponse(
        grauth_token=grauth_result.token,
        session_id=grauth_result.session_id,
        expires_in=grauth_result.expires_at - grauth_result.issued_at,
        nfc_verified=True, # Backend login başarılıysa hesap her zaman NFC verified'dır
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Oturum Kapat",
    description="M-4: GRAuth token'ı geçersiz kılar (DB revoke + cache temizle).",
)
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
    current_user: UserDTO = Depends(get_current_user),
) -> dict:
    """
    M-4: Logout endpoint.
    1. Token hash hesapla
    2. DB'de session'ı revoke et
    3. In-memory cache'i temizle
    """
    settings = get_settings()
    token_str = credentials.credentials
    token_hash = _compute_token_hash(token_str, settings.session_pepper)

    # DB: session'ı revoke et
    await db.execute(
        update(UserSession)
        .where(
            UserSession.grauth_token_hash == token_hash,
            UserSession.is_revoked.is_(False),
        )
        .values(is_revoked=True)
    )
    await db.commit()

    # Cache'den temizle (anlık etki)
    await _session_cache.invalidate(token_hash)

    logger.info("auth.logout.success", user_id=str(current_user.id))
    return {"message": "Oturum başarıyla sonlandırıldı."}

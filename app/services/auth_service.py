"""
Auth Service — Kayıt iş mantığı.
Repository katmanını kullanır, HTTP'den izoledir.
"""
from __future__ import annotations

import asyncio
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.gr_auth import GRAuthToken, generate_grauth_token
from app.core.logging import get_logger
from app.models.audit_event import AuditEventType
from app.repositories.user_repo import UserRepository
from app.schemas.auth import RegisterRequest

logger = get_logger(__name__)


async def register_user(
    request: RegisterRequest,
    db: AsyncSession,
    client_ip: str,
    user_agent: str,
) -> GRAuthToken:
    """
    Yeni müşteri kaydı iş mantığı.

    Adımlar:
      1. TCKN çakışma kontrolü (hash üzerinden)
      2. Argon2id salt üret
      3. GRAuth token üret  (TCKN + PIN + NFC → 4 katmanlı şifreleme)
      4. Kullanıcı ve oturum DB'ye kaydet  (sıfır plaintext PII)
      5. Denetim logu yaz
      6. GRAuth token döndür

    Raises:
        HTTPException 409: TCKN zaten kayıtlı
        HTTPException 500: Beklenmeyen hata
    """
    repo = UserRepository(db)

    # ── 1. TCKN çakışma kontrolü ─────────────────────────────────────────────
    if await repo.exists_by_tckn(request.tckn):
        # Hata mesajında TCKN bilgisi YOK (bilgi sızıntısı önlemi)
        logger.warning(
            "auth.register.tckn_conflict",
            # TCKN'nin hash'ini logla, kendisini değil
            tckn_prefix=request.tckn[:3] + "********",
        )
        await repo.log_event(
            AuditEventType.REGISTER_FAILED,
            client_ip=client_ip,
            user_agent=user_agent,
            details={"reason": "tckn_already_registered"},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "conflict",
                "message": "Bu kimlik bilgileriyle kayıtlı bir hesap zaten mevcut.",
            },
        )

    # ── 1.5 Doğrulama Kontrolü ──────────────────────────────────────
    if request.nfc_verified and request.nfc_uid_hex == "MRTD_BAC_VERIFIED_TCKN":
        # TCKN NFC'den cihaz tarafında (dmrtd) okunmuş ve harfi harfine eşleştirilmiştir.
        pass

    # ── 2. GRAuth Argon2id Salt Üretimi ──────────────────────────────────────
    grauth_salt = secrets.token_bytes(32)

    # ── 3. GRAuth Token Üretimi (TCKN + PIN + NFC → 4 katman kriptografi) ───
    try:
        grauth_result: GRAuthToken = generate_grauth_token(
            tckn=request.tckn,
            pin=request.pin,
            nfc_uid_hex=request.nfc_uid_hex,
            user_id="PENDING",        # Henüz DB'de yok, geçici
            ttl_seconds=1_800,        # 30 dakika
            existing_salt=grauth_salt,
        )
    except Exception as exc:
        logger.error("auth.register.grauth_generation_failed", exc=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "server_error", "message": "Kayıt işlemi başlatılamadı."},
        )

    # ── 4. Kullanıcı Oluşturma ───────────────────────────────────────────────
    user = await repo.create_user(
        tckn=request.tckn,
        pin=request.pin,
        nfc_uid_hex=request.nfc_uid_hex,
        grauth_salt=grauth_salt,
        nfc_verified=request.nfc_verified,
    )

    # ── 4.5. Kullanıcı Cüzdanını (Liability Account) Oluşturma ───────────────
    from app.services.accounting_service import AccountingService
    accounting_svc = AccountingService(db)
    await accounting_svc.setup_user_wallet(user.id)

    # GRAuth token'ı gerçek user_id ile yeniden üret
    grauth_result = generate_grauth_token(
        tckn=request.tckn,
        pin=request.pin,
        nfc_uid_hex=request.nfc_uid_hex,
        user_id=str(user.id),
        ttl_seconds=1_800,
        existing_salt=grauth_salt,
    )

    # ── 5. Oturum Kaydet ─────────────────────────────────────────────────────
    await repo.create_session(
        user_id=user.id,
        session_uuid=grauth_result.session_id,
        grauth_token=grauth_result.token,
        issued_at=datetime.fromtimestamp(grauth_result.issued_at, tz=timezone.utc),
        expires_at=datetime.fromtimestamp(grauth_result.expires_at, tz=timezone.utc),
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # ── 6. Denetim Logu ──────────────────────────────────────────────────────
    await repo.log_event(
        AuditEventType.REGISTER_SUCCESS,
        user_id=user.id,
        client_ip=client_ip,
        user_agent=user_agent,
        details={
            "nfc_verified": request.nfc_verified,
            "session_id": grauth_result.session_id,
        },
    )

    logger.info(
        "auth.register.success",
        user_id=str(user.id),
        nfc_verified=request.nfc_verified,
        session_id=grauth_result.session_id,
    )

    return grauth_result


async def login_user(
    request: LoginRequest,
    db: AsyncSession,
    client_ip: str,
    user_agent: str,
) -> GRAuthToken:
    """
    Kullanıcı giriş (Login) iş mantığı.

    Güvenlik: TCKN bulunamazsa veya PIN yanlışsa aynı sürede yanıt verir
    (Timing Attack koruması - OWASP). Hata mesajında hangisinin yanlış olduğu
    söylenmez.

    NFC login'de istenmediği için boş gönderilir ("").
    """
    repo = UserRepository(db)
    
    # Dummy Argon2id hash'i (Zamanlama saldırısını önlemek için)
    # Eğer user bulunamazsa, sanki varmış gibi bu hash'le verify yapacağız.
    # Gerçek PIN doğrulama süresini taklit eder.
    # (Parola "dummy_pin" için oluşturulmuş örnek bir Argon2id hash).
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRoZXJl$dummyhashvaluefortimingattackprotection"

    user = await repo.get_by_tckn(request.tckn)
    user_found = user is not None
    is_active = user.is_active if user_found else False

    # Güvenlik önlemi: Kullanıcı yoksa da aynı hesaplama yükünü ver (Constant-time trick)
    hash_to_verify = user.pin_hash if user_found else dummy_hash
    
    from argon2.exceptions import VerifyMismatchError, VerificationError
    try:
        from app.repositories.user_repo import _pin_hasher
        # Argon2id CPU-yoğun işlem — event loop'u bloklamaz
        await asyncio.to_thread(_pin_hasher.verify, hash_to_verify, request.pin)
        pin_valid = True
    except (VerifyMismatchError, VerificationError, Exception):
        pin_valid = False

    if not user_found or not pin_valid or not is_active:
        await repo.log_event(
            AuditEventType.LOGIN_FAILED,
            client_ip=client_ip,
            user_agent=user_agent,
            details={"reason": "invalid_credentials"},
        )
        # TCKN mi PIN mi hatalı söylemiyoruz
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "unauthorized",
                "message": "Kimlik bilgileri hatalı.",
            },
        )

    # GRAuth Token Üretimi (Login modunda NFC = boş string)
    try:
        grauth_result: GRAuthToken = generate_grauth_token(
            tckn=request.tckn,
            pin=request.pin,
            nfc_uid_hex="",               # Login'de NFC yok
            user_id=str(user.id),
            ttl_seconds=1_800,
            existing_salt=user.grauth_salt,
        )
    except Exception as exc:
        logger.error("auth.login.grauth_generation_failed", exc=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "server_error", "message": "Giriş işlemi başlatılamadı."},
        )

    # Oturum Kaydet
    await repo.create_session(
        user_id=user.id,
        session_uuid=grauth_result.session_id,
        grauth_token=grauth_result.token,
        issued_at=datetime.fromtimestamp(grauth_result.issued_at, tz=timezone.utc),
        expires_at=datetime.fromtimestamp(grauth_result.expires_at, tz=timezone.utc),
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # Denetim Logu
    await repo.log_event(
        AuditEventType.LOGIN_SUCCESS,
        user_id=user.id,
        client_ip=client_ip,
        user_agent=user_agent,
        details={"session_id": grauth_result.session_id},
    )

    logger.info(
        "auth.login.success",
        user_id=str(user.id),
        session_id=grauth_result.session_id,
    )

    # register dönerken nfc_verified da alıyorduk, onu set edelim
    # model.user'den getattr kullanıyoruz:
    # grauth_result return ediyoruz ama endpoint tarafta nfc_verified eklenecek
    return grauth_result


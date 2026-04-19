"""
Auth Service — Kayıt iş mantığı.
Repository katmanını kullanır, HTTP'den izoledir.
"""
from __future__ import annotations

import asyncio
import re
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.gr_auth import GRAuthToken, generate_grauth_token
from app.core.logging import get_logger
from app.models.audit_event import AuditEventType
from app.models.user import User
from app.repositories.user_repo import UserRepository
from app.schemas.auth import LoginRequest, RegisterRequest

# Hex UID için minimum uzunluk: gerçek ICAO MRTD chip UID'leri 4–10 byte
# (8–20 hex). Bunun altında bir UID kabul edilmez — magic string / placeholder
# atlatması önlenir.
_NFC_UID_HEX_PATTERN = re.compile(r"^[0-9A-Fa-f]{8,32}$")

logger = get_logger(__name__)

# H-9: Dummy hash — zamanlama saldırısı koruması için kullanıcı bulunamadığında
# bu hash ile Argon2id verify yapılır.  _pin_hasher parametreleriyle üretilmiş
# gerçek bir hash olması zorunludur; geçersiz string farklı exception yolu açar.
_DUMMY_PIN_HASH: str = ""


def _get_dummy_pin_hash() -> str:
    """Module başına bir kez _pin_hasher ile gerçek bir Argon2id hash üretir."""
    global _DUMMY_PIN_HASH
    if not _DUMMY_PIN_HASH:
        from app.repositories.user_repo import _pin_hasher
        _DUMMY_PIN_HASH = _pin_hasher.hash("__dummy_timing_protection_pin__")
    return _DUMMY_PIN_HASH


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

    # ── 1.5 NFC doğrulama bayrağını sunucu tarafında yeniden değerlendir ────
    # GÜVENLİK (C-1 / OWASP A07): İstemcinin gönderdiği `nfc_verified` ve
    # `nfc_uid_hex` boolean'ına asla doğrudan güvenilmez. Magic-string
    # atlatması (ör. "MRTD_BAC_VERIFIED_TCKN") veya kısa/placeholder UID'ler
    # sunucu seviyesinde reddedilir; aksi takdirde kayıt sırasında çok
    # faktörlü kimlik doğrulama bypass edilebilir.
    effective_nfc_verified = (
        bool(request.nfc_verified)
        and bool(request.nfc_uid_hex)
        and _NFC_UID_HEX_PATTERN.match(request.nfc_uid_hex) is not None
    )

    if request.nfc_verified and not effective_nfc_verified:
        # İstemci `nfc_verified=True` iddia etti ama UID geçersiz / placeholder.
        # Sahtecilik şüphesi: denetim logu yaz, isteği reddet.
        logger.warning(
            "auth.register.nfc_verified_claim_invalid",
            tckn_prefix=request.tckn[:3] + "********",
            uid_len=len(request.nfc_uid_hex or ""),
        )
        await repo.log_event(
            AuditEventType.REGISTER_FAILED,
            client_ip=client_ip,
            user_agent=user_agent,
            details={"reason": "nfc_verified_claim_with_invalid_uid"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_nfc_attestation",
                "message": (
                    "NFC doğrulama iddiası geçersiz. Lütfen kimlik kartınızı "
                    "yeniden okutun."
                ),
            },
        )

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
    # NOT: `nfc_verified` istemciden değil, sunucunun yeniden değerlendirdiği
    # `effective_nfc_verified` bayrağından alınır.
    user = await repo.create_user(
        tckn=request.tckn,
        pin=request.pin,
        nfc_uid_hex=request.nfc_uid_hex,
        grauth_salt=grauth_salt,
        nfc_verified=effective_nfc_verified,
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
            "nfc_verified": effective_nfc_verified,
            "session_id": grauth_result.session_id,
        },
    )

    logger.info(
        "auth.register.success",
        user_id=str(user.id),
        nfc_verified=effective_nfc_verified,
        session_id=grauth_result.session_id,
    )

    # M-1: Endpoint, sunucu tarafında değerlendirilmiş gerçek bayrağı yansıtır.
    # GRAuthToken'a ek olarak effective flag'i taşıyabilmek için tuple döner.
    return grauth_result, effective_nfc_verified


async def login_user(
    request: LoginRequest,
    db: AsyncSession,
    client_ip: str,
    user_agent: str,
) -> tuple[GRAuthToken, User]:
    """
    Kullanıcı giriş (Login) iş mantığı.

    Güvenlik: TCKN bulunamazsa veya PIN yanlışsa aynı sürede yanıt verir
    (Timing Attack koruması - OWASP). Hata mesajında hangisinin yanlış olduğu
    söylenmez.

    NFC login'de istenmediği için boş gönderilir ("").
    """
    repo = UserRepository(db)
    
    # H-9: Dummy Argon2id hash — gerçek _pin_hasher parametreleriyle üretilmiş
    # geçerli bir hash'tir.  Kullanıcı bulunamazsa bu hash ile verify yapılır,
    # böylece yanıt süresi TCKN var/yok durumunda eşit kalır (Timing Attack önlemi).
    dummy_hash = _get_dummy_pin_hash()

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

    # M-1: Endpoint katmanı `user.nfc_verified` gerçek değerini cevaba koyabilsin
    # diye user nesnesini de geri döneriz.
    return grauth_result, user


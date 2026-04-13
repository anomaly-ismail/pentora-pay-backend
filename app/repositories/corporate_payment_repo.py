"""
Kurumsal Ödeme Repository
"""
import hashlib
import hmac as stdlib_hmac
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.corporate_payment import CorporatePayment, CorporatePaymentStatus


def _hash_otp(otp_plain: str, pepper: str) -> str:
    """
    C-4: OTP'yi unsalted SHA-256 yerine HMAC-SHA256(otp, pepper) ile hashler.
    Pepper sunucu tarafında saklandığından rainbow table saldırıları engellenir.
    """
    return stdlib_hmac.new(
        pepper.encode("utf-8"),
        otp_plain.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class CorporatePaymentRepo:
    _OTP_TTL_MINUTES = 10

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        settings = get_settings()
        self._otp_pepper = settings.otp_pepper

    async def create(
        self,
        *,
        seller_user_id: uuid.UUID,
        recipient_tckn: Optional[str],
        recipient_iban: Optional[str],
        recipient_phone: str,
        gold_gram: Decimal,
        gold_type: str,
        amount: Decimal,
        otp_plain: str,
        mrz_verified: bool = False,
        nfc_verified: bool = False,
    ) -> CorporatePayment:
        # C-4: HMAC-SHA256 ile OTP hash (unsalted SHA-256 yerine)
        otp_hash = _hash_otp(otp_plain, self._otp_pepper)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self._OTP_TTL_MINUTES)

        payment = CorporatePayment(
            seller_user_id=seller_user_id,
            recipient_tckn=recipient_tckn,
            recipient_iban=recipient_iban,
            recipient_phone=recipient_phone,
            gold_gram=gold_gram,
            gold_type=gold_type,
            amount=amount,
            otp_code_hash=otp_hash,
            otp_expires_at=expires_at,
            status=CorporatePaymentStatus.PENDING_OTP,
            mrz_verified=mrz_verified,
            nfc_verified=nfc_verified,
        )
        self._session.add(payment)
        await self._session.flush()
        await self._session.refresh(payment)
        return payment

    async def get_by_id(self, payment_id: uuid.UUID) -> Optional[CorporatePayment]:
        result = await self._session.execute(
            select(CorporatePayment).where(CorporatePayment.id == payment_id)
        )
        return result.scalar_one_or_none()

    async def get_by_id_for_update(self, payment_id: uuid.UUID) -> Optional[CorporatePayment]:
        """
        C-2: OTP doğrulaması öncesi row-level lock ile çeker (TOCTOU önlemi).
        Eşzamanlı OTP denemelerini serialize eder.
        """
        result = await self._session.execute(
            select(CorporatePayment)
            .where(CorporatePayment.id == payment_id)
            .with_for_update()
        )
        return result.scalar_one_or_none()

    async def verify_otp(
        self,
        payment: CorporatePayment,
        otp_plain: str,
    ) -> tuple[bool, str]:
        """OTP doğrular. (başarı, hata_mesajı) döner."""
        now = datetime.now(timezone.utc)

        if payment.status != CorporatePaymentStatus.PENDING_OTP:
            return False, "Bu ödeme zaten tamamlanmış veya geçersiz."

        if payment.otp_expires_at and now > payment.otp_expires_at:
            payment.status = CorporatePaymentStatus.EXPIRED
            await self._session.flush()
            return False, "OTP süreniz dolmuştur. Lütfen yeni bir işlem başlatın."

        if payment.otp_attempts >= 5:
            payment.status = CorporatePaymentStatus.FAILED
            payment.note = "Maksimum OTP deneme aşıldı."
            await self._session.flush()
            return False, "Çok fazla hatalı deneme. İşlem iptal edildi."

        # C-4: Girilen OTP'yi HMAC ile hashle ve saklananla karşılaştır
        entered_hash = _hash_otp(otp_plain, self._otp_pepper)
        if not stdlib_hmac.compare_digest(entered_hash, payment.otp_code_hash):
            payment.otp_attempts += 1
            await self._session.flush()
            remaining = 5 - payment.otp_attempts
            return False, f"Hatalı OTP. Kalan deneme hakkı: {remaining}"

        payment.status = CorporatePaymentStatus.COMPLETED
        payment.completed_at = now
        await self._session.flush()
        return True, "OK"

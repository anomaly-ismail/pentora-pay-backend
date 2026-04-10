"""
Kurumsal Ödeme Repository
"""
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.corporate_payment import CorporatePayment, CorporatePaymentStatus


class CorporatePaymentRepo:
    _OTP_TTL_MINUTES = 10

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
        otp_hash = hashlib.sha256(otp_plain.encode()).hexdigest()
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

        entered_hash = hashlib.sha256(otp_plain.encode()).hexdigest()
        if entered_hash != payment.otp_code_hash:
            payment.otp_attempts += 1
            await self._session.flush()
            remaining = 5 - payment.otp_attempts
            return False, f"Hatalı OTP. Kalan deneme hakkı: {remaining}"

        payment.status = CorporatePaymentStatus.COMPLETED
        payment.completed_at = now
        await self._session.flush()
        return True, "OK"

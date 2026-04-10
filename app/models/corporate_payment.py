"""
Kurumsal Ödeme Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Kurumsal kullanıcıların altın takası / ödeme işlemlerini saklar.
OTP doğrulaması sonrasında bakiyeden düşülür.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Optional

from sqlalchemy import DateTime, Index, Numeric, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CorporatePaymentStatus(StrEnum):
    PENDING_OTP  = "pending_otp"   # OTP gönderildi, bekleniyor
    COMPLETED    = "completed"     # OTP doğrulandı, bakiye düşüldü
    EXPIRED      = "expired"       # OTP süresi doldu
    FAILED       = "failed"        # Hata


class CorporatePayment(Base):
    __tablename__ = "corporate_payments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # İşlemi yapan kurumsal kullanıcı
    seller_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="İşlemi gerçekleştiren kurumsal kullanıcı",
    )

    # Alıcı bilgileri
    recipient_tckn: Mapped[Optional[str]] = mapped_column(
        String(11), nullable=True, comment="Alıcı TCKN"
    )
    recipient_iban: Mapped[Optional[str]] = mapped_column(
        String(34), nullable=True, comment="Alıcı IBAN"
    )
    recipient_phone: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="OTP gönderilecek alıcı telefon"
    )

    # Altın bilgileri
    gold_gram: Mapped[Decimal] = mapped_column(
        Numeric(precision=12, scale=4), nullable=False, comment="Altın miktarı (gram)"
    )
    gold_type: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="Altın tipi (ör: Cumhuriyet Altını)"
    )

    # Tutar
    amount: Mapped[Decimal] = mapped_column(
        Numeric(precision=18, scale=2), nullable=False, comment="İşlem tutarı (TL)"
    )

    # OTP
    otp_code_hash: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, comment="SHA-256 OTP hash (plaintext saklanmaz)"
    )
    otp_attempts: Mapped[int] = mapped_column(
        default=0, server_default=text("0"), comment="Yanlış OTP deneme sayısı"
    )
    otp_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="OTP son geçerlilik zamanı"
    )

    # Durum
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=CorporatePaymentStatus.PENDING_OTP,
        server_default=text("'pending_otp'"),
        index=True,
    )

    note: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="İşlem notu / hata açıklaması"
    )

    # MRZ / NFC verisi (özet)
    mrz_verified: Mapped[bool] = mapped_column(default=False, server_default=text("false"))
    nfc_verified:  Mapped[bool] = mapped_column(default=False, server_default=text("false"))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_corp_payment_seller_created", "seller_user_id", "created_at"),
    )

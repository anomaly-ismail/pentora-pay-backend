"""
Kurumsal Ödeme Alma Talebi Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Akış:
  1. Kurumsal kullanıcı ödeme talebi oluşturur  → PENDING_PAYMENT
  2. Müşteri PayTR linki üzerinden öder          → PENDING_APPROVAL  (para escrow'a alınır)
  3. Müşteri "ONAYLIYORUM" SMS'i gönderir        → COMPLETED         (para Ana Cüzdan'a geçer)

Güvenlik:
  - PayTR webhook HMAC imzası doğrulanır
  - Netgsm SMS reply gizli token + gönderen numarası kontrolü
  - Her adım idempotent referans_id ile kaydedilir
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Optional

from sqlalchemy import Boolean, DateTime, Index, Numeric, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CorporateReceiveStatus(StrEnum):
    PENDING_PAYMENT  = "pending_payment"   # SMS gönderildi, PayTR ödemesi bekleniyor
    PENDING_APPROVAL = "pending_approval"  # PayTR onayladı, ONAYLIYORUM SMS bekleniyor
    COMPLETED        = "completed"         # Tamamlandı, bakiyeye eklendi
    EXPIRED          = "expired"           # Süre doldu
    CANCELLED        = "cancelled"         # İptal edildi


class CorporateReceiveRequest(Base):
    __tablename__ = "corporate_receive_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # İsteği oluşturan kurumsal kuyumcu
    seller_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Ödeme talep eden kurumsal kullanıcı",
    )

    # Alıcı (ödeme yapacak müşteri) bilgileri
    recipient_tckn: Mapped[str] = mapped_column(
        String(11), nullable=False, comment="Müşteri TCKN"
    )
    recipient_phone: Mapped[str] = mapped_column(
        String(20), nullable=False, comment="Müşterinin telefon numarası (SMS gönderilir)"
    )

    # Altın bilgileri
    gold_gram: Mapped[Decimal] = mapped_column(
        Numeric(precision=12, scale=4), nullable=False, comment="Altın miktarı (gram)"
    )
    gold_type: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="Altın tipi (ör: Cumhuriyet Altını)"
    )

    # Talep tutarı
    amount: Mapped[Decimal] = mapped_column(
        Numeric(precision=18, scale=2), nullable=False, comment="Tahsil edilecek TL tutarı"
    )

    # Durum
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default=CorporateReceiveStatus.PENDING_PAYMENT,
        server_default=text("'pending_payment'"),
        index=True,
    )

    # PayTR takip numarası — webhook'ta idempotency kontrolü için
    paytr_oid: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
        comment="PayTR merchant order ID (ödeme onayında set edilir)",
    )

    # MRZ / NFC
    mrz_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )
    nfc_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )

    # MRTD oturum bağlantısı (şifreli MRZ + DG dosyaları burada tutulur)
    mrtd_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="mrtd_sessions.id — approve_id ile audit zinciri",
    )

    # SMS gönderildi mi?
    sms_sent: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 24 saat sonra süresi dolar
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_corp_receive_seller_created", "seller_user_id", "created_at"),
        Index("ix_corp_receive_phone_status", "recipient_phone", "status"),
    )

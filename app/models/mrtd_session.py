"""
MRTD (Machine Readable Travel Document) Oturumu Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Akış:
  1. Kullanıcı kimlik arka yüzünü MRZ olarak tarar   → POST /corporate/mrtd/session
     - Backend MRZ'yi doğrular (check digit)
     - BAC KEnc/KMac anahtarlarını türetir (DÖNDÜRÜLÜR, SAKLANMAZ)
     - Ham MRZ AES-256-GCM ile şifrelenip saklanır → status=mrz_done
     - approve_id (UUIDv4) üretilir, 15 dakika geçerli
  2. İstemci çipi BAC/PACE ile unlock edip DG1/DG2/DG11/SOD okur
     - POST /corporate/mrtd/session/{approve_id}/nfc
     - DG dosyaları şifreli saklanır → status=nfc_done
  3. Kurumsal ödeme veya alma talebi oluşturulurken approve_id iliştirilir
     - status=consumed, linked_payment_id / linked_receive_id set edilir
     - Aynı approve_id ikinci kez kullanılamaz (idempotency)

Güvenlik / Uyumluluk:
  - Tüm MRZ ve DG verisi AES-256-GCM ile şifreli (PCI DSS 3.4)
  - doc_no_hash HMAC-SHA256 ile indekslenir (arama için)
  - user_id AAD'ye gömülüdür (OWASP A08 — blob swap koruması)
  - 15 dk TTL, tek kullanımlık (OWASP A01 — erişim kontrol)
  - BAC ham anahtarları DB'ye yazılmaz — yalnızca session fact saklanır
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MrtdPurpose(StrEnum):
    CORPORATE_PAYMENT = "corporate_payment"
    CORPORATE_RECEIVE = "corporate_receive"


class MrtdStatus(StrEnum):
    PENDING = "pending"       # created, henüz MRZ bile alınmadı (rezerv)
    MRZ_DONE = "mrz_done"     # MRZ doğrulandı, BAC keys istemciye verildi
    NFC_DONE = "nfc_done"     # DG dosyaları alındı, ödemeye hazır
    CONSUMED = "consumed"     # İlişkili payment/receive'e bağlandı, tek kullanım bitti
    EXPIRED = "expired"       # TTL doldu
    FAILED = "failed"         # Hata — tekrar denenebilir


class MrtdSession(Base):
    """
    Her kimlik okuma oturumu için tek satır. `id` alanı aynı zamanda
    "approve_id" olarak Flutter'a döner; kurumsal ödemeye bu kimlikle
    bağlanır.
    """
    __tablename__ = "mrtd_sessions"

    # approve_id == id
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        comment="approve_id — Flutter'a döndürülür, ödeme talebiyle eşleştirilir",
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="İşlemi yürüten kurumsal kullanıcı",
    )

    purpose: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        comment="corporate_payment | corporate_receive",
    )

    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=MrtdStatus.PENDING,
        server_default=text("'pending'"),
        index=True,
    )

    # ── Şifreli MRZ / DG dosyaları (AES-256-GCM envelope) ──────────────────
    mrz_blob: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True, comment="AES-GCM(mrz_raw)"
    )
    dg1_blob: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True, comment="AES-GCM(EF.DG1)"
    )
    dg2_blob: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True, comment="AES-GCM(EF.DG2 — yüz fotoğrafı JP2/JPG)"
    )
    dg11_blob: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True, comment="AES-GCM(EF.DG11 — kişisel ek bilgi)"
    )
    sod_blob: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True, comment="AES-GCM(EF.SOD — passive authentication)"
    )

    # ── Aranabilir HMAC indeksleri (plaintext yok) ─────────────────────────
    doc_no_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="HMAC-SHA256(doc_no) — duplikat / arama için",
    )
    tckn_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="HMAC-SHA256(tckn) — kimlik-hesap eşleşmesi kontrolü",
    )

    # ── Metadata / Audit ────────────────────────────────────────────────────
    doc_type: Mapped[Optional[str]] = mapped_column(
        String(8), nullable=True, comment="TD1 (kimlik) | TD3 (pasaport)"
    )
    issuing_state: Mapped[Optional[str]] = mapped_column(String(3), nullable=True)
    nationality: Mapped[Optional[str]] = mapped_column(String(3), nullable=True)
    date_of_expiry: Mapped[Optional[str]] = mapped_column(
        String(6), nullable=True, comment="YYMMDD (şifrelenmiyor — utility)"
    )

    passive_auth_ok: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"),
        comment="EF.SOD passive authentication başarılı mı",
    )

    client_ip_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, comment="HMAC-SHA256(client_ip)"
    )
    user_agent_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, comment="HMAC-SHA256(ua)"
    )

    # ── Lifecycle ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    mrz_verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    nfc_verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="15 dk TTL — expired sayılır",
    )

    # ── İlişki: consumed olduğunda hangi kayda bağlandı? ───────────────────
    linked_payment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("corporate_payments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    linked_receive_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("corporate_receive_requests.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    attempts: Mapped[int] = mapped_column(
        default=0, server_default=text("0"),
        comment="NFC okuma tekrar deneme sayısı",
    )
    last_error: Mapped[Optional[str]] = mapped_column(
        String(200), nullable=True, comment="Son hata özeti (PII içermez)"
    )

    __table_args__ = (
        Index("ix_mrtd_session_user_status", "user_id", "status"),
        Index("ix_mrtd_session_expires", "expires_at"),
    )

    # ── Yardımcı özellikler ─────────────────────────────────────────────────
    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def is_consumable(self) -> bool:
        return self.status == MrtdStatus.NFC_DONE and not self.is_expired

"""
Kurumsal Başvuru Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Flutter uygulamasından gelen kurumsal hesap başvurularını saklar.
Belgeler (PDF/JPG/PNG) sunucu diskine kaydedilerek yolu veritabanında tutulur.

Güvenlik:
  - Hiçbir belge doğrudan public URL üzerinden erişilebilir değildir.
  - Belge indirme yalnızca admin JWT doğrulaması sonrası streaming ile yapılır.
  - OWASP A01 (Broken Access Control) kapsamında: belge yolu gizli tutulur.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import DateTime, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from typing import Optional

from app.db.base import Base


class ApplicationStatus(StrEnum):
    PENDING  = "pending"    # Beklemede (yeni başvuru)
    APPROVED = "approved"   # Onaylandı
    REJECTED = "rejected"   # Reddedildi
    REVIEWING = "reviewing" # İnceleniyor


class CorporateApplication(Base):
    __tablename__ = "corporate_applications"

    # ── Birincil Anahtar ─────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # ── Başvuruyu Yapan Kullanıcı (nullable — backwardcompat) ───────────────
    # Flutter'dan gelen GRAuth token çözülünce doldurulur.
    # Eski başvurular NULL kalır — bu güvenlidir.
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="Başvuruyu yapan kullanıcı UUID — GRAuth'dan çözülür, nullable",
    )

    # ── Başvuru Durumu ────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=ApplicationStatus.PENDING,
        server_default=text("'pending'"),
        index=True,
        comment="ApplicationStatus enum değeri",
    )

    # ── İşletme Bilgileri ─────────────────────────────────────────────────────
    company_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="İşletme adı / ünvan",
    )

    tax_number: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Vergi numarası",
    )

    tax_office: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Vergi dairesi",
    )

    mersis_no: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
        comment="MERSİS numarası",
    )

    address: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="İşletme tam adresi",
    )

    # ── Yetkili Bilgileri ─────────────────────────────────────────────────────
    applicant_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        comment="Başvuran kişi adı soyadı",
    )

    # L-5: Plaintext TCKN yerine HMAC hash saklanır (128 hex karakter)
    applicant_tckn: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="Başvuran kişinin TCKN HMAC-SHA3-512 hash değeri (plaintext değil)",
    )

    phone: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Başvuran telefon numarası",
    )

    # ── Belge Yolları (Gizli — Public URL yok) ───────────────────────────────
    vergi_levhasi_path: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="Sunucu disk yolu — doğrudan erişim yok",
    )

    imza_sirkuleri_path: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="Sunucu disk yolu — doğrudan erişim yok",
    )

    ticaret_sicil_path: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        comment="Sunucu disk yolu — doğrudan erişim yok",
    )

    # ── İnceleme ─────────────────────────────────────────────────────────────
    reviewer_note: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Admin inceleme notu",
    )

    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Zaman Damgaları ───────────────────────────────────────────────────────
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_corp_app_status_submitted", "status", "submitted_at"),
    )

    def __repr__(self) -> str:
        return f"<CorporateApplication id={self.id} company={self.company_name!r} status={self.status}>"

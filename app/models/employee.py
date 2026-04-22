"""
Çalışan (Employee) Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pentora çalışan kayıtları. Hassas PII alanları (TCKN, IBAN, maaş) kolon-seviyesinde
AES-256-GCM ile şifrelenir; aranabilir alanlar (TCKN) HMAC-SHA256 ile indekslenir.

Güvenlik:
  • PCI DSS 3.4 / 3.5 — PII at rest şifreli
  • OWASP A02 — AEAD (GCM) ile integrity + confidentiality
  • ISO 27001 A.8.2.3 — bilgi sınıflandırma & koruma
  • Plaintext TCKN/IBAN/maaş asla diskte tutulmaz; yalnızca runtime'da decrypt edilir
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import date, datetime, timezone
from enum import StrEnum
from typing import Optional

from sqlalchemy import Boolean, Date, DateTime, Index, LargeBinary, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EmployeeStatus(StrEnum):
    ACTIVE     = "active"      # Aktif çalışan
    ON_LEAVE   = "on_leave"    # İzinde
    INACTIVE   = "inactive"    # Pasif (geçici)
    TERMINATED = "terminated"  # İşten ayrıldı


class Employee(Base):
    __tablename__ = "employees"

    # ── Birincil Anahtar ─────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # ── Çalışan Numarası (insan-okunabilir, unique) ───────────────────────────
    employee_no: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        unique=True,
        index=True,
        comment="Çalışan numarası (örn. EMP-2026-0001)",
    )

    # ── Kişisel Bilgiler (Plaintext — operasyonel) ───────────────────────────
    full_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        comment="Ad Soyad",
    )

    email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Kurumsal e-posta",
    )

    phone: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Telefon (E.164)",
    )

    # ── Hassas PII (Şifreli — at rest encryption) ────────────────────────────
    # TCKN: HMAC-SHA256 indeks (tekrar engelleme + arama) + AES-GCM ciphertext
    tckn_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        unique=True,
        index=True,
        comment="TCKN HMAC-SHA256 hex (aranabilir, tekrar engeller)",
    )

    tckn_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="TCKN AES-256-GCM ciphertext (version || nonce || ct+tag)",
    )

    iban_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="IBAN AES-256-GCM ciphertext",
    )

    salary_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Brüt maaş (TRY) AES-256-GCM ciphertext",
    )

    # ── İş Bilgileri ─────────────────────────────────────────────────────────
    department: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Departman (Teknoloji, İK, Finans, vb.)",
    )

    position: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Pozisyon / Ünvan",
    )

    hire_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        comment="İşe başlama tarihi",
    )

    termination_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        comment="İşten ayrılma tarihi (varsa)",
    )

    # ── Kişisel ─────────────────────────────────────────────────────────────
    birth_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        comment="Doğum tarihi",
    )

    address: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Ev adresi",
    )

    # ── Acil Durum ──────────────────────────────────────────────────────────
    emergency_contact_name: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
        comment="Acil durumda aranacak kişi adı",
    )

    emergency_contact_phone: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        comment="Acil durumda aranacak kişi telefonu",
    )

    # ── Durum ────────────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=EmployeeStatus.ACTIVE,
        server_default=text("'active'"),
        index=True,
        comment="EmployeeStatus enum değeri",
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Admin notları",
    )

    # ── RBAC — Admin Erişimi ────────────────────────────────────────────────
    # True olduğunda bu çalışan için bir `admin_users` kaydı oluşturulur
    # ve @pentorasec.com.tr'li bir e-posta + rastgele güçlü parola üretilir.
    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="Admin paneline erişim yetkisi",
    )

    admin_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="Bağlı AdminUser.id (is_admin=True olduğunda)",
    )

    # ── Audit ────────────────────────────────────────────────────────────────
    created_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Kaydı oluşturan admin email'i",
    )

    updated_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Son güncelleyen admin email'i",
    )

    # ── Zaman Damgaları ─────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_employees_status_created", "status", "created_at"),
        Index("ix_employees_department_status", "department", "status"),
    )

    def __repr__(self) -> str:
        return f"<Employee id={self.id} no={self.employee_no!r} name={self.full_name!r} status={self.status}>"

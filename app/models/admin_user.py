"""
AdminUser Modeli — RBAC tabanlı çoklu admin hesap yönetimi.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pentora Pay admin paneline çalışan bazlı erişim yönetimi. Her admin:
  • @pentorasec.com.tr e-posta ile giriş yapar
  • Argon2id hash ile parola doğrulaması yapılır
  • Plaintext parola AES-256-GCM ile şifrelenip saklanır — YALNIZCA süper admin
    (info@pentorasec.com.tr) bu alanı decrypt edebilir
  • `permissions` alanı ile admin panelindeki sayfa erişimleri kontrol edilir

Güvenlik:
  • OWASP A02 — AEAD şifreleme (AAD = "admin_user:<id>:password")
  • OWASP A07 — Argon2id ile kimlik doğrulama
  • ISO 27001 A.9.2.3 — Ayrıcalıklı erişim yönetimi
  • PCI DSS 8.2.1 — Güçlü parola hash + encryption at rest
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


# Admin panel içinde atanabilecek sayfa/özellik slug'ları (RBAC permission key'leri).
ADMIN_PERMISSION_KEYS: tuple[str, ...] = (
    "dashboard",
    "kurumsal-basvuru",
    "kurumsal-musteri",
    "bireysel-musteri",
    "calisanlar",
    "internal-chat",
    "admin-users",
)


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # Çalışan ile 1-1 bağ (opsiyonel — info@ gibi sistem hesapları olabilir)
    employee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("employees.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
        index=True,
        comment="Bağlı çalışan kaydı",
    )

    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="Admin girişi için e-posta (örn. user@pentorasec.com.tr)",
    )

    # Argon2id hash — login sırasında plaintext ile doğrulanır
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Argon2id password hash",
    )

    # AES-256-GCM ile şifrelenmiş plaintext parola
    # AAD = "admin_user:<id>:password"
    # Yalnızca süper admin decrypt edebilir (info@pentorasec.com.tr).
    password_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Plaintext parola AES-256-GCM ciphertext (yalnızca süper admin görür)",
    )

    display_name: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
        comment="Görünen ad (çalışan adı veya 'Süper Admin')",
    )

    is_super_admin: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        comment="Süper admin (info@pentorasec.com.tr) — tüm yetkilere sahip",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        comment="Hesap aktif mi (giriş yapabilir mi)",
    )

    # PostgreSQL ARRAY(VARCHAR) — her öğe bir permission key
    permissions: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)),
        nullable=False,
        default=list,
        server_default=text("ARRAY[]::varchar[]"),
        comment="Admin panel için yetki slug'ları",
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_by: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Hesabı oluşturan admin e-posta'sı",
    )

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
        Index("ix_admin_users_active_email", "is_active", "email"),
    )

    def __repr__(self) -> str:
        return (
            f"<AdminUser id={self.id} email={self.email!r} "
            f"super={self.is_super_admin} active={self.is_active}>"
        )

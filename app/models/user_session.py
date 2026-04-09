"""
Kullanıcı Oturum Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PII Saklama Politikası — Sıfır Plaintext:
  ┌─────────────────────────────────────────────────────────────────┐
  │ Alan          │ Saklanma biçimi                                 │
  ├─────────────────────────────────────────────────────────────────┤
  │ IP Adresi     │ SHA3-256(ip, IP_PEPPER) — geri dönüştürülemez  │
  │ User-Agent    │ SHA3-256(ua, IP_PEPPER) — parmak izi amaçlı    │
  │ GRAuth Token  │ SHA3-256(token) — iptal kontrolü için          │
  └─────────────────────────────────────────────────────────────────┘

Neden IP adresi de hashlenmelidir?
  - GDPR/KVKK kapsamında IP adresi kişisel veridir.
  - DB sızıntısında kullanıcı konumu/operatörü tespit edilemez.
  - Güvenlik analizi: aynı IP'nin farklı isteklerde aynı hash'e sahip
    olması, korelasyon analizine izin verir (plaintext olmadan).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # ── İlişki ──────────────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Oturum Kimliği (GRAuth payload'undaki sid ile eşleşir) ───────────────
    session_uuid: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        nullable=False,
        comment="GRAuth token payload içindeki oturum UUID'si",
    )

    # ── GRAuth Token Hash (iptal/doğrulama için) ─────────────────────────────
    # SHA3-256(raw_token) — token'ı geri elde etmek için kullanılamaz
    grauth_token_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        comment="SHA3-256(grauth_token) — iptal listesi kontrolü için",
    )

    # ── Zaman ────────────────────────────────────────────────────────────────
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # ── Durum ────────────────────────────────────────────────────────────────
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default=text("false"),
        index=True,
    )

    # ── PII-Free Bağlam Verileri ─────────────────────────────────────────────
    # Ham IP ve UA saklanmaz. Hash'ler korelasyon/güvenlik analizi içindir.

    # SHA3-256(client_ip, IP_PEPPER) — orijinal IP geri elde edilemez
    ip_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA3-256(client_ip || ip_pepper) — plaintext IP saklanmaz",
    )

    # SHA3-256(user_agent, IP_PEPPER) — cihaz parmak izi, PII değil ancak ihtiyatlı
    ua_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA3-256(user_agent || ip_pepper) — cihaz parmak izi",
    )

    # ── İlişki ──────────────────────────────────────────────────────────────
    user: Mapped["User"] = relationship(back_populates=None, lazy="raise")  # type: ignore[name-defined]

    __table_args__ = (
        # Süresi dolmuş + iptal edilmemiş aktif oturumlar
        Index(
            "ix_sessions_active",
            "user_id", "expires_at",
            postgresql_where=text("is_revoked = false"),
        ),
        # Token hash lookup — her auth isteğinde kullanılır, index zorunlu
        Index("ix_sessions_token_hash", "grauth_token_hash", unique=True),
    )

    def __repr__(self) -> str:
        return f"<UserSession session={self.session_uuid} revoked={self.is_revoked}>"

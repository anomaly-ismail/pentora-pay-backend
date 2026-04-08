"""
Kullanıcı Bildirimleri Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Her ortamda (dev/prod) uygulama başlarken CREATE TABLE IF NOT EXISTS çalışır.
Tablo varsa hiçbir şeye dokunulmaz — idempotent, güvenli, migration gerektirmez.

Güvenlik (OWASP A01 / KVKK):
  - user_id → UUID, users.id ile ilişki ama dışa plaintext kullanıcı bilgisi açılmaz.
  - body alanı inceleme notunu içerebilir; PII içermemesi servis katmanının sorumluluğu.
  - related_id: hangi başvuruyla ilgili olduğunu taşır (UUID string).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class NotificationType(StrEnum):
    CORPORATE_APPROVED  = "corporate_approved"
    CORPORATE_REJECTED  = "corporate_rejected"
    CORPORATE_REVIEWING = "corporate_reviewing"
    SYSTEM              = "system"


class Notification(Base):
    __tablename__ = "user_notifications"

    # ── Birincil Anahtar ─────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # ── Hedef Kullanıcı ──────────────────────────────────────────────────────
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Bildirimi alacak kullanıcının UUID'si",
    )

    # ── Bildirim İçeriği ─────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Bildirim başlığı",
    )

    body: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Bildirim gövdesi — PII içermemeli",
    )

    notification_type: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        index=True,
        comment="NotificationType enum değeri",
    )

    # ── İlgili Kayıt (opsiyonel) ─────────────────────────────────────────────
    related_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
        comment="İlgili başvuru/işlem UUID'si (string)",
    )

    # ── Okundu Durumu ────────────────────────────────────────────────────────
    is_read: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    # ── Zaman Damgaları ───────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        # Kullanıcının okunmamış bildirimlerini hızlı sorgula
        Index(
            "ix_notif_user_unread",
            "user_id",
            "is_read",
            "created_at",
        ),
    )

    def __repr__(self) -> str:
        return f"<Notification id={self.id} user={self.user_id} type={self.notification_type} read={self.is_read}>"

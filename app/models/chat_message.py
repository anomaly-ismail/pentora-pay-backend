"""
ChatMessage Modeli — Admin panel iç yazışma kanalı.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Admin kullanıcıları arasında iç iletişim için tek kanallı (global) sohbet.
Her mesaj gönderenin AdminUser id'si ile ilişkilendirilir.

Güvenlik:
  • Yetkilendirme endpoint katmanında `internal-chat` permission'ı ile yapılır
  • Mesajlar plaintext tutulur (uygulama içi notlar) — PII tutulması önerilmez
  • content_length ≤ 4000 — DoS + abuse koruması
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ChatMessage(Base):
    __tablename__ = "admin_chat_messages"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # Gönderen admin kullanıcı (silinse bile mesaj kalır — denormalize name)
    sender_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    sender_email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Gönderen e-posta (denormalize — admin silinse bile görünür)",
    )

    sender_name: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
        comment="Gönderen görünen ad (denormalize)",
    )

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Mesaj içeriği (en fazla 4000 karakter)",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_chat_messages_created_desc", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ChatMessage id={self.id} from={self.sender_email!r} "
            f"at={self.created_at.isoformat()}>"
        )

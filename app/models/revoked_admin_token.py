"""
Revoked Admin Token modeli (H-2)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Admin SSO JWT'leri için kalıcı blacklist.

Eski mimaride blacklist sadece process belleğinde tutuluyordu; bu da:
  • Birden fazla worker/replica arasında tutarsız iptal,
  • Gunicorn yeniden başlatılınca iptal edilmiş tokenların tekrar geçerli olması,
  • Yatay ölçek (Kubernetes pod) durumunda tamamen kullanışsızlık
yaratıyordu (PCI-DSS Req.8.2.6 ve ISO 27001 A.9.4.5 ile çelişir).

Bu tablo `jti` (JWT ID) bazlı revocation kayıtları tutar.
Token doğal süresi (`exp`) dolduğunda kayıt da temizlenir (cleanup task).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RevokedAdminToken(Base):
    __tablename__ = "revoked_admin_tokens"

    # JWT'nin `jti` (JWT ID) claim'i (UUID/cuid).  Birincil anahtar.
    jti: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        nullable=False,
    )

    # Hangi admin (sub claim) — denetim izi.  PII içermez (mail/login adı yok).
    revoked_by: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    # Revoke anı (UTC).
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Token'ın orijinal doğal expiry'si.  Cleanup job bu zamandan sonra siler.
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    __table_args__ = (
        # Cleanup job için süresi geçmiş kayıtları hızlı sil.
        Index("ix_revoked_admin_tokens_expires_at", "expires_at"),
    )

    def __repr__(self) -> str:
        return f"<RevokedAdminToken jti={self.jti[:8]}… exp={self.expires_at.isoformat()}>"

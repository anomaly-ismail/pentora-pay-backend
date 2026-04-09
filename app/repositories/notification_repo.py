"""
Bildirim Repository
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Güvenlik (OWASP A01 Broken Access Control):
  - Her sorgu user_id ile filtrelenir — bir kullanıcı başkasının bildirimini göremez.
  - Tüm sorgular ORM üzerinden → SQL injection imkansız (OWASP A03).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.notification import Notification, NotificationType


class NotificationRepo:

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── Bildirim Oluştur ─────────────────────────────────────────────────────
    async def create(
        self,
        *,
        user_id:           uuid.UUID,
        title:             str,
        body:              str,
        notification_type: NotificationType,
        related_id:        Optional[str] = None,
    ) -> Notification:
        notif = Notification(
            user_id=user_id,
            title=title,
            body=body,
            notification_type=notification_type,
            related_id=related_id,
            is_read=False,
        )
        self._session.add(notif)
        await self._session.flush()
        await self._session.refresh(notif)
        return notif

    # ── Kullanıcının Bildirimlerini Getir ────────────────────────────────────
    async def get_for_user(
        self,
        user_id: uuid.UUID,
        *,
        limit:  int = 50,
        offset: int = 0,
    ) -> tuple[int, int, list[Notification]]:
        """(total, unread_count, notifications)
        
        total ve unread_count tek sorguda FILTER ile hesaplanır.
        """
        # Tek sorguda total + unread_count — iki ayrı COUNT yerine
        stmt_counts = select(
            func.count().label("total"),
            func.count().filter(Notification.is_read.is_(False)).label("unread"),
        ).where(Notification.user_id == user_id)
        counts = (await self._session.execute(stmt_counts)).one()
        total = counts.total
        unread_count = counts.unread

        rows = (await self._session.execute(
            select(Notification)
            .where(Notification.user_id == user_id)
            .order_by(Notification.created_at.desc())
            .limit(limit)
            .offset(offset)
        )).scalars().all()

        return total, unread_count, list(rows)

    # ── Tek Bildirimi Okundu Yap ────────────────────────────────────────────
    async def mark_read(
        self,
        notif_id: uuid.UUID,
        user_id:  uuid.UUID,
    ) -> Optional[Notification]:
        """Kullanıcı kendi bildirimini okundu işaretler (A01: ownership check)."""
        result = await self._session.execute(
            select(Notification).where(
                Notification.id == notif_id,
                Notification.user_id == user_id,
            )
        )
        notif = result.scalar_one_or_none()
        if notif and not notif.is_read:
            notif.is_read = True
            notif.read_at = datetime.now(timezone.utc)
            await self._session.flush()
        return notif

    # ── Tümünü Okundu Yap ───────────────────────────────────────────────────
    async def mark_all_read(self, user_id: uuid.UUID) -> int:
        """Kullanıcının tüm okunmamış bildirimlerini okundu yap. Etkilenen satır sayısını döner."""
        result = await self._session.execute(
            update(Notification)
            .where(
                Notification.user_id == user_id,
                Notification.is_read == False,   # noqa: E712
            )
            .values(is_read=True, read_at=datetime.now(timezone.utc))
        )
        await self._session.flush()
        return result.rowcount

"""
Bildirim Pydantic Şemaları
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class NotificationResponse(BaseModel):
    """Flutter'a dönen tek bildirim."""
    model_config = {"from_attributes": True}

    id:                uuid.UUID
    title:             str
    body:              str
    notification_type: str
    related_id:        Optional[str]
    is_read:           bool
    created_at:        datetime
    read_at:           Optional[datetime]


class NotificationListResponse(BaseModel):
    """Sayfalanmış bildirim listesi."""
    total:         int
    unread_count:  int
    notifications: list[NotificationResponse]


class NotificationMarkReadRequest(BaseModel):
    """Toplu okundu işaretleme isteği (opsiyonel liste)."""
    ids: Optional[list[uuid.UUID]] = None  # None ise tümü

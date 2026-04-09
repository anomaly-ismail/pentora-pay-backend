from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, UserDTO
from app.db.dependencies import get_db
from app.repositories.notification_repo import NotificationRepo
from app.repositories.user_device_repo import UserDeviceRepo
from app.schemas.notification import (
    DeviceTokenRegisterRequest,
    NotificationListResponse,
    NotificationResponse,
)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=NotificationListResponse, summary="Bildirimleri listele")
async def list_notifications(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: UserDTO = Depends(get_current_user),
) -> NotificationListResponse:
    repo = NotificationRepo(db)
    total, unread_count, rows = await repo.get_for_user(
        user_id=user.id,
        limit=min(max(limit, 1), 100),
        offset=max(offset, 0),
    )
    return NotificationListResponse(
        total=total,
        unread_count=unread_count,
        notifications=[NotificationResponse.model_validate(r) for r in rows],
    )


@router.patch("/{notification_id}/read", response_model=NotificationResponse, summary="Bildirimi okundu yap")
async def mark_notification_read(
    notification_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: UserDTO = Depends(get_current_user),
) -> NotificationResponse:
    repo = NotificationRepo(db)
    notif = await repo.mark_read(notification_id, user.id)
    if not notif:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bildirim bulunamadı")
    await db.commit()
    return NotificationResponse.model_validate(notif)


@router.patch("/read-all", summary="Tum bildirimleri okundu yap")
async def mark_all_notifications_read(
    db: AsyncSession = Depends(get_db),
    user: UserDTO = Depends(get_current_user),
) -> dict:
    repo = NotificationRepo(db)
    count = await repo.mark_all_read(user.id)
    await db.commit()
    return {"updated": int(count or 0)}


@router.post("/device-token", summary="Push cihaz token kaydı")
async def register_device_token(
    body: DeviceTokenRegisterRequest,
    db: AsyncSession = Depends(get_db),
    user: UserDTO = Depends(get_current_user),
) -> dict:
    token = body.token.strip()
    if len(token) < 20:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Gecersiz cihaz tokeni")
    platform = (body.platform or "android").strip().lower()
    if platform not in {"android", "ios", "web"}:
        platform = "android"

    repo = UserDeviceRepo(db)
    await repo.upsert_token(user_id=user.id, platform=platform, token=token)
    await db.commit()
    return {"ok": True}

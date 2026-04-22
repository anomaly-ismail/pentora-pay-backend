"""
Admin İç Yazışma API
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GET  /admin/chat/messages  — son N mesajı getir (sıralı, artan)
POST /admin/chat/messages  — yeni mesaj gönder

Yetki: Admin JWT zorunlu + `internal-chat` permission'ı (süper admin her zaman).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import get_db
from app.schemas.chat import (
    ChatMessageCreate,
    ChatMessageListResponse,
    ChatMessageResponse,
)
from app.services import chat_service as svc

router = APIRouter(prefix="/admin/chat", tags=["Admin · Internal Chat"])


async def require_admin_jwt(
    authorization: Optional[str] = Header(None),
    admin_token: Optional[str] = Cookie(None),
) -> dict:
    from app.services.admin_service import verify_admin_token

    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    elif admin_token:
        token = admin_token
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Yetkilendirme token'ı gereklidir",
        )
    return await verify_admin_token(token)


def _has_chat_permission(admin: dict) -> bool:
    if admin.get("is_super_admin") is True:
        return True
    perms = admin.get("permissions") or []
    if isinstance(perms, list):
        return "*" in perms or "internal-chat" in perms
    return False


def require_chat_access(admin: dict = Depends(require_admin_jwt)) -> dict:
    if not _has_chat_permission(admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="İç yazışma yetkiniz bulunmuyor.",
        )
    return admin


@router.get(
    "/messages",
    response_model=ChatMessageListResponse,
    summary="Son mesajlar",
)
async def list_messages_endpoint(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_chat_access),
) -> ChatMessageListResponse:
    return await svc.list_messages(session=db, limit=limit)


@router.post(
    "/messages",
    response_model=ChatMessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Yeni mesaj gönder",
)
async def send_message_endpoint(
    payload: ChatMessageCreate,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_chat_access),
) -> ChatMessageResponse:
    sender_email = admin.get("sub") or "unknown"
    sender_admin_id: Optional[uuid.UUID] = None
    raw_id = admin.get("admin_user_id")
    if raw_id:
        try:
            sender_admin_id = uuid.UUID(str(raw_id))
        except Exception:
            sender_admin_id = None
    return await svc.send_message(
        session=db,
        data=payload,
        sender_email=sender_email,
        sender_name=None,
        sender_admin_id=sender_admin_id,
    )

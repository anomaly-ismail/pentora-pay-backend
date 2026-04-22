"""
Admin iç sohbet servis katmanı.
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.chat_message import ChatMessage
from app.repositories.chat_repo import ChatRepo
from app.schemas.chat import (
    ChatMessageCreate,
    ChatMessageListResponse,
    ChatMessageResponse,
)

logger = get_logger(__name__)


def _to_response(msg: ChatMessage) -> ChatMessageResponse:
    return ChatMessageResponse(
        id=str(msg.id),
        sender_id=str(msg.sender_id) if msg.sender_id else None,
        sender_email=msg.sender_email,
        sender_name=msg.sender_name,
        content=msg.content,
        created_at=msg.created_at,
    )


async def list_messages(
    *, session: AsyncSession, limit: int = 100
) -> ChatMessageListResponse:
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    repo = ChatRepo(session)
    total, rows = await repo.list_recent(limit=limit)
    return ChatMessageListResponse(
        messages=[_to_response(r) for r in rows], total=total
    )


async def send_message(
    *,
    session: AsyncSession,
    data: ChatMessageCreate,
    sender_email: str,
    sender_name: Optional[str] = None,
    sender_admin_id: Optional[uuid.UUID] = None,
) -> ChatMessageResponse:
    content = (data.content or "").strip()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Mesaj boş olamaz."
        )
    if len(content) > 4000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mesaj 4000 karakteri aşamaz.",
        )

    msg = ChatMessage(
        sender_id=sender_admin_id,
        sender_email=sender_email,
        sender_name=sender_name,
        content=content,
    )
    repo = ChatRepo(session)
    await repo.add(msg)
    await session.commit()
    await session.refresh(msg)
    logger.info(
        "admin_chat.message_sent",
        sender=sender_email,
        size=len(content),
    )
    return _to_response(msg)

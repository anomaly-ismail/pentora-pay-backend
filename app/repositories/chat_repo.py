"""
Admin ChatMessage Repository — async CRUD.
"""
from __future__ import annotations

from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.chat_message import ChatMessage


class ChatRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, msg: ChatMessage) -> ChatMessage:
        self._session.add(msg)
        await self._session.flush()
        await self._session.refresh(msg)
        return msg

    async def list_recent(
        self, *, limit: int = 100
    ) -> tuple[int, Sequence[ChatMessage]]:
        total = (
            await self._session.execute(select(func.count()).select_from(ChatMessage))
        ).scalar_one()
        rows = (
            await self._session.execute(
                select(ChatMessage)
                .order_by(ChatMessage.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()
        # Yeni mesajlar sonda görünsün diye tersine çevir
        rows = list(reversed(rows))
        return total, rows

from __future__ import annotations

import hashlib
import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user_device import UserDevice


class UserDeviceRepo:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def upsert_token(self, *, user_id: uuid.UUID, platform: str, token: str) -> UserDevice:
        token_hash = self._hash_token(token)
        existing = (await self._db.execute(
            select(UserDevice).where(
                UserDevice.user_id == user_id,
                UserDevice.token_hash == token_hash,
            ).limit(1)
        )).scalars().first()

        if existing:
            existing.platform = platform
            existing.push_token = token
            existing.is_active = True
            await self._db.flush()
            await self._db.refresh(existing)
            return existing

        row = UserDevice(
            user_id=user_id,
            platform=platform,
            push_token=token,
            token_hash=token_hash,
            is_active=True,
        )
        self._db.add(row)
        await self._db.flush()
        await self._db.refresh(row)
        return row

    async def list_active_tokens(self, *, user_id: uuid.UUID) -> list[str]:
        rows: Sequence[UserDevice] = (await self._db.execute(
            select(UserDevice).where(
                UserDevice.user_id == user_id,
                UserDevice.is_active == True,  # noqa: E712
            )
        )).scalars().all()
        return [r.push_token for r in rows if r.push_token]

    async def deactivate_token(self, token: str) -> None:
        token_hash = self._hash_token(token)
        rows: Sequence[UserDevice] = (await self._db.execute(
            select(UserDevice).where(UserDevice.token_hash == token_hash)
        )).scalars().all()
        for r in rows:
            r.is_active = False
        await self._db.flush()

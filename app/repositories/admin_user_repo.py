"""
AdminUser Repository — async CRUD (SQLAlchemy ORM).
"""
from __future__ import annotations

import uuid
from typing import Optional, Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.admin_user import AdminUser


class AdminUserRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, admin_id: uuid.UUID) -> Optional[AdminUser]:
        return await self._session.get(AdminUser, admin_id)

    async def get_by_email(self, email: str) -> Optional[AdminUser]:
        stmt = select(AdminUser).where(func.lower(AdminUser.email) == email.lower())
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_employee_id(
        self, employee_id: uuid.UUID
    ) -> Optional[AdminUser]:
        stmt = select(AdminUser).where(AdminUser.employee_id == employee_id)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_all(
        self, *, limit: int = 200, offset: int = 0
    ) -> tuple[int, Sequence[AdminUser]]:
        total = (
            await self._session.execute(select(func.count()).select_from(AdminUser))
        ).scalar_one()
        rows = (
            await self._session.execute(
                select(AdminUser)
                .order_by(AdminUser.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars().all()
        return total, rows

    async def add(self, admin: AdminUser) -> AdminUser:
        self._session.add(admin)
        await self._session.flush()
        await self._session.refresh(admin)
        return admin

    async def delete(self, admin: AdminUser) -> None:
        await self._session.delete(admin)
        await self._session.flush()

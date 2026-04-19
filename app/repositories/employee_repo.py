"""
Çalışan Repository — async CRUD + arama
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Tüm sorgular SQLAlchemy ORM üzerinden — sıfır ham SQL, sıfır enjeksiyon.
TCKN tekrar engelleme HMAC indeks üzerinden yapılır (plaintext değil).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from typing import Optional, Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.employee import Employee


class EmployeeRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, employee_id: uuid.UUID) -> Optional[Employee]:
        return await self._session.get(Employee, employee_id)

    async def get_by_tckn_hash(self, tckn_hash: str) -> Optional[Employee]:
        stmt = select(Employee).where(Employee.tckn_hash == tckn_hash)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_employee_no(self, employee_no: str) -> Optional[Employee]:
        stmt = select(Employee).where(Employee.employee_no == employee_no)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list(
        self,
        *,
        status_filter: Optional[str] = None,
        department_filter: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, Sequence[Employee]]:
        """
        Filtre + arama + sayfalama. `search` full_name / employee_no / email
        üzerinde ILIKE araması yapar (TCKN/IBAN aramaz — şifreli).
        """
        base = select(Employee)
        count_base = select(func.count()).select_from(Employee)

        if status_filter:
            base = base.where(Employee.status == status_filter)
            count_base = count_base.where(Employee.status == status_filter)
        if department_filter:
            base = base.where(Employee.department == department_filter)
            count_base = count_base.where(Employee.department == department_filter)
        if search:
            pattern = f"%{search.strip()}%"
            cond = or_(
                Employee.full_name.ilike(pattern),
                Employee.employee_no.ilike(pattern),
                Employee.email.ilike(pattern),
            )
            base = base.where(cond)
            count_base = count_base.where(cond)

        total = (await self._session.execute(count_base)).scalar_one()
        rows = (
            await self._session.execute(
                base.order_by(Employee.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).scalars().all()
        return total, rows

    async def next_employee_no(self) -> str:
        """
        EMP-YYYY-#### formatında sıralı çalışan numarası üretir.
        Çakışma olursa servis katmanı yeniden dener.
        """
        from datetime import datetime, timezone

        year = datetime.now(timezone.utc).year
        prefix = f"EMP-{year}-"
        like_pat = prefix + "%"
        stmt = (
            select(func.count())
            .select_from(Employee)
            .where(Employee.employee_no.like(like_pat))
        )
        count = (await self._session.execute(stmt)).scalar_one()
        return f"{prefix}{count + 1:04d}"

    async def add(self, employee: Employee) -> Employee:
        self._session.add(employee)
        await self._session.flush()
        await self._session.refresh(employee)
        return employee

    async def delete(self, employee: Employee) -> None:
        await self._session.delete(employee)
        await self._session.flush()

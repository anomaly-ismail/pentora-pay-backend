"""
Kurumsal Başvuru Repository
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.corporate_application import ApplicationStatus, CorporateApplication


class CorporateApplicationRepo:

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        user_id:        Optional[uuid.UUID] = None,
        company_name:   str,
        tax_number:     str,
        tax_office:     str,
        mersis_no:      Optional[str],
        address:        str,
        applicant_name: str,
        applicant_tckn: Optional[str],
        phone:          str,
        vergi_levhasi_path:  Optional[str] = None,
        imza_sirkuleri_path: Optional[str] = None,
        ticaret_sicil_path:  Optional[str] = None,
    ) -> CorporateApplication:
        app = CorporateApplication(
            user_id=user_id,
            company_name=company_name,
            tax_number=tax_number,
            tax_office=tax_office,
            mersis_no=mersis_no,
            address=address,
            applicant_name=applicant_name,
            applicant_tckn=applicant_tckn,
            phone=phone,
            vergi_levhasi_path=vergi_levhasi_path,
            imza_sirkuleri_path=imza_sirkuleri_path,
            ticaret_sicil_path=ticaret_sicil_path,
            status=ApplicationStatus.PENDING,
        )
        self._session.add(app)
        await self._session.flush()
        await self._session.refresh(app)
        return app

    async def get_all(
        self,
        *,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[CorporateApplication]]:
        stmt = select(CorporateApplication)
        count_stmt = select(func.count()).select_from(CorporateApplication)

        if status:
            stmt = stmt.where(CorporateApplication.status == status)
            count_stmt = count_stmt.where(CorporateApplication.status == status)

        stmt = stmt.order_by(CorporateApplication.submitted_at.desc()).limit(limit).offset(offset)

        total = (await self._session.execute(count_stmt)).scalar_one()
        result = (await self._session.execute(stmt)).scalars().all()
        return total, list(result)

    async def get_by_id(self, app_id: uuid.UUID) -> Optional[CorporateApplication]:
        result = await self._session.execute(
            select(CorporateApplication).where(CorporateApplication.id == app_id)
        )
        return result.scalar_one_or_none()

    async def update_status(
        self,
        app_id: uuid.UUID,
        status: str,
        reviewer_note: Optional[str] = None,
    ) -> Optional[CorporateApplication]:
        app = await self.get_by_id(app_id)
        if not app:
            return None
        app.status = status
        app.reviewed_at = datetime.now(timezone.utc)
        if reviewer_note is not None:
            app.reviewer_note = reviewer_note
        await self._session.flush()
        await self._session.refresh(app)
        return app

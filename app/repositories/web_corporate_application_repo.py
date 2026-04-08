from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.web_corporate_application import WebCorporateApplication


class WebCorporateApplicationRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        first_name: str,
        last_name: str,
        city: str,
        phone: str,
        kvkk_approved: bool,
    ) -> WebCorporateApplication:
        application = WebCorporateApplication(
            first_name=first_name,
            last_name=last_name,
            city=city,
            phone=phone,
            kvkk_approved=kvkk_approved,
        )
        self._session.add(application)
        await self._session.flush()
        await self._session.refresh(application)
        return application

    async def list_all(self, *, limit: int = 100, offset: int = 0) -> tuple[int, list[WebCorporateApplication]]:
        count_stmt = select(func.count()).select_from(WebCorporateApplication)
        data_stmt = (
            select(WebCorporateApplication)
            .order_by(WebCorporateApplication.submitted_at.desc())
            .limit(limit)
            .offset(offset)
        )
        total = (await self._session.execute(count_stmt)).scalar_one()
        rows = (await self._session.execute(data_stmt)).scalars().all()
        return total, list(rows)

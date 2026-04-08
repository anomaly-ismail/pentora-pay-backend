from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.web_corporate_application_repo import WebCorporateApplicationRepo
from app.schemas.web_corporate_application import (
    WebCorporateApplicationCreate,
    WebCorporateApplicationListResponse,
    WebCorporateApplicationResponse,
)


async def submit_web_application(
    *,
    session: AsyncSession,
    payload: WebCorporateApplicationCreate,
) -> WebCorporateApplicationResponse:
    if not payload.kvkk_approved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="KVKK onayı zorunludur.",
        )
    repo = WebCorporateApplicationRepo(session)
    item = await repo.create(
        first_name=payload.first_name,
        last_name=payload.last_name,
        city=payload.city,
        phone=payload.phone,
        kvkk_approved=payload.kvkk_approved,
    )
    await session.commit()
    return WebCorporateApplicationResponse.model_validate(item)


async def list_web_applications(
    *,
    session: AsyncSession,
    limit: int = 100,
    offset: int = 0,
) -> WebCorporateApplicationListResponse:
    repo = WebCorporateApplicationRepo(session)
    total, items = await repo.list_all(limit=limit, offset=offset)
    return WebCorporateApplicationListResponse(
        total=total,
        applications=[WebCorporateApplicationResponse.model_validate(x) for x in items],
    )

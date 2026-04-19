"""
Çalışan Yönetimi Admin API Endpoint'leri
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Tüm endpointler admin JWT (httpOnly cookie veya Bearer header) zorunludur.
PII alanları (TCKN/IBAN/maaş) yalnızca admin context'inde decrypt edilir;
audit log her CRUD işleminde tutulur.

GET    /api/v1/admin/employees                     → Liste (sayfalı + filtre + arama)
POST   /api/v1/admin/employees                     → Yeni çalışan ekle
GET    /api/v1/admin/employees/{id}                → Detay (decrypt PII dahil)
PATCH  /api/v1/admin/employees/{id}                → Kısmi güncelle
DELETE /api/v1/admin/employees/{id}                → Sil
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import get_db
from app.schemas.employee import (
    EmployeeCreate,
    EmployeeListResponse,
    EmployeeResponse,
    EmployeeUpdate,
)
from app.services import employee_service as svc

router = APIRouter(prefix="/admin/employees", tags=["Admin · Employees"])


# ─── Admin JWT Doğrulama ─────────────────────────────────────────────────────
# (corporate.py içindeki ile aynı mantık — bağımlılık döngüsü olmasın diye burada
#  tekrarlanır; tek doğruluk noktası verify_admin_token servisidir.)
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


def _actor_email(payload: dict) -> Optional[str]:
    return (payload or {}).get("sub") if isinstance(payload, dict) else None


# ─── List ────────────────────────────────────────────────────────────────────
@router.get(
    "",
    response_model=EmployeeListResponse,
    summary="Çalışan listesi",
    description="Filtre, arama ve sayfalama ile çalışan listesi. PII bu uçta decrypt edilmez.",
)
async def list_employees_endpoint(
    status_filter: Optional[str] = Query(None, alias="status"),
    department: Optional[str] = Query(None),
    q: Optional[str] = Query(None, max_length=120, description="Ad/no/email arama"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_admin_jwt),
) -> EmployeeListResponse:
    return await svc.list_employees(
        session=db,
        status_filter=status_filter,
        department_filter=department,
        search=q,
        limit=limit,
        offset=offset,
    )


# ─── Create ──────────────────────────────────────────────────────────────────
@router.post(
    "",
    response_model=EmployeeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Yeni çalışan ekle",
)
async def create_employee_endpoint(
    payload: EmployeeCreate,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_admin_jwt),
) -> EmployeeResponse:
    return await svc.create_employee(
        session=db, data=payload, actor_email=_actor_email(admin)
    )


# ─── Detail ──────────────────────────────────────────────────────────────────
@router.get(
    "/{employee_id}",
    response_model=EmployeeResponse,
    summary="Çalışan detayı (PII dahil)",
)
async def get_employee_endpoint(
    employee_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_admin_jwt),
) -> EmployeeResponse:
    return await svc.get_employee(session=db, employee_id=employee_id)


# ─── Update ──────────────────────────────────────────────────────────────────
@router.patch(
    "/{employee_id}",
    response_model=EmployeeResponse,
    summary="Çalışan bilgilerini güncelle",
)
async def update_employee_endpoint(
    employee_id: uuid.UUID,
    payload: EmployeeUpdate,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_admin_jwt),
) -> EmployeeResponse:
    return await svc.update_employee(
        session=db,
        employee_id=employee_id,
        data=payload,
        actor_email=_actor_email(admin),
    )


# ─── Delete ──────────────────────────────────────────────────────────────────
@router.delete(
    "/{employee_id}",
    summary="Çalışan kaydını sil",
)
async def delete_employee_endpoint(
    employee_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_admin_jwt),
) -> dict:
    return await svc.delete_employee(
        session=db,
        employee_id=employee_id,
        actor_email=_actor_email(admin),
    )

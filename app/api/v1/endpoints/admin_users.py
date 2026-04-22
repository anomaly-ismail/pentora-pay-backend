"""
Admin Kullanıcıları (RBAC) API
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tüm uçlar admin JWT ile korunur.  Plaintext parolalar yalnızca süper admin
(info@pentorasec.com.tr veya JWT claim `is_super_admin=True`) için döner.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import get_db
from app.models.admin_user import ADMIN_PERMISSION_KEYS
from app.schemas.admin_user import (
    AdminUserCreate,
    AdminUserListResponse,
    AdminUserMeResponse,
    AdminUserResponse,
    AdminUserUpdate,
)
from app.services import admin_user_service as svc

router = APIRouter(prefix="/admin/users", tags=["Admin · Users (RBAC)"])


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


def _is_super(admin: dict) -> bool:
    """JWT payload'ına bakarak süper admin mi kontrol eder."""
    if not admin:
        return False
    if admin.get("is_super_admin") is True:
        return True
    sub = (admin.get("sub") or "").lower()
    return svc.is_super_admin_email(sub)


def require_super_admin(admin: dict = Depends(require_admin_jwt)) -> dict:
    if not _is_super(admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlem için süper admin yetkisi gereklidir.",
        )
    return admin


# ─── Mevcut kullanıcı (UI permission filter için) ────────────────────────────
@router.get(
    "/me",
    response_model=AdminUserMeResponse,
    summary="Oturum açmış admin bilgisi",
)
async def get_me(admin: dict = Depends(require_admin_jwt)) -> AdminUserMeResponse:
    email = admin.get("sub") or ""
    is_super = _is_super(admin)
    perms_raw = admin.get("permissions") or []
    # Süper admin için "*" işareti kullanıyoruz → UI tüm sayfaları açabilir.
    if is_super or (isinstance(perms_raw, list) and "*" in perms_raw):
        perms = list(ADMIN_PERMISSION_KEYS)
    else:
        perms = [p for p in perms_raw if isinstance(p, str)]
    return AdminUserMeResponse(
        id=admin.get("admin_user_id"),
        email=email,
        display_name=None,
        is_super_admin=is_super,
        permissions=perms,
    )


@router.get(
    "/permissions/keys",
    summary="Atanabilir yetki slug listesi",
)
async def list_permission_keys(_: dict = Depends(require_admin_jwt)) -> dict:
    return {"permissions": list(ADMIN_PERMISSION_KEYS)}


# ─── Liste ───────────────────────────────────────────────────────────────────
@router.get(
    "",
    response_model=AdminUserListResponse,
    summary="Admin kullanıcı listesi",
    description=(
        "Süper admin için plaintext parolalar dahil döner, diğerleri için hariç."
    ),
)
async def list_admin_users_endpoint(
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_admin_jwt),
) -> AdminUserListResponse:
    reveal = _is_super(admin)
    return await svc.list_admin_users(session=db, reveal_passwords=reveal)


# ─── Oluştur (yalnızca süper admin) ─────────────────────────────────────────
@router.post(
    "",
    response_model=AdminUserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Yeni admin kullanıcı oluştur (süper admin)",
)
async def create_admin_user_endpoint(
    payload: AdminUserCreate,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_super_admin),
) -> AdminUserResponse:
    return await svc.create_admin_user(
        session=db, data=payload, actor_email=admin.get("sub")
    )


# ─── Detay ───────────────────────────────────────────────────────────────────
@router.get(
    "/{admin_id}",
    response_model=AdminUserResponse,
    summary="Admin kullanıcı detayı",
)
async def get_admin_user_endpoint(
    admin_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_admin_jwt),
) -> AdminUserResponse:
    return await svc.get_admin_user(
        session=db, admin_id=admin_id, reveal_password=_is_super(admin)
    )


# ─── Güncelle (süper admin) ─────────────────────────────────────────────────
@router.patch(
    "/{admin_id}",
    response_model=AdminUserResponse,
    summary="Admin kullanıcı güncelle (süper admin)",
)
async def update_admin_user_endpoint(
    admin_id: uuid.UUID,
    payload: AdminUserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_super_admin),
) -> AdminUserResponse:
    return await svc.update_admin_user(
        session=db,
        admin_id=admin_id,
        data=payload,
        actor_email=admin.get("sub"),
    )


# ─── Parolayı sıfırla (süper admin) ─────────────────────────────────────────
@router.post(
    "/{admin_id}/reset-password",
    response_model=AdminUserResponse,
    summary="Admin parolasını yenile (süper admin)",
)
async def reset_admin_password_endpoint(
    admin_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_super_admin),
) -> AdminUserResponse:
    return await svc.reset_admin_password(
        session=db, admin_id=admin_id, actor_email=admin.get("sub")
    )


# ─── Sil (süper admin) ───────────────────────────────────────────────────────
@router.delete(
    "/{admin_id}",
    summary="Admin kullanıcıyı sil (süper admin)",
)
async def delete_admin_user_endpoint(
    admin_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_super_admin),
) -> dict:
    return await svc.delete_admin_user(
        session=db, admin_id=admin_id, actor_email=admin.get("sub")
    )

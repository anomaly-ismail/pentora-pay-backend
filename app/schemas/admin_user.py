"""
AdminUser Pydantic şemaları — RBAC API kontratı.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.admin_user import ADMIN_PERMISSION_KEYS


def _normalize_permissions(values: Optional[list[str]]) -> list[str]:
    if not values:
        return []
    allowed = set(ADMIN_PERMISSION_KEYS)
    out: list[str] = []
    for v in values:
        v = (v or "").strip().lower()
        if v and v in allowed and v not in out:
            out.append(v)
    return out


class AdminUserCreate(BaseModel):
    """
    Süper admin tarafından yeni admin hesabı oluşturma.
    - employee_id verilirse o çalışana bağlanır (genellikle is_admin=True akışı)
    - permissions verilmezse boş (`[]`) kabul edilir
    """
    email: EmailStr
    display_name: Optional[str] = Field(None, max_length=150)
    employee_id: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    is_super_admin: bool = False

    @field_validator("permissions")
    @classmethod
    def _perm(cls, v: Optional[list[str]]) -> list[str]:
        return _normalize_permissions(v)


class AdminUserUpdate(BaseModel):
    """Süper admin tarafından güncelleme — tüm alanlar opsiyonel."""
    display_name: Optional[str] = Field(None, max_length=150)
    permissions: Optional[list[str]] = None
    is_active: Optional[bool] = None

    @field_validator("permissions")
    @classmethod
    def _perm(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return None
        return _normalize_permissions(v)


class AdminUserResponse(BaseModel):
    """
    Admin kullanıcı detayı.
    `password_plain` yalnızca süper admin (info@) tarafından istendiğinde döner;
    diğer kullanıcılar için `None` olarak gelir.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: Optional[str] = None
    employee_id: Optional[str] = None
    is_super_admin: bool
    is_active: bool
    permissions: list[str] = Field(default_factory=list)
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    password_plain: Optional[str] = Field(
        None,
        description="Yalnızca süper admin için döner; plaintext admin parolası.",
    )


class AdminUserListResponse(BaseModel):
    users: list[AdminUserResponse]
    total: int


class AdminUserMeResponse(BaseModel):
    """Oturum açmış admin'in kendi bilgisi — UI permission filtresi için."""
    id: Optional[str] = None
    email: str
    display_name: Optional[str] = None
    is_super_admin: bool
    permissions: list[str] = Field(default_factory=list)


class AdminUserResetPasswordResponse(BaseModel):
    """Süper admin tarafından parola yenileme sonrası dönüş."""
    id: str
    email: str
    password_plain: str

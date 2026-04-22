"""
AdminUser Servis Katmanı — RBAC yönetimi.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Kapsam:
  • Admin hesabı oluşturma (rastgele güçlü parola + @pentorasec.com.tr e-posta)
  • Süper admin (info@pentorasec.com.tr) plaintext parolayı görebilir; AES-GCM
    ile şifreli saklanır.
  • Çalışanlar kısmındaki "Admin Erişimi" toggle bu servis üzerinden yürütülür.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import re
import secrets
import string
import uuid
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.encryption import build_aad, decrypt_blob, encrypt_blob
from app.core.logging import get_logger
from app.models.admin_user import AdminUser
from app.repositories.admin_user_repo import AdminUserRepo
from app.schemas.admin_user import (
    AdminUserCreate,
    AdminUserListResponse,
    AdminUserResponse,
    AdminUserUpdate,
)

logger = get_logger(__name__)

ADMIN_EMAIL_DOMAIN = "pentorasec.com.tr"

_ph = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=4)

# Timing-attack koruma için önceden hesaplanmış "dummy" Argon2 hash.
# Gerçek hash yoksa da aynı süreyi harcamak için kullanılır.
_DUMMY_HASH: Optional[str] = None


def _get_dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = _ph.hash("__timing_dummy__")
    return _DUMMY_HASH


# ─── Yardımcılar ─────────────────────────────────────────────────────────────
def _aad(admin_id: uuid.UUID | str) -> bytes:
    return build_aad("admin_user", str(admin_id), "password")


def _encrypt_password(admin_id: uuid.UUID | str, plaintext: str) -> bytes:
    return encrypt_blob(plaintext.encode("utf-8"), aad=_aad(admin_id))


def _decrypt_password(admin: AdminUser) -> Optional[str]:
    if not admin.password_encrypted:
        return None
    try:
        return decrypt_blob(admin.password_encrypted, aad=_aad(admin.id)).decode(
            "utf-8"
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "admin_user.decrypt_password_failed",
            admin_id=str(admin.id),
            error=str(exc),
        )
        return None


def generate_password(length: int = 16) -> str:
    """Güçlü rastgele parola: 4 sınıf (büyük/küçük/rakam/özel)."""
    if length < 12:
        length = 12
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}"
    alphabet = upper + lower + digits + symbols
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c in upper for c in pwd)
            and any(c in lower for c in pwd)
            and any(c in digits for c in pwd)
            and any(c in symbols for c in pwd)
        ):
            return pwd


def _slugify_for_email(full_name: str) -> str:
    """Ad Soyad → 'ad.soyad' — Türkçe karakterler sadeleşir."""
    tr_map = str.maketrans(
        "ıİğĞüÜşŞöÖçÇ",
        "iIgGuUsSoOcC",
    )
    s = full_name.translate(tr_map).lower()
    s = re.sub(r"[^a-z0-9]+", ".", s).strip(".")
    if not s:
        s = "kullanici"
    # Çok uzun olmasın
    return s[:40]


async def generate_unique_admin_email(
    session: AsyncSession, full_name: str
) -> str:
    repo = AdminUserRepo(session)
    base = _slugify_for_email(full_name)
    candidate = f"{base}@{ADMIN_EMAIL_DOMAIN}"
    if not await repo.get_by_email(candidate):
        return candidate
    # Çakışma varsa 2, 3, … ekle
    for i in range(2, 50):
        candidate = f"{base}{i}@{ADMIN_EMAIL_DOMAIN}"
        if not await repo.get_by_email(candidate):
            return candidate
    # Son çare: kısa rastgele suffix
    suffix = secrets.token_hex(3)
    return f"{base}.{suffix}@{ADMIN_EMAIL_DOMAIN}"


def is_super_admin_email(email: str) -> bool:
    """info@pentorasec.com.tr'yi tanımla (config'den override edilebilir)."""
    if not email:
        return False
    try:
        settings = get_settings()
        if settings.admin_mail and email.lower() == settings.admin_mail.lower():
            return True
    except Exception:
        pass
    return email.lower() == f"info@{ADMIN_EMAIL_DOMAIN}"


# ─── Response builder ────────────────────────────────────────────────────────
def _to_response(
    admin: AdminUser,
    *,
    reveal_password: bool = False,
) -> AdminUserResponse:
    return AdminUserResponse(
        id=str(admin.id),
        email=admin.email,
        display_name=admin.display_name,
        employee_id=str(admin.employee_id) if admin.employee_id else None,
        is_super_admin=bool(admin.is_super_admin),
        is_active=bool(admin.is_active),
        permissions=list(admin.permissions or []),
        last_login_at=admin.last_login_at,
        created_at=admin.created_at,
        updated_at=admin.updated_at,
        password_plain=_decrypt_password(admin) if reveal_password else None,
    )


# ─── Public API ──────────────────────────────────────────────────────────────
async def list_admin_users(
    *,
    session: AsyncSession,
    reveal_passwords: bool = False,
) -> AdminUserListResponse:
    repo = AdminUserRepo(session)
    total, rows = await repo.list_all(limit=500)
    users = [_to_response(r, reveal_password=reveal_passwords) for r in rows]
    return AdminUserListResponse(users=users, total=total)


async def get_admin_user(
    *,
    session: AsyncSession,
    admin_id: uuid.UUID,
    reveal_password: bool = False,
) -> AdminUserResponse:
    repo = AdminUserRepo(session)
    admin = await repo.get_by_id(admin_id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Admin kullanıcı bulunamadı"
        )
    return _to_response(admin, reveal_password=reveal_password)


async def create_admin_user(
    *,
    session: AsyncSession,
    data: AdminUserCreate,
    actor_email: Optional[str] = None,
) -> AdminUserResponse:
    """
    Süper admin tarafından yeni admin kullanıcı oluşturur.
    Eğer e-posta zaten varsa 409 döner; yoksa güçlü bir parola üretir,
    Argon2id hash'ini ve AES-GCM şifreli plaintext'ini saklar.
    """
    repo = AdminUserRepo(session)
    email_norm = data.email.strip().lower()
    if not email_norm.endswith(f"@{ADMIN_EMAIL_DOMAIN}"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Admin e-postası @{ADMIN_EMAIL_DOMAIN} uzantısında olmalıdır.",
        )

    existing = await repo.get_by_email(email_norm)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Bu e-posta ile kayıtlı bir admin zaten mevcut.",
        )

    employee_uuid: Optional[uuid.UUID] = None
    if data.employee_id:
        try:
            employee_uuid = uuid.UUID(data.employee_id)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Geçersiz employee_id",
            )

    new_id = uuid.uuid4()
    plaintext = generate_password()
    pass_hash = _ph.hash(plaintext)
    pass_enc = _encrypt_password(new_id, plaintext)

    admin = AdminUser(
        id=new_id,
        employee_id=employee_uuid,
        email=email_norm,
        password_hash=pass_hash,
        password_encrypted=pass_enc,
        display_name=(data.display_name or None),
        is_super_admin=bool(data.is_super_admin) or is_super_admin_email(email_norm),
        is_active=True,
        permissions=list(data.permissions or []),
        created_by=actor_email,
    )
    await repo.add(admin)
    await session.commit()
    await session.refresh(admin)

    logger.info(
        "admin_user.created",
        admin_id=str(admin.id),
        email=admin.email,
        actor=actor_email,
    )
    # Oluşturucuya plaintext parolayı HER DURUMDA bir kere döndürüyoruz
    # (süper admin değilse bile işlem sahibi ilk kez görmeli).
    resp = _to_response(admin, reveal_password=True)
    return resp


async def update_admin_user(
    *,
    session: AsyncSession,
    admin_id: uuid.UUID,
    data: AdminUserUpdate,
    actor_email: Optional[str] = None,
) -> AdminUserResponse:
    repo = AdminUserRepo(session)
    admin = await repo.get_by_id(admin_id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Admin kullanıcı bulunamadı"
        )

    if data.display_name is not None:
        admin.display_name = data.display_name or None
    if data.permissions is not None:
        admin.permissions = list(data.permissions or [])
    if data.is_active is not None:
        # Süper admin deaktive edilemez
        if admin.is_super_admin and not data.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Süper admin devre dışı bırakılamaz.",
            )
        admin.is_active = bool(data.is_active)

    await session.commit()
    await session.refresh(admin)
    logger.info(
        "admin_user.updated",
        admin_id=str(admin.id),
        actor=actor_email,
    )
    return _to_response(admin)


async def reset_admin_password(
    *,
    session: AsyncSession,
    admin_id: uuid.UUID,
    actor_email: Optional[str] = None,
) -> AdminUserResponse:
    """Admin için yeni rastgele parola üretir ve plaintext'i döner."""
    repo = AdminUserRepo(session)
    admin = await repo.get_by_id(admin_id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Admin kullanıcı bulunamadı"
        )

    plaintext = generate_password()
    admin.password_hash = _ph.hash(plaintext)
    admin.password_encrypted = _encrypt_password(admin.id, plaintext)
    await session.commit()
    await session.refresh(admin)
    logger.warning(
        "admin_user.password_reset",
        admin_id=str(admin.id),
        actor=actor_email,
    )
    return _to_response(admin, reveal_password=True)


async def delete_admin_user(
    *,
    session: AsyncSession,
    admin_id: uuid.UUID,
    actor_email: Optional[str] = None,
) -> dict:
    repo = AdminUserRepo(session)
    admin = await repo.get_by_id(admin_id)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Admin kullanıcı bulunamadı"
        )
    if admin.is_super_admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Süper admin silinemez.",
        )
    email = admin.email
    await repo.delete(admin)
    await session.commit()
    logger.warning(
        "admin_user.deleted",
        admin_id=str(admin_id),
        email=email,
        actor=actor_email,
    )
    return {"deleted": True, "email": email}


# ─── Kimlik doğrulama (login tarafında kullanılır) ───────────────────────────
async def authenticate_db_admin(
    *, session: AsyncSession, email: str, password: str
) -> Optional[AdminUser]:
    """
    DB'deki admin_users tablosunda kayıtlı bir admin'i doğrular.
    Başarılıysa AdminUser, aksi halde None döner.
    """
    repo = AdminUserRepo(session)
    admin = await repo.get_by_email(email)
    if not admin or not admin.is_active:
        # Timing koruması — hash yoksa da aynı süreyi harcıyoruz.
        try:
            _ph.verify(_get_dummy_hash(), password)
        except Exception:
            pass
        return None
    try:
        _ph.verify(admin.password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return None
    except Exception:
        return None
    return admin

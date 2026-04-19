"""
Çalışan Servis Katmanı
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

İş kuralları + PII şifreleme/decryption.

Hassas alanlar (TCKN, IBAN, maaş) yalnızca `aad = "employee:<id>:<field>"`
ile AES-256-GCM şifrelenir → cross-row substitution saldırısına karşı dayanıklı.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import build_aad, decrypt_blob, encrypt_blob, hmac_index
from app.core.logging import get_logger
from app.models.employee import Employee, EmployeeStatus
from app.repositories.employee_repo import EmployeeRepo
from app.schemas.employee import (
    EmployeeCreate,
    EmployeeListItem,
    EmployeeListResponse,
    EmployeeResponse,
    EmployeeUpdate,
)

logger = get_logger(__name__)


# ─── Maskeleme yardımcıları ──────────────────────────────────────────────────
def _mask_tckn(tckn: Optional[str]) -> Optional[str]:
    if not tckn or len(tckn) != 11:
        return None
    return f"{tckn[:3]}****{tckn[-2:]}"


def _mask_iban(iban: Optional[str]) -> Optional[str]:
    if not iban or len(iban) < 8:
        return None
    return f"{iban[:6]}{'*' * (len(iban) - 10)}{iban[-4:]}"


# ─── AAD üretici ─────────────────────────────────────────────────────────────
def _aad(employee_id: uuid.UUID | str, field: str) -> bytes:
    return build_aad("employee", str(employee_id), field)


# ─── Encrypt / Decrypt sarmalları ───────────────────────────────────────────
def _enc(value: Optional[str], employee_id: uuid.UUID | str, field: str) -> Optional[bytes]:
    if value is None or value == "":
        return None
    return encrypt_blob(value.encode("utf-8"), aad=_aad(employee_id, field))


def _dec(blob: Optional[bytes], employee_id: uuid.UUID | str, field: str) -> Optional[str]:
    if not blob:
        return None
    try:
        return decrypt_blob(blob, aad=_aad(employee_id, field)).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "employee.decrypt_failed",
            employee_id=str(employee_id),
            field=field,
            error=str(exc),
        )
        return None


# ─── Response builder ────────────────────────────────────────────────────────
def _to_response(emp: Employee, *, reveal_pii: bool = True) -> EmployeeResponse:
    tckn = _dec(emp.tckn_encrypted, emp.id, "tckn")
    iban = _dec(emp.iban_encrypted, emp.id, "iban")
    salary_raw = _dec(emp.salary_encrypted, emp.id, "salary")
    salary: Optional[Decimal] = None
    if salary_raw:
        try:
            salary = Decimal(salary_raw)
        except Exception:  # noqa: BLE001
            salary = None

    return EmployeeResponse(
        id=str(emp.id),
        employee_no=emp.employee_no,
        full_name=emp.full_name,
        email=emp.email,
        phone=emp.phone,
        tckn=tckn if reveal_pii else None,
        iban=iban if reveal_pii else None,
        salary=salary if reveal_pii else None,
        tckn_masked=_mask_tckn(tckn),
        iban_masked=_mask_iban(iban),
        department=emp.department,
        position=emp.position,
        hire_date=emp.hire_date,
        termination_date=emp.termination_date,
        birth_date=emp.birth_date,
        address=emp.address,
        emergency_contact_name=emp.emergency_contact_name,
        emergency_contact_phone=emp.emergency_contact_phone,
        status=EmployeeStatus(emp.status),
        notes=emp.notes,
        created_by=emp.created_by,
        updated_by=emp.updated_by,
        created_at=emp.created_at,
        updated_at=emp.updated_at,
    )


# ─── Public API ──────────────────────────────────────────────────────────────
async def list_employees(
    *,
    session: AsyncSession,
    status_filter: Optional[str] = None,
    department_filter: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> EmployeeListResponse:
    repo = EmployeeRepo(session)
    total, rows = await repo.list(
        status_filter=status_filter,
        department_filter=department_filter,
        search=search,
        limit=limit,
        offset=offset,
    )
    items = [
        EmployeeListItem(
            id=str(r.id),
            employee_no=r.employee_no,
            full_name=r.full_name,
            email=r.email,
            phone=r.phone,
            department=r.department,
            position=r.position,
            hire_date=r.hire_date,
            status=EmployeeStatus(r.status),
            created_at=r.created_at,
        )
        for r in rows
    ]
    return EmployeeListResponse(
        employees=items, total=total, limit=limit, offset=offset
    )


async def get_employee(
    *, session: AsyncSession, employee_id: uuid.UUID
) -> EmployeeResponse:
    repo = EmployeeRepo(session)
    emp = await repo.get_by_id(employee_id)
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Çalışan bulunamadı",
        )
    return _to_response(emp)


async def create_employee(
    *,
    session: AsyncSession,
    data: EmployeeCreate,
    actor_email: Optional[str] = None,
) -> EmployeeResponse:
    repo = EmployeeRepo(session)

    # TCKN tekrar engeli
    tckn_hash: Optional[str] = None
    if data.tckn:
        tckn_hash = hmac_index(data.tckn)
        existing = await repo.get_by_tckn_hash(tckn_hash)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Bu TCKN ile kayıtlı bir çalışan zaten mevcut",
            )

    employee_no = await repo.next_employee_no()

    # ID önceden üretilir → AAD bağlanır
    new_id = uuid.uuid4()

    emp = Employee(
        id=new_id,
        employee_no=employee_no,
        full_name=data.full_name,
        email=data.email,
        phone=data.phone,
        tckn_hash=tckn_hash,
        tckn_encrypted=_enc(data.tckn, new_id, "tckn"),
        iban_encrypted=_enc(data.iban, new_id, "iban"),
        salary_encrypted=_enc(
            str(data.salary) if data.salary is not None else None,
            new_id,
            "salary",
        ),
        department=data.department,
        position=data.position,
        hire_date=data.hire_date,
        termination_date=data.termination_date,
        birth_date=data.birth_date,
        address=data.address,
        emergency_contact_name=data.emergency_contact_name,
        emergency_contact_phone=data.emergency_contact_phone,
        status=(data.status or EmployeeStatus.ACTIVE).value,
        notes=data.notes,
        created_by=actor_email,
        updated_by=actor_email,
    )

    await repo.add(emp)
    await session.commit()
    await session.refresh(emp)

    logger.info(
        "employee.created",
        employee_id=str(emp.id),
        employee_no=emp.employee_no,
        actor=actor_email,
    )
    return _to_response(emp)


async def update_employee(
    *,
    session: AsyncSession,
    employee_id: uuid.UUID,
    data: EmployeeUpdate,
    actor_email: Optional[str] = None,
) -> EmployeeResponse:
    repo = EmployeeRepo(session)
    emp = await repo.get_by_id(employee_id)
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Çalışan bulunamadı",
        )

    # Düz alanlar — yalnızca verilenler güncellenir
    if data.full_name is not None:
        emp.full_name = data.full_name
    if data.email is not None:
        emp.email = data.email or None
    if data.phone is not None:
        emp.phone = data.phone
    if data.department is not None:
        emp.department = data.department or None
    if data.position is not None:
        emp.position = data.position or None
    if data.hire_date is not None:
        emp.hire_date = data.hire_date
    if data.termination_date is not None:
        emp.termination_date = data.termination_date
    if data.birth_date is not None:
        emp.birth_date = data.birth_date
    if data.address is not None:
        emp.address = data.address or None
    if data.emergency_contact_name is not None:
        emp.emergency_contact_name = data.emergency_contact_name or None
    if data.emergency_contact_phone is not None:
        emp.emergency_contact_phone = data.emergency_contact_phone or None
    if data.status is not None:
        emp.status = data.status.value
        if (
            data.status == EmployeeStatus.TERMINATED
            and emp.termination_date is None
        ):
            emp.termination_date = datetime.now(timezone.utc).date()
    if data.notes is not None:
        emp.notes = data.notes or None

    # Hassas alanlar
    if data.tckn is not None:
        new_hash = hmac_index(data.tckn) if data.tckn else None
        if new_hash and new_hash != emp.tckn_hash:
            existing = await repo.get_by_tckn_hash(new_hash)
            if existing and existing.id != emp.id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Bu TCKN ile kayıtlı başka bir çalışan mevcut",
                )
        emp.tckn_hash = new_hash
        emp.tckn_encrypted = _enc(data.tckn, emp.id, "tckn")

    if data.iban is not None:
        emp.iban_encrypted = _enc(data.iban, emp.id, "iban")

    if data.salary is not None:
        emp.salary_encrypted = _enc(
            str(data.salary) if data.salary is not None else None,
            emp.id,
            "salary",
        )

    emp.updated_by = actor_email
    emp.updated_at = datetime.now(timezone.utc)

    await session.commit()
    await session.refresh(emp)

    logger.info(
        "employee.updated",
        employee_id=str(emp.id),
        employee_no=emp.employee_no,
        actor=actor_email,
    )
    return _to_response(emp)


async def delete_employee(
    *,
    session: AsyncSession,
    employee_id: uuid.UUID,
    actor_email: Optional[str] = None,
) -> dict:
    repo = EmployeeRepo(session)
    emp = await repo.get_by_id(employee_id)
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Çalışan bulunamadı",
        )
    employee_no = emp.employee_no
    await repo.delete(emp)
    await session.commit()
    logger.warning(
        "employee.deleted",
        employee_id=str(employee_id),
        employee_no=employee_no,
        actor=actor_email,
    )
    return {"deleted": True, "employee_no": employee_no}

"""
Çalışan Pydantic Şemaları
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

API katmanı için request / response modelleri. Hassas alanlar (TCKN, IBAN,
maaş) yalnızca admin response içinde decrypt edilmiş olarak döner — list
endpoint'inde maskelenir veya hiç gönderilmez.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import re
from datetime import date, datetime
from decimal import Decimal
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.employee import EmployeeStatus


# ─── TCKN doğrulama (resmi algoritma) ─────────────────────────────────────────
_TCKN_RE = re.compile(r"^[1-9][0-9]{10}$")


def _is_valid_tckn(value: str) -> bool:
    if not _TCKN_RE.match(value):
        return False
    digits = [int(c) for c in value]
    odd_sum = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    even_sum = digits[1] + digits[3] + digits[5] + digits[7]
    d10 = (odd_sum * 7 - even_sum) % 10
    if d10 != digits[9]:
        return False
    d11 = (sum(digits[:10])) % 10
    return d11 == digits[10]


# ─── Telefon basit normalizasyon ─────────────────────────────────────────────
_PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{7,20}$")


def _normalize_phone(value: str) -> str:
    cleaned = re.sub(r"[^\d+]", "", value)
    if not cleaned.startswith("+"):
        if cleaned.startswith("0"):
            cleaned = "+9" + cleaned  # 05xx → +905xx (TR varsayım)
        elif cleaned.startswith("90"):
            cleaned = "+" + cleaned
        elif len(cleaned) == 10 and cleaned.startswith("5"):
            cleaned = "+90" + cleaned
    return cleaned


# ─── IBAN basit doğrulama (TR formatı / mod-97) ──────────────────────────────
def _is_valid_iban(value: str) -> bool:
    iban = value.replace(" ", "").upper()
    if not re.match(r"^[A-Z]{2}[0-9A-Z]{13,32}$", iban):
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


# ─── Base ────────────────────────────────────────────────────────────────────
class _EmployeeBase(BaseModel):
    """Hem create hem update tarafından kullanılan ortak alan kümesi."""
    full_name: Optional[str] = Field(None, min_length=2, max_length=150)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, min_length=7, max_length=20)
    tckn: Optional[str] = Field(None, min_length=11, max_length=11, description="11 haneli TCKN")
    iban: Optional[str] = Field(None, min_length=15, max_length=40)
    salary: Optional[Decimal] = Field(None, ge=0, decimal_places=2, max_digits=12)
    department: Optional[str] = Field(None, max_length=100)
    position: Optional[str] = Field(None, max_length=100)
    hire_date: Optional[date] = None
    termination_date: Optional[date] = None
    birth_date: Optional[date] = None
    address: Optional[str] = Field(None, max_length=500)
    emergency_contact_name: Optional[str] = Field(None, max_length=150)
    emergency_contact_phone: Optional[str] = Field(None, max_length=20)
    status: Optional[EmployeeStatus] = None
    notes: Optional[str] = Field(None, max_length=2000)

    @field_validator("tckn")
    @classmethod
    def _validate_tckn(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        v = v.strip()
        if not _is_valid_tckn(v):
            raise ValueError("Geçersiz TCKN (algoritma doğrulaması başarısız)")
        return v

    @field_validator("phone", "emergency_contact_phone")
    @classmethod
    def _validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        v = v.strip()
        if not _PHONE_RE.match(v):
            raise ValueError("Geçersiz telefon numarası")
        return _normalize_phone(v)

    @field_validator("iban")
    @classmethod
    def _validate_iban(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        v = v.replace(" ", "").upper()
        if not _is_valid_iban(v):
            raise ValueError("Geçersiz IBAN (mod-97 doğrulaması başarısız)")
        return v


# ─── Create ──────────────────────────────────────────────────────────────────
class EmployeeCreate(_EmployeeBase):
    """Yeni çalışan ekleme — full_name + phone zorunlu."""
    full_name: str = Field(..., min_length=2, max_length=150)
    phone: str = Field(..., min_length=7, max_length=20)


# ─── Update (tüm alanlar opsiyonel) ──────────────────────────────────────────
class EmployeeUpdate(_EmployeeBase):
    """Kısmi güncelleme — yalnızca verilen alanlar değişir."""
    pass


# ─── Response ────────────────────────────────────────────────────────────────
class EmployeeResponse(BaseModel):
    """
    Tek çalışan detayı — hassas alanlar decrypt edilmiş olarak döner.
    Bu endpoint sadece admin JWT ile erişilebilir; audit log'lanır.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str
    employee_no: str
    full_name: str
    email: Optional[str] = None
    phone: str

    # Decrypt edilmiş hassas alanlar (admin görebilir)
    tckn: Optional[str] = None
    iban: Optional[str] = None
    salary: Optional[Decimal] = None

    # Maskelenmiş varyantlar (UI default görünüm için)
    tckn_masked: Optional[str] = None
    iban_masked: Optional[str] = None

    department: Optional[str] = None
    position: Optional[str] = None
    hire_date: Optional[date] = None
    termination_date: Optional[date] = None
    birth_date: Optional[date] = None
    address: Optional[str] = None
    emergency_contact_name: Optional[str] = None
    emergency_contact_phone: Optional[str] = None
    status: EmployeeStatus
    notes: Optional[str] = None

    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class EmployeeListItem(BaseModel):
    """
    Liste görünümü — yalnızca operasyonel alanlar; PII (TCKN/IBAN/maaş)
    burada decrypt edilmez (DoS + log leak koruma).
    """
    model_config = ConfigDict(from_attributes=True)

    id: str
    employee_no: str
    full_name: str
    email: Optional[str] = None
    phone: str
    department: Optional[str] = None
    position: Optional[str] = None
    hire_date: Optional[date] = None
    status: EmployeeStatus
    created_at: datetime


class EmployeeListResponse(BaseModel):
    employees: list[EmployeeListItem]
    total: int
    limit: int
    offset: int

"""
Kurumsal Başvuru Pydantic Şemaları
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Güvenlik (OWASP A03 Injection / A02 Cryptographic Failures):
  - tax_number tam 10 hane zorunlu (ne 9 ne 11 kabul edilmez)
  - applicant_tckn_masked: hash[0:4]...hash[-4:] (geriye dönük kayıtlar için)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class CorporateApplicationCreate(BaseModel):
    """Flutter'dan gelen form alanları (belgeler ayrı multipart olarak gelir)."""

    company_name:   str = Field(..., min_length=2, max_length=255)
    # Vergi numarası TAM 10 hane olmalı — ne 9 ne 11 kabul edilmez
    tax_number:     str = Field(..., min_length=10, max_length=10)
    tax_office:     str = Field(..., min_length=2, max_length=100)
    mersis_no:      Optional[str] = Field(None, max_length=30)
    address:        str = Field(..., min_length=10, max_length=1000)
    applicant_name: str = Field(..., min_length=2, max_length=150)
    applicant_tckn: Optional[str] = Field(None, min_length=11, max_length=11)
    phone:          str = Field(..., min_length=10, max_length=20)

    @field_validator("tax_number")
    @classmethod
    def validate_tax_number(cls, v: str) -> str:
        cleaned = v.replace(" ", "").replace("-", "")
        if not cleaned.isdigit():
            raise ValueError("Vergi numarası yalnızca rakam içermeli")
        if len(cleaned) != 10:
            raise ValueError("Vergi numarası tam 10 hane olmalıdır")
        return cleaned

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        cleaned = v.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if not cleaned.lstrip("+").isdigit():
            raise ValueError("Geçersiz telefon numarası")
        return cleaned

    @field_validator("applicant_tckn")
    @classmethod
    def validate_applicant_tckn(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        cleaned = v.strip()
        if not cleaned.isdigit() or len(cleaned) != 11:
            raise ValueError("T.C. Kimlik numarası tam 11 hane olmalıdır")
        return cleaned


class CorporateApplicationStatusUpdate(BaseModel):
    """Admin tarafından durum güncelleme."""
    status: str = Field(..., pattern="^(approved|rejected|reviewing|pending)$")
    reviewer_note: Optional[str] = Field(None, max_length=2000)


class CorporateApplicationResponse(BaseModel):
    """Admin paneline dönen başvuru verisi."""
    model_config = {"from_attributes": True}

    id:                    uuid.UUID
    status:                str
    company_name:          str
    tax_number:            str
    tax_office:            str
    mersis_no:             Optional[str]
    address:               str
    applicant_name:        str
    applicant_tckn:        Optional[str]
    phone:                 str
    reviewer_note:         Optional[str]
    reviewed_at:           Optional[datetime]
    submitted_at:          datetime
    updated_at:            datetime
    # Belge YOLLARINI döndürmüyoruz — yalnızca var mı yok mu (OWASP A01)
    has_vergi_levhasi:     bool = False
    has_imza_sirkuleri:    bool = False
    has_ticaret_sicil:     bool = False
    # Başvuruyu yapan kullanıcı — admin denetimi için (nullable: eski başvurular)
    user_id:               Optional[uuid.UUID] = None
    # TCKN hash maskelenmiş özet — admin kimlik referansı için
    # Format: "abcd••••••••••••••••efgh" — plaintext TCKN ASLA gönderilmez
    applicant_tckn_masked: Optional[str] = None

    @classmethod
    def from_orm_with_docs(
        cls,
        obj,
        tckn_hash: Optional[str] = None,
    ) -> "CorporateApplicationResponse":
        # TCKN hash maskeleme: hash[0:4] + gizli bölüm + hash[-4:]
        masked: Optional[str] = None
        if tckn_hash and len(tckn_hash) >= 8:
            masked = f"{tckn_hash[:4]}{'•' * 16}{tckn_hash[-4:]}"

        data = {
            "id":                    obj.id,
            "status":                obj.status,
            "company_name":          obj.company_name,
            "tax_number":            obj.tax_number,
            "tax_office":            obj.tax_office,
            "mersis_no":             obj.mersis_no,
            "address":               obj.address,
            "applicant_name":        obj.applicant_name,
            "applicant_tckn":        getattr(obj, "applicant_tckn", None),
            "phone":                 obj.phone,
            "reviewer_note":         obj.reviewer_note,
            "reviewed_at":           obj.reviewed_at,
            "submitted_at":          obj.submitted_at,
            "updated_at":            obj.updated_at,
            "has_vergi_levhasi":     bool(obj.vergi_levhasi_path),
            "has_imza_sirkuleri":    bool(obj.imza_sirkuleri_path),
            "has_ticaret_sicil":     bool(obj.ticaret_sicil_path),
            "user_id":               obj.user_id,
            "applicant_tckn_masked": masked,
        }
        return cls(**data)


class CorporateApplicationListResponse(BaseModel):
    """Sayfalanmış liste yanıtı."""
    total:        int
    applications: list[CorporateApplicationResponse]

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class WebCorporateApplicationCreate(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=80)
    last_name: str = Field(..., min_length=2, max_length=80)
    city: str = Field(..., min_length=2, max_length=80)
    phone: str = Field(..., min_length=10, max_length=20)
    kvkk_approved: bool = Field(...)

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        cleaned = (
            value.replace(" ", "")
            .replace("-", "")
            .replace("(", "")
            .replace(")", "")
        )
        if not cleaned.lstrip("+").isdigit():
            raise ValueError("Geçersiz telefon numarası")
        return cleaned

    @field_validator("first_name", "last_name", "city")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return " ".join(value.strip().split())


class WebCorporateApplicationResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    first_name: str
    last_name: str
    city: str
    phone: str
    kvkk_approved: bool
    submitted_at: datetime


class WebCorporateApplicationListResponse(BaseModel):
    total: int
    applications: list[WebCorporateApplicationResponse]

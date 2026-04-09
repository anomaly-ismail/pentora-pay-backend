"""
Kurumsal Başvuru API Endpoint'leri
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

POST  /api/v1/corporate/apply                        → Flutter (ClientAuth)
GET   /api/v1/admin/corporate/applications           → Admin JWT
PATCH /api/v1/admin/corporate/applications/{id}      → Admin JWT
GET   /api/v1/admin/corporate/applications/{id}/doc/{doc_type} → Admin JWT (streaming)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from pathlib import Path
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.dependencies import get_db
from app.api.dependencies import get_current_user_optional, UserDTO
from app.schemas.corporate_application import (
    CorporateApplicationCreate,
    CorporateApplicationListResponse,
    CorporateApplicationResponse,
    CorporateApplicationStatusUpdate,
)
from app.schemas.web_corporate_application import (
    WebCorporateApplicationCreate,
    WebCorporateApplicationListResponse,
    WebCorporateApplicationResponse,
)
from app.services import corporate_application_service as svc
from app.services import web_corporate_application_service as web_svc
from app.repositories.corporate_application_repo import CorporateApplicationRepo

logger = get_logger(__name__)

# ─── Router tanımlamaları ─────────────────────────────────────────────────────
# Flutter'dan gelen başvurular
flutter_router = APIRouter(prefix="/corporate", tags=["Corporate Applications"])

# Admin yönetim endpoint'leri
admin_corp_router = APIRouter(prefix="/admin/corporate", tags=["Admin · Corporate"])


# ─── Admin JWT Doğrulama Bağımlılığı ─────────────────────────────────────────
async def require_admin_jwt(authorization: str = Header(...)) -> dict:
    """
    Authorization: Bearer <admin_token> header'ını doğrular.
    Token admin SSO login'den alınır.
    """
    settings = get_settings()
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz yetkilendirme formatı",
        )
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Yetki yetersiz")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token süresi dolmuş")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Geçersiz token")


# ─── Flutter: Başvuru Gönder ──────────────────────────────────────────────────
@flutter_router.post(
    "/apply",
    status_code=status.HTTP_201_CREATED,
    summary="Kurumsal Hesap Başvurusu",
    description="Flutter uygulamasından multipart/form-data ile başvuru alır. ECDH ClientAuth zorunludur.",
)
async def submit_corporate_application(
    # Form alanları
    company_name:   str = Form(...),
    tax_number:     str = Form(...),
    tax_office:     str = Form(...),
    address:        str = Form(...),
    applicant_name: str = Form(...),
    applicant_tckn: Optional[str] = Form(None),
    phone:          str = Form(...),
    mersis_no:      Optional[str] = Form(None),
    # Dosyalar
    vergi_levhasi:  UploadFile = File(..., description="Vergi levhası (PDF/JPG/PNG, maks 5MB)"),
    imza_sirkuleri: UploadFile = File(..., description="İmza sirküleri (PDF/JPG/PNG, maks 5MB)"),
    ticaret_sicil:  UploadFile = File(..., description="Ticaret sicil gazetesi (PDF/JPG/PNG, maks 5MB)"),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[UserDTO] = Depends(get_current_user_optional),
) -> dict:
    form_data = CorporateApplicationCreate(
        company_name=company_name,
        tax_number=tax_number,
        tax_office=tax_office,
        mersis_no=mersis_no,
        address=address,
        applicant_name=applicant_name,
        applicant_tckn=applicant_tckn,
        phone=phone,
    )

    application = await svc.submit_application(
        session=db,
        form_data=form_data,
        vergi_levhasi=vergi_levhasi,
        imza_sirkuleri=imza_sirkuleri,
        ticaret_sicil=ticaret_sicil,
    )
    if current_user is not None:
        await svc.attach_user_to_application(
            session=db,
            application_id=application.id,
            user_id=current_user.id,
        )
        await db.commit()
    return {
        "message": "Başvurunuz alındı. 24 saat içinde sizinle iletişime geçilecektir.",
        "application_id": str(application.id),
        "status": application.status,
    }


@flutter_router.post(
    "/web-apply",
    status_code=status.HTTP_201_CREATED,
    response_model=WebCorporateApplicationResponse,
    summary="Web Kurumsal Başvuru Formu",
    description="Kurumsal landing sayfasındaki kısa formdan başvuru alır.",
)
async def submit_web_corporate_application(
    body: WebCorporateApplicationCreate,
    db: AsyncSession = Depends(get_db),
) -> WebCorporateApplicationResponse:
    return await web_svc.submit_web_application(session=db, payload=body)


# ─── Admin: Başvuruları Listele ───────────────────────────────────────────────
@admin_corp_router.get(
    "/applications",
    response_model=CorporateApplicationListResponse,
    summary="Kurumsal Başvuru Listesi",
)
async def list_corporate_applications(
    status_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_admin_jwt),
) -> CorporateApplicationListResponse:
    return await svc.list_applications(
        session=db,
        status_filter=status_filter,
        limit=min(limit, 100),
        offset=offset,
    )


@admin_corp_router.get(
    "/web-applications",
    response_model=WebCorporateApplicationListResponse,
    summary="Web Kurumsal Başvuru Listesi",
)
async def list_web_corporate_applications(
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_admin_jwt),
) -> WebCorporateApplicationListResponse:
    return await web_svc.list_web_applications(
        session=db,
        limit=min(limit, 200),
        offset=offset,
    )


# ─── Admin: Başvuruyu Getir ───────────────────────────────────────────────────
@admin_corp_router.get(
    "/applications/{app_id}",
    response_model=CorporateApplicationResponse,
    summary="Başvuru Detayı",
)
async def get_corporate_application(
    app_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_admin_jwt),
) -> CorporateApplicationResponse:
    repo = CorporateApplicationRepo(db)
    app = await repo.get_by_id(app_id)
    if not app:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Başvuru bulunamadı")
    tckn_hash = None
    if app.user_id:
        user = await db.get(User, app.user_id)
        tckn_hash = user.tckn_hash if user else None
    return CorporateApplicationResponse.from_orm_with_docs(app, tckn_hash=tckn_hash)


# ─── Admin: Durum Güncelle ────────────────────────────────────────────────────
@admin_corp_router.patch(
    "/applications/{app_id}/status",
    response_model=CorporateApplicationResponse,
    summary="Başvuru Durumu Güncelle",
)
async def update_status(
    app_id: uuid.UUID,
    update: CorporateApplicationStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_admin_jwt),
) -> CorporateApplicationResponse:
    return await svc.update_application_status(session=db, app_id=app_id, update=update)


# ─── Admin: Belge İndir (Streaming — OWASP A01) ───────────────────────────────
@admin_corp_router.get(
    "/applications/{app_id}/document/{doc_type}",
    summary="Belge İndir (Streaming)",
    description="Belge yolu hiçbir zaman istemciye açıklanmaz. Yalnızca içerik stream edilir.",
)
async def download_document(
    app_id: uuid.UUID,
    doc_type: str,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_admin_jwt),
) -> StreamingResponse:
    if doc_type not in ("vergi", "imza", "sicil"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Geçersiz belge türü")

    repo = CorporateApplicationRepo(db)
    app = await repo.get_by_id(app_id)
    if not app:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Başvuru bulunamadı")

    path_map = {
        "vergi": app.vergi_levhasi_path,
        "imza":  app.imza_sirkuleri_path,
        "sicil": app.ticaret_sicil_path,
    }
    file_path = path_map[doc_type]
    if not file_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bu belge henüz yüklenmemiş")

    p = Path(file_path)
    if not p.exists() or not p.is_file():
        logger.error("corporate.document.missing", path=file_path, app_id=str(app_id))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Dosya bulunamadı")

    # MIME tespiti (uzantıya göre)
    suffix = p.suffix.lower()
    mime_map = {".pdf": "application/pdf", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png"}
    media_type = mime_map.get(suffix, "application/octet-stream")

    def _iter():
        with p.open("rb") as f:
            while chunk := f.read(65536):  # 64KB chunks
                yield chunk

    return StreamingResponse(
        _iter(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{doc_type}_{app_id}.{suffix.lstrip(".")}"'},
    )

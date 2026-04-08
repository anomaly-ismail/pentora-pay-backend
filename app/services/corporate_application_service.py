"""
Kurumsal Başvuru Service
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dosya güvenliği (OWASP A05):
  - İzin verilen MIME türleri: PDF, JPEG, PNG
  - Magic bytes doğrulaması (sadece uzantıya güvenilmez)
  - Maksimum dosya boyutu: 5 MB
  - Rastgele UUID ile yeniden adlandırma (path traversal önleme)
  - Belgeler public dizin dışında saklanır
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.corporate_application import CorporateApplication
from app.repositories.corporate_application_repo import CorporateApplicationRepo
from app.schemas.corporate_application import (
    CorporateApplicationCreate,
    CorporateApplicationListResponse,
    CorporateApplicationResponse,
    CorporateApplicationStatusUpdate,
)
from app.core.logging import get_logger

logger = get_logger(__name__)

# Belgeler public web root dışında saklanır
_UPLOAD_DIR = Path("/app/uploads/corporate")

# İzin verilen dosya tipleri: (MIME prefix, magic bytes)
_ALLOWED_TYPES: dict[str, bytes] = {
    "application/pdf": b"%PDF",
    "image/jpeg":      b"\xff\xd8\xff",
    "image/png":       b"\x89PNG",
}
_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


async def _save_file(upload: UploadFile, subfolder: str) -> str:
    """
    Dosyayı güvenli şekilde disk'e kaydeder.
    - Magic bytes kontrolü
    - Boyut kontrolü
    - UUID ile yeniden adlandırma
    Returns: disk yolu (string)
    """
    content = await upload.read()

    # Boyut kontrolü
    if len(content) > _MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Dosya boyutu 5 MB sınırını aşıyor: {upload.filename}",
        )

    # Magic bytes doğrulaması
    matched_ext = None
    for mime, magic in _ALLOWED_TYPES.items():
        if content.startswith(magic):
            matched_ext = mime.split("/")[1].replace("jpeg", "jpg")
            break

    if not matched_ext:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Desteklenmeyen dosya formatı: {upload.filename}. Yalnızca PDF, JPG, PNG kabul edilir.",
        )

    # Güvenli dosya adı (path traversal önleme)
    safe_name = f"{uuid.uuid4().hex}.{matched_ext}"
    target_dir = _UPLOAD_DIR / subfolder
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / safe_name

    target_path.write_bytes(content)
    logger.info("corporate.file.saved", path=str(target_path), size=len(content))

    return str(target_path)


async def submit_application(
    *,
    session: AsyncSession,
    form_data: CorporateApplicationCreate,
    vergi_levhasi:  UploadFile,
    imza_sirkuleri: UploadFile,
    ticaret_sicil:  UploadFile,
) -> CorporateApplication:
    """Flutter'dan gelen başvuruyu kaydeder."""

    # Belgeleri diske kaydet
    app_folder = uuid.uuid4().hex  # Her başvuruya özel klasör
    vergi_path  = await _save_file(vergi_levhasi,  f"{app_folder}/vergi")
    imza_path   = await _save_file(imza_sirkuleri, f"{app_folder}/imza")
    sicil_path  = await _save_file(ticaret_sicil,  f"{app_folder}/sicil")

    repo = CorporateApplicationRepo(session)
    application = await repo.create(
        company_name=form_data.company_name,
        tax_number=form_data.tax_number,
        tax_office=form_data.tax_office,
        mersis_no=form_data.mersis_no,
        address=form_data.address,
        applicant_name=form_data.applicant_name,
        phone=form_data.phone,
        vergi_levhasi_path=vergi_path,
        imza_sirkuleri_path=imza_path,
        ticaret_sicil_path=sicil_path,
    )
    await session.commit()

    logger.info(
        "corporate.application.submitted",
        application_id=str(application.id),
        company=application.company_name,
    )
    return application


async def list_applications(
    *,
    session: AsyncSession,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> CorporateApplicationListResponse:
    """Admin için başvuru listesi."""
    repo = CorporateApplicationRepo(session)
    total, apps = await repo.get_all(status=status_filter, limit=limit, offset=offset)
    return CorporateApplicationListResponse(
        total=total,
        applications=[CorporateApplicationResponse.from_orm_with_docs(a) for a in apps],
    )


async def update_application_status(
    *,
    session: AsyncSession,
    app_id: uuid.UUID,
    update: CorporateApplicationStatusUpdate,
) -> CorporateApplicationResponse:
    """Admin durum günceller."""
    repo = CorporateApplicationRepo(session)
    app = await repo.update_status(app_id, update.status, update.reviewer_note)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Başvuru bulunamadı.",
        )
    await session.commit()
    return CorporateApplicationResponse.from_orm_with_docs(app)

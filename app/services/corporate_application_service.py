"""
Kurumsal Başvuru Service
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Dosya güvenliği (OWASP A05):
  - İzin verilen MIME türleri: PDF, JPEG, PNG
  - Magic bytes doğrulaması — L-6: backend'de de uygulanır (sadece uzantıya güvenilmez)
  - Maksimum dosya boyutu: 5 MB
  - Rastgele UUID ile yeniden adlandırma (path traversal önleme)
  - Belgeler public dizin dışında saklanır

L-5: applicant_tckn plaintext değil HMAC-SHA3-512 hash olarak saklanır.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import hashlib
import hmac as stdlib_hmac
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.corporate_application import CorporateApplication
from app.models.notification import NotificationType
from app.models.user import User
from app.repositories.corporate_application_repo import CorporateApplicationRepo
from app.repositories.notification_repo import NotificationRepo
from app.services.push_notification_service import send_user_push
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


def _hash_tckn(tckn: str | None) -> str | None:
    """
    L-5: applicant_tckn'yi HMAC-SHA3-512 ile hashler.
    DB'de plaintext TCKN saklanmaz.
    """
    if not tckn:
        return None
    from app.core.config import get_settings
    settings = get_settings()
    return stdlib_hmac.new(
        settings.tckn_pepper.encode("utf-8"),
        tckn.encode("utf-8"),
        hashlib.sha3_512,
    ).hexdigest()

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
    # İlk 16 byte: magic bytes kontrolü
    await upload.seek(0)
    head = await upload.read(16)

    # Magic bytes doğrulaması
    matched_ext = None
    for mime, magic in _ALLOWED_TYPES.items():
        if head.startswith(magic):
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

    # Stream ederek diske yaz (RAM kullanımı düşük, büyük dosyada daha hızlı)
    await upload.seek(0)
    size = 0
    with target_path.open("wb") as f:
        while True:
            chunk = await upload.read(1024 * 1024)  # 1MB
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_FILE_SIZE:
                f.close()
                target_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Dosya boyutu 5 MB sınırını aşıyor: {upload.filename}",
                )
            f.write(chunk)

    logger.info("corporate.file.saved", path=str(target_path), size=size)

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
    from sqlalchemy.exc import SQLAlchemyError

    # Belgeleri diske kaydet
    app_folder = uuid.uuid4().hex  # Her başvuruya özel klasör
    vergi_path  = await _save_file(vergi_levhasi,  f"{app_folder}/vergi")
    imza_path   = await _save_file(imza_sirkuleri, f"{app_folder}/imza")
    sicil_path  = await _save_file(ticaret_sicil,  f"{app_folder}/sicil")

    try:
        repo = CorporateApplicationRepo(session)
        application = await repo.create(
            user_id=None,  # endpoint katmanı bu değeri ayrı günceller
            company_name=form_data.company_name,
            tax_number=form_data.tax_number,
            tax_office=form_data.tax_office,
            mersis_no=form_data.mersis_no,
            address=form_data.address,
            applicant_name=form_data.applicant_name,
            # L-5: plaintext TCKN yerine HMAC hash sakla
            applicant_tckn=_hash_tckn(form_data.applicant_tckn),
            phone=form_data.phone,
            vergi_levhasi_path=vergi_path,
            imza_sirkuleri_path=imza_path,
            ticaret_sicil_path=sicil_path,
        )
        await session.commit()
    except SQLAlchemyError as exc:
        await session.rollback()
        logger.error(
            "corporate.application.db_error",
            error=str(exc),
            hint="corporate_applications tablosu DB'de mevcut olmayabilir — backend yeniden başlatın",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Başvuru kaydedilemedi. Lütfen daha sonra tekrar deneyin.",
        ) from exc

    logger.info(
        "corporate.application.submitted",
        application_id=str(application.id),
        company=application.company_name,
    )
    return application


async def attach_user_to_application(
    *,
    session: AsyncSession,
    application_id: uuid.UUID,
    user_id: uuid.UUID,
) -> None:
    repo = CorporateApplicationRepo(session)
    app = await repo.get_by_id(application_id)
    if not app:
        return
    app.user_id = user_id
    await session.flush()


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
    user_hash_map: dict[uuid.UUID, str] = {}
    user_ids = [a.user_id for a in apps if a.user_id]
    if user_ids:
        result = await session.execute(
            select(User.id, User.tckn_hash).where(User.id.in_(user_ids))
        )
        user_hash_map = {row[0]: row[1] for row in result.all()}

    return CorporateApplicationListResponse(
        total=total,
        applications=[
            CorporateApplicationResponse.from_orm_with_docs(
                a,
                tckn_hash=user_hash_map.get(a.user_id) if a.user_id else None,
            )
            for a in apps
        ],
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
    if app.user_id:
        notif_repo = NotificationRepo(session)
        status_title_map = {
            "approved": "Kurumsal başvurunuz onaylandı",
            "rejected": "Kurumsal başvurunuz reddedildi",
            "reviewing": "Kurumsal başvurunuz incelemede",
            "pending": "Kurumsal başvurunuz beklemeye alındı",
        }
        status_type_map = {
            "approved": NotificationType.CORPORATE_APPROVED,
            "rejected": NotificationType.CORPORATE_REJECTED,
            "reviewing": NotificationType.CORPORATE_REVIEWING,
            "pending": NotificationType.SYSTEM,
        }
        note = (update.reviewer_note or "").strip()
        base_body = (
            f"Basvuru durumunuz: {app.status}. "
            f"Basvuru No: {app.id}."
        )
        body = f"{base_body} Inceleme notu: {note}" if note else base_body
        await notif_repo.create(
            user_id=app.user_id,
            title=status_title_map.get(app.status, "Kurumsal basvuru guncellendi"),
            body=body,
            notification_type=status_type_map.get(app.status, NotificationType.SYSTEM),
            related_id=str(app.id),
        )
        await send_user_push(
            db=session,
            user_id=app.user_id,
            title=status_title_map.get(app.status, "Kurumsal basvuru guncellendi"),
            body=body,
            data={"related_id": str(app.id), "status": app.status},
        )

    await session.commit()
    tckn_hash = None
    if app.user_id:
        user = await session.get(User, app.user_id)
        tckn_hash = user.tckn_hash if user else None
    return CorporateApplicationResponse.from_orm_with_docs(app, tckn_hash=tckn_hash)

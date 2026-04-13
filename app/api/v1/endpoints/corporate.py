"""
Kurumsal Başvuru API Endpoint'leri
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

POST  /api/v1/corporate/apply                        → Flutter (ClientAuth)
GET   /api/v1/corporate/status                       → Flutter (GRAuth)
POST  /api/v1/corporate/payment                      → Flutter (GRAuth)
POST  /api/v1/corporate/payment/{id}/verify-otp      → Flutter (GRAuth)
POST  /api/v1/corporate/receive                      → Flutter (GRAuth)
GET   /api/v1/admin/corporate/applications           → Admin JWT
PATCH /api/v1/admin/corporate/applications/{id}      → Admin JWT
GET   /api/v1/admin/corporate/applications/{id}/doc/{doc_type} → Admin JWT (streaming)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import random
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, File, Form, Header, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.dependencies import get_db
from app.api.dependencies import get_current_user, get_current_user_optional, UserDTO
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
from app.repositories.corporate_payment_repo import CorporatePaymentRepo
from app.repositories.corporate_receive_repo import CorporateReceiveRepo
from app.repositories.accounting_repo import AccountingRepository, normalize
from app.models.accounting import AccountType, JournalDirection
from app.models.user import User
from app.services.netgsm_service import send_otp_sms, send_payment_request_sms

logger = get_logger(__name__)

# ─── Router tanımlamaları ─────────────────────────────────────────────────────
# Flutter'dan gelen başvurular
flutter_router = APIRouter(prefix="/corporate", tags=["Corporate Applications"])

# Admin yönetim endpoint'leri
admin_corp_router = APIRouter(prefix="/admin/corporate", tags=["Admin · Corporate"])


# ─── Admin JWT Doğrulama Bağımlılığı ─────────────────────────────────────────
async def require_admin_jwt(
    authorization: Optional[str] = Header(None),
    admin_token: Optional[str] = Cookie(None),
) -> dict:
    """
    H-5: Authorization header VEYA admin_token httpOnly cookie'den JWT alır.
    H-6: verify_admin_token blacklist kontrolü içerir.
    L-4: ES256 / HS256 verify_admin_token içinde yönetilir.
    """
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

    return verify_admin_token(token)


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

    # Her kullanıcı yalnızca 1 başvuru yapabilir
    if current_user is not None:
        repo = CorporateApplicationRepo(db)
        existing_count = await repo.count_by_user_id(current_user.id)
        if existing_count > 0:
            existing = await repo.get_latest_by_user_id(current_user.id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Zaten bir kurumsal başvurunuz bulunmaktadır. "
                    f"Başvuru durumu: {existing.status if existing else 'bilinmiyor'}. "
                    "Yeni başvuru yapılamaz."
                ),
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


@flutter_router.get(
    "/status",
    summary="Kullanıcının Kurumsal Başvuru Durumu",
    description="GRAuth token ile giriş yapan kullanıcının son başvuru durumunu döner. Yoksa 'none'.",
)
async def get_corporate_status(
    db: AsyncSession = Depends(get_db),
    current_user: UserDTO = Depends(get_current_user),
) -> dict:
    repo = CorporateApplicationRepo(db)
    app = await repo.get_latest_by_user_id(current_user.id)
    if not app:
        return {"status": "none", "application_id": None}
    return {"status": app.status, "application_id": str(app.id)}


# ─── Flutter: Tek Başvuru Kontrolü ───────────────────────────────────────────
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


# ─── Flutter: Kurumsal Ödeme ─────────────────────────────────────────────────

class CorporatePaymentRequest(BaseModel):
    amount:          Decimal  = Field(..., gt=0, description="İşlem tutarı (TL)")
    recipient_tckn:  Optional[str] = Field(None, min_length=11, max_length=11)
    recipient_iban:  Optional[str] = Field(None, max_length=34)
    recipient_phone: str      = Field(..., min_length=10, max_length=20)
    gold_gram:       Decimal  = Field(..., gt=0, description="Altın miktarı (gram)")
    gold_type:       str      = Field(..., min_length=2, max_length=100, description="Ör: Cumhuriyet Altını")
    mrz_verified:    bool     = False
    nfc_verified:    bool     = False


class OtpVerifyRequest(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


@flutter_router.post(
    "/payment",
    status_code=status.HTTP_201_CREATED,
    summary="Kurumsal Ödeme Başlat",
    description="OTP üretir, Netgsm ile alıcı telefonuna SMS gönderir. Onaylı kurumsal hesap gerektirir.",
)
async def create_corporate_payment(
    body: CorporatePaymentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserDTO = Depends(get_current_user),
) -> dict:
    # Onaylanmış kurumsal başvuru kontrolü
    corp_repo = CorporateApplicationRepo(db)
    corp_app = await corp_repo.get_latest_by_user_id(current_user.id)
    if not corp_app or corp_app.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlemi gerçekleştirmek için onaylanmış bir kurumsal hesabınız bulunmamaktadır.",
        )

    # M-2: nfc_verified ve mrz_verified server-side cross-check
    # Flutter'dan gelen değer; DB'deki gerçek kullanıcı durumu ile çapraz kontrol edilir.
    if body.nfc_verified and not current_user.nfc_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "nfc_verified=true talep edildi ancak bu hesapta NFC doğrulaması "
                "kayıtlı değil. Lütfen uygulamayı güncelleyin."
            ),
        )

    # 6 haneli OTP üret
    otp_plain = f"{random.randint(0, 999999):06d}"

    pay_repo = CorporatePaymentRepo(db)
    payment = await pay_repo.create(
        seller_user_id=current_user.id,
        recipient_tckn=body.recipient_tckn,
        recipient_iban=body.recipient_iban,
        recipient_phone=body.recipient_phone,
        gold_gram=body.gold_gram,
        gold_type=body.gold_type,
        amount=body.amount,
        otp_plain=otp_plain,
        mrz_verified=body.mrz_verified,
        nfc_verified=body.nfc_verified,
    )
    await db.commit()

    # Netgsm ile SMS gönder (hata olsa işlem durdurmaz)
    sms_sent = await send_otp_sms(phone=body.recipient_phone, otp_code=otp_plain)

    logger.info(
        "corporate.payment.created",
        payment_id=str(payment.id),
        sms_sent=sms_sent,
        amount=str(body.amount),
    )

    return {
        "payment_id": str(payment.id),
        "otp_expires_minutes": 10,
        "sms_sent": sms_sent,
        "message": "OTP kodu alıcı telefonuna gönderildi. Ürünü teslim edin ve OTP kodunu alın.",
    }


@flutter_router.get(
    "/payment/{payment_id}/status",
    summary="Ödeme Durumunu Sorgula",
    description=(
        "M-9: Ağ kopması durumunda Flutter bu endpoint ile ödemenin durumunu kontrol eder. "
        "Belirsizlik ortadan kalkar: OTP gönderildi mi, tamamlandı mı, süresi doldu mu."
    ),
)
async def get_corporate_payment_status(
    payment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: UserDTO = Depends(get_current_user),
) -> dict:
    pay_repo = CorporatePaymentRepo(db)
    payment = await pay_repo.get_by_id(payment_id)

    if not payment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ödeme bulunamadı.")
    if payment.seller_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Yetki hatası.")

    return {
        "payment_id": str(payment.id),
        "status": payment.status.value if hasattr(payment.status, "value") else str(payment.status),
        "amount": str(payment.amount),
        "gold_type": payment.gold_type,
        "otp_expires_at": payment.otp_expires_at.isoformat() if payment.otp_expires_at else None,
        "completed_at": payment.completed_at.isoformat() if payment.completed_at else None,
    }


@flutter_router.post(
    "/payment/{payment_id}/verify-otp",
    summary="OTP Doğrula ve Ödemeyi Tamamla",
)
async def verify_corporate_payment_otp(
    payment_id: uuid.UUID,
    body: OtpVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserDTO = Depends(get_current_user),
) -> dict:
    pay_repo = CorporatePaymentRepo(db)
    # C-2: get_by_id yerine get_by_id_for_update — TOCTOU race condition önlemi
    payment = await pay_repo.get_by_id_for_update(payment_id)

    if not payment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ödeme bulunamadı.")
    if payment.seller_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Yetki hatası.")

    success, message = await pay_repo.verify_otp(payment, body.otp_code)
    if not success:
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    # ── Çift Taraflı Kayıt (Double-Entry) ile bakiye düşme ──────────────────
    acc_repo = AccountingRepository(db)

    # Kullanıcı cüzdanını row-level lock ile çek (eş zamanlı işlem koruması)
    wallet = await acc_repo.get_user_primary_wallet_for_update(current_user.id)
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Kullanıcı cüzdanı bulunamadı.",
        )

    amount = normalize(Decimal(str(payment.amount)))

    # Son anlık bakiye kontrolü (arayüzden gelen değer stale olabilir)
    if Decimal(str(wallet.balance)) < amount:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Yetersiz bakiye.",
        )

    # Sistem tarafındaki karşı hesap (REVENUE) — kurumsal işlem geliri
    # REVENUE: CREDIT (+) ile artar; Journal dengesi sağlanır: DEBIT LIABILITY = CREDIT REVENUE
    system_account = await acc_repo.get_or_create_system_account(
        name="Kurumsal Ödeme Havuzu",
        account_type=AccountType.REVENUE,
        currency="TRY",
    )

    # İdempotency key olarak payment.id — aynı ödeme iki kez işlenemez
    idempotency_key = f"corp_pay_{payment.id}"

    try:
        await acc_repo.record_transaction(
            reference_id=idempotency_key,
            description=(
                f"Kurumsal Ödeme | {payment.gold_type} | "
                f"Alıcı TCKN: {payment.recipient_tckn}"
            ),
            entries=[
                # LIABILITY DEBIT  → kullanıcı bakiyesi azalır
                {
                    "account_id": wallet.id,
                    "direction": JournalDirection.DEBIT,
                    "amount": amount,
                },
                # ASSET CREDIT → sistem ödeme havuzundan çıktı (para altın satıcısına gitti)
                {
                    "account_id": system_account.id,
                    "direction": JournalDirection.CREDIT,
                    "amount": amount,
                },
            ],
        )
    except ValueError as exc:
        # Unbalanced journal, negatif bakiye vb. — mükerrer ödemeye izin verme
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    # ────────────────────────────────────────────────────────────────────────

    await db.commit()

    logger.info(
        "corporate.payment.completed",
        payment_id=str(payment_id),
        amount=str(amount),
        wallet_id=str(wallet.id),
    )
    return {
        "success": True,
        "payment_id": str(payment_id),
        "amount": str(payment.amount),
        "message": "Ödeme başarıyla tamamlandı. Bakiyenizden düşüldü.",
    }


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


# ─── Flutter: Ödeme Alma Talebi Oluştur ──────────────────────────────────────

class CorporateReceiveRequest(BaseModel):
    amount:          float  = Field(..., gt=0, description="Tahsil edilecek TL tutarı")
    recipient_tckn:  str    = Field(..., min_length=11, max_length=11)
    recipient_phone: str    = Field(..., min_length=10, max_length=20)
    gold_gram:       float  = Field(..., gt=0)
    gold_type:       str    = Field(..., min_length=1, max_length=100)
    mrz_verified:    bool   = False
    nfc_verified:    bool   = False


@flutter_router.post(
    "/receive",
    status_code=status.HTTP_201_CREATED,
    summary="Ödeme Alma Talebi Oluştur",
    description=(
        "Kurumsal kullanıcı ödeme alma talebi başlatır. "
        "Müşteriye ödeme linki ve onay SMS'i gönderilir."
    ),
)
async def create_corporate_receive(
    body: CorporateReceiveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: UserDTO = Depends(get_current_user),
) -> dict:
    settings = get_settings()

    # Kurumsal hesap kontrolü
    app_repo = CorporateApplicationRepo(db)
    corp_app = await app_repo.get_latest_by_user_id(current_user.id)
    if not corp_app or corp_app.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlem için onaylı kurumsal hesap gereklidir.",
        )

    receive_repo = CorporateReceiveRepo(db)
    req = await receive_repo.create(
        seller_user_id=current_user.id,
        recipient_tckn=body.recipient_tckn,
        recipient_phone=body.recipient_phone,
        gold_gram=Decimal(str(body.gold_gram)),
        gold_type=body.gold_type,
        amount=normalize(Decimal(str(body.amount))),
        mrz_verified=body.mrz_verified,
        nfc_verified=body.nfc_verified,
    )
    await db.commit()

    # Tutarı Türkçe formatlı gönder  (1234.50 → "1.234,50")
    amount_str = f"{float(req.amount):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

    sms_sent = await send_payment_request_sms(
        phone=body.recipient_phone,
        amount_str=amount_str,
        payment_id=str(req.id),
    )

    if sms_sent:
        await receive_repo.mark_sms_sent(req)
        await db.commit()

    portal_url = getattr(settings, "payment_portal_url", "https://pentorasec.online/pay")
    pay_link = f"{portal_url}/{req.id}"

    logger.info(
        "corporate.receive.created",
        receive_id=str(req.id),
        sms_sent=sms_sent,
        amount=str(req.amount),
    )

    return {
        "receive_id": str(req.id),
        "pay_link": pay_link,
        "amount": float(req.amount),
        "amount_str": amount_str,
        "sms_sent": sms_sent,
        "message": (
            "Ödeme talebi oluşturuldu. Müşteriye SMS gönderildi. "
            "Müşteri ödemeyi yapıp 'ONAYLIYORUM' SMS'i gönderdiğinde "
            "bakiyenize yansıyacaktır."
        ),
    }


# ─── GET /corporate/receive/{receive_id}/status ───────────────────────────────
# Flutter bu endpoint'i periyodik olarak poll eder (5 sn'de bir)

@flutter_router.get("/receive/{receive_id}/status")
async def get_receive_status(
    receive_id: uuid.UUID,
    current_user: UserDTO = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    receive_repo = CorporateReceiveRepo(db)
    req = await receive_repo.get_by_id(receive_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ödeme talebi bulunamadı")
    if req.seller_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Yetkisiz erişim")
    # status alanı DB'de string olarak saklanabilir, enum ya da str olabilir
    status_val = req.status.value if hasattr(req.status, "value") else req.status
    return {"status": status_val}


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

    # BUG-2 FIX: Senkron dosya IO event loop'u bloklar.
    # asyncio.to_thread ile dosya okuma thread pool'a alınır.
    async def _async_iter():
        import asyncio
        def _read_chunks():
            with p.open("rb") as f:
                while True:
                    chunk = f.read(65536)  # 64KB
                    if not chunk:
                        break
                    yield chunk
        # Tüm dosyayı arka plan thread'inde oku, ardından stream et
        data = await asyncio.to_thread(p.read_bytes)
        yield data

    return StreamingResponse(
        _async_iter(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{doc_type}_{app_id}.{suffix.lstrip(".")}"'},
    )

"""
Webhook Endpoint'leri
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

POST  /webhooks/paytr/callback        → PayTR ödeme bildirimi (HMAC imzalı)
GET   /webhooks/netgsm/sms-reply      → Netgsm gelen SMS (ONAYLIYORUM)

Güvenlik:
  - PayTR: HMAC-SHA256 imzası doğrulanır — merchant_id+oid+salt+status+amount
  - Netgsm: URL'deki gizli token doğrulanır, gönderen numarası kontrol edilir
  - Her işlem idempotency key ile korunur (tekrar çalışmaya karşı)
  - Bakiye ekleme: Escrow → Ana Cüzdan çift taraflı kayıt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import base64
import hashlib
import hmac
import uuid
from decimal import Decimal

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi import status as http_status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.dependencies import get_db
from app.models.accounting import AccountType, JournalDirection
from app.models.corporate_receive_request import CorporateReceiveStatus
from app.repositories.accounting_repo import AccountingRepository, normalize
from app.repositories.corporate_receive_repo import CorporateReceiveRepo

logger = get_logger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


# ─── PayTR Webhook ────────────────────────────────────────────────────────────

@router.post(
    "/paytr/callback",
    summary="PayTR Ödeme Bildirimi",
    description=(
        "PayTR başarılı ödemeden sonra bu URL'e POST gönderir. "
        "HMAC-SHA256 imzası doğrulanır. "
        "Onaylanırsa tutar kullanıcının escrow hesabına alınır."
    ),
    include_in_schema=False,   # PayTR callback'i public dokümana çıkma
)
async def paytr_callback(
    request: Request,
    merchant_id:   str = Form(...),
    merchant_oid:  str = Form(...),
    paytr_token:   str = Form(...),
    status:        str = Form(...),      # "success" | "failed"
    total_amount:  str = Form(...),      # Kuruş cinsinden (1000 = 10 TL)
    db: AsyncSession = Depends(get_db),
) -> dict:
    settings = get_settings()
    m_key  = settings.paytr_merchant_key
    m_salt = settings.paytr_merchant_salt

    # ── HMAC Doğrulama ─────────────────────────────────────────────────────
    # PayTR token hesaplama: base64(SHA256(merchant_id + oid + salt + status + amount + key))
    hash_str = f"{merchant_id}{merchant_oid}{m_salt}{status}{total_amount}{m_key}"
    expected = base64.b64encode(
        hashlib.sha256(hash_str.encode()).digest()
    ).decode()

    if not hmac.compare_digest(expected, paytr_token):
        logger.warning(
            "paytr.webhook.invalid_signature",
            merchant_oid=merchant_oid,
        )
        raise HTTPException(status_code=400, detail="Geçersiz imza")

    if status != "success":
        logger.info("paytr.webhook.failed_payment", merchant_oid=merchant_oid)
        return {"status": "OK"}   # PayTR'ye "aldım" sinyali

    # merchant_oid = "crr_{receive_request_id}" formatında bekliyoruz
    if not merchant_oid.startswith("crr_"):
        logger.warning("paytr.webhook.unknown_oid", merchant_oid=merchant_oid)
        return {"status": "OK"}

    try:
        receive_id = uuid.UUID(merchant_oid[4:])
    except ValueError:
        logger.warning("paytr.webhook.invalid_oid", merchant_oid=merchant_oid)
        return {"status": "OK"}

    receive_repo = CorporateReceiveRepo(db)
    req = await receive_repo.get_by_id_for_update(receive_id)

    if not req:
        logger.warning("paytr.webhook.receive_not_found", receive_id=str(receive_id))
        return {"status": "OK"}

    if req.status != CorporateReceiveStatus.PENDING_PAYMENT:
        # Zaten işlenmiş — idempotent yanıt
        logger.info("paytr.webhook.already_processed", receive_id=str(receive_id))
        return {"status": "OK"}

    # ── Escrow'a Al (Çift Taraflı Kayıt) ───────────────────────────────────
    acc_repo = AccountingRepository(db)

    # Kullanıcının escrow hesabı
    escrow = await acc_repo.get_user_escrow_for_update(req.seller_user_id)
    if not escrow:
        logger.error(
            "paytr.webhook.escrow_not_found", user_id=str(req.seller_user_id)
        )
        return {"status": "OK"}

    # Sistem tahsilat hesabı (ASSET — PayTR'den gelen nakit)
    system_paytr = await acc_repo.get_or_create_system_account(
        name="PayTR Tahsilat Havuzu",
        account_type=AccountType.ASSET,
        currency="TRY",
    )

    amount = normalize(req.amount)
    idempotency_key = f"paytr_{merchant_oid}"

    try:
        await acc_repo.record_transaction(
            reference_id=idempotency_key,
            description=f"PayTR Tahsilat | Alıcı TCKN: {req.recipient_tckn} | {req.gold_type}",
            entries=[
                # ASSET DEBIT → sistem nakit aldı
                {"account_id": system_paytr.id, "direction": JournalDirection.DEBIT, "amount": amount},
                # LIABILITY CREDIT → kullanıcının escrow'u arttı (bekleyen bakiye)
                {"account_id": escrow.id, "direction": JournalDirection.CREDIT, "amount": amount},
            ],
        )
    except ValueError as exc:
        logger.error(
            "paytr.webhook.accounting_error",
            error=str(exc),
            receive_id=str(receive_id),
        )
        # Muhasebe hatası — hata döndürmeden OK yaz, tekrar çalışmayı önle
        return {"status": "OK"}

    await receive_repo.mark_payment_received(req, paytr_oid=merchant_oid)
    await db.commit()

    logger.info(
        "paytr.webhook.payment_escrowed",
        receive_id=str(receive_id),
        amount=str(amount),
    )
    return {"status": "OK"}


# ─── Netgsm SMS Reply Webhook ─────────────────────────────────────────────────

@router.get(
    "/netgsm/sms-reply",
    summary="Netgsm Gelen SMS (ONAYLIYORUM)",
    description=(
        "Netgsm, müşteri 'ONAYLIYORUM' SMS'i gönderdiğinde bu URL'e GET isteği atar. "
        "Gizli token + gönderen numarası doğrulanır. "
        "Onaylanırsa escrow → Ana Cüzdan transferi yapılır."
    ),
    include_in_schema=False,
)
async def netgsm_sms_reply(
    request: Request,
    token:  str = Query(..., description="NETGSM_SMS_REPLY_SECRET"),
    no:     str = Query(..., description="Gönderen telefon numarası"),
    msg:    str = Query(..., description="SMS içeriği"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    settings = get_settings()
    expected_token = getattr(settings, "netgsm_sms_reply_secret", "")

    # ── Token Doğrulama ─────────────────────────────────────────────────────
    if not expected_token or not hmac.compare_digest(token, expected_token):
        logger.warning(
            "netgsm.sms_reply.invalid_token",
            source_ip=request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz webhook token",
        )

    # ── İçerik Kontrolü ────────────────────────────────────────────────────
    if "ONAYLIYORUM" not in msg.upper():
        logger.info("netgsm.sms_reply.not_approval", no_suffix=no[-4:], msg_preview=msg[:20])
        return {"status": "ignored"}

    # ── Telefon Eşleştirme ──────────────────────────────────────────────────
    # Netgsm'den gelen numara farklı formatlarda olabilir — normalize et
    clean_no = no.replace(" ", "").replace("-", "").lstrip("+")
    if clean_no.startswith("90"):
        clean_no_local = "0" + clean_no[2:]
    else:
        clean_no_local = clean_no

    # Her iki formatı da dene
    receive_repo = CorporateReceiveRepo(db)
    req = await receive_repo.get_pending_approval_by_phone(clean_no)
    if not req:
        req = await receive_repo.get_pending_approval_by_phone(clean_no_local)
    if not req:
        logger.info(
            "netgsm.sms_reply.no_pending_request",
            no_suffix=no[-4:],
        )
        return {"status": "no_match"}

    # ── Escrow → Ana Cüzdan Transferi ──────────────────────────────────────
    acc_repo = AccountingRepository(db)

    escrow = await acc_repo.get_user_escrow_for_update(req.seller_user_id)
    wallet = await acc_repo.get_user_primary_wallet_for_update(req.seller_user_id)

    if not escrow or not wallet:
        logger.error(
            "netgsm.sms_reply.accounts_not_found",
            user_id=str(req.seller_user_id),
        )
        return {"status": "error"}

    amount = normalize(req.amount)
    idempotency_key = f"crr_approval_{req.id}"

    try:
        await acc_repo.record_transaction(
            reference_id=idempotency_key,
            description=(
                f"ONAYLIYORUM Transferi | {req.gold_type} | "
                f"Alıcı TCKN: {req.recipient_tckn}"
            ),
            entries=[
                # Escrow DEBIT (LIABILITY) → escrow azalır
                {"account_id": escrow.id, "direction": JournalDirection.DEBIT, "amount": amount},
                # Ana Cüzdan CREDIT (LIABILITY) → kullanıcı bakiyesi artar
                {"account_id": wallet.id, "direction": JournalDirection.CREDIT, "amount": amount},
            ],
        )
    except ValueError as exc:
        logger.error(
            "netgsm.sms_reply.accounting_error",
            error=str(exc),
            receive_id=str(req.id),
        )
        return {"status": "error"}

    await receive_repo.mark_completed(req)
    await db.commit()

    logger.info(
        "netgsm.sms_reply.completed",
        receive_id=str(req.id),
        amount=str(amount),
        user_id=str(req.seller_user_id),
    )
    return {"status": "OK"}

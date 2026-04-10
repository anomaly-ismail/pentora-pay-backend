"""
Ödeme Portalı — Müşteri Ödeme Sayfası
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

GET  /pay/{receive_id}          → Ödeme detay sayfası (HTML)
POST /pay/{receive_id}/confirm  → Mock ödeme onayı (test) — escrow'a alır
GET  /pay/{receive_id}/success  → Başarı sayfası
GET  /pay/{receive_id}/fail     → Başarısız ödeme sayfası

⚠️  /confirm endpoint'i yalnızca TEST/MOCK amaçlıdır.
    Üretimde PayTR'nin kendi callback'i (/api/v1/webhooks/paytr/callback)
    kullanılacak; bu endpoint kaldırılabilir veya feature flag ile korunabilir.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.dependencies import get_db
from app.models.accounting import AccountType, JournalDirection
from app.models.corporate_receive_request import CorporateReceiveStatus
from app.repositories.accounting_repo import AccountingRepository, normalize
from app.repositories.corporate_receive_repo import CorporateReceiveRepo

logger = get_logger(__name__)
router = APIRouter(prefix="/pay", tags=["Payment Portal"])

# ─── HTML şablon yardımcıları ─────────────────────────────────────────────────

_BASE_STYLE = """
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d0f14;color:#e8e9ec;font-family:'Segoe UI',system-ui,sans-serif;
       min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
  .card{background:#161920;border:1px solid #2a2d38;border-radius:16px;
        max-width:460px;width:100%;padding:32px 28px}
  .logo{display:flex;align-items:center;gap:10px;margin-bottom:28px}
  .logo-mark{width:38px;height:38px;background:linear-gradient(135deg,#c9a84c,#f0d080);
             border-radius:8px;display:flex;align-items:center;justify-content:center;
             font-weight:900;font-size:16px;color:#0d0f14}
  .logo-text{font-size:17px;font-weight:700;color:#f0d080}
  .logo-sub{font-size:11px;color:#8a8d9a;margin-left:2px}
  h2{font-size:20px;font-weight:700;color:#f0d080;margin-bottom:6px}
  .subtitle{font-size:13px;color:#8a8d9a;margin-bottom:24px}
  .amount-box{background:linear-gradient(135deg,#1c1f28,#1a1e25);
              border:1px solid rgba(201,168,76,0.3);border-radius:12px;
              padding:20px 22px;margin-bottom:20px;text-align:center}
  .amount-label{font-size:11px;color:#8a8d9a;text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}
  .amount-value{font-size:32px;font-weight:800;color:#f0d080}
  .amount-currency{font-size:16px;color:#c9a84c;margin-left:4px}
  .detail-row{display:flex;justify-content:space-between;align-items:center;
              padding:10px 0;border-bottom:1px solid #1e2130}
  .detail-row:last-child{border-bottom:none}
  .detail-label{font-size:12px;color:#8a8d9a}
  .detail-value{font-size:13px;color:#c8cad4;font-weight:500;text-align:right;max-width:60%}
  .details-card{background:#111318;border:1px solid #1e2130;border-radius:10px;
                padding:4px 14px;margin-bottom:22px}
  .btn{display:block;width:100%;padding:15px;border:none;border-radius:10px;
       font-size:15px;font-weight:700;cursor:pointer;text-align:center;
       text-decoration:none;transition:opacity .15s}
  .btn-pay{background:linear-gradient(135deg,#c9a84c,#f0d080);color:#0d0f14}
  .btn-pay:hover{opacity:.9}
  .btn-fail{background:#1e2130;color:#8a8d9a;border:1px solid #2a2d38;margin-top:10px;font-size:13px}
  .btn-fail:hover{opacity:.8}
  .badge{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;
         border-radius:999px;font-size:11px;font-weight:600;margin-bottom:18px}
  .badge-test{background:rgba(255,171,64,.12);color:#ffab40;border:1px solid rgba(255,171,64,.3)}
  .badge-ok{background:rgba(105,240,174,.1);color:#69f0ae;border:1px solid rgba(105,240,174,.25)}
  .badge-err{background:rgba(239,83,80,.1);color:#ef5350;border:1px solid rgba(239,83,80,.25)}
  .icon{font-size:48px;margin-bottom:16px;display:block;text-align:center}
  .result-title{font-size:22px;font-weight:700;text-align:center;margin-bottom:8px}
  .result-sub{font-size:13px;color:#8a8d9a;text-align:center;line-height:1.6;margin-bottom:24px}
  .info-box{background:#111318;border:1px solid rgba(201,168,76,.2);border-radius:10px;
            padding:14px 16px;margin-bottom:20px;font-size:13px;color:#c8cad4;line-height:1.6}
  .step-list{list-style:none;padding:0;margin:0}
  .step-list li{display:flex;align-items:flex-start;gap:10px;padding:8px 0;
                border-bottom:1px solid #1e2130;font-size:13px;color:#8a8d9a}
  .step-list li:last-child{border-bottom:none}
  .step-num{background:rgba(201,168,76,.15);color:#f0d080;border-radius:999px;
            min-width:22px;height:22px;display:flex;align-items:center;
            justify-content:center;font-size:11px;font-weight:700;margin-top:1px}
  .secure-bar{display:flex;align-items:center;justify-content:center;gap:6px;
              margin-top:20px;font-size:11px;color:#4a4d5a}
  .sep{color:#2a2d38}
  form{margin:0}
</style>
"""


def _html(body: str, title: str = "Pentora Pay — Ödeme") -> HTMLResponse:
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  {_BASE_STYLE}
</head>
<body>{body}</body>
</html>""")


def _fmt_amount(amount: Decimal) -> str:
    return f"{float(amount):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


# ─── GET /pay/{receive_id} ────────────────────────────────────────────────────

@router.get("/{receive_id}", response_class=HTMLResponse, include_in_schema=False)
async def payment_page(
    receive_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    repo = CorporateReceiveRepo(db)
    req  = await repo.get_by_id(receive_id)

    if not req:
        return _html("""
          <div class="card">
            <div class="logo"><div class="logo-mark">P</div>
              <div><div class="logo-text">Pentora Pay</div><div class="logo-sub">Güvenli Ödeme</div></div>
            </div>
            <span class="icon">❌</span>
            <p class="result-title" style="color:#ef5350">Bağlantı Bulunamadı</p>
            <p class="result-sub">Bu ödeme bağlantısı geçersiz veya süresi dolmuş.</p>
          </div>
        """, "Bağlantı Geçersiz")

    if req.status == CorporateReceiveStatus.EXPIRED:
        return _html("""
          <div class="card">
            <div class="logo"><div class="logo-mark">P</div>
              <div><div class="logo-text">Pentora Pay</div><div class="logo-sub">Güvenli Ödeme</div></div>
            </div>
            <span class="icon">⏰</span>
            <p class="result-title" style="color:#ffab40">Süre Doldu</p>
            <p class="result-sub">Bu ödeme talebinin geçerlilik süresi dolmuştur.<br>Lütfen kuyumcu ile tekrar iletişime geçin.</p>
          </div>
        """, "Süre Doldu")

    if req.status == CorporateReceiveStatus.COMPLETED:
        return _html(f"""
          <div class="card">
            <div class="logo"><div class="logo-mark">P</div>
              <div><div class="logo-text">Pentora Pay</div><div class="logo-sub">Güvenli Ödeme</div></div>
            </div>
            <span class="icon">✅</span>
            <p class="result-title" style="color:#69f0ae">Ödeme Tamamlandı</p>
            <p class="result-sub">Bu ödeme zaten başarıyla tamamlanmıştır.<br>
              <strong style="color:#f0d080">{_fmt_amount(req.amount)} TL</strong> tutarındaki işlem onaylandı.</p>
          </div>
        """, "Ödeme Tamamlandı")

    if req.status == CorporateReceiveStatus.PENDING_APPROVAL:
        return _html(f"""
          <div class="card">
            <div class="logo"><div class="logo-mark">P</div>
              <div><div class="logo-text">Pentora Pay</div><div class="logo-sub">Güvenli Ödeme</div></div>
            </div>
            <span class="icon">⏳</span>
            <p class="result-title" style="color:#f0d080">Ödeme Alındı</p>
            <p class="result-sub">Ödemeniz alındı. Ürünü teslim aldıktan sonra<br>
              SMS'e <strong style="color:#69f0ae">ONAYLIYORUM</strong> yazarak işlemi tamamlayın.</p>
            <div class="info-box">
              Ödeme tutarı: <strong style="color:#f0d080">{_fmt_amount(req.amount)} TL</strong><br>
              Ürün: {req.gold_type}
            </div>
          </div>
        """, "Ödeme Onay Bekleniyor")

    # PENDING_PAYMENT — expiry kontrolü
    if req.expires_at and datetime.now(timezone.utc) > req.expires_at:
        # Veritabanında durumu da güncelle
        req.status = CorporateReceiveStatus.EXPIRED
        await db.commit()
        return _html("""
          <div class="card">
            <div class="logo"><div class="logo-mark">P</div>
              <div><div class="logo-text">Pentora Pay</div><div class="logo-sub">Güvenli Ödeme</div></div>
            </div>
            <span class="icon">⏰</span>
            <p class="result-title" style="color:#ffab40">Süre Doldu</p>
            <p class="result-sub">Bu ödeme bağlantısının 5 dakikalık geçerlilik süresi dolmuştur.<br>
              Lütfen kuyumcu ile tekrar iletişime geçin.</p>
          </div>
        """, "Süre Doldu")

    # PENDING_PAYMENT — ödeme sayfasını göster
    is_mock = not (settings.paytr_merchant_id and settings.paytr_merchant_key)
    mock_badge = (
        '<span class="badge badge-test">⚠ TEST MODU — Gerçek para çekilmez</span>'
        if is_mock else ""
    )

    tckn_masked = req.recipient_tckn[:3] + "****" + req.recipient_tckn[-4:] \
        if req.recipient_tckn and len(req.recipient_tckn) >= 8 else "—"

    return _html(f"""
      <div class="card">
        <div class="logo">
          <div class="logo-mark">P</div>
          <div><div class="logo-text">Pentora Pay</div>
               <div class="logo-sub">Güvenli Ödeme Sistemi</div></div>
        </div>

        {mock_badge}

        <h2>Ödeme Talebi</h2>
        <p class="subtitle">Altın alım işlemi için ödeme onayı</p>

        <div class="amount-box">
          <div class="amount-label">Ödenecek Tutar</div>
          <div>
            <span class="amount-value">{_fmt_amount(req.amount)}</span>
            <span class="amount-currency">TL</span>
          </div>
        </div>

        <div class="details-card">
          <div class="detail-row">
            <span class="detail-label">Ürün</span>
            <span class="detail-value">{req.gold_type}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Miktar</span>
            <span class="detail-value">{float(req.gold_gram):g} Gram</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">T.C. Kimlik</span>
            <span class="detail-value">{tckn_masked}</span>
          </div>
        </div>

        <div class="info-box">
          <ul class="step-list">
            <li><span class="step-num">1</span>Aşağıdaki butona tıklayarak ödemeyi tamamlayın.</li>
            <li><span class="step-num">2</span>Ödeme onaylandıktan sonra ürünü kuyumcudan teslim alın.</li>
            <li><span class="step-num">3</span>SMS'e <strong style="color:#69f0ae">ONAYLIYORUM</strong> yazın — işlem kapanır.</li>
          </ul>
        </div>

        <form method="POST" action="/pay/{receive_id}/confirm">
          <button type="submit" class="btn btn-pay">
            {'🧪 Mock Ödeme Yap (Test)' if is_mock else '🔒 Güvenli Ödeme Yap'}
          </button>
        </form>

        <form method="POST" action="/pay/{receive_id}/confirm?fail=1">
          <button type="submit" class="btn btn-fail">Ödemeyi İptal Et</button>
        </form>

        <div class="secure-bar">
          🔒 SSL Şifreli
          <span class="sep">|</span>
          Pentora Pay Güvencesi
          <span class="sep">|</span>
          256-bit TLS
        </div>
      </div>
    """, "Pentora Pay — Ödeme")


# ─── POST /pay/{receive_id}/confirm ──────────────────────────────────────────

@router.post("/{receive_id}/confirm", response_class=HTMLResponse, include_in_schema=False)
async def confirm_payment(
    receive_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """
    Mock PayTR onayı:
    - PENDING_PAYMENT → PENDING_APPROVAL
    - Tutarı kullanıcının escrow hesabına ekler
    - Gerçek PayTR'de bu işi /webhooks/paytr/callback yapar
    """
    fail = request.query_params.get("fail") == "1"

    if fail:
        return RedirectResponse(f"/pay/{receive_id}/fail", status_code=303)

    repo = CorporateReceiveRepo(db)
    req  = await repo.get_by_id_for_update(receive_id)

    if not req:
        return RedirectResponse(f"/pay/{receive_id}/fail", status_code=303)

    if req.status != CorporateReceiveStatus.PENDING_PAYMENT:
        # Zaten işlenmiş — başarı sayfasına yönlendir
        return RedirectResponse(f"/pay/{receive_id}/success", status_code=303)

    # ── Escrow'a Al ──────────────────────────────────────────────────────────
    acc_repo    = AccountingRepository(db)
    escrow      = await acc_repo.get_user_escrow_for_update(req.seller_user_id)
    system_acct = await acc_repo.get_or_create_system_account(
        name="PayTR Tahsilat Havuzu",
        account_type=AccountType.ASSET,
        currency="TRY",
    )

    if not escrow:
        logger.error("payment_portal.mock.escrow_not_found",
                     user_id=str(req.seller_user_id))
        return RedirectResponse(f"/pay/{receive_id}/fail", status_code=303)

    amount          = normalize(req.amount)
    mock_paytr_oid  = f"mock_{receive_id}"
    idempotency_key = f"paytr_{mock_paytr_oid}"

    try:
        await acc_repo.record_transaction(
            reference_id=idempotency_key,
            description=f"[MOCK] PayTR Tahsilat | {req.gold_type} | TCKN: {req.recipient_tckn}",
            entries=[
                # Sistem nakit aldı (ASSET DEBIT)
                {"account_id": system_acct.id, "direction": JournalDirection.DEBIT,  "amount": amount},
                # Satıcının escrow'u arttı (LIABILITY CREDIT)
                {"account_id": escrow.id,      "direction": JournalDirection.CREDIT, "amount": amount},
            ],
        )
    except ValueError as exc:
        logger.error("payment_portal.mock.accounting_error", error=str(exc))
        return RedirectResponse(f"/pay/{receive_id}/fail", status_code=303)

    await repo.mark_payment_received(req, paytr_oid=mock_paytr_oid)
    await db.commit()

    logger.info("payment_portal.mock.escrowed",
                receive_id=str(receive_id), amount=str(amount))

    return RedirectResponse(f"/pay/{receive_id}/success", status_code=303)


# ─── GET /pay/{receive_id}/success ───────────────────────────────────────────

@router.get("/{receive_id}/success", response_class=HTMLResponse, include_in_schema=False)
async def success_page(
    receive_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    settings_obj = get_settings()
    is_mock = not (settings_obj.paytr_merchant_id and settings_obj.paytr_merchant_key)

    repo = CorporateReceiveRepo(db)
    req  = await repo.get_by_id(receive_id)
    amount_str = _fmt_amount(req.amount) if req else "—"
    phone_masked = ("***" + req.recipient_phone[-4:]) if req and req.recipient_phone else "—"

    # Zaten tamamlandıysa ayrı mesaj göster
    if req and req.status == CorporateReceiveStatus.COMPLETED:
        return _html(f"""
          <div class="card">
            <div class="logo"><div class="logo-mark">P</div>
              <div><div class="logo-text">Pentora Pay</div><div class="logo-sub">Güvenli Ödeme</div></div>
            </div>
            <span class="icon">🎉</span>
            <p class="result-title" style="color:#69f0ae">İşlem Tamamlandı!</p>
            <p class="result-sub">
              <strong style="color:#f0d080">{amount_str} TL</strong> kuyumcunun hesabına aktarıldı.<br>
              Teşekkür ederiz.
            </p>
          </div>
        """, "İşlem Tamamlandı")

    mock_block = ""
    if is_mock:
        mock_block = f"""
        <form method="POST" action="/pay/{receive_id}/mock-approve" style="margin-top:22px">
          <p style="color:#ffab40;font-size:12px;margin-bottom:10px;text-align:center">
            ⚠ TEST MODU — Ürünü teslim aldınız mı?
          </p>
          <button type="submit" class="btn btn-pay" style="
            background:linear-gradient(135deg,#2e7d32,#1b5e20);
            border:1px solid #4caf50;
            font-size:16px;font-weight:700;letter-spacing:.5px;
            display:block;width:100%;text-align:center;
          ">
            ✅ Mock — ONAYLIYORUM Gönder
          </button>
        </form>"""

    return _html(f"""
      <div class="card">
        <div class="logo">
          <div class="logo-mark">P</div>
          <div><div class="logo-text">Pentora Pay</div>
               <div class="logo-sub">Güvenli Ödeme Sistemi</div></div>
        </div>

        <span class="badge badge-ok">✓ Ödeme Alındı</span>

        <span class="icon">✅</span>
        <p class="result-title" style="color:#69f0ae">Ödeme Başarılı!</p>
        <p class="result-sub">
          <strong style="color:#f0d080">{amount_str} TL</strong> tutarındaki ödemeniz alındı.<br>
          Ödemeniz güvende — kuyumcu onayı bekleniyor.
        </p>

        <div class="info-box">
          <strong style="color:#f0d080">Son bir adım kaldı:</strong><br><br>
          Ürünü kuyumcudan teslim aldıktan sonra,<br>
          <strong style="color:#c8cad4">{phone_masked}</strong> numarasına gelen SMS'e:<br><br>
          <span style="font-size:18px;font-weight:800;color:#69f0ae;letter-spacing:1px">ONAYLIYORUM</span><br><br>
          yazarak gönderin. İşleminiz tamamlanacaktır.
        </div>

        {mock_block}

        <div class="secure-bar">
          🔒 Paranız güvende — kuyumcu teslim sonrası serbest bırakır
        </div>
      </div>
    """, "Ödeme Başarılı")


# ─── POST /pay/{receive_id}/mock-approve ─────────────────────────────────────
# Sadece test modunda çalışır (PayTR credentials yoksa). ONAYLIYORUM webhook'unu simüle eder.

@router.post("/{receive_id}/mock-approve", include_in_schema=False)
async def mock_approve(
    receive_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    settings_obj = get_settings()
    is_mock = not (settings_obj.paytr_merchant_id and settings_obj.paytr_merchant_key)
    if not is_mock:
        # Gerçek prod ortamında bu endpoint devre dışı
        return RedirectResponse(f"/pay/{receive_id}/success", status_code=303)

    repo     = CorporateReceiveRepo(db)
    acc_repo = AccountingRepository(db)

    req = await repo.get_by_id_for_update(receive_id)
    if not req:
        return RedirectResponse(f"/pay/{receive_id}/fail", status_code=303)
    if req.status == CorporateReceiveStatus.COMPLETED:
        return RedirectResponse(f"/pay/{receive_id}/success", status_code=303)
    if req.status != CorporateReceiveStatus.PENDING_APPROVAL:
        logger.warning("payment_portal.mock_approve.wrong_status",
                       receive_id=str(receive_id), status=req.status.value)
        return RedirectResponse(f"/pay/{receive_id}/success", status_code=303)

    # Escrow → Ana Cüzdan (webhooks.py'deki ONAYLIYORUM mantığını aynen uygula)
    escrow = await acc_repo.get_user_escrow_for_update(req.seller_user_id)
    wallet = await acc_repo.get_user_primary_wallet_for_update(req.seller_user_id)

    if not escrow or not wallet:
        logger.error("payment_portal.mock_approve.accounts_missing",
                     receive_id=str(receive_id))
        return RedirectResponse(f"/pay/{receive_id}/fail", status_code=303)

    amount            = normalize(req.amount)
    idempotency_key   = f"mock_approve_{receive_id}"

    try:
        await acc_repo.record_transaction(
            reference_id=idempotency_key,
            description=f"[MOCK] Müşteri Onayı | {req.gold_type} | TCKN: {req.recipient_tckn}",
            entries=[
                # Escrow azaldı (LIABILITY DEBIT)
                {"account_id": escrow.id, "direction": JournalDirection.DEBIT,  "amount": amount},
                # Ana cüzdan arttı (LIABILITY CREDIT)
                {"account_id": wallet.id, "direction": JournalDirection.CREDIT, "amount": amount},
            ],
        )
    except ValueError as exc:
        logger.error("payment_portal.mock_approve.accounting_error", error=str(exc))
        return RedirectResponse(f"/pay/{receive_id}/fail", status_code=303)

    await repo.mark_completed(req)
    await db.commit()

    logger.info("payment_portal.mock_approve.completed",
                receive_id=str(receive_id), amount=str(amount))

    return RedirectResponse(f"/pay/{receive_id}/success", status_code=303)


# ─── GET /pay/{receive_id}/fail ───────────────────────────────────────────────

@router.get("/{receive_id}/fail", response_class=HTMLResponse, include_in_schema=False)
async def fail_page(receive_id: uuid.UUID) -> HTMLResponse:
    return _html(f"""
      <div class="card">
        <div class="logo">
          <div class="logo-mark">P</div>
          <div><div class="logo-text">Pentora Pay</div>
               <div class="logo-sub">Güvenli Ödeme Sistemi</div></div>
        </div>

        <span class="badge badge-err">✗ Ödeme Başarısız</span>

        <span class="icon">❌</span>
        <p class="result-title" style="color:#ef5350">Ödeme Yapılamadı</p>
        <p class="result-sub">
          İşleminiz tamamlanamadı veya iptal edildi.<br>
          Hiçbir ücret tahsil edilmedi.
        </p>

        <div class="info-box">
          Tekrar denemek için kuyumcudan yeni bir ödeme bağlantısı talep edin
          veya ödeme bağlantısına geri dönün.
        </div>

        <a href="/pay/{receive_id}" class="btn btn-pay" style="text-align:center;display:block;">
          ← Ödeme Sayfasına Dön
        </a>

        <div class="secure-bar">
          🔒 SSL Şifreli <span class="sep">|</span> Pentora Pay Güvencesi
        </div>
      </div>
    """, "Ödeme Başarısız")

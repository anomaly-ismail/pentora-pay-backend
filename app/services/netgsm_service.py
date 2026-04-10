"""
Netgsm SMS Servisi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OTP SMS gönderimi için Netgsm API entegrasyonu.
API belgesi: https://www.netgsm.com.tr/dokuman/#http-api-sms

Ortam değişkenleri (.env):
  NETGSM_USERCODE   — Netgsm kullanıcı kodu (API hesabı)
  NETGSM_PASSWORD   — Netgsm şifresi
  NETGSM_HEADER     — Gönderici başlığı (maks 11 karakter)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import httpx
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_NETGSM_API_URL = "https://api.netgsm.com.tr/sms/send/get"


async def send_otp_sms(*, phone: str, otp_code: str) -> bool:
    """
    Verilen numaraya OTP SMS gönderir.
    Başarı → True, herhangi bir hata → False (işlemi durdurmaz, log düşer).

    phone: Uluslararası veya yerel format (905xxxxxxxxx ya da 05xxxxxxxxx)
    otp_code: 6 haneli OTP kodu
    """
    settings = get_settings()

    usercode = getattr(settings, "netgsm_usercode", "")
    password = getattr(settings, "netgsm_password", "")
    header   = getattr(settings, "netgsm_header", "PentoraPay")

    if not usercode or not password:
        logger.warning(
            "netgsm.otp.skipped",
            reason="Netgsm kimlik bilgileri ayarlanmamış. OTP gönderilmedi.",
            phone=phone[-4:],
            dev_otp=f"[DEV MODE] Generated OTP: {otp_code}",
        )
        return False

    # Netgsm için numara temizle (başındaki 0 varsa 9'lu formata çevir)
    cleaned = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if cleaned.startswith("0"):
        cleaned = "90" + cleaned[1:]
    elif not cleaned.startswith("+") and not cleaned.startswith("90"):
        cleaned = "90" + cleaned

    message = f"Pentora Pay OTP kodunuz: {otp_code}. Bu kodu kimseyle paylasmayiniz. Gecerlilik: 10 dakika."

    params = {
        "usercode": usercode,
        "password": password,
        "gsmno": cleaned,
        "message": message,
        "msgheader": header,
        "dil": "TR",
    }

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(_NETGSM_API_URL, params=params)
        response_text = response.text.strip()

        if response_text.startswith("00"):
            logger.info("netgsm.otp.sent", phone_suffix=phone[-4:])
            return True
        else:
            logger.error("netgsm.otp.failed", code=response_text, phone_suffix=phone[-4:])
            return False

    except Exception as exc:
        logger.error("netgsm.otp.exception", error=str(exc), phone_suffix=phone[-4:])
        return False

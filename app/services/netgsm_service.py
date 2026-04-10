"""
Netgsm SMS Servisi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OTP ve serbest metin SMS gönderimi için Netgsm API entegrasyonu.
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


def _clean_phone(phone: str) -> str:
    """Telefon numarasını Netgsm 905xxxxxxxxx formatına dönüştürür."""
    cleaned = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if cleaned.startswith("0"):
        cleaned = "90" + cleaned[1:]
    elif not cleaned.startswith("+") and not cleaned.startswith("90"):
        cleaned = "90" + cleaned
    return cleaned.lstrip("+")


async def _send_sms(*, phone: str, message: str, log_tag: str) -> bool:
    """
    Netgsm'e SMS gönderir. Kimlik bilgileri yoksa dev modda loglar.
    Başarı → True, herhangi bir hata → False.
    """
    settings = get_settings()

    usercode = getattr(settings, "netgsm_usercode", "")
    password = getattr(settings, "netgsm_password", "")
    header   = getattr(settings, "netgsm_header", "PentoraPay")

    if not usercode or not password:
        logger.warning(
            f"netgsm.{log_tag}.skipped",
            reason="Netgsm kimlik bilgileri ayarlanmamış. SMS gönderilmedi.",
            phone=phone[-4:],
            dev_message=f"[DEV MODE] SMS to ...{phone[-4:]}: {message}",
        )
        return False

    params = {
        "usercode": usercode,
        "password": password,
        "gsmno": _clean_phone(phone),
        "message": message,
        "msgheader": header,
        "dil": "TR",
    }

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(_NETGSM_API_URL, params=params)
        response_text = response.text.strip()

        if response_text.startswith("00"):
            logger.info(f"netgsm.{log_tag}.sent", phone_suffix=phone[-4:])
            return True
        else:
            logger.error(
                f"netgsm.{log_tag}.failed", code=response_text, phone_suffix=phone[-4:]
            )
            return False

    except Exception as exc:
        logger.error(
            f"netgsm.{log_tag}.exception", error=str(exc), phone_suffix=phone[-4:]
        )
        return False


async def send_otp_sms(*, phone: str, otp_code: str) -> bool:
    """
    Verilen numaraya OTP SMS gönderir.
    phone: Uluslararası veya yerel format (905xxxxxxxxx ya da 05xxxxxxxxx)
    """
    message = (
        f"Pentora Pay OTP kodunuz: {otp_code}. "
        "Bu kodu kimseyle paylasmayiniz. Gecerlilik: 10 dakika."
    )
    return await _send_sms(phone=phone, message=message, log_tag="otp")


async def send_payment_request_sms(
    *,
    phone: str,
    amount_str: str,
    payment_id: str,
) -> bool:
    """
    Ödeme alma talebi SMS'i gönderir.
    Müşteriye ödeme linki ve onay talimatı iletilir.
    """
    settings = get_settings()
    portal_url = getattr(settings, "payment_portal_url", "https://pentorasec.online/pay")
    pay_link = f"{portal_url}/{payment_id}"

    message = (
        f"{amount_str} TL tutarinda odeme talebi olusmustur. "
        f"Asagidaki linkten odemeyi yapiniz. "
        f"Odemeyi yaptiktan sonra, satin aldiginiz urunu teslim aliniz "
        f"ve bu SMS'e ONAYLIYORUM yaziniz.\n"
        f"Link: {pay_link}"
    )
    return await _send_sms(phone=phone, message=message, log_tag="payment_request")

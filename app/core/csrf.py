"""
CSRF (Cross-Site Request Forgery) Korumaları (M-21)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pentora Pay ödeme portalı POST uçları (`/pay/{id}/confirm`, `/pay/{id}/mock-approve`,
`/webhooks/...` HARİÇ) tarayıcıdan kullanıcı etkileşimiyle tetiklenir. Bu uçlar
herhangi bir kullanıcı kimlik doğrulama cookie'si taşımasa bile, **idempotent
olmayan** iş mantığı (escrow movement, mark_payment_received) yürütür ve UUID
zaten link kanalıyla bilinir. Saldırgan kullanıcıyı kötü niyetli bir sayfaya
çekerse `<form>` POST ile mock onayı tetikleyebilir.

Bu modül üç katman koruma sağlar:

1. **Origin / Referer allowlist** (en hızlı, ilk savunma)
   - Browser'lar POST için Origin header'ını otomatik gönderir; XHR/fetch ise
     Origin'i daima ekler.
   - Allowlist `Settings.csrf_allowed_origins_list`'ten okunur (CORS allowlist
     fallback).
   - Origin yoksa Referer'ın scheme+host'u kontrol edilir.

2. **Webhook bypass**: PayTR/Netgsm sunucu-sunucu çağrıları için bu kontrol
   yapılmaz; o uçların kendi imza/HMAC doğrulaması vardır.

3. **Same-site cookie zaten var** (admin panelinde): admin oturumu
   `samesite="strict"` cookie ile tutulur (H-12); admin endpoint'leri için bu
   modüle gerek yok.

NOT: PCI-DSS Req 6.5.9 ve OWASP A01-Broken Access Control için "defense in
depth" bileşenidir; tek başına CSRF token yerine geçmez ama mevcut akış için
yeterlidir (POST sonrası 303 redirect → ek state mutation yok).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import HTTPException, Request, status

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def _origin_of(value: str) -> str | None:
    """`scheme://host[:port]` döndürür; geçersizse None."""
    if not value:
        return None
    try:
        parts = urlsplit(value.strip())
        if not parts.scheme or not parts.netloc:
            return None
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}".rstrip("/")
    except Exception:
        return None


def assert_same_origin(request: Request) -> None:
    """
    M-21: Origin/Referer'ı CSRF allowlist'e karşı doğrula.

    Reject davranışı: 403 Forbidden — bilgi sızıntısını minimumda tutmak için
    detail mesajı sabit ve generic ("Forbidden").

    Allowlist boş tanımlanmışsa (örn. tüm CORS açık) yine de en azından bir
    Origin/Referer header'ı bulunmasını ister; tamamen başlıksız POST'ları
    reddeder (curl/script'le yapılan saldırılar engellenir).
    """
    settings = get_settings()
    allowed = {o.lower() for o in settings.csrf_allowed_origins_list}

    raw_origin = request.headers.get("origin", "")
    raw_referer = request.headers.get("referer", "")

    candidate = _origin_of(raw_origin) or _origin_of(raw_referer)

    if candidate is None:
        logger.warning(
            "csrf.missing_origin",
            path=request.url.path,
            method=request.method,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if allowed and candidate not in allowed:
        logger.warning(
            "csrf.origin_not_allowed",
            path=request.url.path,
            origin=candidate,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


__all__ = ["assert_same_origin"]

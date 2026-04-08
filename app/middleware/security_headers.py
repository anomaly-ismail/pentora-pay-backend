"""
Global Güvenlik Header'ları Middleware
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Her HTTP yanıtına aşağıdaki header grupları eklenir:

  [A] Standart Tarayıcı Güvenlik Header'ları (OWASP Top 10 / ISO 27001 A.14)
  [B] Bilgi Sızıntısı Önleme (Server, X-Powered-By kaldırma)
  [C] X-Pentora-Signature  — İstek/Yanıt bütünlük imzası
  [D] X-Pentora-SQL        — SQL enjeksiyon tarama sonucu
  [E] X-Pentora-GRAuth     — Genel istek doğrulama durumu
  [F] İzlenebilirlik       — X-Request-ID, X-Response-Time

Middleware uygulama sırası (main.py'de ters sıra ile eklenir):
  1. RequestIDMiddleware     → istek kimliği üretimi
  2. AuditLogMiddleware      → istek/yanıt loglaması
  3. RateLimitMiddleware     → hız sınırlama
  4. SecurityHeadersMiddleware → bu dosya
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import (
    generate_signature,
    scan_for_sql_injection,
    verify_signature,
)

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# [A+B+C+D+E+F] Ana Güvenlik Header Middleware
# ─────────────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Tüm yanıtlara kapsamlı güvenlik header'ları ekler.

    Uygulanan standartlar:
      - OWASP Top 10 (A05: Security Misconfiguration)
      - ISO 27001 Annex A.14 (System Acquisition, Development and Maintenance)
      - OWASP Secure Headers Project önerileri
      - Mozilla Observatory önerileri
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        t0 = time.perf_counter()

        # multipart/form-data body'sini ASLA okuma — multipart parser'ı bozar
        content_type = request.headers.get("content-type", "")
        is_multipart = "multipart/form-data" in content_type or "application/octet-stream" in content_type

        if is_multipart:
            body = b""  # Binary body taranmaz, boş geç
        else:
            # İstek gövdesini oku (imza ve SQL taraması için)
            body = await request.body()

        # ── [D] SQL Taraması ────────────────────────────────────────────────
        sql_scan_result = _perform_sql_scan(request, body)

        # İsteği işle
        response: Response = await call_next(request)

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        # ── [A] Standart Tarayıcı Güvenlik Header'ları ─────────────────────
        _apply_standard_headers(response, self.settings)

        # ── [B] Bilgi Sızıntısı Önleme ─────────────────────────────────────
        _remove_disclosure_headers(response)

        # ── [C] X-Pentora-Signature ─────────────────────────────────────────
        _apply_pentora_signature(response, request, body)

        # ── [D] X-Pentora-SQL ───────────────────────────────────────────────
        response.headers["X-Pentora-SQL"] = sql_scan_result.to_header_value()

        # ── [E] X-Pentora-GRAuth ────────────────────────────────────────────
        _apply_pentora_grauth(response, request)

        # ── [F] İzlenebilirlik ──────────────────────────────────────────────
        request_id = request.state.__dict__.get("request_id", "n/a")
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{elapsed_ms}ms"

        return response


# ─────────────────────────────────────────────────────────────────────────────
# [A] Standart Header Uygulayıcıları
# ─────────────────────────────────────────────────────────────────────────────

def _apply_standard_headers(response: Response, settings) -> None:
    """
    OWASP Secure Headers Project ve Mozilla Observatory'ye göre
    tüm standart güvenlik header'larını ekler.
    """
    h = response.headers

    # ── Transport Security (OWASP A02, ISO 27001 A.10) ──────────────────────
    # HSTS — yalnızca HTTPS üzerinden erişimi zorlar (üretimde)
    if settings.is_production:
        h["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
    else:
        # Geliştirmede daha kısa süre, subdomains yok
        h["Strict-Transport-Security"] = "max-age=3600"

    # ── Content Type (OWASP A05) ─────────────────────────────────────────────
    # MIME-sniffing saldırılarını önler
    h["X-Content-Type-Options"] = "nosniff"

    # ── Clickjacking Koruması (OWASP A05) ───────────────────────────────────
    # Sayfanın iframe içine alınmasını engeller
    h["X-Frame-Options"] = "DENY"

    # ── Content Security Policy (OWASP A05, ISO 27001 A.14) ─────────────────
    # API için katı CSP — sadece kendi origin'den yükleme
    h["Content-Security-Policy"] = (
        "default-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "upgrade-insecure-requests"
    )

    # ── XSS Koruması (eski tarayıcılar için) ────────────────────────────────
    # Modern tarayıcılarda CSP yeterli; 0 = tarayıcı XSS filtrini devre dışı
    # bırak çünkü yanlış pozitif riski var, CSP bunu karşılar
    h["X-XSS-Protection"] = "0"

    # ── Referrer Policy (OWASP A01, ISO 27001 A.13) ─────────────────────────
    # Hassas URL parametrelerinin Referer header'ında sızdırılmasını önler
    h["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # ── Permissions Policy (Feature Policy) ─────────────────────────────────
    # Gereksiz tarayıcı API'larını devre dışı bırakır
    h["Permissions-Policy"] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=(), "
        "payment=(), "
        "usb=(), "
        "bluetooth=(), "
        "accelerometer=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "ambient-light-sensor=()"
    )

    # ── Cache Kontrolü (ISO 27001 A.13) ─────────────────────────────────────
    # API yanıtlarının önbelleklenmesini engeller — hassas veri sızıntısını önler
    h["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    h["Pragma"] = "no-cache"
    h["Expires"] = "0"

    # ── Cross-Origin Politikaları ────────────────────────────────────────────
    # Spectre / Meltdown yan kanal saldırılarına karşı izolasyon
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Cross-Origin-Embedder-Policy"] = "require-corp"

    # ── DNS Prefetch Kontrolü ────────────────────────────────────────────────
    h["X-DNS-Prefetch-Control"] = "off"

    # ── Download Options (IE için) ───────────────────────────────────────────
    h["X-Download-Options"] = "noopen"

    # ── Permitted Cross-Domain Policies ────────────────────────────────────
    h["X-Permitted-Cross-Domain-Policies"] = "none"


# ─────────────────────────────────────────────────────────────────────────────
# [B] Bilgi Sızıntısı Önleme
# ─────────────────────────────────────────────────────────────────────────────

def _remove_disclosure_headers(response: Response) -> None:
    """
    Sunucu teknolojisi hakkında bilgi sızdıran header'ları kaldırır.
    OWASP A05: Security Misconfiguration — Information Leakage
    ISO 27001 A.14.2: System Security in Development and Support
    """
    for header in ("Server", "X-Powered-By", "X-AspNet-Version",
                   "X-AspNetMvc-Version", "Via"):
        if header in response.headers:
            del response.headers[header]

    # Sunucu bilgisini genel bir değerle maskele
    response.headers["Server"] = "GuvenlIOdeme"


# ─────────────────────────────────────────────────────────────────────────────
# [C] X-Pentora-Signature
# ─────────────────────────────────────────────────────────────────────────────

def _apply_pentora_signature(
    response: Response,
    request: Request,
    body: bytes,
) -> None:
    """
    Yanıt için HMAC-SHA256 imzası hesaplar ve header olarak ekler.
    Format: X-Pentora-Signature: v1=<hex>; ts=<unix_timestamp>

    İstemci bu değeri kullanarak yanıtın backend'den geldiğini doğrulayabilir.
    Ayrıca gelen istekteki X-Pentora-Signature doğrulanır; geçersizse uyarı loglanır.
    """
    sig, ts = generate_signature(
        method=request.method,
        path=request.url.path,
        body=body,
    )
    response.headers["X-Pentora-Signature"] = f"v1={sig}; ts={ts}"

    # Gelen istek imzasını kontrol et (varsa)
    incoming_sig_header = request.headers.get("X-Pentora-Signature", "")
    if incoming_sig_header:
        try:
            parts = dict(p.strip().split("=", 1) for p in incoming_sig_header.split(";"))
            incoming_sig = parts.get("v1", "")
            incoming_ts = int(parts.get("ts", "0"))
            valid = verify_signature(incoming_sig, request.method, request.url.path, body, incoming_ts)
            if not valid:
                logger.warning(
                    "pentora_signature.invalid",
                    path=request.url.path,
                    method=request.method,
                )
        except Exception:
            logger.warning("pentora_signature.parse_error", header=incoming_sig_header)


# ─────────────────────────────────────────────────────────────────────────────
# [D] SQL Tarama Yardımcısı
# ─────────────────────────────────────────────────────────────────────────────

def _perform_sql_scan(request: Request, body: bytes) -> object:
    """İstek URL ve query string'ini SQL enjeksiyon örüntüleri için tarar.
    NOT: Binary/multipart body asla taranmaz — yanlış pozitif üretir ve performansı düşürür.
    """
    settings = get_settings()

    # SQL guard kapalıysa veya muaf path'teyse atla
    if not settings.pentora_sql_guard_enabled:
        from app.core.security import SQLScanResult
        return SQLScanResult(False, 0)

    path = str(request.url.path)

    # Sadece path+query tara; body sadece JSON/text için taranır
    scan_target_parts = [path, str(request.url.query)]

    # Binary olmayan body'leri de tara
    if body:
        content_type = request.headers.get("content-type", "")
        is_binary = (
            "multipart" in content_type
            or "octet-stream" in content_type
            or "image/" in content_type
            or "application/pdf" in content_type
        )
        if not is_binary:
            try:
                scan_target_parts.append(body.decode("utf-8", errors="replace"))
            except Exception:
                pass

    combined = " ".join(scan_target_parts)
    return scan_for_sql_injection(combined, path=path)


# ─────────────────────────────────────────────────────────────────────────────
# [E] X-Pentora-GRAuth
# ─────────────────────────────────────────────────────────────────────────────

def _apply_pentora_grauth(response: Response, request: Request) -> None:
    """
    Genel istek doğrulama durumunu yanıta ekler.
    Format: X-Pentora-GRAuth: <AUTHENTICATED|ANONYMOUS|INVALID>; method=<Bearer|APIKey|None>

    İleride JWT/API-Key doğrulaması burada gerçekleştirilecek.
    Şu an istek state'inden doğrulama bilgisini okur.
    """
    auth_state = getattr(request.state, "auth_state", None)

    if auth_state is None:
        # Authorization header'ı varlığını kontrol et
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            # Token var ama henüz doğrulanmamış (endpoint doğrulaması yapılır)
            value = "PENDING; method=Bearer"
        elif request.headers.get("X-API-Key"):
            value = "PENDING; method=APIKey"
        else:
            value = "ANONYMOUS; method=None"
    else:
        # Endpoint'te doğrulama yapıldıysa state üzerinden yayılır
        value = f"{auth_state.get('status', 'UNKNOWN')}; method={auth_state.get('method', 'Unknown')}"

    response.headers["X-Pentora-GRAuth"] = value

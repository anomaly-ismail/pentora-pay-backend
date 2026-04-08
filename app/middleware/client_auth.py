"""
Flutter-Only İstemci Kimlik Doğrulama Middleware (ECDH Tabanlı)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Statik APK secret YOKTUR. Bunun yerine ECDH Ephemeral Key Exchange:
  - Flutter her uygulama başlatışında yeni P-256 keypair üretir
  - /auth/handshake ile sunucuyla anahtar değişimi yapar
  - session_key yalnızca RAM'de yaşar (5 dakika), hiç diske yazılmaz
  - İstekler bu dinamik session_key ile imzalanır

Doğrulama Katmanları (sırayla):
  1. User-Agent — Dart/Flutter HTTP imzası
  2. X-Pentora-Bundle-ID — uygulama paket kimliği
  3. X-Pentora-Handshake-ID — handhake oturum kimliği (RAM'den bulunur)
  4. X-Pentora-Client-Ts — zaman damgası (±5 dk replay koruması)
  5. X-Pentora-Client-Sig — HMAC-SHA256(handshake_id:ts:path, session_key)

Güvenlik özellikleri:
  - APK tersine mühendisliği sırrı açıklamaz (statik secret yok)
  - Her oturum tamamen bağımsız ephemeral anahtar
  - Forward secrecy: eski oturumlar sonradan çözülemez
  - Session key 5 dakika sonra hem RAM'den hem de sunucudan silinir

OWASP A07 (Identification and Authentication Failures) ve
ISO 27001 A.9.4 (System and Application Access Control) uyumlu.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.core.config import get_settings
from app.core.handshake import compute_request_sig, get_session_key
from app.core.logging import get_logger

logger = get_logger(__name__)

_TS_TOLERANCE_SECONDS = 300  # ±5 dakika

# Auth devre dışı path'ler (handshake kendi kimliğini kendin sağlayamaz)
_BYPASS_PATHS = frozenset({
    "/health",
    "/healthz",
    "/ping",
    "/metrics",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/handshake",   # Handshake başlatma — session yok, bypass
    "/api/v1/admin/sso/login",  # Admin SSO Giriş — Tarayıcı tabanlı, bypass
})

_FLUTTER_UA_KEYWORDS = ("Dart/", "dart:", "Flutter/")


class ClientAuthMiddleware(BaseHTTPMiddleware):
    """
    Sadece meşru Flutter uygulamasından gelen, ECDH handshake tamamlanmış
    istekleri geçirir. Diğer her kaynak 403 alır.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in _BYPASS_PATHS:
            return await call_next(request)

        if not self.settings.flutter_client_auth_enabled:
            return await call_next(request)

        # ── Katman 1: User-Agent ──────────────────────────────────────────────
        user_agent = request.headers.get("user-agent", "")
        if not _is_flutter_agent(user_agent):
            return _reject(request, "invalid_agent",
                           "Yetkisiz istemci — Dart/Flutter User-Agent bekleniyor")

        # ── Katman 2: Bundle ID ───────────────────────────────────────────────
        bundle_id = request.headers.get("X-Pentora-Bundle-ID", "")
        if bundle_id != self.settings.flutter_bundle_id:
            return _reject(request, "invalid_bundle_id", "Geçersiz uygulama kimliği")

        # ── Katman 3: Handshake ID ────────────────────────────────────────────
        handshake_id = request.headers.get("X-Pentora-Handshake-ID", "")
        if not handshake_id:
            return _reject(request, "missing_handshake",
                           "Geçerli oturum bulunamadı — önce /auth/handshake çağırın")

        session_key = await get_session_key(handshake_id)
        if session_key is None:
            return _reject(request, "handshake_expired",
                           "Oturum süresi dolmuş — yeni handshake gerekiyor")

        # ── Katman 4: Zaman Damgası ───────────────────────────────────────────
        ts_str = request.headers.get("X-Pentora-Client-Ts", "")
        try:
            client_ts = int(ts_str)
        except (ValueError, TypeError):
            return _reject(request, "invalid_timestamp", "Zaman damgası geçersiz")

        if abs(int(time.time()) - client_ts) > _TS_TOLERANCE_SECONDS:
            return _reject(request, "timestamp_stale",
                           "İstek süresi dolmuş veya tekrar saldırısı")

        # ── Katman 5: HMAC-SHA256 İmza ───────────────────────────────────────
        client_sig = request.headers.get("X-Pentora-Client-Sig", "")
        if not client_sig:
            return _reject(request, "missing_signature", "İmza eksik")

        expected = compute_request_sig(
            handshake_id=handshake_id,
            timestamp=client_ts,
            path=request.url.path,
            session_key=session_key,
        )

        import hmac
        if not hmac.compare_digest(expected, client_sig.lower()):
            return _reject(request, "invalid_signature",
                           "İmza doğrulanamadı")

        # Handshake ID'yi request state'e ekle (endpoint'lerde kullanılabilir)
        request.state.handshake_id = handshake_id

        return await call_next(request)


def _is_flutter_agent(ua: str) -> bool:
    return bool(ua) and any(kw in ua for kw in _FLUTTER_UA_KEYWORDS)


def _reject(request: Request, reason: str, message: str) -> JSONResponse:
    logger.warning(
        "client_auth.rejected",
        reason=reason,
        path=request.url.path,
        ip=request.client.host if request.client else "unknown",
        ua=request.headers.get("user-agent", "")[:80],
    )
    return JSONResponse(
        status_code=403,
        content={
            "error": "forbidden",
            "message": "Bu API yalnızca yetkili istemciler tarafından kullanılabilir.",
        },
    )

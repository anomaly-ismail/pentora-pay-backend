"""
Audit Log Middleware — Her isteği ve yanıtı yapısal şekilde loglar.
ISO 27001 A.12.4 (Log Yönetimi): Tüm kullanıcı eylemleri, sistem olayları ve
güvenlik denetimleri kaydedilmelidir.
OWASP A09: Security Logging and Monitoring Failures
"""
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.client_ip import get_real_client_ip
from app.core.logging import get_logger

logger = get_logger(__name__)

# Hassas header'lar log'a düşürülmez (ISO 27001 A.18)
_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-key",
        "x-pentora-grauth",
        "x-pentora-signature",
        "proxy-authorization",
    }
)

# Log'a düşürülmeyecek path'ler (health check gibi gürültülü endpointler)
_SKIP_PATHS = frozenset({"/health", "/healthz", "/ping", "/metrics"})


class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Her HTTP isteğini ve yanıtını yapısal JSON formatında loglar.

    Log alanları:
      - event: "http.request" | "http.response"
      - method, path, query
      - status_code
      - duration_ms
      - client_ip
      - user_agent
      - request_id
      - safe_headers (hassaslar maskelenir)
    """

    def __init__(self, app: ASGIApp, skip_paths: set[str] | None = None) -> None:
        super().__init__(app)
        self._skip = _SKIP_PATHS | (skip_paths or set())

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        if path in self._skip:
            return await call_next(request)

        client_ip = _get_client_ip(request)
        t0 = time.perf_counter()

        # ── İstek logu ──────────────────────────────────────────────────────
        logger.info(
            "http.request",
            method=request.method,
            path=path,
            query=str(request.url.query) or None,
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent", "")[:200],
            headers=_safe_headers(dict(request.headers)),
        )

        try:
            response: Response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            logger.error(
                "http.unhandled_exception",
                method=request.method,
                path=path,
                client_ip=client_ip,
                duration_ms=duration_ms,
                exc_type=type(exc).__name__,
                exc_msg=str(exc),
            )
            raise

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        # ── Yanıt logu ──────────────────────────────────────────────────────
        log_fn = logger.warning if response.status_code >= 400 else logger.info
        log_fn(
            "http.response",
            method=request.method,
            path=path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            client_ip=client_ip,
            content_length=response.headers.get("content-length"),
        )

        return response


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    """Hassas header'ları maskeler."""
    return {
        k: ("***REDACTED***" if k.lower() in _SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def _get_client_ip(request: Request) -> str:
    """
    H-3: Gerçek istemci IP'sini alır.

    Eski sürüm `X-Forwarded-For`'u herkesin spoof edebileceği bir header
    olarak kabul ediyordu — bu da log korelasyonunu, rate limit'i ve fraud
    sinyallerini bozuyordu. Yeni mantık `trusted_proxy_ips` ayarlı reverse
    proxy'lerden gelen XFF'i kabul eder; aksi halde TCP peer IP'sini döndürür.
    """
    return get_real_client_ip(request)

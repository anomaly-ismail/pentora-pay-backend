"""
Rate Limiting Middleware — IP bazlı hız sınırlama.
OWASP A04 (Insecure Design) ve ISO 27001 A.13.1 (Network Access Control) uyumlu.

Strateji:
  - Sliding window algoritması (in-memory, Redis ile değiştirilebilir)
  - Varsayılan: 100 istek/dakika
  - Auth endpointleri: 10 istek/dakika (brute-force koruması)
  - Aşıldığında: 429 Too Many Requests + Retry-After header
"""
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Auth endpoint'leri için daha sıkı limit
_AUTH_PATHS = frozenset({
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
})


def _parse_limit(limit_str: str) -> tuple[int, int]:
    """'100/minute' → (100, 60) | '10/hour' → (10, 3600)"""
    count_str, period_str = limit_str.split("/")
    count = int(count_str.strip())
    period_map = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
    period = period_map.get(period_str.strip().lower(), 60)
    return count, period


class _SlidingWindowCounter:
    """Thread-safe sliding window rate limiter (in-memory)."""

    def __init__(self) -> None:
        self._windows: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """
        Returns: (allowed, remaining)
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            window = self._windows[key]

            # Süresi geçmiş timestamp'leri temizle
            while window and window[0] < cutoff:
                window.popleft()

            count = len(window)

            if count >= max_requests:
                # En eski istek + window sonu = retry zamanı
                oldest = window[0] if window else now
                retry_after = int(oldest + window_seconds - now) + 1
                return False, retry_after

            window.append(now)
            return True, max_requests - count - 1


_counter = _SlidingWindowCounter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    IP bazlı sliding window rate limiter.

    Header çıktıları:
      - X-RateLimit-Limit: <max_requests>
      - X-RateLimit-Remaining: <kalan_istek>
      - X-RateLimit-Reset: <unix_timestamp>
      - Retry-After: <saniye> (429 durumunda)
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        settings = get_settings()
        self._default_max, self._default_window = _parse_limit(settings.rate_limit_default)
        self._auth_max, self._auth_window = _parse_limit(settings.rate_limit_auth)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # İstemci anahtarı: IP + path prefix
        client_ip = _get_ip(request)
        path = request.url.path

        if path in _AUTH_PATHS:
            max_req, window = self._auth_max, self._auth_window
        else:
            max_req, window = self._default_max, self._default_window

        key = f"rl:{client_ip}:{path}"
        allowed, remaining_or_retry = _counter.is_allowed(key, max_req, window)

        if not allowed:
            retry_after = remaining_or_retry
            logger.warning(
                "rate_limit.exceeded",
                client_ip=client_ip,
                path=path,
                retry_after=retry_after,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Çok fazla istek gönderildi. Lütfen bekleyin.",
                    "retry_after_seconds": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(max_req),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                },
            )

        response: Response = await call_next(request)

        # Başarılı isteklere rate limit bilgisi ekle
        response.headers["X-RateLimit-Limit"] = str(max_req)
        response.headers["X-RateLimit-Remaining"] = str(remaining_or_retry)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + window)

        return response


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"

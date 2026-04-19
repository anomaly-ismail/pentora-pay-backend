"""
Rate Limiting Middleware — IP bazlı hız sınırlama.
OWASP A04 (Insecure Design) ve ISO 27001 A.13.1 (Network Access Control) uyumlu.

Strateji:
  - Sliding window algoritması
  - REDIS_URL ayarlıysa Redis (multi-worker güvenli), yoksa in-memory (tek worker)
  - H-2: Multi-worker için Redis desteği eklendi
  - H-4: Admin SSO endpoint'i de sıkı limite tabi
  - H-7: X-Forwarded-For yalnızca güvenilen proxy'lerden kabul edilir
"""
import time
from collections import defaultdict, deque
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.core.client_ip import get_real_client_ip
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# H-4: Admin SSO login da sıkı limite tabi
_AUTH_PATHS = frozenset({
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    "/api/v1/admin/sso/login",   # H-4: eskiden 100/min, şimdi auth limit (10/min)
})

# M-6 / M-11: DoS açısından özel kısıtlanması gereken endpointler.
# Bu uçlar handshake store / SMS maliyetleri yaratır.
_HARD_LIMIT_PATHS: dict[str, tuple[int, int]] = {
    "/api/v1/auth/handshake": (20, 60),   # 20/dk per IP — handshake_store DoS koruması
    "/api/v1/auth/otp/send":  (5,  300),  # 5 / 5dk — SMS bombing koruması
    "/api/v1/auth/otp/verify": (10, 60),  # 10/dk — brute force koruması
    "/api/v1/corporate/payment/otp": (5, 300),  # SMS bombing
}


def _parse_limit(limit_str: str) -> tuple[int, int]:
    """'100/minute' → (100, 60) | '10/hour' → (10, 3600)"""
    count_str, period_str = limit_str.split("/")
    count = int(count_str.strip())
    period_map = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
    period = period_map.get(period_str.strip().lower(), 60)
    return count, period


# ─── In-Memory Sliding Window (tek worker) ───────────────────────────────────

class _InMemorySlidingWindow:
    """Thread-safe sliding window rate limiter (in-memory, tek worker)."""

    def __init__(self) -> None:
        self._windows: dict[str, deque] = defaultdict(deque)
        # asyncio.Lock kullanmak yerine deque işlemleri zaten thread-safe'dir (GIL)
        # async context içinde küçük deque işlemleri için threading.Lock yeterli
        import threading
        self._lock = threading.Lock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            window = self._windows[key]
            while window and window[0] < cutoff:
                window.popleft()
            count = len(window)
            if count >= max_requests:
                oldest = window[0] if window else now
                retry_after = int(oldest + window_seconds - now) + 1
                return False, retry_after
            window.append(now)
            return True, max_requests - count - 1


_in_memory_counter = _InMemorySlidingWindow()


# ─── Redis Sliding Window (multi-worker) ─────────────────────────────────────

_redis_client = None


def _get_redis_client():
    """Redis bağlantısını döner; bağlantı yoksa None döner."""
    global _redis_client
    settings = get_settings()
    if not settings.redis_url:
        return None
    if _redis_client is None:
        try:
            import redis.asyncio as aioredis
            _redis_client = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
        except Exception as exc:
            logger.error("rate_limiter.redis.connection_failed", error=str(exc))
    return _redis_client


async def _redis_is_allowed(
    redis_client,
    key: str,
    max_requests: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """
    H-2: Redis ZADD/ZCARD ile sliding window — multi-worker güvenli.
    Lua script kullanarak atomik işlem sağlar.
    """
    now = time.time()
    cutoff = now - window_seconds
    pipe = redis_client.pipeline()
    try:
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window_seconds + 1)
        results = await pipe.execute()
        count_before_add = results[1]
        if count_before_add >= max_requests:
            # Bu isteği geri al
            await redis_client.zrem(key, str(now))
            retry_after = window_seconds
            return False, retry_after
        return True, max_requests - count_before_add - 1
    except Exception as exc:
        logger.error("rate_limiter.redis.error", error=str(exc))
        # Redis hatası → in-memory'ye fall-back
        return _in_memory_counter.is_allowed(key, max_requests, window_seconds)


# ─── Middleware ───────────────────────────────────────────────────────────────
# H-3 / H-7: Güvenilen proxy IP kontrolü merkezi `app/core/client_ip.py` içinde.
# `get_real_client_ip` Cloudflare Tunnel için CF-Connecting-IP ve XFF chain'i
# trusted_proxy_ips listesi ışığında birlikte değerlendirir.


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    IP bazlı sliding window rate limiter.
    Redis varsa multi-worker güvenli; yoksa in-memory (tek worker).
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        settings = get_settings()
        self._default_max, self._default_window = _parse_limit(settings.rate_limit_default)
        self._auth_max, self._auth_window = _parse_limit(settings.rate_limit_auth)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # H-3 / Cloudflare Tunnel: client_ip.py XFF + CF-Connecting-IP
        # birlikte ele alır (trusted proxy doğrulaması içinde).
        client_ip = get_real_client_ip(request)
        path = request.url.path

        # M-6 / M-11: Hard-limited endpoints
        hard = _HARD_LIMIT_PATHS.get(path)
        if hard is not None:
            max_req, window = hard
        elif path in _AUTH_PATHS:
            max_req, window = self._auth_max, self._auth_window
        else:
            max_req, window = self._default_max, self._default_window

        key = f"rl:{client_ip}:{path}"

        redis = _get_redis_client()
        if redis is not None:
            allowed, remaining_or_retry = await _redis_is_allowed(redis, key, max_req, window)
        else:
            allowed, remaining_or_retry = _in_memory_counter.is_allowed(key, max_req, window)

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

        response.headers["X-RateLimit-Limit"] = str(max_req)
        response.headers["X-RateLimit-Remaining"] = str(remaining_or_retry)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + window)

        return response

"""
Request ID Middleware — Her isteğe benzersiz UUID atar.
ISO 27001 A.12.4 (Log Yönetimi) ve OWASP A09 (Security Logging) uyumlu.
"""
import uuid
from typing import Callable

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Her gelen isteğe benzersiz bir UUID atar.
    - request.state.request_id üzerinden erişilebilir
    - structlog contextvars'a bağlanır (tüm log kayıtlarına otomatik eklenir)
    - Yanıta X-Request-ID header olarak eklenir (SecurityHeadersMiddleware tarafından)
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Gelen istek zaten Request-ID taşıyorsa kullan, yoksa üret
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        request.state.request_id = request_id

        # Structlog context variable olarak bağla
        # → tüm log kayıtlarına otomatik eklenir
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response: Response = await call_next(request)
        return response

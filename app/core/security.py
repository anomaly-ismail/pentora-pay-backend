"""
Güvenlik yardımcı araçları — HMAC imzalama, SQL enjeksiyon tespiti, token utils.
OWASP A03 (Injection) ve OWASP A02 (Cryptographic Failures) kapsamında.
"""
import hashlib
import hmac
import re
import time
import uuid
from typing import Optional

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# X-Pentora-Signature — İstek bütünlük imzası
# Format: HMAC-SHA256( timestamp + "." + method + "." + path + "." + body_hash )
# ─────────────────────────────────────────────────────────────────────────────

SIGNATURE_TOLERANCE_SECONDS = 300  # ±5 dakika replay koruması


def generate_signature(
    method: str,
    path: str,
    body: bytes,
    timestamp: Optional[int] = None,
    secret: Optional[str] = None,
) -> tuple[str, int]:
    """
    İstek için HMAC-SHA256 imzası üretir.
    Returns: (signature_hex, timestamp_used)
    """
    settings = get_settings()
    ts = timestamp or int(time.time())
    key = (secret or settings.pentora_signature_secret).encode()
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{ts}.{method.upper()}.{path}.{body_hash}".encode()
    sig = hmac.new(key, message, hashlib.sha256).hexdigest()
    return sig, ts


def verify_signature(
    signature: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    secret: Optional[str] = None,
) -> bool:
    """HMAC-SHA256 imzasını ve zaman damgasını doğrular."""
    now = int(time.time())
    if abs(now - timestamp) > SIGNATURE_TOLERANCE_SECONDS:
        logger.warning("signature.replay_attempt", ts=timestamp, now=now)
        return False

    expected, _ = generate_signature(method, path, body, timestamp, secret)
    return hmac.compare_digest(expected, signature)


# ─────────────────────────────────────────────────────────────────────────────
# X-Pentora-SQL — SQL Enjeksiyon Tespit Katmanı
# OWASP A03: Injection
# ─────────────────────────────────────────────────────────────────────────────

# Yaygın SQL enjeksiyon örüntüleri (heuristic, parameterized queries asıl koruma)
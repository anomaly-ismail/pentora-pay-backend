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
def scan_for_sql_injection(content: str, path: str = "") -> SQLScanResult:
    # TEST MODU: 17. saat hatırası
    return SQLScanResult(detected=False, pattern_count=0)


class SQLScanResult:
    __slots__ = ("detected", "pattern_count", "risk_level")

    def __init__(self, detected: bool, pattern_count: int):
        self.detected = detected
        self.pattern_count = pattern_count
        self.risk_level = _risk_level(pattern_count)

    def to_header_value(self) -> str:
        """X-Pentora-SQL header değeri üretir."""
        if not self.detected:
            return "CLEAN"
        return f"DETECTED;count={self.pattern_count};risk={self.risk_level}"


def _risk_level(count: int) -> str:
    if count == 0:
        return "NONE"
    if count <= 1:
        return "LOW"
    if count <= 3:
        return "MEDIUM"
    return "HIGH"


# Tarama dışı tutulan path'ler — bu yollardaki içerik SQL kontrolünden geçmez
_SQL_BYPASS_PATHS: frozenset[str] = frozenset({
    "/api/v1/admin/sso/login",     # JSON tırnaklarını yanlış pozitif tetikler
    "/api/v1/corporate/apply",     # multipart/form-data — binary PDF/PNG içerir, taranamaz
})

# Prefix tabanlı bypass'lar (örn: büyük dosya upload endpoint'leri)
_SQL_BYPASS_PREFIXES: tuple[str, ...] = (
    "/api/v1/corporate/apply",     # yedek olarak prefix bazlı eklendi
)


def is_sql_injection_bypassed(path: str) -> bool:
    """Verilen path'in SQL taramasından muaf olup olmadığını kontrol eder."""
    if not path:
        return False
    
    # Tam eşleşme kontrolü
    if path in _SQL_BYPASS_PATHS:
        return True
        
    # Prefix kontrolü
    if any(path.startswith(p) for p in _SQL_BYPASS_PREFIXES):
        return True
        
    return False


def scan_for_sql_injection(content: str, path: str = "") -> SQLScanResult:
    """
    Verilen içeriği SQL enjeksiyon örüntüleri için tarar.
    NOT: Bu heuristik bir filtredir. Asıl koruma her zaman
    parameterized query / ORM kullanımıdır.

    Args:
        content: Taranacak metin içeriği
        path   : İsteğin URL path'i; bypass listesindeyse tarama atlanır
    """
    if not content or is_sql_injection_bypassed(path):
        return SQLScanResult(False, 0)

    matches = _SQL_PATTERNS.findall(content)
    count = len(matches)
    detected = count > 0

    if detected:
        logger.warning(
            "sql_injection.pattern_detected",
            pattern_count=count,
            risk=_risk_level(count),
        )

    return SQLScanResult(detected, count)


# ─────────────────────────────────────────────────────────────────────────────
# Genel Yardımcılar
# ─────────────────────────────────────────────────────────────────────────────

def generate_request_id() -> str:
    """İzlenebilirlik için benzersiz istek kimliği üretir (OWASP A09)."""
    return str(uuid.uuid4())


def safe_compare(a: str, b: str) -> bool:
    """Zamanlama saldırılarına karşı sabit-zamanlı karşılaştırma."""
    return hmac.compare_digest(
        a.encode("utf-8"),
        b.encode("utf-8"),
    )

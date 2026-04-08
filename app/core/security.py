"""
Güvenlik yardımcı araçları — HMAC imzalama, SQL enjeksiyon heuristics, güvenli kıyaslama.
OWASP A02 (Cryptographic Failures) ve OWASP A03 (Injection) prensiplerine göre.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

SIGNATURE_TOLERANCE_SECONDS = 300  # ±5 dakika replay koruması


def generate_signature(
    method: str,
    path: str,
    body: bytes,
    timestamp: Optional[int] = None,
    secret: Optional[str] = None,
) -> tuple[str, int]:
    """İstek/yanıt için HMAC-SHA256 imzası üretir."""
    settings = get_settings()
    ts = timestamp or int(time.time())
    key = (secret or settings.pentora_signature_secret).encode("utf-8")
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{ts}.{method.upper()}.{path}.{body_hash}".encode("utf-8")
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
    """İmza + zaman damgası doğrulaması yapar."""
    now = int(time.time())
    if abs(now - timestamp) > SIGNATURE_TOLERANCE_SECONDS:
        logger.warning("signature.replay_attempt", ts=timestamp, now=now)
        return False

    expected, _ = generate_signature(method, path, body, timestamp, secret)
    return hmac.compare_digest(expected, signature)


@dataclass
class SQLScanResult:
    detected: bool = False
    pattern_count: int = 0
    risk_level: str = "NONE"

    def to_header_value(self) -> str:
        if not self.detected:
            return "CLEAN"
        return f"{self.risk_level}:{self.pattern_count}"


_SQL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bunion\s+select\b"),
    re.compile(r"(?i)\bdrop\s+table\b"),
    re.compile(r"(?i)\binsert\s+into\b"),
    re.compile(r"(?i)\bdelete\s+from\b"),
    re.compile(r"(?i)\bupdate\s+\w+\s+set\b"),
    re.compile(r"(?i)\bor\s+1\s*=\s*1\b"),
    re.compile(r"(?i)['\"];?\s*--"),
    re.compile(r"(?i)/\*.*?\*/"),
    re.compile(r"(?i)\bbenchmark\s*\("),
    re.compile(r"(?i)\bsleep\s*\("),
)

_SQL_BYPASS_PATH_PREFIXES: tuple[str, ...] = (
    "/api/v1/auth/handshake",
    "/health",
    "/ping",
)


def is_sql_injection_bypassed(path: str) -> bool:
    """Performans/kritik path'ler için SQL heuristics taramayı bypass eder."""
    return any(path.startswith(prefix) for prefix in _SQL_BYPASS_PATH_PREFIXES)


def scan_for_sql_injection(content: str, path: str = "") -> SQLScanResult:
    """
    Heuristic SQL pattern taraması.
    Not: Parametrik sorgu kullanımı asıl korumadır; bu katman ilave erken uyarıdır.
    """
    if is_sql_injection_bypassed(path):
        return SQLScanResult(False, 0, "NONE")

    haystack = (content or "")[:200_000]  # performans sınırı
    if not haystack:
        return SQLScanResult(False, 0, "NONE")

    count = 0
    for rx in _SQL_PATTERNS:
        if rx.search(haystack):
            count += 1

    if count == 0:
        return SQLScanResult(False, 0, "NONE")

    if count >= 4:
        risk = "HIGH"
    elif count >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    logger.warning(
        "sql_injection.pattern_detected",
        pattern_count=count,
        risk=risk,
        path=path,
    )
    return SQLScanResult(True, count, risk)


def generate_request_id() -> str:
    return str(uuid.uuid4())


def safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
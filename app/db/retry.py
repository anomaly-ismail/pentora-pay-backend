"""
DB İşlemleri için Yeniden Deneme (Retry) Yardımcısı
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PostgreSQL serialization failure (SQLSTATE 40001) ve deadlock (40P01)
hatalarında otomatik üstel geri çekilme (exponential backoff) ile retry.

Kullanım Kuralları:
  1. Bu dekoratör YALNIZCA kendi session'ını yöneten servis fonksiyonlarında
     kullanılmalıdır (örn: get_db bağımlılığını doğrudan alan endpoint handler).
  2. Retry her seferinde tam bir yeni DB transaction başlatır. Bu nedenle
     fonksiyon içindeki tüm DB işlemleri idempotent olmalıdır.
  3. record_transaction() gibi atomik çekirdek fonksiyonlara uygulanmak
     YANLIŞ olur; bunun yerine bu fonksiyonu çağıran servis katmanına uygulanın.

Örnek:
    from app.db.retry import db_retry

    @db_retry()
    async def process_payment(db: AsyncSession, payment_id: uuid.UUID) -> None:
        async with db.begin():
            await accounting_repo.record_transaction(...)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import logging

from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

logger = logging.getLogger(__name__)

# PostgreSQL hata kodları (SQLSTATE)
_RETRYABLE_STATES = frozenset(["40001", "40p01"])


def _is_retryable(exc: BaseException) -> bool:
    """asyncpg / SQLAlchemy serialization failure veya deadlock hatası mı?"""
    msg = str(exc).lower()
    return (
        any(state in msg for state in _RETRYABLE_STATES)
        or "deadlock" in msg
        or "serialization failure" in msg
        or "could not serialize access" in msg
    )


def db_retry(max_attempts: int = 3, wait_min: float = 0.05, wait_max: float = 0.5):
    """
    PostgreSQL deadlock / serialization failure için retry dekoratörü.

    Args:
        max_attempts: Maksimum deneme sayısı (varsayılan: 3)
        wait_min: İlk bekleme süresi saniye (varsayılan: 50ms)
        wait_max: Maksimum bekleme süresi saniye (varsayılan: 500ms)

    Kullanım:
        @db_retry(max_attempts=3)
        async def my_transactional_service(db: AsyncSession, ...) -> ...:
            ...
    """
    return retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=0.1, min=wait_min, max=wait_max),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )

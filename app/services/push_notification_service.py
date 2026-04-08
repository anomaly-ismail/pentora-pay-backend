from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

import firebase_admin
from firebase_admin import credentials, messaging
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.repositories.user_device_repo import UserDeviceRepo

logger = get_logger(__name__)

_firebase_initialized = False


def _ensure_firebase_initialized() -> bool:
    global _firebase_initialized
    if _firebase_initialized:
        return True

    settings = get_settings()
    backend_root = Path(__file__).resolve().parents[2]
    service_account_path = backend_root / settings.firebase_service_account_file
    if not service_account_path.exists():
        logger.warning("push.firebase.service_account_missing", path=str(service_account_path))
        return False

    try:
        if not firebase_admin._apps:
            cred = credentials.Certificate(str(service_account_path))
            firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        return True
    except Exception as exc:
        logger.warning("push.firebase.init_failed", error=str(exc))
        return False


async def send_user_push(
    *,
    db: AsyncSession,
    user_id: uuid.UUID,
    title: str,
    body: str,
    data: Optional[dict[str, str]] = None,
) -> int:
    """
    Firebase Admin SDK ile push gönderimi.
    """
    if not _ensure_firebase_initialized():
        return 0

    repo = UserDeviceRepo(db)
    tokens = await repo.list_active_tokens(user_id=user_id)
    if not tokens:
        return 0

    try:
        message = messaging.MulticastMessage(
            tokens=tokens,
            notification=messaging.Notification(title=title, body=body),
            data=data or {},
            android=messaging.AndroidConfig(priority="high"),
        )
        result = messaging.send_each_for_multicast(message)
    except Exception as exc:
        logger.warning("push.send.exception", error=str(exc))
        return 0

    for idx, resp in enumerate(result.responses):
        if resp.success:
            continue
        err = str(resp.exception or "")
        if "registration-token-not-registered" in err or "invalid-registration-token" in err:
            await repo.deactivate_token(tokens[idx])

    return int(result.success_count)

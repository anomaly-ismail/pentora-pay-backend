"""
Kurumsal Ödeme Alma Repository
"""
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.corporate_receive_request import (
    CorporateReceiveRequest,
    CorporateReceiveStatus,
)

_REQUEST_TTL_HOURS = 24


class CorporateReceiveRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        seller_user_id: uuid.UUID,
        recipient_tckn: str,
        recipient_phone: str,
        gold_gram: Decimal,
        gold_type: str,
        amount: Decimal,
        mrz_verified: bool = False,
        nfc_verified: bool = False,
    ) -> CorporateReceiveRequest:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=_REQUEST_TTL_HOURS)
        req = CorporateReceiveRequest(
            seller_user_id=seller_user_id,
            recipient_tckn=recipient_tckn,
            recipient_phone=recipient_phone,
            gold_gram=gold_gram,
            gold_type=gold_type,
            amount=amount,
            mrz_verified=mrz_verified,
            nfc_verified=nfc_verified,
            status=CorporateReceiveStatus.PENDING_PAYMENT,
            expires_at=expires_at,
        )
        self._session.add(req)
        await self._session.flush()
        await self._session.refresh(req)
        return req

    async def get_by_id(self, req_id: uuid.UUID) -> Optional[CorporateReceiveRequest]:
        result = await self._session.execute(
            select(CorporateReceiveRequest).where(CorporateReceiveRequest.id == req_id)
        )
        return result.scalar_one_or_none()

    async def get_by_id_for_update(
        self, req_id: uuid.UUID
    ) -> Optional[CorporateReceiveRequest]:
        """Row-level lock ile çeker — eş zamanlı webhook koruması."""
        result = await self._session.execute(
            select(CorporateReceiveRequest)
            .where(CorporateReceiveRequest.id == req_id)
            .with_for_update()
        )
        return result.scalar_one_or_none()

    async def get_pending_approval_by_phone(
        self, phone: str
    ) -> Optional[CorporateReceiveRequest]:
        """
        ONAYLIYORUM SMS'i eşleştirmek için gönderen telefona göre arar.
        Birden fazla açık talep varsa en yenisini döner.
        """
        result = await self._session.execute(
            select(CorporateReceiveRequest)
            .where(
                CorporateReceiveRequest.recipient_phone == phone,
                CorporateReceiveRequest.status == CorporateReceiveStatus.PENDING_APPROVAL,
            )
            .order_by(CorporateReceiveRequest.created_at.desc())
            .limit(1)
            .with_for_update()
        )
        return result.scalar_one_or_none()

    async def mark_payment_received(
        self, req: CorporateReceiveRequest, paytr_oid: str
    ) -> None:
        """
        PayTR webhook çağırdığında:
        PENDING_PAYMENT → PENDING_APPROVAL
        paytr_oid set edilir (idempotency key).
        """
        req.status = CorporateReceiveStatus.PENDING_APPROVAL
        req.paytr_oid = paytr_oid
        await self._session.flush()

    async def mark_completed(self, req: CorporateReceiveRequest) -> None:
        req.status = CorporateReceiveStatus.COMPLETED
        req.completed_at = datetime.now(timezone.utc)
        await self._session.flush()

    async def mark_sms_sent(self, req: CorporateReceiveRequest) -> None:
        req.sms_sent = True
        await self._session.flush()

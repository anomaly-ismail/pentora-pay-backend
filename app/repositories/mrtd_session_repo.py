"""
MRTD Session Repository
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MRZ + NFC oturumlarını yönetir. Şifreleme katmanı ile DG dosyalarını saklar,
approve_id ile kurumsal ödeme/alma'ya bağlama mantığını kapsar.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import build_aad, decrypt_blob, encrypt_blob, hmac_index
from app.core.mrtd import MrzData
from app.models.mrtd_session import MrtdPurpose, MrtdSession, MrtdStatus

# approve_id TTL — OWASP A01 zorunluluğu: dar zaman penceresi
SESSION_TTL_MINUTES = 15


class MrtdSessionRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    # ── CREATE: MRZ tamamlandı ─────────────────────────────────────────────
    async def create_from_mrz(
        self,
        *,
        user_id: uuid.UUID,
        purpose: MrtdPurpose,
        mrz: MrzData,
        tckn: Optional[str],
        client_ip: Optional[str],
        user_agent: Optional[str],
    ) -> MrtdSession:
        now = datetime.now(timezone.utc)
        sess_id = uuid.uuid4()

        # AAD: user + approve_id + alan adı — blob swap önler
        aad_mrz = build_aad(str(user_id), str(sess_id), "mrz")

        sess = MrtdSession(
            id=sess_id,
            user_id=user_id,
            purpose=purpose,
            status=MrtdStatus.MRZ_DONE,
            mrz_blob=encrypt_blob(mrz.raw.encode("utf-8"), aad=aad_mrz),
            doc_no_hash=hmac_index(mrz.document_number),
            tckn_hash=hmac_index(tckn) if tckn else None,
            doc_type=mrz.doc_type,
            issuing_state=mrz.issuing_state,
            nationality=mrz.nationality,
            date_of_expiry=mrz.date_of_expiry,
            client_ip_hash=hmac_index(client_ip) if client_ip else None,
            user_agent_hash=hmac_index(user_agent) if user_agent else None,
            created_at=now,
            mrz_verified_at=now,
            expires_at=now + timedelta(minutes=SESSION_TTL_MINUTES),
        )
        self._s.add(sess)
        await self._s.flush()
        await self._s.refresh(sess)
        return sess

    # ── Yeniden erişim ─────────────────────────────────────────────────────
    async def get_owned(
        self, approve_id: uuid.UUID, user_id: uuid.UUID
    ) -> Optional[MrtdSession]:
        """Yalnızca o kullanıcıya ait oturumu döner (OWASP A01)."""
        result = await self._s.execute(
            select(MrtdSession).where(
                MrtdSession.id == approve_id,
                MrtdSession.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    # ── UPDATE: NFC DG verileri alındı ─────────────────────────────────────
    async def set_nfc_payload(
        self,
        sess: MrtdSession,
        *,
        dg1: Optional[bytes],
        dg2: Optional[bytes],
        dg11: Optional[bytes],
        sod: Optional[bytes],
        passive_auth_ok: bool,
    ) -> None:
        def _enc(field: str, data: Optional[bytes]) -> Optional[bytes]:
            if data is None:
                return None
            aad = build_aad(str(sess.user_id), str(sess.id), field)
            return encrypt_blob(data, aad=aad)

        sess.dg1_blob = _enc("dg1", dg1)
        sess.dg2_blob = _enc("dg2", dg2)
        sess.dg11_blob = _enc("dg11", dg11)
        sess.sod_blob = _enc("sod", sod)
        sess.passive_auth_ok = passive_auth_ok
        sess.nfc_verified_at = datetime.now(timezone.utc)
        sess.status = MrtdStatus.NFC_DONE
        await self._s.flush()

    # ── UPDATE: Hata / tekrar deneme ───────────────────────────────────────
    async def record_attempt_failure(
        self, sess: MrtdSession, *, error: str
    ) -> None:
        sess.attempts = (sess.attempts or 0) + 1
        # PII sızmasını önlemek için sabit 200 karakter ve genel formatla
        sess.last_error = error[:200]
        # Çok fazla başarısız denemede oturumu kilitle
        if sess.attempts >= 5:
            sess.status = MrtdStatus.FAILED
        await self._s.flush()

    # ── CONSUME: payment/receive bağlandı ──────────────────────────────────
    async def consume(
        self,
        sess: MrtdSession,
        *,
        payment_id: Optional[uuid.UUID] = None,
        receive_id: Optional[uuid.UUID] = None,
    ) -> None:
        """
        Oturumu tek-kullanımlık olarak kapatır ve ilişkili kaynağa bağlar.
        İkinci çağrı idempotent değildir: zaten CONSUMED ise hata yükseltmez.
        """
        if sess.status == MrtdStatus.CONSUMED:
            return
        sess.status = MrtdStatus.CONSUMED
        sess.consumed_at = datetime.now(timezone.utc)
        if payment_id:
            sess.linked_payment_id = payment_id
        if receive_id:
            sess.linked_receive_id = receive_id
        await self._s.flush()

    # ── DECRYPT yardımcı (iç kullanım) ─────────────────────────────────────
    @staticmethod
    def decrypt_field(
        sess: MrtdSession, field: str
    ) -> Optional[bytes]:
        blob_map = {
            "mrz": sess.mrz_blob,
            "dg1": sess.dg1_blob,
            "dg2": sess.dg2_blob,
            "dg11": sess.dg11_blob,
            "sod": sess.sod_blob,
        }
        blob = blob_map.get(field)
        if not blob:
            return None
        aad = build_aad(str(sess.user_id), str(sess.id), field)
        return decrypt_blob(blob, aad=aad)

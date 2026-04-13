"""
User Repository — Tüm veritabanı işlemleri buradan.
Sıfır ham SQL: tüm sorgular SQLAlchemy ORM üzerinden → SQL injection imkânsız.
Repository pattern: service katmanı DB'yi doğrudan görmez.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.user import User
from app.models.user_session import UserSession
from app.models.audit_event import AuditEvent, AuditEventType

logger = get_logger(__name__)

# Argon2id hasher — PIN için (GRAuth Argon2id'den bağımsız)
_pin_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,   # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def _hmac_sha3_512(value: str, pepper: str) -> str:
    """
    HMAC-SHA3-512(value, pepper) → 128-hex karakter.
    TCKN ve NFC UID'yi plaintext saklamadan doğrulanabilir biçimde hashler.
    """
    return hmac.new(
        pepper.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha3_512,
    ).hexdigest()


def _sha3_256_hash(value: str, pepper: str) -> str:
    """SHA3-256(value || pepper) → 64-hex karakter. IP/UA için."""
    return hashlib.sha3_256(
        value.encode("utf-8") + pepper.encode("utf-8")
    ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# User Repository
# ─────────────────────────────────────────────────────────────────────────────

class UserRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._settings = get_settings()
        self._pepper = self._settings.tckn_pepper
        # M-6: grauth_token_hash için tckn_pepper'dan ayrı pepper
        self._session_pepper = self._settings.session_pepper

    # ── TCKN Hash Hesaplama ──────────────────────────────────────────────────
    def hash_tckn(self, tckn: str) -> str:
        """HMAC-SHA3-512(tckn, TCKN_PEPPER) — sadece bu metod çağrılmalı."""
        return _hmac_sha3_512(tckn, self._pepper)

    def hash_nfc_uid(self, nfc_uid_hex: str) -> str:
        """HMAC-SHA3-512(nfc_uid, TCKN_PEPPER)."""
        return _hmac_sha3_512(nfc_uid_hex.upper(), self._pepper)

    def hash_context(self, value: str) -> str:
        """SHA3-256 — IP adresi ve UA için."""
        return _sha3_256_hash(value, self._pepper)

    # ── Var mı kontrolü ─────────────────────────────────────────────────────
    async def exists_by_tckn(self, tckn: str) -> bool:
        """TCKN ile kayıtlı kullanıcı var mı? (plaintext TCKN kullanılmaz)"""
        tckn_hash = self.hash_tckn(tckn)
        result = await self._db.execute(
            select(User.id).where(User.tckn_hash == tckn_hash).limit(1)
        )
        return result.scalar() is not None

    async def get_by_tckn(self, tckn: str) -> User | None:
        """TCKN'ye göre kullanıcı getir (hash üzerinden)."""
        tckn_hash = self.hash_tckn(tckn)
        result = await self._db.execute(
            select(User).where(User.tckn_hash == tckn_hash)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return await self._db.get(User, user_id)

    # ── Kullanıcı Oluşturma ──────────────────────────────────────────────────
    async def create_user(
        self,
        tckn: str,
        pin: str,
        nfc_uid_hex: str,
        grauth_salt: bytes,
        nfc_verified: bool = False,
    ) -> User:
        """
        Yeni kullanıcı kaydı oluşturur.
        Tüm hassas veriler hashlenir/şifrelenir — DB'ye plaintext girilmez.
        """
        user = User(
            id=uuid.uuid4(),
            tckn_hash=self.hash_tckn(tckn),
            pin_hash=_pin_hasher.hash(pin),           # Argon2id
            nfc_uid_hash=self.hash_nfc_uid(nfc_uid_hex) if nfc_uid_hex else None,
            grauth_salt=grauth_salt,
            nfc_verified=nfc_verified,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self._db.add(user)
        await self._db.flush()   # ID'ye ihtiyaç varsa hemen al
        return user

    # ── PIN Doğrulama ────────────────────────────────────────────────────────
    def verify_pin(self, user: User, pin: str) -> bool:
        """Argon2id ile PIN doğrulama."""
        try:
            return _pin_hasher.verify(user.pin_hash, pin)
        except VerifyMismatchError:
            return False

    # ── Session Kayıt ────────────────────────────────────────────────────────
    async def create_session(
        self,
        user_id: uuid.UUID,
        session_uuid: str,
        grauth_token: str,
        issued_at: datetime,
        expires_at: datetime,
        client_ip: str,
        user_agent: str,
    ) -> UserSession:
        session = UserSession(
            user_id=user_id,
            session_uuid=session_uuid,
            # M-6: grauth_token_hash için session_pepper (tckn_pepper'dan ayrı)
            grauth_token_hash=_sha3_256_hash(grauth_token, self._session_pepper),
            issued_at=issued_at,
            expires_at=expires_at,
            is_revoked=False,
            ip_hash=self.hash_context(client_ip),
            ua_hash=self.hash_context(user_agent),
        )
        self._db.add(session)
        await self._db.flush()
        return session

    # ── Denetim Logu ─────────────────────────────────────────────────────────
    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: uuid.UUID | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
        details: dict | None = None,
    ) -> None:
        """
        Denetim olayı kaydeder.
        IP ve UA hashlenir — plaintext ASLA kaydedilmez.
        Details dict'i PII içermemeli (servis katmanı sorumludur).
        """
        event = AuditEvent(
            event_type=event_type.value,
            user_id=user_id,
            ip_hash=self.hash_context(client_ip) if client_ip else None,
            ua_hash=self.hash_context(user_agent) if user_agent else None,
            details=details,
            created_at=datetime.now(timezone.utc),
        )
        self._db.add(event)
        # Audit log'lar commit'e bırakılır (servis katmanı commitli)

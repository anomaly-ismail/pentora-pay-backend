"""
Denetim Olayı Modeli (Audit Log)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ISO 27001 A.12.4 gerektirir: Tüm kullanıcı eylemleri kaydedilmeli.
Ancak kişisel veri yönetmeliği (KVKK 4/2) eş zamanlı geçerlidir:
Amaç için gerekli olmayan kişisel veriler saklanmamalıdır.

Bu çelişkiyi çözen yaklaşım:
  - Kullanıcı identity: user_id (UUID) — doğrudan kimlik açıklamaz
  - IP adresi: SHA3-256(ip, pepper) — orijinal geri elde edilemez
  - User-Agent: SHA3-256(ua, pepper) — cihaz parmak izi
  - Olay detayları: PII içermemelidir. Service katmanı bunu sağlar.
    Örn: {"action":"register","nfc_verified":true}  ✓
         {"tckn":"12345678901","ip":"1.2.3.4"}       ✗

Tabloya yazma sadece service katmanı üzerinden yapılır.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    DateTime,
    Index,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditEventType(StrEnum):
    """Denetim olayı türleri — tüm güvenlik olayları burada tanımlanır."""
    # Kimlik doğrulama
    REGISTER_SUCCESS      = "auth.register.success"
    REGISTER_FAILED       = "auth.register.failed"
    LOGIN_SUCCESS         = "auth.login.success"
    LOGIN_FAILED          = "auth.login.failed"
    LOGIN_TCKN_NOT_FOUND  = "auth.login.tckn_not_found"
    LOGIN_PIN_INVALID     = "auth.login.pin_invalid"
    LOGOUT                = "auth.logout"
    TOKEN_REVOKED         = "auth.token.revoked"
    TOKEN_EXPIRED         = "auth.token.expired"

    # NFC
    NFC_VERIFIED          = "nfc.verified"
    NFC_FAILED            = "nfc.failed"

    # Güvenlik
    RATE_LIMIT_HIT        = "security.rate_limit"
    CLIENT_AUTH_FAILED    = "security.client_auth_failed"
    SQL_INJECTION_ATTEMPT = "security.sql_injection"
    SIGNATURE_INVALID     = "security.signature_invalid"
    ACCOUNT_LOCKED        = "security.account_locked"

    # Ödeme
    PAYMENT_REQUEST       = "payment.request"
    PAYMENT_COMPLETED     = "payment.completed"
    PAYMENT_FAILED        = "payment.failed"


class AuditEvent(Base):
    __tablename__ = "audit_events"

    # Büyük hacim için BigInteger PK
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # ── Olay Türü ────────────────────────────────────────────────────────────
    event_type: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        index=True,
        comment="AuditEventType enum değeri",
    )

    # ── Kullanıcı (varsa) ────────────────────────────────────────────────────
    # UUID olarak: kimseyi doğrudan tanımlamaz, User tablosuyla join gerekir
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="Kullanıcı UUID — varsa. JOIN olmadan kimse tanımlanamaz.",
    )

    # ── PII-Free Bağlam ──────────────────────────────────────────────────────
    # SHA3-256(client_ip, IP_PEPPER)
    ip_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA3-256(ip || pepper) — plaintext IP saklanmaz",
    )

    # SHA3-256(user_agent, IP_PEPPER)
    ua_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        comment="SHA3-256(ua || pepper) — plaintext UA saklanmaz",
    )

    # ── Olay Detayı (PII-free JSONB) ─────────────────────────────────────────
    # Service katmanı burada PII içermemesini garanti eder.
    # İzin verilen alanlar: action, nfc_verified, error_code, risk_level vb.
    # Yasak alanlar: tckn, pin, nfc_uid, ip, email, phone, ad-soyad vb.
    details: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        comment="Olay detayları — PII içermemeli",
    )

    # ── Zaman ────────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        # Belirli kullanıcı + olay tipinin zaman serisi analizi
        Index("ix_audit_user_event_time", "user_id", "event_type", "created_at"),
        # Belirli IP hash'inin olayları (anomali tespiti)
        Index(
            "ix_audit_ip_hash",
            "ip_hash",
            postgresql_where=text("ip_hash IS NOT NULL"),
        ),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent id={self.id} type={self.event_type} user={self.user_id}>"

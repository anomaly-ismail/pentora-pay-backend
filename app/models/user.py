"""
Kullanıcı Modeli
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TCKN Gizleme — Kritik Güvenlik Tasarımı:
  Veritabanında TCKN ASLA plaintext saklanmaz.
  Bunun yerine: tckn_hash = HMAC-SHA3-512(tckn, TCKN_PEPPER)

  Neden HMAC, düz hash değil?
    - SHA3(TCKN): Türkiye'deki ~100M TCKN'nin rainbow tablosu dakikalar içinde
      oluşturulabilir (11 rakam, makul aralık).
    - HMAC(TCKN, PEPPER): Pepper olmadan rainbow tablo üretmek imkensizdir.
      Pepper (sunucu sırrı) HSM/vault'ta korunmalıdır.
    - PMAC bütünlük de sağlar — pepper bilinmeden hash değeri taklid edilemez.

  Erişim paterni: Lookup için tckn alanına hash hesaplanır → eşitlik kontrolü.
  TCKN hiçbir zaman geri döndürülemez (tek yönlü).

PIN:
  Argon2id ile hashlenir (gr_auth.py'deki KDF parametreleriyle).
  GRAuth derivation salt'ından farklı bir PIN salt kullanılır.

NFC UID:
  SHA3-256(nfc_uid, TCKN_PEPPER) — aynı pepper, ayrı hash.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    # ── Birincil Anahtar ─────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
        comment="Kullanıcı UUID'si — dahili tanımlayıcı",
    )

    # ── TCKN Hash (plaintext YOK) ────────────────────────────────────────────
    # HMAC-SHA3-512(tckn, TCKN_PEPPER) → 128-hex karakter
    tckn_hash: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
        comment="HMAC-SHA3-512(TCKN, TCKN_PEPPER) — plaintext TCKN saklanmaz",
    )

    # ── PIN Hash (Argon2id) ──────────────────────────────────────────────────
    # Argon2id(pin, pin_salt) → $argon2id$... formatı
    pin_hash: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        comment="Argon2id(PIN, pin_salt) — plaintext PIN saklanmaz",
    )

    # ── NFC UID Hash ─────────────────────────────────────────────────────────
    # SHA3-256(nfc_uid_hex, TCKN_PEPPER) → 64-hex karakter
    nfc_uid_hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        comment="SHA3-256(NFC_UID, TCKN_PEPPER) — NFC doğrulandıysa dolu",
    )

    # ── GRAuth Argon2id Tuzu ─────────────────────────────────────────────────
    # GRAuth token üretimi için kullanılan Argon2id tuzu (32 byte)
    # Her kullanıcıya özgü — token doğrulaması için DB'den okunur
    grauth_salt: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        nullable=False,
        comment="GRAuth Argon2id tuzu (32 byte CSPRNG)",
    )

    # ── Durum ────────────────────────────────────────────────────────────────
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        server_default=text("true"),
    )

    nfc_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default=text("false"),
        comment="NFC kimlik doğrulaması tamamlandı mı?",
    )

    # ── Zaman Damgaları ──────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Bileşik indeksler ────────────────────────────────────────────────────
    __table_args__ = (
        # NFC hash için kısmi indeks (yalnızca dolu kayıtlarda)
        Index("ix_users_nfc_uid_hash", "nfc_uid_hash",
              postgresql_where=text("nfc_uid_hash IS NOT NULL")),
        # Aktif kullanıcılar için hızlı sorgulama
        Index("ix_users_active", "is_active",
              postgresql_where=text("is_active = true")),
    )

    def __repr__(self) -> str:
        # Güvenlik: repr'de TCKN hash'in bile tamamı gösterilmez
        return f"<User id={self.id} active={self.is_active} nfc={self.nfc_verified}>"

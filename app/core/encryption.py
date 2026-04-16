"""
Kolon-Seviyesi Şifreleme (AES-256-GCM + HMAC Indexing)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Kimlik belgesi içerikleri (MRZ ham verisi, EF.DG1/DG2/DG11, EF.SOD, BAC seed)
PCI DSS Level 1 veri koruma gereksinimlerine uyacak şekilde şifrelenir.

Şema:
  1. Master key  = HKDF-SHA256(pentora_grauth_secret, info="mrtd-col-key-v1")
  2. Her kayıt için rastgele 12-byte nonce üretilir
  3. ciphertext = AES-256-GCM-Encrypt(master_key, nonce, plaintext, aad=aad)
  4. DB'ye saklanan: nonce || ciphertext (tag 16 byte içinde)
  5. Aranabilir alanlar için HMAC-SHA256(value, master_key) hex olarak indekslenir

Güvenlik:
  - OWASP A02: AEAD (GCM) ile integrity + confidentiality aynı anda
  - OWASP A08: AAD alanı (user_id + approve_id) ile cross-row substitution önlenir
  - PCI DSS 3.4 / 3.5: key derivation KDF ile türetilir, plaintext asla diskte
  - Forward-rotation: master key yenilendiğinde versioning headerı (v1) ile
    geriye dönük decryption uyumu korunabilir.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

NONCE_LEN = 12          # 96-bit nonce (GCM için önerilen)
VERSION_BYTE = b"\x01"  # Format versiyonu (rotation için)
_HKDF_INFO = b"mrtd-col-key-v1"
_HKDF_SALT = b"pentora.mrtd.col.salt.v1"


@lru_cache(maxsize=1)
def _master_key() -> bytes:
    settings = get_settings()
    # pentora_grauth_secret (>=32 char) üzerinden deterministik 32-byte türet
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    return hkdf.derive(settings.pentora_grauth_secret.encode("utf-8"))


@lru_cache(maxsize=1)
def _index_key() -> bytes:
    """HMAC indeksleri için ayrı subkey — confidentiality ile index'i ayırır."""
    settings = get_settings()
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=b"mrtd-index-key-v1",
    )
    return hkdf.derive(settings.pentora_grauth_secret.encode("utf-8"))


@dataclass(frozen=True)
class CipherBlob:
    """Şifrelenmiş veri zarfı — DB'de tek `bytea` kolonunda saklanır."""
    ciphertext: bytes  # [version(1)] || [nonce(12)] || [gcm_ciphertext+tag]

    def to_bytes(self) -> bytes:
        return self.ciphertext


def encrypt_blob(plaintext: bytes, *, aad: Optional[bytes] = None) -> bytes:
    """
    Veriyi AES-256-GCM ile şifreler.

    Dönen format:
      byte[0]       : version (0x01)
      byte[1..12]   : nonce (12 byte)
      byte[13..]    : ciphertext || tag (GCM)

    AAD verilirse decryption sırasında mutlaka aynı AAD ile çağrılmalıdır.
    """
    if plaintext is None:
        raise ValueError("plaintext None olamaz")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext bytes olmalı")

    key = _master_key()
    nonce = os.urandom(NONCE_LEN)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, bytes(plaintext), aad)
    return VERSION_BYTE + nonce + ct


def decrypt_blob(blob: bytes, *, aad: Optional[bytes] = None) -> bytes:
    """
    encrypt_blob ile şifrelenmiş veriyi çözer. AAD'ler eşleşmezse ValueError.
    """
    if not blob or len(blob) < 1 + NONCE_LEN + 16:
        raise ValueError("geçersiz şifreli blob: çok kısa")

    version = blob[0:1]
    if version != VERSION_BYTE:
        raise ValueError(f"desteklenmeyen şifreleme versiyonu: {version!r}")

    nonce = blob[1 : 1 + NONCE_LEN]
    ct = blob[1 + NONCE_LEN :]

    key = _master_key()
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ct, aad)
    except Exception as exc:
        logger.warning("mrtd.col.decrypt_failed", error=str(exc))
        raise ValueError("şifre çözme başarısız (integrity / aad hatası)") from exc


def hmac_index(value: str | bytes) -> str:
    """
    Aranabilir sabit-uzunluk HMAC-SHA256 indeksi üretir.
    Örnek: MRZ doküman numarasının tekrarını tespit etmek için kullanılır.
    """
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hmac.new(_index_key(), value, hashlib.sha256).hexdigest()


def build_aad(*parts: str) -> bytes:
    """
    AAD'yi kararlı biçimde oluşturur — `user_id:approve_id:field_name` gibi.
    Null parçalar boş string kabul edilir.
    """
    safe = [p if p is not None else "" for p in parts]
    return "|".join(safe).encode("utf-8")


__all__ = [
    "encrypt_blob",
    "decrypt_blob",
    "hmac_index",
    "build_aad",
    "CipherBlob",
]

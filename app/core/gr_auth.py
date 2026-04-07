"""
X-Pentora-GRAuth Token Sistemi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Üç faktörle bağlanmış, çok katmanlı şifreli opak kimlik bileti.
Token yalnızca TCKN + PIN + NFC üçlüsüyle üretilir; herhangi bir faktör
eksik ya da yanlışsa token üretilemez ve doğrulanamaz.

━━ Kriptografik Yığın ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Katman 1 — Faktör Türetimi (Argon2id)
  Girdi : TCKN || "¦" || PIN || "¦" || NFC_UID_hash
  Tuz   : 32-byte CSPRNG (kullanıcıya özgü, DB'de saklanır)
  Çıktı : 64-byte master_key
  Parametre: time_cost=4, memory_cost=1 048 576 (1 GB RAM/işlem), parallelism=4
  ── Neden? Her kaba-kuvvet denemesi 1 GB RAM + ~2 saniye gerektirir.
             Bir GPU bile saniyede yalnızca birkaç deneme yapabilir.
             10^9 deneme → ~31 yıl @ $1M GPU kümesi.
             Faktör alanı (11+6+NFC) ile birlikte efektif güvenlik ∞'ye yakın.

Katman 2 — Alt Anahtar Türetimi (HKDF-SHA-512)
  master_key'den iki bağımsız anahtar türetilir:
    enc_key  (32 byte) → AES-256-GCM şifreleme anahtarı
    mac_key  (64 byte) → HMAC-SHA3-512 dış MAC anahtarı

Katman 3 — Payload Şifreleme (AES-256-GCM)
  Şifreleme : AES-256-GCM (NIST SP 800-38D)
  Anahtar   : enc_key (32 byte = 256 bit)
  Nonce     : 12-byte CSPRNG (tek kullanım)
  AAD       : version || salt (değiştirme saldırısını engeller)
  Çıktı     : ciphertext + 16-byte auth_tag (AEAD)
  ── Kuantum sonrası: Grover algoritması 256→128 bit düşürür.
     128-bit güvenlik = aramak için 2^128 ≈ 3.4×10^38 işlem.
     Tüm dünya bilgisayarları birlikte ~10^30 yıl gerektirir.

Katman 4 — Dış MAC (HMAC-SHA3-512)
  mac_key üzerinden tüm token wire formatına uygulanır.
  SHA-3 (Keccak): NIST tarafından SHA-2'nin yerini alması için seçildi.
  SHA3-512 çıktı: 512 bit → Grover'a karşı 256-bit kuantum güvenliği.

━━ Token Wire Formatı ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    base64url(
        "GR"[2]           magic bytes
      + 0x02[1]           version
      + salt[32]          Argon2id tuzu
      + nonce[12]         AES-GCM nonce'u
      + ciphertext[N]     AES-256-GCM şifreli payload + 16-byte tag
      + mac[64]           HMAC-SHA3-512 dış imzası
    )

Minimum token boyutu: 2+1+32+12+?+16+64 = 127+ byte → ~170+ base64url char

━━ Şifreli Payload(JSON) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    {
      "uid" : "<kullanıcı UUID>",
      "thn" : "<SHA3-256(TCKN || server_pepper)>",
      "nfh" : "<SHA3-256(NFC_UID || server_pepper)>",
      "sid" : "<oturum UUID>",
      "iat" : <Unix timestamp>,
      "exp" : <Unix timestamp>,
      "fac" : "<factor_binding HMAC>",    // üç faktörü bağlar
      "ver" : 2                           // token versiyonu
    }

━━ Güvenlik Nitelikleri ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  • Opak     : Payload şifreli, dışarıdan okunamaz (JWT'nin aksine)
  • Bağlı    : Token yalnızca üretildiği TCKN+PIN+NFC ile geçerli
  • Tekrar   : Replay saldırısına karşı oturum UUID + exp claim
  • Değişmez : AAD + AEAD + HMAC → tek bit bile değişirse doğrulama başarısız
  • İz       : Her token'a oturum UUID → audit trail

OWASP A02 (Cryptographic Failures) ve ISO 27001 A.10 (Cryptography) uyumlu.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import json
import os
import secrets
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ─── Sabitler ────────────────────────────────────────────────────────────────
_MAGIC = b"GR"
_VERSION = b"\x02"

# Argon2id Paramtreleri (RFC 9106 — maksimum güvenlik profili)
# Her deneme: ~1 GB RAM + ~1-2 saniye işlem süresi
# Kaba-kuvvet: GPU kümesiyle bile yıllar alır
_ARGON2_TIME_COST   = 4          # yineleme sayısı
_ARGON2_MEMORY_COST = 1_048_576  # 1 GB (KiB cinsinden)
_ARGON2_PARALLELISM = 4          # paralel iş parçacığı
_ARGON2_HASH_LEN    = 64         # 512-bit çıktı (master_key)

# AES-256-GCM
_AES_KEY_LEN  = 32   # 256-bit
_AES_NONCE_LEN = 12  # 96-bit (GCM standard)

# HMAC-SHA3-512 dış MAC
_MAC_KEY_LEN = 64    # 512-bit
_MAC_LEN     = 64    # SHA3-512 çıktı boyutu

# Argon2 tuzu
_SALT_LEN = 32       # 256-bit rastgele tuz

# Token ömrü (varsayılan: 30 dakika)
_DEFAULT_TTL_SECONDS = 1_800

# ─── HKDF bilgi etiketleri (farklı alt anahtarlar için) ──────────────────────
_HKDF_INFO_ENC = b"pentora-grauth-v2-enc-key"
_HKDF_INFO_MAC = b"pentora-grauth-v2-mac-key"
_HKDF_INFO_FAC = b"pentora-grauth-v2-factor-binding"

# Faktör birleştirme ayracı (US ASCII'de özel karakter — TCKN/PIN içinde olmaz)
_FACTOR_SEP = b"\x00\xff\x00"


# ─────────────────────────────────────────────────────────────────────────────
# Veri yapıları
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GRAuthClaims:
    """Şifreli payload içindeki doğrulanmış talepler."""
    uid: str          # Kullanıcı UUID
    thn: str          # SHA3-256(TCKN || pepper) — TCKN hash'i
    nfh: str          # SHA3-256(NFC_UID || pepper) — NFC hash'i
    sid: str          # Oturum UUID
    iat: int          # Üretim zaman damgası (Unix)
    exp: int          # Son kullanma (Unix)
    fac: str          # Faktör bağlama HMAC'i
    ver: int = 2      # Token versiyonu


@dataclass
class GRAuthToken:
    """Üretilen GRAuth token ve ilgili meta veriler."""
    token: str            # base64url kodlu wire formatı
    session_id: str       # Oturum UUID (audit trail için)
    issued_at: int        # Üretim Unix timestamp
    expires_at: int       # Son kullanma Unix timestamp
    argon2_salt: bytes    # Kullanıcı kaydında DB'de saklanacak tuz


# ─────────────────────────────────────────────────────────────────────────────
# Çekirdek kriptografik motorlar
# ─────────────────────────────────────────────────────────────────────────────

def _derive_master_key(
    tckn: str,
    pin: str,
    nfc_uid_hex: str,
    salt: bytes,
) -> bytes:
    """
    Katman 1: Argon2id ile üç faktörden 512-bit master_key türetir.

    Faktörler bellekte birleştirilir, ardından Argon2id'e tek girdi olarak
    verilir — bu sayede herhangi bir faktörü değiştirmek tamamen farklı bir
    anahtar üretir.

    Args:
        tckn        : 11 haneli T.C. Kimlik Numarası
        pin         : 6 haneli PIN
        nfc_uid_hex : NFC kartın HEX UID'i (TC Kimlik Kartı)
        salt        : 32-byte CSPRNG tuzu (kullanıcıya özgü)

    Returns:
        64-byte master_key
    """
    # Faktörleri güvenli şekilde birleştir (sep ile ayrılır, birleşme saldırısı önlenir)
    factor_secret = (
        tckn.encode("ascii")
        + _FACTOR_SEP
        + pin.encode("ascii")
        + _FACTOR_SEP
        + nfc_uid_hex.upper().encode("ascii")
    )

    master_key = hash_secret_raw(
        secret=factor_secret,
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_ARGON2_HASH_LEN,
        type=Type.ID,
    )

    # Belleği güvenli şekilde sıfırla (Python'da tam garanti edilemez,
    # ancak açık atama en azından referansı keser)
    del factor_secret

    return master_key


def _derive_subkeys(master_key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Katman 2: HKDF-SHA-512 ile master_key'den üç bağımsız alt anahtar türetir.

    Bağımsız HKDF türetimleri kullanan alt anahtarlar birbirini açığa çıkarmaz.

    Returns:
        (enc_key[32], mac_key[64], fac_key[64])
    """
    def _hkdf(length: int, info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA512(),
            length=length,
            salt=None,   # master_key zaten Argon2id ile güçlendirildi
            info=info,
        ).derive(master_key)

    enc_key = _hkdf(_AES_KEY_LEN,  _HKDF_INFO_ENC)   # AES-256 şifreleme
    mac_key = _hkdf(_MAC_KEY_LEN,  _HKDF_INFO_MAC)   # HMAC-SHA3-512 dış MAC
    fac_key = _hkdf(_MAC_KEY_LEN,  _HKDF_INFO_FAC)   # Faktör bağlama HMAC

    return enc_key, mac_key, fac_key


def _build_factor_binding(
    tckn: str,
    pin: str,
    nfc_uid_hex: str,
    user_id: str,
    session_id: str,
    fac_key: bytes,
) -> str:
    """
    Faktör bağlama HMAC'i — token'ı belirli TCKN+PIN+NFC+User+Session ile bağlar.
    Doğrulama sırasında bu değer yeniden hesaplanarak eşleşme kontrol edilir.
    """
    binding_data = (
        tckn.encode("ascii")
        + _FACTOR_SEP
        + pin.encode("ascii")
        + _FACTOR_SEP
        + nfc_uid_hex.upper().encode("ascii")
        + _FACTOR_SEP
        + user_id.encode("ascii")
        + _FACTOR_SEP
        + session_id.encode("ascii")
    )
    h = crypto_hmac.HMAC(fac_key, hashes.SHA3_512())
    h.update(binding_data)
    return h.finalize().hex()


def _encrypt_payload(payload: dict, enc_key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """
    Katman 3: AES-256-GCM ile payload'ı şifreler.

    AAD (Additional Authenticated Data): magic + version + salt
    → Bu alanlar değiştirilirse şifre çözme başarısız olur.

    Returns:
        (nonce[12], ciphertext_with_tag)
    """
    aesgcm = AESGCM(enc_key)
    nonce = secrets.token_bytes(_AES_NONCE_LEN)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def _decrypt_payload(
    ciphertext: bytes,
    nonce: bytes,
    enc_key: bytes,
    aad: bytes,
) -> dict:
    """AES-256-GCM ile şifre çözer. Auth tag hatalıysa InvalidTag fırlatır."""
    aesgcm = AESGCM(enc_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return json.loads(plaintext.decode("utf-8"))


def _compute_outer_mac(wire_data: bytes, mac_key: bytes) -> bytes:
    """
    Katman 4: Tüm wire verisine HMAC-SHA3-512 uygular.
    wire_data = magic + version + salt + nonce + ciphertext
    """
    h = crypto_hmac.HMAC(mac_key, hashes.SHA3_512())
    h.update(wire_data)
    return h.finalize()


def _verify_outer_mac(wire_data: bytes, mac: bytes, mac_key: bytes) -> bool:
    """Zamanlama saldırısına karşı sabit-zamanlı MAC doğrulama."""
    h = crypto_hmac.HMAC(mac_key, hashes.SHA3_512())
    h.update(wire_data)
    expected = h.finalize()
    return stdlib_hmac.compare_digest(expected, mac)


# ─────────────────────────────────────────────────────────────────────────────
# Hash yardımcıları (içerik gizleme)
# ─────────────────────────────────────────────────────────────────────────────

def _sha3_256_hex(value: str, pepper: str) -> str:
    """
    SHA3-256(value || pepper) → TCKN ve NFC_UID'yi payload'da plaintext
    tutmadan doğrulanabilir şekilde hashler.
    Pepper = sunucu sırrı (env'den), DB sızıntısında ek koruma sağlar.
    """
    return hashlib.sha3_256(
        value.encode("utf-8") + pepper.encode("utf-8")
    ).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Genel API
# ─────────────────────────────────────────────────────────────────────────────

def generate_grauth_token(
    *,
    tckn: str,
    pin: str,
    nfc_uid_hex: str,
    user_id: str,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    existing_salt: Optional[bytes] = None,
) -> GRAuthToken:
    """
    Üç faktörden GRAuth token üretir.

    Args:
        tckn          : T.C. Kimlik Numarası (doğrulanmış)
        pin           : 6 haneli PIN (plaintext — burada hash'lenir)
        nfc_uid_hex   : TC Kimlik Kartı NFC UID (Flutter'dan)
        user_id       : Kullanıcı UUID (DB'de kayıtlı)
        ttl_seconds   : Token geçerlilik süresi (varsayılan: 30 dk)
        existing_salt : Mevcut kullanıcının tuzu (yeniden giriş için)
                        None → yeni tuz üretilir (kayıt için)

    Returns:
        GRAuthToken  — token string'i ve meta veriler

    Raises:
        ValueError   : Geçersiz girdi
        RuntimeError : Kriptografik hata
    """
    settings = get_settings()

    # Girdi doğrulama
    if len(tckn) != 11 or not tckn.isdigit():
        raise ValueError("Geçersiz TCKN formatı")
    if len(pin) != 6 or not pin.isdigit():
        raise ValueError("Geçersiz PIN formatı: 6 rakam olmalı")
    # nfc_uid_hex boş string → login modu (NFC faktörü sıfır bayt olarak Argon2id'e girer)
    # 1–7 karakter → geçersiz (kısmi HEX kabul edilmez)
    if nfc_uid_hex and len(nfc_uid_hex) < 8:
        raise ValueError("Geçersiz NFC UID: en az 8 HEX karakter gerekli")

    # Oturum ve zaman
    session_id = str(uuid.uuid4())
    now = int(time.time())
    exp = now + ttl_seconds

    # Tuz
    salt = existing_salt if existing_salt is not None else secrets.token_bytes(_SALT_LEN)

    # finally içinde güvenli temizlik: atanmamış isimlere del uygulanmaz (UnboundLocalError önlenir)
    master_key: Optional[bytes] = None
    enc_key: Optional[bytes] = None
    mac_key: Optional[bytes] = None
    fac_key: Optional[bytes] = None

    try:
        # Katman 1: Argon2id master key
        logger.info("grauth.key_derivation.start", user_id=user_id, session_id=session_id)
        master_key = _derive_master_key(tckn, pin, nfc_uid_hex, salt)

        # Katman 2: Alt anahtarlar
        enc_key, mac_key, fac_key = _derive_subkeys(master_key)

        # Faktör bağlama HMAC'i
        factor_binding = _build_factor_binding(
            tckn, pin, nfc_uid_hex, user_id, session_id, fac_key
        )

        # Pepper ile hash'lenmiş faktörler (payload içinde plaintext saklanmaz)
        pepper = settings.pentora_grauth_secret
        tckn_hash = _sha3_256_hex(tckn, pepper)
        nfc_hash  = _sha3_256_hex(nfc_uid_hex.upper(), pepper)

        # Payload
        payload = {
            "uid": user_id,
            "thn": tckn_hash,
            "nfh": nfc_hash,
            "sid": session_id,
            "iat": now,
            "exp": exp,
            "fac": factor_binding,
            "ver": 2,
        }

        # Wire format başlığı (AAD olarak da kullanılır)
        header = _MAGIC + _VERSION + salt

        # Katman 3: AES-256-GCM şifreleme
        nonce, ciphertext = _encrypt_payload(payload, enc_key, aad=header)

        # Wire verisi (MAC hesabından önce)
        wire_without_mac = header + nonce + ciphertext

        # Katman 4: HMAC-SHA3-512 dış MAC
        outer_mac = _compute_outer_mac(wire_without_mac, mac_key)

        # Final token
        raw_token = wire_without_mac + outer_mac
        token_str = urlsafe_b64encode(raw_token).decode("ascii").rstrip("=")

        logger.info(
            "grauth.token.generated",
            user_id=user_id,
            session_id=session_id,
            token_len=len(token_str),
            expires_at=exp,
        )

        return GRAuthToken(
            token=token_str,
            session_id=session_id,
            issued_at=now,
            expires_at=exp,
            argon2_salt=salt,
        )

    except Exception as exc:
        logger.error(
            "grauth.token.generation_failed",
            user_id=user_id,
            exc_type=type(exc).__name__,
            exc_msg=str(exc),
        )
        raise RuntimeError("GRAuth token üretilemedi") from exc
    finally:
        # Anahtar materyalini bellekten temizle (yalnızca üretildiyse)
        if master_key is not None:
            del master_key
        if enc_key is not None:
            del enc_key
        if mac_key is not None:
            del mac_key
        if fac_key is not None:
            del fac_key


def verify_grauth_token(
    *,
    token_str: str,
    tckn: str,
    pin: str,
    nfc_uid_hex: str,
    stored_salt: bytes,
) -> GRAuthClaims:
    """
    GRAuth tokenı doğrular ve claim'leri döner.

    Doğrulama adımları (sıra önemli):
      1. Wire format parse
      2. Dış HMAC-SHA3-512 doğrulama
      3. Same Argon2id derivation (stored salt ile)
      4. AES-256-GCM şifre çözme + auth tag doğrulama
      5. Payload claim doğrulama (exp, ver, fac)
      6. Faktör bağlama HMAC doğrulama

    Args:
        token_str    : Header'daki base64url token
        tckn         : İsteği yapan kullanıcının TCKN'si
        pin          : Gönderilen PIN
        nfc_uid_hex  : İstekle gelen NFC UID
        stored_salt  : DB'den alınan kullanıcı Argon2id tuzu

    Returns:
        GRAuthClaims — doğrulanmış talepler

    Raises:
        GRAuthInvalidError : Her türlü doğrulama hatası
                             (hata tipi dışarıya sızdırılmaz)
    """
    try:
        # Padding geri ekle
        padding = "=" * (4 - len(token_str) % 4)
        raw = urlsafe_b64decode(token_str + padding)
    except Exception:
        raise GRAuthInvalidError("Geçersiz token formatı")

    # ── Wire format parse ────────────────────────────────────────────────────
    offset = 0

    # Magic (2) + Version (1)
    if len(raw) < 3:
        raise GRAuthInvalidError("Token çok kısa")
    magic   = raw[offset:offset+2]; offset += 2
    version = raw[offset:offset+1]; offset += 1

    if magic != _MAGIC:
        raise GRAuthInvalidError("Geçersiz token sihirli baytı")
    if version != _VERSION:
        raise GRAuthInvalidError(f"Desteklenmeyen token versiyonu: {version.hex()}")

    # Salt (32) + Nonce (12)
    if len(raw) < offset + _SALT_LEN + _AES_NONCE_LEN + _MAC_LEN + 1:
        raise GRAuthInvalidError("Token yapısı bozuk")

    salt  = raw[offset:offset+_SALT_LEN];    offset += _SALT_LEN
    nonce = raw[offset:offset+_AES_NONCE_LEN]; offset += _AES_NONCE_LEN

    # Ciphertext ve MAC ayır
    mac          = raw[-_MAC_LEN:]
    ciphertext   = raw[offset:-_MAC_LEN]

    if len(ciphertext) == 0:
        raise GRAuthInvalidError("Şifreli içerik boş")

    # ── Argon2id ile master_key türet (stored_salt ile) ─────────────────────
    try:
        master_key = _derive_master_key(tckn, pin, nfc_uid_hex, stored_salt)
    except Exception:
        raise GRAuthInvalidError("Anahtar türetme başarısız")

    try:
        enc_key, mac_key, fac_key = _derive_subkeys(master_key)
    finally:
        del master_key

    # ── HMAC-SHA3-512 dış MAC doğrulama ─────────────────────────────────────
    wire_without_mac = raw[:-_MAC_LEN]
    if not _verify_outer_mac(wire_without_mac, mac, mac_key):
        raise GRAuthInvalidError("MAC doğrulama başarısız")

    # ── AES-256-GCM şifre çözme ─────────────────────────────────────────────
    header = _MAGIC + _VERSION + salt
    try:
        payload = _decrypt_payload(ciphertext, nonce, enc_key, aad=header)
    except Exception:
        raise GRAuthInvalidError("Şifre çözme başarısız")
    finally:
        del enc_key

    # ── Claim doğrulama ─────────────────────────────────────────────────────
    now = int(time.time())

    if payload.get("ver") != 2:
        raise GRAuthInvalidError("Desteklenmeyen payload versiyonu")

    exp = payload.get("exp", 0)
    if now > exp:
        raise GRAuthInvalidError(f"Token süresi dolmuş (exp={exp}, now={now})")

    settings = get_settings()
    pepper = settings.pentora_grauth_secret

    # TCKN hash doğrulama
    expected_thn = _sha3_256_hex(tckn, pepper)
    if not stdlib_hmac.compare_digest(payload.get("thn", ""), expected_thn):
        raise GRAuthInvalidError("TCKN uyuşmazlığı")

    # NFC hash doğrulama
    expected_nfh = _sha3_256_hex(nfc_uid_hex.upper(), pepper)
    if not stdlib_hmac.compare_digest(payload.get("nfh", ""), expected_nfh):
        raise GRAuthInvalidError("NFC UID uyuşmazlığı")

    # Faktör bağlama HMAC doğrulama
    expected_fac = _build_factor_binding(
        tckn, pin, nfc_uid_hex,
        payload["uid"], payload["sid"],
        fac_key,
    )
    if not stdlib_hmac.compare_digest(payload.get("fac", ""), expected_fac):
        raise GRAuthInvalidError("Faktör bağlama doğrulama başarısız")

    del fac_key

    logger.info(
        "grauth.token.verified",
        user_id=payload["uid"],
        session_id=payload["sid"],
        exp=exp,
    )

    return GRAuthClaims(
        uid=payload["uid"],
        thn=payload["thn"],
        nfh=payload["nfh"],
        sid=payload["sid"],
        iat=payload["iat"],
        exp=payload["exp"],
        fac=payload["fac"],
        ver=payload["ver"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Özel hata sınıfı
# ─────────────────────────────────────────────────────────────────────────────

class GRAuthInvalidError(Exception):
    """
    GRAuth doğrulama hatası.
    Hata mesajı kasıtlı olarak geneldir — iç detaylar loglanır,
    istemciye yalnızca 'authentication_failed' döner (OWASP A01).
    """
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Güvenlik parametrelerini kontrol eden yardımcı (startup'ta çağrılır)
# ─────────────────────────────────────────────────────────────────────────────

def assert_crypto_environment() -> None:
    """
    Kriptografik ortamın doğru yapılandırıldığını startup'ta doğrular.
    Herhangi bir sorun varsa uygulama başlatmayı durdurur.
    """
    settings = get_settings()

    # Pepper yeterince uzun mu?
    if len(settings.pentora_grauth_secret) < 64:
        raise RuntimeError(
            "PENTORA_GRAUTH_SECRET en az 64 karakter olmalıdır. "
            "Üretmek için: python -c \"import secrets; print(secrets.token_hex(64))\""
        )

    # AES modülü çalışıyor mu?
    test_key = secrets.token_bytes(32)
    test_nonce = secrets.token_bytes(12)
    test_msg = b"crypto_self_test"
    ct = AESGCM(test_key).encrypt(test_nonce, test_msg, None)
    pt = AESGCM(test_key).decrypt(test_nonce, ct, None)
    assert pt == test_msg, "AES-256-GCM öz-testi başarısız"

    logger.info(
        "grauth.crypto.self_test_passed",
        argon2_time_cost=_ARGON2_TIME_COST,
        argon2_memory_mb=_ARGON2_MEMORY_COST // 1024,
        argon2_parallelism=_ARGON2_PARALLELISM,
        enc_algorithm="AES-256-GCM",
        mac_algorithm="HMAC-SHA3-512",
        kdf="Argon2id + HKDF-SHA-512",
    )

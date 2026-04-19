"""
ECDH Ephemeral Key Exchange — Dinamik Session Secret Yönetimi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Neden statik APK secret yerine bu?
  - Statik secret: APK içinde bulunur, tersine mühendislikle çıkarılabilir.
  - ECDH Ephemeral: Her oturumda yeni anahtar çifti, shared secret hiç
    diskten geçmez, sadece RAM'de yaşar, oturum bitince yok olur.
    Forward secrecy garantisi: eski oturumlar sonradan da çözülemez.

Protokol (uygulama katmanı mini-TLS):
  1. Flutter: P-256 ephemeral keypair üret → pubkey + nonce gönder
  2. Sunucu: Kendi ephemeral keypair üretir
  3. Sunucu: shared = ECDH(server_priv, client_pub)
  4. Her iki taraf: session_key = HKDF-SHA256(shared, server_nonce||client_nonce)
  5. Sunucu: session_key → RAM store (TTL: 5dk)
  6. Flutter: session_key → RAM only, APK'ye kaydedilmez
  7. Sonraki istekler: HMAC-SHA256(handshake_id:ts:path, session_key)

Kullanılan algoritmalar:
  - Eğri: P-256 (NIST, FIPS 186-4) — yaygın destek, yüksek güvenlik
  - KDF: HKDF-SHA-256 (RFC 5869)
  - MAC: HMAC-SHA256 (request signing)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory Session Store (üretimde Redis ile değiştirilebilir)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HandshakeEntry:
    session_key: bytes          # 32-byte ECDH türevli session key (RAM-only)
    expires_at: float           # Unix timestamp
    bundle_id: str              # Hangi Flutter bundle'dan geldi
    used_count: int = 0         # Kullanım sayısı (abuse tespiti için)


class _HandshakeStore:
    """
    Thread-safe in-memory handshake store.
    Her entry TTL sonunda temizlenir.
    Üretimde Redis + encryption kullanın.
    """

    def __init__(self) -> None:
        self._store: dict[str, HandshakeEntry] = {}
        self._lock = asyncio.Lock()

    async def put(self, handshake_id: str, entry: HandshakeEntry) -> None:
        async with self._lock:
            # M-5: Maksimum store boyutunu kontrol et (DoS koruması)
            settings = get_settings()
            max_size = settings.handshake_store_max_size
            await self._evict_expired()
            if len(self._store) >= max_size:
                # Kapasiteye ulaşıldı: en erken sona erecek girişi çıkar
                oldest_key = min(
                    self._store, key=lambda k: self._store[k].expires_at
                )
                del self._store[oldest_key]
                logger.warning(
                    "handshake_store.evicted_oldest",
                    store_size=len(self._store),
                    max_size=max_size,
                )
            self._store[handshake_id] = entry

    async def get(self, handshake_id: str) -> HandshakeEntry | None:
        async with self._lock:
            entry = self._store.get(handshake_id)
            if entry is None:
                return None
            if time.time() > entry.expires_at:
                del self._store[handshake_id]
                return None
            return entry

    async def revoke(self, handshake_id: str) -> None:
        async with self._lock:
            self._store.pop(handshake_id, None)

    async def _evict_expired(self) -> None:
        now = time.time()
        expired = [k for k, v in self._store.items() if now > v.expires_at]
        for k in expired:
            del self._store[k]

    def __len__(self) -> int:
        return len(self._store)


# Singleton store (app başına bir instance)
handshake_store = _HandshakeStore()


# ─────────────────────────────────────────────────────────────────────────────
# ECDH Key Exchange Motoru
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HandshakeResult:
    handshake_id: str
    server_public_key_b64: str    # Flutter'a gönderilecek server pubkey
    server_nonce_b64: str         # HKDF için server nonce
    expires_in: int               # Saniye cinsinden TTL


async def perform_handshake(
    client_public_key_b64: str,
    client_nonce_b64: str,
    bundle_id: str,
) -> HandshakeResult:
    """
    ECDH Handshake gerçekleştirir:
      1. Client public key'i deserialize et
      2. Server ephemeral keypair üret
      3. ECDH shared secret hesapla
      4. HKDF ile session_key türet
      5. RAM store'a kaydet
      6. Server public key'i döndür

    Args:
        client_public_key_b64: Flutter'ın P-256 public key'i (DER, base64)
        client_nonce_b64     : Flutter'ın random nonce'u (base64, 32 byte)
        bundle_id            : Flutter app bundle ID'si

    Returns:
        HandshakeResult — Flutter'a iletilecek sunucu bilgileri
    """
    settings = get_settings()
    ttl = settings.handshake_ttl_seconds

    # ── Client public key deserialize ────────────────────────────────────────
    try:
        client_pubbytes = b64decode(client_public_key_b64)
        if len(client_pubbytes) != 32:
            raise ValueError("Sadece X25519 public key (32 bytes) desteklenir")
        
        client_public_key = X25519PublicKey.from_public_bytes(client_pubbytes)
    except Exception as exc:
        raise HandshakeError("Geçersiz client public key formatı") from exc

    # Client nonce
    try:
        client_nonce = b64decode(client_nonce_b64)
        if len(client_nonce) < 16:
            raise ValueError("Nonce çok kısa")
    except Exception as exc:
        raise HandshakeError("Geçersiz client nonce") from exc

    # ── Server ephemeral keypair ──────────────────────────────────────────────
    server_private_key = X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()
    server_nonce = secrets.token_bytes(32)

    # ── ECDH Shared Secret ───────────────────────────────────────────────────
    shared_secret = server_private_key.exchange(client_public_key)

    # ── HKDF-SHA256: Session Key Türetimi ───────────────────────────────────
    # info = server_nonce || client_nonce (her iki taraf deterministic türetir)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pentora-session-key-v1:" + server_nonce + client_nonce,
    ).derive(shared_secret)

    # ── Store'a kaydet ───────────────────────────────────────────────────────
    handshake_id = secrets.token_urlsafe(32)
    entry = HandshakeEntry(
        session_key=session_key,
        expires_at=time.time() + ttl,
        bundle_id=bundle_id,
    )
    await handshake_store.put(handshake_id, entry)

    # ── Server public key serialize (Raw X,Y bytes → base64) ────────────────
    server_pubbytes_raw = server_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Belleği temizle
    del shared_secret, server_private_key

    logger.info(
        "handshake.completed",
        handshake_id=handshake_id,
        bundle_id=bundle_id,
        expires_in=ttl,
        store_size=len(handshake_store),
    )

    return HandshakeResult(
        handshake_id=handshake_id,
        server_public_key_b64=b64encode(server_pubbytes_raw).decode(),
        server_nonce_b64=b64encode(server_nonce).decode(),
        expires_in=ttl,
    )


async def get_session_key(handshake_id: str) -> bytes | None:
    """Middleware tarafından çağrılır — geçerli session key'i döndürür."""
    entry = await handshake_store.get(handshake_id)
    if entry is None:
        return None
    entry.used_count += 1
    return entry.session_key


async def revoke_handshake(handshake_id: str) -> None:
    """Logout veya güvenlik olaylarında oturumu geçersiz kıl."""
    await handshake_store.revoke(handshake_id)
    logger.info("handshake.revoked", handshake_id=handshake_id)


# ─────────────────────────────────────────────────────────────────────────────
# Request İmza Hesaplama (Flutter ile aynı algoritma)
# ─────────────────────────────────────────────────────────────────────────────

def compute_request_sig(
    handshake_id: str,
    timestamp: int,
    path: str,
    session_key: bytes,
    *,
    nonce: str = "",
    body: bytes | None = None,
) -> str:
    """
    HMAC-SHA256(f"{handshake_id}:{timestamp}:{path}:{nonce}:{body_sha256}", session_key) → hex

    M-16: nonce + body hash imzaya dahil edilir.
      • nonce: Client tarafından her istekte yeni üretilir (replay koruma).
      • body : POST/PUT body'sinin SHA-256 hash'i hex (tampering koruma).
        Body yoksa boş string ("").

    Geriye dönük uyumluluk:
      • Eski istemciler nonce/body göndermez → ikisi de "" → eski hash sonucu
        elde edilir, üretim açısından kırıcı değildir; ancak yeni istemciler
        zorunlu olarak nonce + body_sha256 ile imzalar.

    Flutter tarafı aynı fonksiyonu uygulamalıdır:
    ```dart
    final bodyHash = body == null ? '' : sha256.convert(body).toString();
    final msg = '$handshakeId:$timestamp:$path:$nonce:$bodyHash';
    final sig = Hmac(sha256, sessionKey).convert(utf8.encode(msg)).toString();
    ```
    """
    import hmac as stdlib_hmac
    if body is None or len(body) == 0:
        body_sha = ""
    else:
        body_sha = hashlib.sha256(body).hexdigest()
    message = f"{handshake_id}:{timestamp}:{path}:{nonce}:{body_sha}".encode("utf-8")
    return stdlib_hmac.new(session_key, message, hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Hata
# ─────────────────────────────────────────────────────────────────────────────

class HandshakeError(Exception):
    """ECDH handshake hatası."""
    pass

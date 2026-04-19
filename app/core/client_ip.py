"""
Güvenilir Reverse-Proxy IP Çözümleyicisi  (H-3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

`X-Forwarded-For` (XFF) ve `X-Real-IP` başlıkları HTTP istemcisinin doğrudan
spoof edebileceği değerlerdir. Audit log, rate limiter ve fraud kararlarında
kötüye kullanılırsa:

  • Saldırgan loglarda farklı IP gibi görünür → izi sürmek zorlaşır
    (PCI-DSS Req. 10.2 / ISO 27001 A.12.4 ihlali).
  • Rate limiter atlanır.
  • Coğrafi/IP tabanlı fraud skorları manipüle olur.

Bu yardımcı, sadece `trusted_proxy_ips` listesinde olan reverse proxy'lerden
gelen `XFF`/`X-Real-IP` değerlerini güvenir; aksi halde TCP-level peer IP'si
(`request.client.host`) kullanılır.

Üretimde:
  • Edge proxy (Cloudflare/Nginx/Traefik) IP'sini `TRUSTED_PROXY_IPS`'e koyun.
  • Cloudflare Tunnel kullanıyorsanız `cloudflared` localhost'tan istek atar
    (genellikle `127.0.0.1` veya `::1`); bu IP'leri allowlist'e ekleyin ve
    `CF-Connecting-IP` header'ı gerçek istemci IP'si olarak kullanılır.
  • Birden fazla hop varsa (Cloudflare → Nginx → app) hepsini ekleyin.

Notlar:
  • XFF formatı:  "client, hop1, hop2"  (en soldan en sağa)
  • Bu sürüm tek-hop trusted proxy varsayımı yapar; çok hop için
    `num_trusted_hops` parametresi opsiyonel olarak XFF'in en sağdan o kadar
    IP'yi atar.  Varsayılan davranış: TCP peer trusted ise XFF'in en sol
    IP'sini "gerçek istemci" olarak döndürür.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

from starlette.requests import Request

from app.core.config import Settings, get_settings


def _normalize_ip(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _trusted_set(settings: Settings | None = None) -> frozenset[str]:
    settings = settings or get_settings()
    raw = settings.trusted_proxy_ips or ""
    out: set[str] = set()
    for part in raw.split(","):
        ip = _normalize_ip(part)
        if ip:
            out.add(ip)
    return frozenset(out)


def get_real_client_ip(
    request: Request,
    *,
    num_trusted_hops: int = 1,
) -> str:
    """
    Güvenli istemci IP çözümleme.

    1. `request.client.host` belirsizse → "unknown".
    2. TCP peer **trusted_proxy_ips** içinde değilse → peer IP döner;
       XFF/X-Real-IP **TAMAMEN GÖZ ARDI EDİLİR**.
    3. Aksi halde XFF okunur:
       - En sağdan `num_trusted_hops` adet IP atılır (her hop kendi gördüğü
         peer'i ekler);
       - kalan en sağdaki IP gerçek istemci olarak döner.
       - XFF yoksa X-Real-IP fallback.
       - Hiçbiri yoksa peer IP.
    """
    settings = get_settings()
    trusted = _trusted_set(settings)

    peer_ip = (request.client.host if request.client else "") or ""
    peer_norm = _normalize_ip(peer_ip)

    if peer_norm is None:
        return "unknown"
    if peer_norm not in trusted:
        # Reverse proxy'den geçmedi → istemcinin XFF/X-Real-IP/CF-Connecting-IP'sine güvenme.
        return peer_norm

    # Güvenilir proxy → önce Cloudflare-spesifik header (en doğru tek-IP kaynağı).
    cf_ip = _normalize_ip(request.headers.get("CF-Connecting-IP", ""))
    if cf_ip:
        return cf_ip

    # Sonra XFF zincirini ayrıştır.
    raw_xff = request.headers.get("X-Forwarded-For", "")
    if raw_xff:
        chain = [ip for ip in (_normalize_ip(p) for p in raw_xff.split(",")) if ip]
        if chain:
            # En sağdan trusted hop sayısı kadar at; kalan en sağdaki gerçek istemcidir.
            keep = chain[: max(1, len(chain) - max(0, num_trusted_hops - 1))]
            if keep:
                return keep[-1]
    real_ip = _normalize_ip(request.headers.get("X-Real-IP", ""))
    if real_ip:
        return real_ip
    return peer_norm


__all__ = ["get_real_client_ip"]

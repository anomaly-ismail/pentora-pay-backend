"""
PII maskeleme yardımcıları (H-6, KVKK/GDPR Madde 25, PCI-DSS Req. 3.3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Düz metin TCKN, IBAN, e-posta, telefon vs. **hiçbir** log, accounting
description, audit event detail veya hata mesajına yazılmamalıdır.

Bu modül, "context'te göstermek için yeterli ama yeniden kullanılamayacak"
biçimde maskeli temsiller üretir. İndekslemek/eşleştirmek için her zaman
HMAC tabanlı `hmac_index()` (app/core/encryption.py) kullanın.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import re


def mask_tckn(tckn: str | None) -> str:
    """
    TCKN için maske: ilk 3 hane + 4 yıldız + son 2 hane.
    Örn: 12345678901 → 123****8901  (görsel kullanımlık)

    Geçersiz girişlerde "***" döner.
    """
    if not tckn:
        return "***"
    digits = re.sub(r"\D", "", tckn)
    if len(digits) != 11:
        return "***"
    return f"{digits[:3]}****{digits[-4:]}"


def mask_iban(iban: str | None) -> str:
    """
    IBAN için maske: ilk 4 + son 4 karakter.
    Örn: TR330006100519786457841326 → TR33...1326
    """
    if not iban:
        return "***"
    s = re.sub(r"\s+", "", iban).upper()
    if len(s) < 10:
        return "***"
    return f"{s[:4]}...{s[-4:]}"


def mask_phone(phone: str | None) -> str:
    """
    Telefon için maske: yalnızca son 4 hane.
    Örn: 5551234567 → ***4567
    """
    if not phone:
        return "***"
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "***"
    return f"***{digits[-4:]}"


def mask_email(email: str | None) -> str:
    """
    E-posta için maske: ilk harf + ... + @ + domain.
    Örn: ahmet@example.com → a***@example.com
    """
    if not email or "@" not in email:
        return "***"
    local, _, domain = email.partition("@")
    if not local:
        return "***"
    return f"{local[0]}***@{domain}"


__all__ = ["mask_tckn", "mask_iban", "mask_phone", "mask_email"]

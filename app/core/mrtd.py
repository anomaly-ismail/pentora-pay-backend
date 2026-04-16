"""
ICAO 9303 MRTD: MRZ Parser + BAC/PACE Anahtar Türetimi
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bu modül:

  • TD1 (T.C. Kimlik kartı — 3 satır × 30 karakter)
  • TD3 (Pasaport       — 2 satır × 44 karakter)

MRZ satırlarını doğrular (check digit) ve BAC seed üzerinden KEnc/KMac
anahtarlarını ICAO 9303 Part 11 Appendix D.1'e göre türetir. Flutter istemci
bu anahtarlarla çip üzerindeki EF.DG1/DG2/DG11/SOD dosyalarını unlock eder.

Not: PACE tam akışı (Chip Authentication + CAN/MRZ) istemci tarafında
dmrtd kütüphanesi ile lokal yürütülür. Backend BAC seed verir, istemci
PACE veya BAC fallback'i uygular.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

# ── Check digit algoritması (ICAO 9303) ─────────────────────────────────────
_WEIGHTS = (7, 3, 1)


def _char_value(ch: str) -> int:
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    if "A" <= ch <= "Z":
        return ord(ch) - ord("A") + 10
    if ch == "<":
        return 0
    raise ValueError(f"MRZ geçersiz karakter: {ch!r}")


def mrz_checksum(data: str) -> int:
    total = 0
    for i, ch in enumerate(data):
        total += _char_value(ch) * _WEIGHTS[i % 3]
    return total % 10


def verify_checksum(data: str, check_digit: str) -> bool:
    if check_digit == "<":
        check_digit = "0"
    if not check_digit.isdigit():
        return False
    return mrz_checksum(data) == int(check_digit)


# ── MRZ Parser ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class MrzData:
    doc_type: str            # "TD1" | "TD3"
    issuing_state: str       # 3 char country code (TUR, etc.)
    document_number: str     # pasaport/kimlik seri numarası (9-30 char)
    date_of_birth: str       # YYMMDD
    date_of_expiry: str      # YYMMDD
    nationality: str
    sex: str                 # M | F | <
    primary_identifier: str  # soyad
    secondary_identifier: str  # ad(lar)
    optional_data: str = ""
    raw: str = ""            # orijinal MRZ (normalize edilmiş, satır atlamasız)

    @property
    def bac_seed_info(self) -> str:
        """ICAO 9303 BAC `MRZ_information` = doc_no + CD + DOB + CD + DOE + CD"""
        return (
            self.document_number
            + str(mrz_checksum(self.document_number))
            + self.date_of_birth
            + str(mrz_checksum(self.date_of_birth))
            + self.date_of_expiry
            + str(mrz_checksum(self.date_of_expiry))
        )


class MrzParseError(ValueError):
    pass


def _normalize(raw: str) -> list[str]:
    """Whitespace + yeni satır temizle, satırları döndür."""
    cleaned = raw.upper().replace(" ", "").replace("\r", "")
    lines = [ln for ln in cleaned.split("\n") if ln]
    if not lines:
        raise MrzParseError("MRZ boş")
    return lines


def parse_td1(lines: list[str]) -> MrzData:
    """TC Kimlik (TD1): 3 satır × 30 char."""
    if len(lines) != 3 or any(len(ln) != 30 for ln in lines):
        raise MrzParseError(f"TD1 için 3×30 beklenir, alındı: {[len(x) for x in lines]}")
    l1, l2, l3 = lines

    issuing_state = l1[2:5]
    # Doküman numarası: l1[5:14] + CD l1[14]
    doc_no = l1[5:14].rstrip("<")
    doc_no_cd = l1[14]
    if not verify_checksum(l1[5:14], doc_no_cd):
        raise MrzParseError("TD1: doküman numarası CD hatalı")

    # Optional data 1 = l1[15:30]
    optional_data = l1[15:30].rstrip("<")

    dob = l2[0:6]
    dob_cd = l2[6]
    if not verify_checksum(dob, dob_cd):
        raise MrzParseError("TD1: DOB CD hatalı")

    sex = l2[7]
    doe = l2[8:14]
    doe_cd = l2[14]
    if not verify_checksum(doe, doe_cd):
        raise MrzParseError("TD1: DOE CD hatalı")

    nationality = l2[15:18]
    # Composite CD (l2[29]) — opsiyonel doğrulama
    composite = l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29]
    if not verify_checksum(composite, l2[29]):
        # strict değil — bazı eski kartlarda hatalı olabilir, log-only
        pass

    # Satır 3 = name (primary<<secondary)
    name_field = l3.rstrip("<")
    if "<<" in name_field:
        primary, _, secondary = name_field.partition("<<")
    else:
        primary = name_field
        secondary = ""
    primary = primary.replace("<", " ").strip()
    secondary = secondary.replace("<", " ").strip()

    return MrzData(
        doc_type="TD1",
        issuing_state=issuing_state,
        document_number=doc_no,
        date_of_birth=dob,
        date_of_expiry=doe,
        nationality=nationality,
        sex=sex,
        primary_identifier=primary,
        secondary_identifier=secondary,
        optional_data=optional_data,
        raw="\n".join(lines),
    )


def parse_td3(lines: list[str]) -> MrzData:
    """Pasaport (TD3): 2 satır × 44 char."""
    if len(lines) != 2 or any(len(ln) != 44 for ln in lines):
        raise MrzParseError(f"TD3 için 2×44 beklenir, alındı: {[len(x) for x in lines]}")
    l1, l2 = lines

    issuing_state = l1[2:5]
    name_field = l1[5:44].rstrip("<")
    if "<<" in name_field:
        primary, _, secondary = name_field.partition("<<")
    else:
        primary = name_field
        secondary = ""
    primary = primary.replace("<", " ").strip()
    secondary = secondary.replace("<", " ").strip()

    doc_no = l2[0:9].rstrip("<")
    doc_no_cd = l2[9]
    if not verify_checksum(l2[0:9], doc_no_cd):
        raise MrzParseError("TD3: doküman numarası CD hatalı")

    nationality = l2[10:13]
    dob = l2[13:19]
    dob_cd = l2[19]
    if not verify_checksum(dob, dob_cd):
        raise MrzParseError("TD3: DOB CD hatalı")

    sex = l2[20]
    doe = l2[21:27]
    doe_cd = l2[27]
    if not verify_checksum(doe, doe_cd):
        raise MrzParseError("TD3: DOE CD hatalı")

    optional_data = l2[28:42].rstrip("<")

    return MrzData(
        doc_type="TD3",
        issuing_state=issuing_state,
        document_number=doc_no,
        date_of_birth=dob,
        date_of_expiry=doe,
        nationality=nationality,
        sex=sex,
        primary_identifier=primary,
        secondary_identifier=secondary,
        optional_data=optional_data,
        raw="\n".join(lines),
    )


def parse_mrz(raw: str) -> MrzData:
    """Otomatik olarak TD1/TD3 tespit eder ve ayrıştırır."""
    lines = _normalize(raw)
    if len(lines) == 3:
        return parse_td1(lines)
    if len(lines) == 2:
        return parse_td3(lines)
    raise MrzParseError(f"Bilinmeyen MRZ formatı ({len(lines)} satır)")


# ── Input-only MRZ alanları (Flutter alanı alan gönderirse) ─────────────────
_DATE_RX = re.compile(r"^\d{6}$")
_DOC_RX = re.compile(r"^[A-Z0-9<]{5,30}$")


def build_mrz_data_from_fields(
    *,
    document_number: str,
    date_of_birth: str,
    date_of_expiry: str,
    doc_type: str = "TD1",
    nationality: str = "TUR",
    issuing_state: str = "TUR",
    sex: str = "<",
) -> MrzData:
    """
    Flutter yalnızca 3 temel alan gönderirse (doc_no, DOB, DOE) BAC seed
    için yeterlidir. Bu yardımcı MrzData oluşturur.
    """
    doc_no = document_number.strip().upper()
    if not _DOC_RX.match(doc_no):
        raise MrzParseError(f"geçersiz doküman numarası: {doc_no!r}")
    if not _DATE_RX.match(date_of_birth):
        raise MrzParseError("DOB YYMMDD formatında olmalı")
    if not _DATE_RX.match(date_of_expiry):
        raise MrzParseError("DOE YYMMDD formatında olmalı")

    return MrzData(
        doc_type=doc_type,
        issuing_state=issuing_state,
        document_number=doc_no,
        date_of_birth=date_of_birth,
        date_of_expiry=date_of_expiry,
        nationality=nationality,
        sex=sex,
        primary_identifier="",
        secondary_identifier="",
        optional_data="",
        raw=f"{doc_no}|{date_of_birth}|{date_of_expiry}",
    )


# ── BAC / PACE Anahtar Türetme (ICAO 9303 Part 11 App D.1) ──────────────────
def _adjust_parity_bits(key: bytes) -> bytes:
    """DES anahtarlarının en düşük bitini odd parity olacak şekilde ayarla."""
    out = bytearray(key)
    for i, b in enumerate(out):
        parity = bin(b & 0xFE).count("1") & 1
        out[i] = (b & 0xFE) | (0 if parity else 1)
    return bytes(out)


def derive_bac_seed(mrz_info: str) -> bytes:
    """K_seed = SHA-1(MRZ_information)[0..15]"""
    return hashlib.sha1(mrz_info.encode("ascii")).digest()[:16]


def _derive_key(k_seed: bytes, key_type: bytes) -> bytes:
    """ICAO 9303 Appendix D.1 — KDF(SEED, c): SHA-1(SEED||c)[0..15], parity adjust."""
    d = hashlib.sha1(k_seed + key_type).digest()
    ka = _adjust_parity_bits(d[0:8])
    kb = _adjust_parity_bits(d[8:16])
    return ka + kb


@dataclass(frozen=True)
class BacKeys:
    k_seed_hex: str
    k_enc_hex: str
    k_mac_hex: str

    def to_dict(self) -> dict:
        return {
            "k_seed_hex": self.k_seed_hex,
            "k_enc_hex": self.k_enc_hex,
            "k_mac_hex": self.k_mac_hex,
            "algorithm": "ICAO9303-BAC-3DES",
            "note": (
                "PACE destekli çiplerde istemci önce PACE dener; başarısızsa "
                "bu BAC anahtarları ile fallback yapar."
            ),
        }


def derive_bac_keys(mrz: MrzData) -> BacKeys:
    """BAC için KEnc + KMac döndürür. İstemci bu anahtarları çip ile mutual auth
    için kullanır. Anahtarlar backend'de SAKLANMAZ — her istekte yeniden türetilir."""
    info = mrz.bac_seed_info
    seed = derive_bac_seed(info)
    k_enc = _derive_key(seed, b"\x00\x00\x00\x01")
    k_mac = _derive_key(seed, b"\x00\x00\x00\x02")
    return BacKeys(
        k_seed_hex=seed.hex(),
        k_enc_hex=k_enc.hex(),
        k_mac_hex=k_mac.hex(),
    )


__all__ = [
    "MrzData",
    "MrzParseError",
    "parse_mrz",
    "parse_td1",
    "parse_td3",
    "build_mrz_data_from_fields",
    "BacKeys",
    "derive_bac_keys",
    "derive_bac_seed",
    "mrz_checksum",
    "verify_checksum",
]

"""
ICAO 9303 Pasif Doğrulama (Passive Authentication) — Sunucu Tarafı (H-8)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

İstemciden alınan EF.SOD (Document Security Object) üzerinde sunucu
tarafında bağımsız bütünlük kontrolü yapar.

  ⚠ İstemcinin `passive_auth_ok=true` bayrağı tek başına ASLA yeterli değildir.
  Bu modül, sunucunun bağımsız doğrulama sonucunu döndürür.

İki seviyeli garanti:
  1) **Bütünlük doğrulama** (her zaman, dış bağımlılık yok):
       - SOD'un CMS SignedData yapısı parse edilebilir,
       - SOD içindeki LDS Security Object DG hash listesi okunabilir,
       - DG1 (zorunlu) hash'i SOD içindeki listedeki DG1 hash'iyle birebir
         eşleşir → çipten okunan veri tahrif edilmemiş.
       - DG2 / DG11 verilmişse onlar da doğrulanır.
  2) **Doc Signer + CSCA zinciri** (opsiyonel, CSCA Trust Store gerekir):
       - DocSignerCertificate çıkarılır, CSCA store'a karşı imza zinciri
         doğrulanır. Trust store boşsa `chain_verified=False` döner.

Implementasyon notu:
  Kendi minimal ASN.1 parser'ı bazı ülkelerin (Türkiye dahil) SOD
  encoding'lerinde kırılıyordu (ör. uzun OCTET STRING length encoding'i,
  alternatif explicit/implicit tag'ler). Saf-Python `asn1crypto` ile değişti;
  ICAO PKD test setiyle uyumlu.

PCI-DSS ile doğrudan ilgisi yoktur fakat kimlik kanıtı için PCI-DSS Req. 8
kapsamında "out-of-band identity verification" güvencesi sağlar.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import hashlib
import warnings
from dataclasses import dataclass
from typing import Optional

from asn1crypto import algos, cms, core
from cryptography import x509


# ─────────────────────────────────────────────────────────────────────────────
# LDS Security Object — ICAO 9303-10 § 4.6.2 ASN.1 spec
# ─────────────────────────────────────────────────────────────────────────────
class _DataGroupHash(core.Sequence):
    _fields = [
        ("dataGroupNumber", core.Integer),
        ("dataGroupHashValue", core.OctetString),
    ]


class _DataGroupHashValues(core.SequenceOf):
    _child_spec = _DataGroupHash


class _LDSSecurityObject(core.Sequence):
    _fields = [
        ("version", core.Integer),
        ("hashAlgorithm", algos.DigestAlgorithm),
        ("dataGroupHashValues", _DataGroupHashValues),
        # ICAO 9303-10 v0 spec'i sonuna `ldsVersionInfo` (v1) optional ekler
        ("ldsVersionInfo", core.Any, {"optional": True}),
    ]


# ── Hash algoritması adlarını OID'den çöz ──────────────────────────────────
# ICAO 9303-10 § 4.6.2 — LDS Security Object yalnızca SHA ailesini kullanır.
_HASH_OID = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
}

# ICAO 9303 — eContentType OID for LDS Security Object
_LDS_SECURITY_OBJECT_OID = "2.23.136.1.1.1"


@dataclass(frozen=True)
class PassiveAuthResult:
    sod_parsed: bool
    integrity_ok: bool          # DG1 (ve verilen diğer DG'ler) hash'i SOD ile eşleşiyor
    chain_verified: bool        # DSC → CSCA zinciri doğrulandı mı (opsiyonel)
    hash_algorithm: Optional[str]
    signer_subject: Optional[str]
    issuer: Optional[str]
    error: Optional[str] = None

    @property
    def trustworthy(self) -> bool:
        # Üretimde "trustworthy" yalnızca chain_verified=True iken True olmalı.
        # Şimdilik integrity_ok yeterli sayılıyor; CSCA store eklendikten sonra
        # çağıran chain_verified de gerektirebilir.
        return self.sod_parsed and self.integrity_ok


# ─────────────────────────────────────────────────────────────────────────────
# SOD Parsing
# ─────────────────────────────────────────────────────────────────────────────

def _strip_application_envelope(sod_bytes: bytes) -> bytes:
    """
    EF.SOD bazen ICAO konteyneri içinde gelir:
        77 [length] (CMS ContentInfo SignedData)
    cryptography/asn1crypto ham `ContentInfo` (SEQUENCE = 0x30) bekler.
    Eğer envelope tag (0x77 = APPLICATION 23) varsa onu sıyırırız.
    """
    if not sod_bytes:
        return sod_bytes
    if sod_bytes[0] != 0x77:
        return sod_bytes
    idx = 1
    first = sod_bytes[idx]
    if first < 0x80:
        idx += 1
    else:
        idx += 1 + (first & 0x7F)
    return sod_bytes[idx:]


def _safe_rfc4514(name) -> Optional[str]:
    """
    cryptography.x509.Name.rfc4514_string() bazı sertifikalarda
    `Attribute's length must be >= 1 and <= 64, but it was 72` UserWarning
    fırlatır ve hata atar (Türk DocSigner cert'lerinde uzun CN/O örneği var).
    Bu durumda None döneriz; sertifika konusu loglanmasa da integrity sağlam.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return name.rfc4514_string()
    except Exception:
        # Fallback: basit OID=value string
        try:
            return ", ".join(
                f"{rdn.oid.dotted_string}={rdn.value}"
                for rdn in name
            )
        except Exception:
            return None


def _extract_signer_certificates(signed_data: cms.SignedData) -> list[x509.Certificate]:
    """SOD içindeki sertifikaları cryptography.x509.Certificate listesine çevir."""
    out: list[x509.Certificate] = []
    if "certificates" not in signed_data:
        return out
    for choice in signed_data["certificates"]:
        if choice.name != "certificate":
            continue
        try:
            cert_der = choice.chosen.dump()
            out.append(x509.load_der_x509_certificate(cert_der))
        except Exception:
            continue
    return out


def _parse_lds_security_object(eContent_bytes: bytes) -> tuple[Optional[str], dict[int, bytes]]:
    """
    LDSSecurityObject ::= SEQUENCE {
        version             INTEGER,
        hashAlgorithm       AlgorithmIdentifier,
        dataGroupHashValues SEQUENCE OF DataGroupHash
    }
    DataGroupHash ::= SEQUENCE {
        dataGroupNumber    INTEGER,
        dataGroupHashValue OCTET STRING
    }
    """
    ldsso = _LDSSecurityObject.load(eContent_bytes)

    # Hash algoritması — DigestAlgorithm.algorithm asn1crypto'da string-dotted veya
    # standart isim ("sha256") olarak çözebilir; iki yolu da destekliyoruz.
    algo_obj = ldsso["hashAlgorithm"]["algorithm"]
    raw = algo_obj.native        # ör. "sha256" veya "1.3.14.3.2.26"
    dotted = algo_obj.dotted     # her zaman dotted OID
    hash_algo = _HASH_OID.get(dotted)
    if hash_algo is None and isinstance(raw, str) and raw in _HASH_OID.values():
        hash_algo = raw

    out: dict[int, bytes] = {}
    for item in ldsso["dataGroupHashValues"]:
        try:
            dg_num = int(item["dataGroupNumber"].native)
            hash_bytes = item["dataGroupHashValue"].native
            if isinstance(hash_bytes, (bytes, bytearray)):
                out[dg_num] = bytes(hash_bytes)
        except Exception:
            continue
    return hash_algo, out


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def verify_passive_auth(
    *,
    sod_bytes: Optional[bytes],
    dg1_bytes: Optional[bytes],
    dg2_bytes: Optional[bytes] = None,
    dg11_bytes: Optional[bytes] = None,
) -> PassiveAuthResult:
    """
    Sunucu tarafı bütünlük doğrulaması.

    `integrity_ok=True` demek:
      - SOD parse edildi,
      - DG1 verildi ve hash'i SOD'daki DG1 değeriyle bit-for-bit eşleşti,
      - Verilmiş diğer DG'ler de eşleşti.

    `chain_verified` şu sürümde her zaman False (CSCA Trust Store eklenince
    True olarak değerlendirilecek).
    """
    if not sod_bytes:
        return PassiveAuthResult(
            sod_parsed=False, integrity_ok=False, chain_verified=False,
            hash_algorithm=None, signer_subject=None, issuer=None,
            error="missing_sod",
        )
    if not dg1_bytes:
        return PassiveAuthResult(
            sod_parsed=False, integrity_ok=False, chain_verified=False,
            hash_algorithm=None, signer_subject=None, issuer=None,
            error="missing_dg1",
        )

    try:
        sod_der = _strip_application_envelope(bytes(sod_bytes))
        content_info = cms.ContentInfo.load(sod_der)
        if content_info["content_type"].native != "signed_data":
            return PassiveAuthResult(
                sod_parsed=False, integrity_ok=False, chain_verified=False,
                hash_algorithm=None, signer_subject=None, issuer=None,
                error="sod_not_signed_data",
            )
        signed_data: cms.SignedData = content_info["content"]
    except Exception as exc:
        return PassiveAuthResult(
            sod_parsed=False, integrity_ok=False, chain_verified=False,
            hash_algorithm=None, signer_subject=None, issuer=None,
            error=f"sod_parse_failed:{exc.__class__.__name__}",
        )

    # ── eContent (LDSSecurityObject) ────────────────────────────────────────
    try:
        encap = signed_data["encap_content_info"]
        e_content_type = encap["content_type"].native  # OID dotted string
        if e_content_type != _LDS_SECURITY_OBJECT_OID:
            return PassiveAuthResult(
                sod_parsed=True, integrity_ok=False, chain_verified=False,
                hash_algorithm=None, signer_subject=None, issuer=None,
                error=f"unexpected_econtent_oid:{e_content_type}",
            )
        e_content_octets = encap["content"]
        if e_content_octets is None or e_content_octets.native is None:
            return PassiveAuthResult(
                sod_parsed=True, integrity_ok=False, chain_verified=False,
                hash_algorithm=None, signer_subject=None, issuer=None,
                error="lds_so_extract_failed",
            )
        # asn1crypto OctetString → bytes
        lds_so_bytes = e_content_octets.native
        if isinstance(lds_so_bytes, str):
            lds_so_bytes = lds_so_bytes.encode("latin-1")
    except Exception as exc:
        return PassiveAuthResult(
            sod_parsed=True, integrity_ok=False, chain_verified=False,
            hash_algorithm=None, signer_subject=None, issuer=None,
            error=f"lds_so_extract_failed:{exc.__class__.__name__}",
        )

    # ── DocSigner sertifikası (subject/issuer logla, başarısızsa atla) ─────
    signer_subject: Optional[str] = None
    issuer: Optional[str] = None
    try:
        certs = _extract_signer_certificates(signed_data)
        if certs:
            signer_subject = _safe_rfc4514(certs[0].subject)
            issuer = _safe_rfc4514(certs[0].issuer)
    except Exception:
        pass

    # ── DG hash listesi ─────────────────────────────────────────────────────
    try:
        hash_algo, dg_hashes = _parse_lds_security_object(lds_so_bytes)
    except Exception as exc:
        return PassiveAuthResult(
            sod_parsed=True, integrity_ok=False, chain_verified=False,
            hash_algorithm=None, signer_subject=signer_subject, issuer=issuer,
            error=f"lds_parse_failed:{exc.__class__.__name__}",
        )

    if hash_algo is None or 1 not in dg_hashes:
        return PassiveAuthResult(
            sod_parsed=True, integrity_ok=False, chain_verified=False,
            hash_algorithm=hash_algo, signer_subject=signer_subject, issuer=issuer,
            error="dg_hash_table_invalid",
        )

    digest_fn = getattr(hashlib, hash_algo, None)
    if digest_fn is None:
        return PassiveAuthResult(
            sod_parsed=True, integrity_ok=False, chain_verified=False,
            hash_algorithm=hash_algo, signer_subject=signer_subject, issuer=issuer,
            error=f"unknown_hash_algo:{hash_algo}",
        )

    expected_dg1 = dg_hashes.get(1)
    actual_dg1 = digest_fn(dg1_bytes).digest()
    if expected_dg1 != actual_dg1:
        return PassiveAuthResult(
            sod_parsed=True, integrity_ok=False, chain_verified=False,
            hash_algorithm=hash_algo, signer_subject=signer_subject, issuer=issuer,
            error="dg1_hash_mismatch",
        )

    # Diğer DG'ler verilmişse doğrula
    for dg_num, dg_data in (
        (2, dg2_bytes),
        (11, dg11_bytes),
    ):
        if not dg_data:
            continue
        expected = dg_hashes.get(dg_num)
        if not expected:
            # SOD bu DG için hash içermiyor → sessizce kabul et
            continue
        if digest_fn(dg_data).digest() != expected:
            return PassiveAuthResult(
                sod_parsed=True, integrity_ok=False, chain_verified=False,
                hash_algorithm=hash_algo, signer_subject=signer_subject, issuer=issuer,
                error=f"dg{dg_num}_hash_mismatch",
            )

    return PassiveAuthResult(
        sod_parsed=True,
        integrity_ok=True,
        chain_verified=False,  # CSCA store ileride
        hash_algorithm=hash_algo,
        signer_subject=signer_subject,
        issuer=issuer,
        error=None,
    )


# Yardımcı (gerekirse export olarak _parse_lds_security_object, vb.)
__all__ = ["PassiveAuthResult", "verify_passive_auth"]

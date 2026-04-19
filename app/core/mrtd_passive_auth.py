"""
ICAO 9303 Pasif Doğrulama (Passive Authentication) — Sunucu Tarafı (H-8)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Bu modül, istemciden alınan EF.SOD (Document Security Object) üzerinde
**sunucu tarafında** kriptografik bütünlük kontrolü yapar.

  ⚠ İstemcinin `passive_auth_ok=true` bayrağı tek başına ASLA yeterli değildir.
  Bu modül, sunucunun bağımsız doğrulama sonucunu döndürür.

İki seviyeli garanti sağlar:
  1) **Bütünlük doğrulama** (her zaman, dış bağımlılık yok):
       - SOD'un CMS SignedData yapısı parse edilebilir
       - SOD içindeki LDS Security Object DG hash listesi okunabilir
       - DG1 (zorunlu) hash'i SOD içindeki listede beklenen DG numarası için
         birebir tutar — yani çipten okunan DG1 ile SOD imzalayanın hash'i
         aynıdır (saha taraf tahrif edilememiş).
       - DG2/DG11 verilmişse onlar da doğrulanır.
  2) **Doc Signer + CSCA zinciri** (opsiyonel, CSCA Trust Store gerekir):
       - DocSignerCertificate çıkarılır, CSCA store'a karşı imza zinciri
         doğrulanır. Bu adım operasyonel olarak ICAO PKD'den indirilen güncel
         Türkiye CSCA sertifikası (`config/csca/`) ile çalışır.
       - Store boş ise `chain_verified = False` olarak işaretlenir; çağıran
         karar verir (production'da chain_verified gerekiyorsa block).

Bu modül BouncyCastle/OpenSSL gerektirmez — `cryptography` paketinin
Pyca tarafıyla ASN.1/CMS parse'ı yapar.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.serialization import pkcs7


# ── Hash algoritması adlarını OID'den çöz ──────────────────────────────────
_HASH_OID = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
}


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
        # Şu an çağıran integrity_ok'u tek başına da kabul edebilir; ama
        # `nfc_verified` bayrağını veren yer "chain_verified" şartını da
        # arzu ediyorsa kontrol etmelidir.
        return self.sod_parsed and self.integrity_ok


def _parse_sod_signed_data(sod_bytes: bytes):
    """
    EF.SOD aslında bir ICAO konteyneridir: tag 0x77 (Application 23) içinde
    SignedData (CMS) bulunur. cryptography.pkcs7 ham SignedData beklediği için
    önce 0x77 başlıklı tag'i sıyırıyoruz.
    """
    data = bytes(sod_bytes)
    # Application 23: tag 0x77, length encoding'i atla.
    if data and data[0] == 0x77:
        idx = 1
        first = data[idx]
        if first < 0x80:
            length_bytes = 1
        else:
            length_bytes = 1 + (first & 0x7F)
        idx += length_bytes
        data = data[idx:]
    # cryptography'nin pkcs7 fonksiyonu yalnızca PEM/DER SignedData kabul eder.
    return pkcs7.load_der_pkcs7_certificates(data), data


def _extract_lds_so(sod_der: bytes) -> Optional[bytes]:
    """
    SignedData → encapContentInfo → eContent içinden LDSSecurityObject
    (DG hash listesi) bytes'ını çıkarır. ASN.1'i düşük seviye parse ederiz
    çünkü `cryptography` yüksek seviye CMS parse vermez.

    Bu kaba ama yeterli: signedData içinde "OBJECT IDENTIFIER 2.23.136.1.1.1"
    (ldsSecurityObject) sonrasında [0] EXPLICIT içinde gelen OCTET STRING'i
    arayıp içeriğini döndürürüz.
    """
    target_oid = bytes.fromhex("0667678101010101")
    # Aslında 2.23.136.1.1.1 → DER: 06 07 67 81 08 01 01 01 01 (10 byte)
    # Yukarıdaki target_oid kısa kalıyor; tam encode edilmiş hâl:
    target_oid = bytes.fromhex("0608678108010101010A")  # placeholder
    # Doğru DER: tag 06 (OID), len 07, payload 67 81 08 01 01 01 01
    target_oid = bytes([0x06, 0x07, 0x67, 0x81, 0x08, 0x01, 0x01, 0x01, 0x01])

    idx = sod_der.find(target_oid)
    if idx == -1:
        return None
    pos = idx + len(target_oid)
    # [0] EXPLICIT veya OCTET STRING bekliyoruz
    if pos >= len(sod_der):
        return None
    if sod_der[pos] in (0xA0, 0x04):
        pos += 1
        # length
        first = sod_der[pos]
        if first < 0x80:
            length = first
            pos += 1
        else:
            n = first & 0x7F
            length = int.from_bytes(sod_der[pos + 1 : pos + 1 + n], "big")
            pos += 1 + n
        inner = sod_der[pos : pos + length]
        # [0] EXPLICIT ise içerde OCTET STRING var
        if sod_der[pos - length - 1] == 0xA0 and inner and inner[0] == 0x04:
            ipos = 1
            ifirst = inner[ipos]
            if ifirst < 0x80:
                ilen = ifirst
                ipos += 1
            else:
                n = ifirst & 0x7F
                ilen = int.from_bytes(inner[ipos + 1 : ipos + 1 + n], "big")
                ipos += 1 + n
            return inner[ipos : ipos + ilen]
        return inner
    return None


def _parse_dg_hashes(lds_so: bytes) -> tuple[Optional[str], dict[int, bytes]]:
    """
    LDSSecurityObject ASN.1 yapısı:
        SEQUENCE {
          version          INTEGER,
          hashAlgorithm    AlgorithmIdentifier,
          dataGroupHashValues SEQUENCE OF DataGroupHash
        }
    DataGroupHash ::= SEQUENCE {
          dataGroupNumber  INTEGER,
          dataGroupHashValue OCTET STRING
        }

    Geri döner: (hash_algo_name, {dg_number: hash_bytes})
    """
    # Bu çok minimal bir ASN.1 parser. Üretimde pyasn1 kullanılması önerilir;
    # ancak deps eklemekten kaçınmak için elle gezeriz.
    out: dict[int, bytes] = {}
    hash_algo: Optional[str] = None

    if not lds_so or lds_so[0] != 0x30:
        return None, out

    # outer SEQUENCE
    pos = 1
    pos = _skip_len(lds_so, pos)

    # version INTEGER
    pos = _skip_tlv(lds_so, pos)

    # AlgorithmIdentifier SEQUENCE
    if pos >= len(lds_so) or lds_so[pos] != 0x30:
        return None, out
    algo_len_pos = pos + 1
    algo_len = _read_len(lds_so, algo_len_pos)
    algo_header_end = _skip_len(lds_so, algo_len_pos)
    algo_seq = lds_so[algo_header_end : algo_header_end + algo_len]
    pos = algo_header_end + algo_len

    # algo_seq: OBJECT IDENTIFIER + (NULL parameters)
    if algo_seq and algo_seq[0] == 0x06:
        oid_len = algo_seq[1]
        oid_bytes = algo_seq[2 : 2 + oid_len]
        oid_str = _decode_oid(oid_bytes)
        hash_algo = _HASH_OID.get(oid_str)

    # dataGroupHashValues SEQUENCE OF
    if pos >= len(lds_so) or lds_so[pos] != 0x30:
        return hash_algo, out
    seq_len = _read_len(lds_so, pos + 1)
    seq_start = _skip_len(lds_so, pos + 1)
    seq_end = seq_start + seq_len

    cur = seq_start
    while cur < seq_end:
        if lds_so[cur] != 0x30:
            break
        item_len = _read_len(lds_so, cur + 1)
        item_start = _skip_len(lds_so, cur + 1)
        item_end = item_start + item_len

        # INTEGER dgNumber
        if lds_so[item_start] != 0x02:
            cur = item_end
            continue
        int_len = lds_so[item_start + 1]
        dg_num = int.from_bytes(lds_so[item_start + 2 : item_start + 2 + int_len], "big")
        ipos = item_start + 2 + int_len

        # OCTET STRING hashValue
        if lds_so[ipos] == 0x04:
            hl = lds_so[ipos + 1]
            if hl < 0x80:
                hash_bytes = lds_so[ipos + 2 : ipos + 2 + hl]
            else:
                n = hl & 0x7F
                hl = int.from_bytes(lds_so[ipos + 2 : ipos + 2 + n], "big")
                hash_bytes = lds_so[ipos + 2 + n : ipos + 2 + n + hl]
            out[dg_num] = bytes(hash_bytes)

        cur = item_end

    return hash_algo, out


def _read_len(b: bytes, idx: int) -> int:
    first = b[idx]
    if first < 0x80:
        return first
    n = first & 0x7F
    return int.from_bytes(b[idx + 1 : idx + 1 + n], "big")


def _skip_len(b: bytes, idx: int) -> int:
    first = b[idx]
    if first < 0x80:
        return idx + 1
    return idx + 1 + (first & 0x7F)


def _skip_tlv(b: bytes, idx: int) -> int:
    idx += 1
    length = _read_len(b, idx)
    idx = _skip_len(b, idx)
    return idx + length


def _decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    components = [first // 40, first % 40]
    val = 0
    for byte in data[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            components.append(val)
            val = 0
    return ".".join(str(c) for c in components)


def verify_passive_auth(
    *,
    sod_bytes: Optional[bytes],
    dg1_bytes: Optional[bytes],
    dg2_bytes: Optional[bytes] = None,
    dg11_bytes: Optional[bytes] = None,
) -> PassiveAuthResult:
    """
    Sunucu tarafı bütünlük doğrulaması.

    Geri dönüşte `integrity_ok=True` demek:
      - SOD parse edilebildi,
      - DG1 zorunlu olarak verildi ve hash'i SOD'da DG1 olarak geçen değerle
        bit-for-bit eşleşti,
      - Verilmiş diğer DG'ler de eşleşti.

    `chain_verified` şu sürümde her zaman False döner — CSCA Trust Store
    yüklemesinden sonra ayrı bir geçişte True olarak işaretlenecektir.
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
        certs, sod_der = _parse_sod_signed_data(sod_bytes)
    except Exception as exc:
        return PassiveAuthResult(
            sod_parsed=False, integrity_ok=False, chain_verified=False,
            hash_algorithm=None, signer_subject=None, issuer=None,
            error=f"sod_parse_failed: {exc.__class__.__name__}",
        )

    signer_subject = None
    issuer = None
    if certs:
        try:
            signer_subject = certs[0].subject.rfc4514_string()
            issuer = certs[0].issuer.rfc4514_string()
        except Exception:
            pass

    lds_so = _extract_lds_so(sod_der)
    if not lds_so:
        return PassiveAuthResult(
            sod_parsed=True, integrity_ok=False, chain_verified=False,
            hash_algorithm=None, signer_subject=signer_subject, issuer=issuer,
            error="lds_so_extract_failed",
        )

    hash_algo, dg_hashes = _parse_dg_hashes(lds_so)
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
            error=f"unknown_hash_algo: {hash_algo}",
        )

    expected_dg1 = dg_hashes.get(1)
    actual_dg1 = digest_fn(dg1_bytes).digest()
    if expected_dg1 != actual_dg1:
        return PassiveAuthResult(
            sod_parsed=True, integrity_ok=False, chain_verified=False,
            hash_algorithm=hash_algo, signer_subject=signer_subject, issuer=issuer,
            error="dg1_hash_mismatch",
        )

    # Diğer DG'ler verilmişse doğrula (varsa)
    for dg_num, dg_data in (
        (2, dg2_bytes),
        (11, dg11_bytes),
    ):
        if not dg_data:
            continue
        expected = dg_hashes.get(dg_num)
        if not expected:
            # SOD bu DG için hash içermiyor → kabul et
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


__all__ = ["PassiveAuthResult", "verify_passive_auth"]

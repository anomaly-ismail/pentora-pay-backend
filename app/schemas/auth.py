"""
Kayıt (Register) Pydantic Şemaları
"""
from pydantic import BaseModel, Field, field_validator
import re


# ─── Handshake ───────────────────────────────────────────────────────────────
class HandshakeRequest(BaseModel):
    client_public_key_b64: str = Field(
        ...,
        description="Flutter'ın X25519 raw public key'i (base64)",
        min_length=40,
        max_length=512,
    )
    client_nonce_b64: str = Field(
        ...,
        description="Flutter'ın rastgele nonce'u (base64, ≥16 byte)",
        min_length=20,
        max_length=64,
    )


class HandshakeResponse(BaseModel):
    handshake_id: str
    server_public_key_b64: str
    server_nonce_b64: str
    expires_in: int
    message: str = "Handshake tamamlandı. Şimdiden session_key hesaplayın."


# ─── Kayıt ───────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    """
    Müşteri kayıt isteği.
    Tüm alanlar sunucu tarafında tekrar doğrulanır — client-side
    validation'a güvenilmez (OWASP A04).
    """
    tckn: str = Field(
        ...,
        description="11 haneli T.C. Kimlik Numarası",
        min_length=11,
        max_length=11,
    )
    pin: str = Field(
        ...,
        description="6 haneli rakamsal PIN",
        min_length=6,
        max_length=6,
    )
    nfc_uid_hex: str = Field(
        "",
        description="TC Kimlik Kartı NFC UID (HEX string) — NFC atlanırsa boş bırakılabilir",
        min_length=0,
        max_length=64,
    )
    nfc_verified: bool = Field(
        ...,
        description="NFC doğrulaması tamamlandı mı?",
    )

    @field_validator("tckn")
    @classmethod
    def validate_tckn_format(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("TCKN yalnızca rakamlardan oluşmalıdır")
        if v[0] == "0":
            raise ValueError("TCKN sıfırla başlayamaz")
        # TCKN checksum algoritması (OWASP A04: sunuco tarafında tekrar doğrula)
        d = [int(c) for c in v]
        d10 = ((d[0]+d[2]+d[4]+d[6]+d[8])*7 - (d[1]+d[3]+d[5]+d[7])) % 10
        if d10 < 0 or d10 != d[9]:
            raise ValueError("Geçersiz TCKN checksum")
        d11 = sum(d[:10]) % 10
        if d11 != d[10]:
            raise ValueError("Geçersiz TCKN checksum")
        return v

    @field_validator("pin")
    @classmethod
    def validate_pin_format(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("PIN yalnızca rakamlardan oluşmalıdır")
        # Basit örüntü kontrolü (123456, 000000 vb. zayıf PIN'ler)
        if len(set(v)) == 1:
            raise ValueError("PIN tüm haneler aynı olamaz")
        if v in ("123456", "654321", "012345", "543210"):
            raise ValueError("Bu PIN çok yaygın, daha güvenli bir PIN seçin")
        return v

    @field_validator("nfc_uid_hex")
    @classmethod
    def validate_nfc_uid(cls, v: str) -> str:
        if v == "":
            return v  # NFC atlandı — boş string geçerli
        # C-1: Magic-string atlatması yasak (tarihte "MRTD_BAC_VERIFIED_TCKN"
        # gibi placeholder kullanan istemciler vardı). Yalnızca [0-9A-F]
        # ve gerçekçi uzunlukta UID'ler kabul edilir (4–16 byte → 8–32 hex).
        if not re.fullmatch(r"[0-9A-Fa-f]{8,32}", v):
            raise ValueError(
                "NFC UID geçerli bir HEX string olmalıdır (8–32 karakter, sadece 0-9A-F)."
            )
        return v.upper()


class RegisterResponse(BaseModel):
    """
    Kayıt başarı yanıtı.
    GRAuth token döndürülür (şifreli, opak).
    Kullanıcıya ait hiçbir PII geri gönderilmez.
    """
    grauth_token: str = Field(description="X-Pentora-GRAuth token (opak, şifreli)")
    session_id: str   = Field(description="Oturum UUID (audit trail)")
    expires_in: int   = Field(description="Token geçerlilik süresi (saniye)")
    nfc_verified: bool
    message: str = "Kayıt başarıyla tamamlandı."


# ─── Giriş ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    """
    Kullanıcı giriş isteği — TCKN + PIN.
    NFC login akışında istenmez; kayıt sırasında zaten doğrulandı.
    Tüm alanlar sunucu tarafında tekrar doğrulanır (OWASP A04).
    """
    tckn: str = Field(
        ...,
        description="11 haneli T.C. Kimlik Numarası",
        min_length=11,
        max_length=11,
    )
    pin: str = Field(
        ...,
        description="6 haneli rakamsal PIN",
        min_length=6,
        max_length=6,
    )

    @field_validator("tckn")
    @classmethod
    def validate_tckn_format(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("TCKN yalnızca rakamlardan oluşmalıdır")
        if v[0] == "0":
            raise ValueError("TCKN sıfırla başlayamaz")
        d = [int(c) for c in v]
        d10 = ((d[0]+d[2]+d[4]+d[6]+d[8])*7 - (d[1]+d[3]+d[5]+d[7])) % 10
        if d10 < 0 or d10 != d[9]:
            raise ValueError("Geçersiz TCKN checksum")
        d11 = sum(d[:10]) % 10
        if d11 != d[10]:
            raise ValueError("Geçersiz TCKN checksum")
        return v

    @field_validator("pin")
    @classmethod
    def validate_pin_format(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("PIN yalnızca rakamlardan oluşmalıdır")
        if len(set(v)) == 1:
            raise ValueError("PIN tüm haneler aynı olamaz")
        if v in ("123456", "654321", "012345", "543210"):
            raise ValueError("Bu PIN çok yaygın, daha güvenli bir PIN seçin")
        return v


class LoginResponse(BaseModel):
    """
    Giriş başarı yanıtı.
    GRAuth token döner — istemci bunu sonraki authenticated isteklerde kullanır.
    NFC doğrulama durumu da taşınır (kayıt sırasında set edildi).
    """
    grauth_token: str  = Field(description="X-Pentora-GRAuth token (opak, şifreli)")
    session_id: str    = Field(description="Oturum UUID (audit trail)")
    expires_in: int    = Field(description="Token geçerlilik süresi (saniye)")
    nfc_verified: bool = Field(description="Kullanıcının NFC doğrulaması var mı?")
    message: str = "Giriş başarılı."

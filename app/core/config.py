"""
Uygulama ayarları — Pydantic BaseSettings ile tip-güvenli ortam değişkeni yönetimi.
ISO 27001 A.9 (Erişim Kontrolü) ve OWASP Configuration Management ilkelerine uygun.
"""
from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Uygulama ────────────────────────────────────────────────────────────────
    app_name: str = "GuvenlIOdeme-Backend"
    app_env: Literal["development", "staging", "production"] = "development"
    app_version: str = "1.0.0"
    debug: bool = False

    # ── Sunucu ──────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # ── Pentora Güvenlik Anahtarları ────────────────────────────────────────────
    pentora_signature_secret: str
    pentora_grauth_secret: str
    pentora_sql_guard_enabled: bool = True

    # ── TCKN Gizleme Pepperı (DB'de plaintext TCKN YOK) ────────────────────────
    # HMAC-SHA3-512(TCKN, tckn_pepper) olarak saklanır
    # GRAuth pepperından FARKLI olmalıdır — tamamen izole iki sır
    tckn_pepper: str

    # ── Flutter İstemci Kimlik Doğrulama ────────────────────────────────────────
    # Statik secret YOK — ECDH Ephemeral Key Exchange kullanılır
    # Her oturum başında sunucudan dinamik session_key alınır (sadece RAM)
    flutter_bundle_id: str = "com.guvenliodeme.app"
    flutter_client_auth_enabled: bool = True
    # ECDH session key TTL (saniye) — bu süre sonra yeni handshake gerekir
    handshake_ttl_seconds: int = 300   # 5 dakika

    # ── CORS ────────────────────────────────────────────────────────────────────
    cors_allowed_origins: str = "http://localhost:3000"
    cors_allow_credentials: bool = True

    # ── Rate Limiting ───────────────────────────────────────────────────────────
    rate_limit_default: str = "100/minute"
    rate_limit_auth: str = "10/minute"

    # ── JWT ─────────────────────────────────────────────────────────────────────
    jwt_algorithm: str = "HS256"
    jwt_secret: str
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # ── Admin SSO ───────────────────────────────────────────────────────────────
    admin_mail: str
    admin_pass: str

    # ── PostgreSQL ───────────────────────────────────────────────────────────────
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "guvenliodeme"
    postgres_user: str = "guvenliodeme_app"
    postgres_password: str
    postgres_pool_size: int = 10
    postgres_max_overflow: int = 20

    # ── Loglama ─────────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: Literal["json", "pretty"] = "json"

    # ── PayTR ────────────────────────────────────────────────────────────────────
    paytr_merchant_id: str = ""
    paytr_merchant_key: str = ""
    paytr_merchant_salt: str = ""

    # ── Push Notifications (Firebase Admin SDK) ───────────────────────────────
    firebase_service_account_file: str = "pentora-pay-firebase-adminsdk-fbsvc-ea94983dab.json"

    # ── Netgsm SMS (OTP gönderimi) ───────────────────────────────────────────
    netgsm_usercode: str = ""
    netgsm_password: str = ""
    netgsm_header:   str = "PentoraPay"
    # Netgsm gelen SMS webhook gizli token — URL query param olarak iletilir
    # Üretim: python -c "import secrets; print(secrets.token_urlsafe(32))"
    netgsm_sms_reply_secret: str = ""

    # ── Ödeme Portalı ─────────────────────────────────────────────────────────
    # PayTR ödeme linki tabanı — {id} payment_id ile tamamlanır
    payment_portal_url: str = "https://pentorasec.online/pay"

    # ── Validators ──────────────────────────────────────────────────────────────

    @field_validator("pentora_signature_secret", "pentora_grauth_secret", "tckn_pepper")
    @classmethod
    def validate_secret_strength(cls, v: str, info) -> str:
        if len(v) < 32:
            raise ValueError(
                f"{info.field_name} en az 32 karakter olmalıdır. "
                "Üretimde 64+ karakter rastgele değer kullanın."
            )
        return v

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if self.app_env == "production":
            if self.debug:
                raise ValueError("Üretimde DEBUG=true olamaz.")
            if self.tckn_pepper == self.pentora_grauth_secret:
                raise ValueError(
                    "tckn_pepper ve pentora_grauth_secret FARKLI olmalıdır!"
                )
        return self

    @property
    def database_url(self) -> str:
        """SQLAlchemy async DSN."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

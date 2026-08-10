"""Configuration per SPEC §4 — eager, fail-fast, key as SecretStr."""

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    abuseipdb_api_key: SecretStr
    score_threshold: int = Field(default=30, ge=0, le=100)
    max_age_days: int = Field(default=30, ge=1, le=365)
    upstream_timeout_s: float = Field(default=5.0, gt=0)

    @field_validator("abuseipdb_api_key")
    @classmethod
    def _key_not_blank(cls, value: SecretStr) -> SecretStr:
        # The classic template-copy accident: ABUSEIPDB_API_KEY= with no value
        # satisfies "required" and would surface only as 502s on first lookup.
        if not value.get_secret_value().strip():
            raise ValueError("ABUSEIPDB_API_KEY must not be blank")
        return value

"""12-factor configuration. Every value comes from the environment (TAXSTAMPS_*
prefix); no secrets in code, no defaults for secrets.

Fail-closed policy:
- the service refuses to boot with placeholder/dummy key material
  (see crypto.eddsa.load_signing_key);
- optional integrations (Kafka, JWKS endpoint, payment rails) report
  unavailable via GET /v1/capabilities and return 503 from dependent routes
  rather than fabricating success.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PRODUCER = "blueeconomy-tax-stamps"
KEY_EPOCH = 0
KID = f"{PRODUCER}-{KEY_EPOCH}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TAXSTAMPS_", env_file=".env", extra="ignore")

    # --- required ---
    database_url: str = ""
    signing_key_path: str = ""          # Ed25519 PKCS#8 PEM, file-mounted
    issuer_did: str = ""                # e.g. did:web:taxstamps.blueeconomy.gov.ng
    policy_dir: str = ""                # PBAC policy directory (boot-fatal when bad)

    # --- optional but fail-closed consumers when absent ---
    redis_url: str = ""                 # nonce / rate-limit / velocity (fail-closed on outage)
    key_directory_path: str = ""        # {kid: b64u pubkey} for inbound envelope verification
    kafka_bootstrap_servers: str = ""   # outbox publisher + declarations consumer
    kafka_declarations_topic_pattern: str = "declarations.*"
    kafka_consumer_group: str = "blueeconomy-tax-stamps"

    # --- OIDC (Keycloak RS256/EdDSA via JWKS) ---
    oidc_jwks_url: str = ""             # https://keycloak/.../certs
    oidc_jwks_path: str = ""            # local JWKS file alternative (file-mounted)
    oidc_issuer: str = ""
    oidc_audience: str = ""

    # --- payment rails (financial-controls boundary) ---
    payment_rail: str = ""              # "" | "cvff-tigerbeetle" | "mojaloop"
    financial_controls_endpoint: str = ""

    # --- service ---
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    status_list_base_url: str = ""      # public base for status-list credential ids
    stamp_validity_days: int = 365
    issuance_chunk_size: int = 500
    velocity_window_hours: int = 24
    velocity_distinct_devices: int = 3
    rate_limit_per_minute: int = 120

    @field_validator("database_url")
    @classmethod
    def _db_url(cls, v: str) -> str:
        if v and not v.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must be a postgresql+asyncpg:// URL")
        return v

    @property
    def kid(self) -> str:
        return KID

    @property
    def redis_configured(self) -> bool:
        return bool(self.redis_url)

    @property
    def kafka_configured(self) -> bool:
        return bool(self.kafka_bootstrap_servers)

    @property
    def oidc_configured(self) -> bool:
        return bool((self.oidc_jwks_url or self.oidc_jwks_path) and self.oidc_issuer)

    @property
    def payment_rail_configured(self) -> bool:
        return bool(self.payment_rail and self.financial_controls_endpoint)


@lru_cache
def get_settings() -> Settings:
    return Settings()

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
    # Comma-separated topic patterns (fnmatch-style '*' wildcards). The
    # port-interoperability producer publishes declarations on
    # trade.declarations.v1, so it is part of the default set.
    kafka_declarations_topic_pattern: str = "declarations.*,trade.declarations.v1"
    kafka_consumer_group: str = "blueeconomy-tax-stamps"
    # Producer-contract normalization: eventType=mode comma pairs mapping
    # producer eventTypes (FHIR Basic domain-payload string extension) onto
    # the structural declaration resource. Fail-closed on unknown modes and
    # malformed payloads.
    declaration_event_map: str = "trade.declaration.submitted.v1=declaration"
    # Trusted JWS kid prefix allow-list for inbound declaration envelopes
    # (comma-separated). Rejection reason: untrusted-kid.
    trusted_kid_prefixes: str = "port-interoperability-"

    # --- OIDC (Keycloak RS256/EdDSA via JWKS) ---
    oidc_jwks_url: str = ""             # https://keycloak/.../certs
    oidc_jwks_path: str = ""            # local JWKS file alternative (file-mounted)
    oidc_issuer: str = ""
    oidc_audience: str = ""

    # --- payment rails (financial-controls boundary) ---
    payment_rail: str = ""              # "" | "cvff-tigerbeetle" | "mojaloop"
    financial_controls_endpoint: str = ""
    financial_controls_token: str = ""  # bearer token for the FC boundary (env-only secret)

    # --- service ---
    http_host: str = "0.0.0.0"  # noqa: S104 -- container listener, ingress-terminated
    http_port: int = 8080
    status_list_base_url: str = ""      # public base for status-list credential ids
    stamp_validity_days: int = 365
    issuance_chunk_size: int = 500
    velocity_window_hours: int = 24
    velocity_distinct_devices: int = 3
    rate_limit_per_minute: int = 120
    # Anomaly throttle for the NON-CONSUMING public scan path: per-serial
    # scan-rate cap (beyond per-IP) when Redis is present.
    public_serial_rate_limit_per_minute: int = 10

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
        # A rail is only usable with BOTH an endpoint and a caller token for
        # the financial-controls boundary; partial configuration fails closed.
        return bool(
            self.payment_rail
            and self.financial_controls_endpoint
            and self.financial_controls_token
        )

    @property
    def kafka_declarations_topic_patterns(self) -> tuple[str, ...]:
        from taxstamps.events.normalize import parse_kid_prefixes

        return parse_kid_prefixes(self.kafka_declarations_topic_pattern)

    @property
    def declaration_event_map_parsed(self) -> dict[str, str]:
        from taxstamps.events.normalize import parse_event_map

        return parse_event_map(self.declaration_event_map)

    @property
    def trusted_kid_prefix_list(self) -> tuple[str, ...]:
        from taxstamps.events.normalize import parse_kid_prefixes

        return parse_kid_prefixes(self.trusted_kid_prefixes)


@lru_cache
def get_settings() -> Settings:
    return Settings()

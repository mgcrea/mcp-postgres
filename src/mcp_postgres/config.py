"""Configuration management from environment variables."""

import os
from dataclasses import dataclass


@dataclass
class PostgresConfig:
    """Postgres connection configuration."""

    host: str
    port: int
    user: str
    password: str
    database: str
    readonly: bool

    @property
    def connection_string(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


def get_config() -> PostgresConfig:
    """Load Postgres configuration from environment variables."""
    return PostgresConfig(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        user=os.environ.get("POSTGRES_USER", "postgres"),
        password=os.environ.get("POSTGRES_PASSWORD", ""),
        database=os.environ.get("POSTGRES_DB", "postgres"),
        readonly=os.environ.get("POSTGRES_READONLY", "true").lower() in ("true", "1", "yes"),
    )

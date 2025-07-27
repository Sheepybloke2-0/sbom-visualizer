"""
Configuration management for SBOM Visualizer.

Handles environment variables, application settings, and configuration validation.
"""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Application
    app_name: str = Field(default="sbom-analyzer", description="Application name")
    version: str = Field(default="0.1.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")

    # API
    api_host: str = Field(default="0.0.0.0", description="API host address")
    api_port: int = Field(default=8000, description="API port number")

    # Database
    database_url: Optional[str] = Field(
        default=None, description="Database connection URL"
    )

    # AI Integration
    claude_api_key: Optional[str] = Field(default=None, description="Claude API key")

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string",
    )

    # File handling
    max_file_size: int = Field(
        default=100 * 1024 * 1024, description="Maximum file size in bytes"
    )
    allowed_extensions: list[str] = Field(
        default=[".json", ".xml", ".spdx", ".cdx"],
        description="Allowed file extensions",
    )

    class Config:
        env_file = ".env"
        case_sensitive = False
        env_prefix = "SBOM_"


# Global settings instance
settings = Settings()

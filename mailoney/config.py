"""
Configuration handling for Mailoney
"""
import os
import logging
from typing import Dict, Any, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)

class Settings(BaseSettings):
    """Application settings"""
    # Server settings
    bind_ip: str = Field(default="0.0.0.0")
    bind_port: int = Field(default=25)
    server_name: str = Field(default="mail.example.com")
    
    # Database settings
    db_url: str = Field(default="sqlite:///mailoney.db")
    
    # Logging settings
    log_level: str = Field(default="INFO")
    
    # Configure the settings to use the MAILONEY_ prefix for environment variables
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MAILONEY_",
        case_sensitive=False,
        extra="ignore"
    )

def get_settings() -> Settings:
    """
    Get application settings
    
    Returns:
        Settings object
    """
    return Settings()

def configure_logging(level: Optional[str] = None) -> None:
    """
    Configure application logging
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    if level is None:
        level = get_settings().log_level
        
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

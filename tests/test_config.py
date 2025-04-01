"""
Tests for the configuration module
"""
import os
import pytest
from mailoney.config import get_settings, configure_logging, Settings

def test_default_settings():
    """Test default settings"""
    settings = get_settings()
    
    assert settings.bind_ip == "0.0.0.0"
    assert settings.bind_port == 25
    assert settings.server_name == "mail.example.com"
    assert settings.db_url == "sqlite:///mailoney.db"
    assert settings.log_level == "INFO"

def test_env_settings(monkeypatch):
    """Test settings from environment variables"""
    # Set environment variables
    monkeypatch.setenv("MAILONEY_BIND_IP", "127.0.0.1")
    monkeypatch.setenv("MAILONEY_BIND_PORT", "2525")
    monkeypatch.setenv("MAILONEY_SERVER_NAME", "honeypot.local")
    monkeypatch.setenv("MAILONEY_DB_URL", "postgresql://user:pass@localhost/honeypot")
    monkeypatch.setenv("MAILONEY_LOG_LEVEL", "DEBUG")
    
    # Recreate settings to pick up environment variables
    settings = Settings()
    
    assert settings.bind_ip == "127.0.0.1"
    assert settings.bind_port == 2525
    assert settings.server_name == "honeypot.local"
    assert settings.db_url == "postgresql://user:pass@localhost/honeypot"
    assert settings.log_level == "DEBUG"

def test_configure_logging():
    """Test logging configuration"""
    # This is more of a smoke test since it's hard to test logging configuration
    configure_logging("DEBUG")
    configure_logging("INFO")
    
    # Test with invalid level
    with pytest.raises(ValueError):
        configure_logging("NOT_A_LEVEL")

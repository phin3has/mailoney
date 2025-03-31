"""
Tests for the database module
"""
import pytest
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mailoney.db import Base, init_db, create_session, update_session_data, log_credential

@pytest.fixture
def test_db():
    """Test database fixture"""
    # Use in-memory SQLite for testing
    db_url = "sqlite:///:memory:"
    
    # Initialize the database
    init_db(db_url)
    
    # Create tables
    from mailoney.db import engine
    Base.metadata.create_all(engine)
    
    yield
    
    # Clean up
    Base.metadata.drop_all(engine)

def test_create_session(test_db):
    """Test creating a session record"""
    session = create_session("192.168.1.1", 12345, "test.example.com")
    assert session.id is not None
    assert session.ip_address == "192.168.1.1"
    assert session.port == 12345
    assert session.server_name == "test.example.com"

def test_update_session_data(test_db):
    """Test updating session data"""
    session = create_session("192.168.1.1", 12345, "test.example.com")
    update_session_data(session.id, '{"test": "data"}')
    
    # Verify the data was updated
    from mailoney.db import Session, SMTPSession
    db_session = Session()
    try:
        updated_session = db_session.query(SMTPSession).filter_by(id=session.id).first()
        assert updated_session.session_data == '{"test": "data"}'
    finally:
        db_session.close()

def test_log_credential(test_db):
    """Test logging a credential"""
    session = create_session("192.168.1.1", 12345, "test.example.com")
    log_credential(session.id, "dGVzdDp0ZXN0")  # test:test in base64
    
    # Verify the credential was logged
    from mailoney.db import Session, Credential
    db_session = Session()
    try:
        credential = db_session.query(Credential).filter_by(session_id=session.id).first()
        assert credential is not None
        assert credential.auth_string == "dGVzdDp0ZXN0"
    finally:
        db_session.close()

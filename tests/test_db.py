"""
Tests for the database module
"""
import pytest
import os
import logging
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from mailoney.db import Base, init_db, create_session, update_session_data, log_credential

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

@pytest.fixture
def test_db():
    """Test database fixture"""
    # Use in-memory SQLite for testing
    db_url = "sqlite:///:memory:"
    
    # Force re-initialization of the database
    import mailoney.db
    mailoney.db.engine = None
    mailoney.db.Session = None
    
    # Create a direct engine for this test
    test_engine = create_engine(db_url)
    
    # Create all tables directly
    Base.metadata.create_all(test_engine)
    
    # Now initialize the database with our engine
    init_db(db_url)
    
    # Verify tables exist
    from mailoney.db import engine
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    logging.debug(f"Tables in database: {table_names}")
    
    # Make sure our tables are there
    assert "smtp_sessions" in table_names
    assert "credentials" in table_names
    
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

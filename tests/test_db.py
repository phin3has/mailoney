"""
Tests for the database module
"""
import pytest
import os
import logging
import sqlalchemy as sa
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from mailoney.db import Base, init_db, create_session, update_session_data, log_credential

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

@pytest.fixture
def test_db():
    """Simple test database fixture that ensures a clean state before each test"""
    # The actual setup is done in conftest.py
    # This fixture just ensures each test starts with a clean db state
    
    from mailoney.db import engine
    
    # Verify tables are there (debugging)
    insp = inspect(engine)
    tables = insp.get_table_names()
    logging.info(f"Available tables for test: {tables}")
    
    yield
    
    # No cleanup needed - handled in conftest

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
        # SQLAlchemy 2.0 syntax
        stmt = sa.select(SMTPSession).filter_by(id=session.id)
        updated_session = db_session.execute(stmt).scalar_one()
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
        # SQLAlchemy 2.0 syntax
        stmt = sa.select(Credential).filter_by(session_id=session.id)
        credential = db_session.execute(stmt).scalar_one()
        assert credential is not None
        assert credential.auth_string == "dGVzdDp0ZXN0"
    finally:
        db_session.close()

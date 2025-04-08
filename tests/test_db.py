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
    """Test database fixture"""
    # Use in-memory SQLite for testing
    db_url = "sqlite:///:memory:"
    
    # Force re-initialization of the database
    import mailoney.db as db_module
    
    # Reset global variables
    db_module.engine = None
    db_module.Session = None
    
    # Create the engine and ensure tables exist
    engine = create_engine(db_url)
    Base.metadata.drop_all(engine)  # Make sure we start fresh
    Base.metadata.create_all(engine)
    
    # Check if tables were created using SQLAlchemy 2.0+ compatible methods
    insp = inspect(engine)
    has_tables = all(table in insp.get_table_names() for table in ['smtp_sessions', 'credentials'])
    
    if not has_tables:
        logging.warning("Tables not detected, forcing creation...")
        # Create tables manually if needed
        connection = engine.connect()
        try:
            connection.execute(sa.text("CREATE TABLE IF NOT EXISTS smtp_sessions "
                             "(id INTEGER PRIMARY KEY, "
                             "timestamp DATETIME, "
                             "ip_address VARCHAR(255) NOT NULL, "
                             "port INTEGER NOT NULL, "
                             "server_name VARCHAR(255), "
                             "session_data TEXT)"))
            
            connection.execute(sa.text("CREATE TABLE IF NOT EXISTS credentials "
                             "(id INTEGER PRIMARY KEY, "
                             "timestamp DATETIME, "
                             "session_id INTEGER, "
                             "auth_string VARCHAR(255), "
                             "FOREIGN KEY(session_id) REFERENCES smtp_sessions(id))"))
            connection.commit()
        finally:
            connection.close()
    
    # Initialize the database (this should connect to our in-memory DB)
    db_module.init_db(db_url)
    
    # Final verification
    insp = inspect(db_module.engine)
    tables = insp.get_table_names()
    logging.debug(f"Tables in database after initialization: {tables}")
    
    # Now proceed with tests
    yield
    
    # Clean up
    try:
        Base.metadata.drop_all(db_module.engine)
    except Exception as e:
        logging.warning(f"Error during cleanup: {e}")

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

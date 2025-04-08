"""
Shared test fixtures and configuration
"""
import pytest
import logging
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
import sys

from mailoney.db import Base

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """
    Set up the test environment with the correct database
    This fixture runs automatically once before all tests
    """
    # Ensure we can import our modules
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
    # Set up in-memory SQLite for testing
    import mailoney.db as db_module
    
    # Create a persistent in-memory database for all tests
    db_url = "sqlite:///:memory:"
    test_engine = create_engine(db_url, echo=True)  # echo=True for SQL debugging
    
    # Create all tables
    Base.metadata.drop_all(test_engine)  # Start clean
    Base.metadata.create_all(test_engine)
    
    # Verify tables were created
    inspector = inspect(test_engine)
    tables = inspector.get_table_names()
    logging.info(f"Tables created in test environment: {tables}")
    
    # Save original values
    original_engine = db_module.engine
    original_session = db_module.Session
    
    # Replace with our test engine/session
    db_module.engine = test_engine
    db_module.Session = sessionmaker(bind=test_engine)
    
    yield
    
    # Restore original values after all tests
    db_module.engine = original_engine
    db_module.Session = original_session

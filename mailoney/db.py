"""
Database handling module for Mailoney
"""
import os
import logging
import sqlalchemy as sa
from datetime import datetime
from typing import Dict, Any, Optional

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import NullPool

Base = declarative_base()
engine = None
Session = None
logger = logging.getLogger(__name__)

class SMTPSession(Base):
    """Model for SMTP session data"""
    __tablename__ = "smtp_sessions"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    server_name = Column(String(255))
    session_data = Column(Text)
    
class Credential(Base):
    """Model for captured credentials"""
    __tablename__ = "credentials"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    session_id = Column(Integer, ForeignKey("smtp_sessions.id"))
    auth_string = Column(String(255))
    
    session = relationship("SMTPSession", back_populates="credentials")

# Add relationship to SMTPSession
SMTPSession.credentials = relationship("Credential", order_by=Credential.id, back_populates="session")

def init_db(db_url: Optional[str] = None) -> None:
    """
    Initialize the database connection.
    
    Args:
        db_url: Database connection URL. If None, uses MAILONEY_DB_URL environment variable.
    """
    global engine, Session
    
    if db_url is None:
        db_url = os.environ.get("MAILONEY_DB_URL")
        
    if not db_url:
        # Default to SQLite for development
        db_url = "sqlite:///mailoney.db"
        logger.warning(f"No database URL provided, using default: {db_url}")
    
    logger.info(f"Initializing database with URL: {db_url}")
    
    # For in-memory SQLite, we need to use specific settings
    is_memory_db = db_url == "sqlite:///:memory:"
    connect_args = {}
    if is_memory_db:
        # Use a shared connection for in-memory SQLite
        connect_args = {"check_same_thread": False}
        logger.info("Using in-memory SQLite database with shared connection")
    
    # Create the engine with appropriate settings
    engine = create_engine(db_url, poolclass=NullPool, connect_args=connect_args, future=True)
    Session = sessionmaker(bind=engine, future=True)
    
    # Always ensure tables exist
    Base.metadata.create_all(engine)
    logger.info("Tables created successfully")
    
    # Verify tables were created (for debugging)
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        logger.info(f"Tables in database: {tables}")
        if 'smtp_sessions' not in tables or 'credentials' not in tables:
            logger.warning("Expected tables not found after create_all!")
    except Exception as e:
        logger.error(f"Error inspecting tables: {e}")
    
    # Run migrations if not using in-memory DB
    if not is_memory_db:
        try:
            import os
            from alembic import command
            from alembic.config import Config
            
            # Find the alembic.ini file
            alembic_ini = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'alembic.ini')
            if os.path.exists(alembic_ini):
                alembic_cfg = Config(alembic_ini)
                alembic_cfg.set_main_option('sqlalchemy.url', db_url)
                command.upgrade(alembic_cfg, 'head')
                logger.info("Database migrations applied successfully")
        except ImportError:
            logger.warning("Alembic not installed, skipping database migrations")
        except Exception as e:
            logger.warning(f"Error applying migrations: {e}")

def create_session(ip_address: str, port: int, server_name: str) -> SMTPSession:
    """
    Create a new session record in the database.
    
    Args:
        ip_address: Client IP address
        port: Client port
        server_name: Server name used
        
    Returns:
        The created SMTPSession instance
    """
    global engine, Session
    
    if Session is None:
        init_db()
    
    # First verify that tables exist
    insp = inspect(engine)
    tables = insp.get_table_names()
    if 'smtp_sessions' not in tables:
        # Recreate tables if they don't exist
        logger.warning("Tables missing, recreating...")
        Base.metadata.create_all(engine)
    
    session = Session()
    try:
        smtp_session = SMTPSession(
            ip_address=ip_address,
            port=port,
            server_name=server_name
        )
        session.add(smtp_session)
        session.commit()
        return smtp_session
    except Exception as e:
        session.rollback()
        logger.error(f"Error creating session: {e}")
        raise
    finally:
        session.close()

def update_session_data(session_id: int, session_data: str) -> None:
    """
    Update session data for an existing session.
    
    Args:
        session_id: The ID of the session to update
        session_data: Session data to store
    """
    if Session is None:
        init_db()
    
    session = Session()
    try:
        # SQLAlchemy 2.0 style
        stmt = sa.select(SMTPSession).filter_by(id=session_id)
        smtp_session = session.execute(stmt).scalar_one_or_none()
        if smtp_session:
            smtp_session.session_data = session_data
            session.commit()
        else:
            logger.warning(f"Session ID {session_id} not found")
    except Exception as e:
        session.rollback()
        logger.error(f"Error updating session: {e}")
        raise
    finally:
        session.close()

def log_credential(session_id: int, auth_string: str) -> None:
    """
    Log a credential attempt.
    
    Args:
        session_id: The ID of the session
        auth_string: The authentication string
    """
    if Session is None:
        init_db()
    
    session = Session()
    try:
        credential = Credential(
            session_id=session_id,
            auth_string=auth_string
        )
        session.add(credential)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Error logging credential: {e}")
        raise
    finally:
        session.close()

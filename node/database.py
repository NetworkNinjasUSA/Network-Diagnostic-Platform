"""SQLite database setup for test node."""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from .config import get_config

Base = declarative_base()


class TestResult(Base):
    """Local test results storage."""
    __tablename__ = "test_results"
    
    id = Column(Integer, primary_key=True, index=True)
    test_type = Column(String(50), index=True, nullable=False)
    customer_id = Column(String(100), index=True)
    client_ip = Column(String(45))
    config = Column(Text)  # JSON
    result = Column(Text)  # JSON
    status = Column(String(20), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime)
    synced = Column(Boolean, default=False, index=True)


class CustomerToken(Base):
    """Customer test tokens."""
    __tablename__ = "customer_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(100), unique=True, nullable=False, index=True)
    customer_id = Column(String(100), index=True)
    note = Column(String(500))
    expires_at = Column(DateTime, nullable=False)
    max_uses = Column(Integer, default=1)
    use_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(50))


class User(Base):
    """Local user accounts (for standalone mode)."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="engineer")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)


class ContinuousPing(Base):
    """Active continuous ping sessions."""
    __tablename__ = "continuous_pings"
    
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    interval = Column(Integer, default=1)
    duration = Column(Integer, default=60)
    status = Column(String(20), default="running")
    started_at = Column(DateTime, default=datetime.utcnow)
    results = Column(Text)  # JSON array of ping results


# Database connection
_engine = None
_SessionLocal = None


def init_db(db_path: str = None):
    """Initialize the database."""
    global _engine, _SessionLocal
    
    if db_path is None:
        db_path = get_config().database_path
    
    _engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False}
    )
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    
    # Create tables
    Base.metadata.create_all(bind=_engine)


def get_db():
    """Get database session."""
    global _SessionLocal
    
    if _SessionLocal is None:
        init_db()
    
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session():
    """Get a database session directly (not as generator)."""
    global _SessionLocal
    
    if _SessionLocal is None:
        init_db()
    
    return _SessionLocal()

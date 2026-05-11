"""
Database Models for Dynamic Access Control System
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timezone

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./access_control.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utc_now():
    """Helper function to get current UTC datetime"""
    return datetime.now(timezone.utc)


class User(Base):
    """User model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)  # In production, store hashed passwords
    email = Column(String, unique=True, index=True)
    role = Column(String, default="employee", nullable=False)  # admin, employee, auditor
    failed_attempts = Column(Integer, default=0, nullable=False)
    last_failed_login_at = Column(DateTime)
    auth_risk_score = Column(Float, default=0.0, nullable=False)
    account_locked_until = Column(DateTime)
    last_login_ip = Column(String)
    last_login_user_agent = Column(String)
    created_at = Column(DateTime, default=utc_now)
    
    # Relationships
    behavioral_profile = relationship("BehavioralProfile", back_populates="user", uselist=False)
    access_logs = relationship("AccessLog", back_populates="user")


class BehavioralProfile(Base):
    """Stores user's behavioral baseline"""
    __tablename__ = "behavioral_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    
    # Typing metrics
    avg_typing_speed = Column(Float, default=0.0)  # Characters per second
    avg_dwell_time = Column(Float, default=0.0)  # Average time key is held (ms)
    avg_flight_time = Column(Float, default=0.0)  # Average time between key presses (ms)
    
    # Mouse metrics
    avg_mouse_velocity = Column(Float, default=0.0)  # Pixels per millisecond
    
    # Sample counts for averaging
    typing_samples = Column(Integer, default=0)
    mouse_samples = Column(Integer, default=0)
    
    # Last known IP address
    last_ip_address = Column(String)
    
    last_updated = Column(DateTime, default=utc_now, onupdate=utc_now)
    
    # Relationships
    user = relationship("User", back_populates="behavioral_profile")


class AccessLog(Base):
    """Logs all access attempts with risk scores"""
    __tablename__ = "access_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ip_address = Column(String)
    action = Column(String)  # login, behavior_analysis, access_denied, etc.
    risk_score = Column(Float, default=0.0)
    details = Column(Text)  # JSON string with additional details
    timestamp = Column(DateTime, default=utc_now, index=True)
    
    # Relationships
    user = relationship("User", back_populates="access_logs")

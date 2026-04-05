from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import os

# Presentation Vault Configuration (Single-Use Forensic Store)
DB_PATH = "c:/Users/Utkarsh Dubey/.gemini/antigravity/DNSentinel/backend/presentation_vault.db"
engine = create_engine(
    f"sqlite:///{DB_PATH}", 
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
    pool_recycle=3600
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DNSAuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String, index=True)
    query = Column(String)
    qtype = Column(String)
    risk_score = Column(Float)
    risk_level = Column(String)
    prediction = Column(String)
    priority = Column(String, default="LOW")
    priority_score = Column(Float, default=0.0)
    is_blocked = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    mitre_data = Column(JSON)
    features = Column(JSON)
    explanation = Column(String)
    
class SecurityRule(Base):
    """Unified SOAR Rule Store (Blacklist + Redirects)"""
    __tablename__ = "security_rules"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, unique=True, index=True) # IP or Domain
    rule_type = Column(String) # 'IP_BLOCK', 'DOMAIN_SINKHOLE'
    action = Column(String) # 'BLOCK', 'DROP', 'LOG'
    reason = Column(String)
    risk_score = Column(Float)
    is_active = Column(Boolean, default=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True) # Cooldown Timer

class Whitelist(Base):
    __tablename__ = "whitelist"
    id = Column(Integer, primary_key=True, index=True)
    entity = Column(String, unique=True, index=True)
    reason = Column(String)
    added_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class Attacker(Base):
    __tablename__ = "attackers"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    city = Column(String, nullable=True)
    country = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    risk_score = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    commands = relationship("HoneypotCommand", back_populates="attacker")
    web_attacks = relationship("WebAttack", back_populates="attacker")
    credentials = relationship("Credential", back_populates="attacker")

class HoneypotCommand(Base):
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    command = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    attacker = relationship("Attacker", back_populates="commands")

class WebAttack(Base):
    __tablename__ = "web_attacks"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    endpoint = Column(String)
    payload = Column(String) # For SQLi etc.
    user_agent = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    attacker = relationship("Attacker", back_populates="web_attacks")

class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    username = Column(String)
    password = Column(String)
    source = Column(String) # "ssh" or "web"
    timestamp = Column(DateTime, default=datetime.utcnow)

    attacker = relationship("Attacker", back_populates="credentials")

class ThreatReport(Base):
    __tablename__ = "threat_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    severity = Column(String) # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(String)
    recommended_action = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

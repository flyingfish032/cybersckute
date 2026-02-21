from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text
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
    # TTP tags as comma-separated string (e.g. "T1059,T1082,T1110")
    ttp_tags = Column(Text, nullable=True, default="")
    # AI-generated attacker profile narrative
    attacker_profile = Column(Text, nullable=True, default="")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    commands = relationship("HoneypotCommand", back_populates="attacker", cascade="all, delete-orphan")
    web_attacks = relationship("WebAttack", back_populates="attacker", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="attacker", cascade="all, delete-orphan")
    threat_reports = relationship("ThreatReport", back_populates="attacker", cascade="all, delete-orphan")
    service_interactions = relationship("ServiceInteraction", back_populates="attacker", cascade="all, delete-orphan")


class HoneypotCommand(Base):
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    command = Column(String)
    severity = Column(String, nullable=True, default="LOW")
    ttp = Column(String, nullable=True, default="")
    timestamp = Column(DateTime, default=datetime.utcnow)

    attacker = relationship("Attacker", back_populates="commands")


class WebAttack(Base):
    __tablename__ = "web_attacks"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    endpoint = Column(String)
    payload = Column(String)
    user_agent = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    attacker = relationship("Attacker", back_populates="web_attacks")


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    username = Column(String)
    password = Column(String)
    source = Column(String)  # "ssh", "web", "ftp", "mysql"
    timestamp = Column(DateTime, default=datetime.utcnow)

    attacker = relationship("Attacker", back_populates="credentials")


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(Integer, primary_key=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id"))
    severity = Column(String)  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text)
    recommended_action = Column(Text)
    service_type = Column(String, nullable=True, default="ssh")  # which honeypot triggered it
    full_report_json = Column(Text, nullable=True, default="{}")  # Full Gemini report as JSON string
    timestamp = Column(DateTime, default=datetime.utcnow)

    attacker = relationship("Attacker", back_populates="threat_reports")


class DynamicService(Base):
    """Tracks which fake honeypot services are currently active."""
    __tablename__ = "dynamic_services"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)  # e.g. "mysql", "ftp"
    port = Column(Integer)
    banner = Column(String, nullable=True)
    interaction_count = Column(Integer, default=0)
    is_active = Column(Integer, default=1)  # 1=active, 0=stopped
    started_at = Column(DateTime, default=datetime.utcnow)

    interactions = relationship("ServiceInteraction", back_populates="service", cascade="all, delete-orphan")


class ServiceInteraction(Base):
    """Logs raw interactions with dynamic honeypot services."""
    __tablename__ = "service_interactions"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("dynamic_services.id"))
    attacker_id = Column(Integer, ForeignKey("attackers.id"), nullable=True)
    attacker_ip = Column(String)
    raw_data = Column(Text, nullable=True)  # What the attacker sent
    timestamp = Column(DateTime, default=datetime.utcnow)

    service = relationship("DynamicService", back_populates="interactions")
    attacker = relationship("Attacker", back_populates="service_interactions")

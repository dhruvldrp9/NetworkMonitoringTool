from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Get database URL from environment
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

# Create SQLAlchemy engine and session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class PacketLog(Base):
    """Model for storing packet information"""
    __tablename__ = "packet_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String)
    dst_ip = Column(String)
    protocol = Column(String)
    length = Column(Integer)
    details = Column(JSON)

class ThreatLog(Base):
    """Model for storing detected threats"""
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    type = Column(String)
    source = Column(String)
    details = Column(String)
    severity = Column(String)
    category = Column(String)
    confidence = Column(Float, nullable=True)

class AnomalyLog(Base):
    """Model for storing ML-detected anomalies"""
    __tablename__ = "anomaly_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    type = Column(String)
    source = Column(String)
    details = Column(String)
    confidence = Column(Float)
    features = Column(JSON)
    baseline_stats = Column(JSON)

class DatabaseManager:
    def __init__(self):
        """Initialize database manager"""
        self.SessionLocal = SessionLocal
        self._create_tables()

    def _create_tables(self):
        """Create database tables"""
        try:
            # Use checkfirst=True to prevent errors if tables already exist
            Base.metadata.create_all(bind=engine, checkfirst=True)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
            raise

    def log_packet(self, packet_info):
        """Log packet information to database"""
        try:
            with self.SessionLocal() as session:
                packet_log = PacketLog(
                    src_ip=packet_info['src_ip'],
                    dst_ip=packet_info['dst_ip'],
                    protocol=packet_info['protocol'],
                    length=packet_info['length'],
                    details=packet_info['details']
                )
                session.add(packet_log)
                session.commit()
        except Exception as e:
            logger.error(f"Error logging packet: {e}")

    def log_threat(self, threat_info):
        """Log threat detection to database"""
        try:
            with self.SessionLocal() as session:
                threat_log = ThreatLog(
                    type=threat_info['type'],
                    source=threat_info['source'],
                    details=threat_info['details'],
                    severity=threat_info['severity'],
                    category=threat_info['category'],
                    confidence=threat_info.get('confidence')
                )
                session.add(threat_log)
                session.commit()
        except Exception as e:
            logger.error(f"Error logging threat: {e}")

    def log_anomaly(self, anomaly_info, features=None, baseline_stats=None):
        """Log ML-detected anomaly to database"""
        try:
            with self.SessionLocal() as session:
                anomaly_log = AnomalyLog(
                    type=anomaly_info['type'],
                    source=anomaly_info['source'],
                    details=anomaly_info['details'],
                    confidence=anomaly_info['confidence'],
                    features=features if features is not None else {},
                    baseline_stats=baseline_stats if baseline_stats is not None else {}
                )
                session.add(anomaly_log)
                session.commit()
        except Exception as e:
            logger.error(f"Error logging anomaly: {e}")

    def get_recent_threats(self, limit=100):
        """Get recent threat detections"""
        with self.SessionLocal() as session:
            return session.query(ThreatLog)\
                .order_by(ThreatLog.timestamp.desc())\
                .limit(limit)\
                .all()

    def get_recent_anomalies(self, limit=100):
        """Get recent anomalies"""
        with self.SessionLocal() as session:
            return session.query(AnomalyLog)\
                .order_by(AnomalyLog.timestamp.desc())\
                .limit(limit)\
                .all()
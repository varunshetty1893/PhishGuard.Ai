import json
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    Boolean,
    DateTime,
    ForeignKey
)
from sqlalchemy.orm import relationship
from app.db.session import Base


def utc_now():
    return datetime.now(timezone.utc)


class ScanHistory(Base):
    """Stores every URL scanned by users, strictly linked to an authenticated user."""
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(String(36), unique=True, index=True, nullable=False)
    
    # Ownership: Every scan is strictly bound to the authenticated user's account
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True)

    submitted_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False)
    predicted_class = Column(String(20), nullable=False)  # Legitimate / Phishing
    risk_level = Column(String(20), nullable=False)       # Low Risk / Suspicious / High Risk
    model_score = Column(Float, nullable=True)            # 0.0 - 1.0 probability
    
    # JSON-encoded fields
    extracted_features_json = Column(Text, nullable=False)
    suspicious_reasons_json = Column(Text, nullable=True)
    
    combined_interpretation = Column(Text, nullable=False)
    model_version = Column(String(20), nullable=False, default="2.1.0")
    created_at = Column(DateTime, default=utc_now, index=True, nullable=False)

    # Relationships
    user = relationship("User", back_populates="scans")
    threat_logs = relationship("ThreatCheckLog", back_populates="scan", cascade="all, delete-orphan")

    @property
    def extracted_features(self):
        try:
            return json.loads(self.extracted_features_json)
        except Exception:
            return {}

    @extracted_features.setter
    def extracted_features(self, value):
        self.extracted_features_json = json.dumps(value)

    @property
    def suspicious_reasons(self):
        try:
            return json.loads(self.suspicious_reasons_json) if self.suspicious_reasons_json else []
        except Exception:
            return []

    @suspicious_reasons.setter
    def suspicious_reasons(self, value):
        self.suspicious_reasons_json = json.dumps(value)


class ThreatCheckLog(Base):
    """Stores external threat-intelligence provider queries for each scan."""
    __tablename__ = "threat_check_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scan_history.scan_id", ondelete="CASCADE"), index=True, nullable=False)
    provider_name = Column(String(50), nullable=False)
    check_status = Column(String(30), nullable=False)
    threat_found = Column(Boolean, default=False, nullable=False)
    threat_category = Column(String(100), nullable=True)
    raw_response = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=utc_now, nullable=False)

    scan = relationship("ScanHistory", back_populates="threat_logs")


class ModelMetadata(Base):
    """Stores the audit trail and evaluation metrics of trained ML models."""
    __tablename__ = "model_metadata"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    model_version = Column(String(20), unique=True, nullable=False)
    algorithm = Column(String(100), nullable=False)
    dataset_name = Column(String(150), nullable=False)
    training_date = Column(DateTime, default=utc_now, nullable=False)
    total_samples = Column(Integer, nullable=False)
    train_samples = Column(Integer, nullable=False)
    test_samples = Column(Integer, nullable=False)
    
    # JSON-encoded metrics
    evaluation_metrics_json = Column(Text, nullable=False)
    confusion_matrix_json = Column(Text, nullable=False)
    feature_schema_json = Column(Text, nullable=False)
    feature_importances_json = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    @property
    def evaluation_metrics(self):
        try:
            return json.loads(self.evaluation_metrics_json)
        except Exception:
            return {}

    @evaluation_metrics.setter
    def evaluation_metrics(self, value):
        self.evaluation_metrics_json = json.dumps(value)

    @property
    def confusion_matrix(self):
        try:
            return json.loads(self.confusion_matrix_json)
        except Exception:
            return {}

    @confusion_matrix.setter
    def confusion_matrix(self, value):
        self.confusion_matrix_json = json.dumps(value)

    @property
    def feature_schema(self):
        try:
            return json.loads(self.feature_schema_json)
        except Exception:
            return []

    @feature_schema.setter
    def feature_schema(self, value):
        self.feature_schema_json = json.dumps(value)

    @property
    def feature_importances(self):
        try:
            return json.loads(self.feature_importances_json) if self.feature_importances_json else {}
        except Exception:
            return {}

    @feature_importances.setter
    def feature_importances(self, value):
        self.feature_importances_json = json.dumps(value)

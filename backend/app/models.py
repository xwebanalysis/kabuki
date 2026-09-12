from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (stored without timezone in SQLite/PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Analysis(Base):
    """An analysis session against a target (xwa-sdk Analysis)."""

    __tablename__ = "analyses"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    status = Column(String, default="RUNNING")  # PENDING, RUNNING, COMPLETED, ERROR, CANCELLED
    analysis_type = Column(String, default="waf_profile")
    created_at = Column(DateTime, default=utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    findings = relationship(
        "Finding", back_populates="analysis", cascade="all, delete-orphan"
    )
    waf_detections = relationship(
        "WafDetection", back_populates="analysis", cascade="all, delete-orphan"
    )
    cdn_observations = relationship(
        "CdnObservation", back_populates="analysis", cascade="all, delete-orphan"
    )
    challenges = relationship(
        "Challenge", back_populates="analysis", cascade="all, delete-orphan"
    )
    rate_limit_observations = relationship(
        "RateLimitObservation", back_populates="analysis", cascade="all, delete-orphan"
    )


class Finding(Base):
    """A unified finding (xwa-sdk Finding) produced by the analysis."""

    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    tool = Column(String, default="kabuki")
    severity = Column(String, default="info")  # pass, info, low, medium, high, critical
    category = Column(String, nullable=True)  # waf, cdn, challenge, rate_limit
    check = Column(String, nullable=True)
    title = Column(String)
    description = Column(Text, nullable=True)
    target_url = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)  # JSON object
    cvss_score = Column(String, nullable=True)
    confidence = Column(String, nullable=True)  # high, medium, low
    detected_at = Column(DateTime, default=utcnow)

    analysis = relationship("Analysis", back_populates="findings")


class WafDetection(Base):
    """A WAF fingerprint observed on the target (xwa-sdk Waf item)."""

    __tablename__ = "waf_detections"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    vendor = Column(String)
    product = Column(String, nullable=True)
    confidence = Column(String, nullable=True)  # high, medium, low
    detection_method = Column(String, nullable=True)  # header, cookie, body, status, dns, tls
    evidence = Column(Text, nullable=True)
    blocked = Column(Integer, default=0)

    analysis = relationship("Analysis", back_populates="waf_detections")


class CdnObservation(Base):
    """A CDN fingerprint observed on the target (xwa-sdk Cdn item)."""

    __tablename__ = "cdn_observations"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    provider = Column(String)
    edge_nodes = Column(Text, nullable=True)  # JSON array of strings
    origin_hidden = Column(Integer, default=0)
    caching = Column(String, nullable=True)  # hit, miss, stale, unknown
    evidence = Column(Text, nullable=True)

    analysis = relationship("Analysis", back_populates="cdn_observations")


class Challenge(Base):
    """A bot challenge / interstitial observed (xwa-sdk Challenge item)."""

    __tablename__ = "challenges"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    kind = Column(String)  # captcha, js_challenge, block_page, interstitial
    status_code = Column(Integer, nullable=True)
    headers = Column(Text, nullable=True)  # JSON object
    bypass_indicators = Column(Text, nullable=True)  # JSON array
    response_time_ms = Column(Float, nullable=True)
    severity_hint = Column(String, nullable=True)  # unified severity

    analysis = relationship("Analysis", back_populates="challenges")


class RateLimitObservation(Base):
    """Rate-limit headers and a conservative recommendation (xwa-sdk RateLimit item)."""

    __tablename__ = "rate_limit_observations"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    scope = Column(String, default="unknown")  # ip, session, global, unknown
    limit = Column(Integer, nullable=True)
    window_seconds = Column(Integer, nullable=True)
    headers = Column(Text, nullable=True)  # JSON object
    threshold_estimate = Column(Integer, nullable=True)
    recommended_delay_ms = Column(Integer, nullable=True)

    analysis = relationship("Analysis", back_populates="rate_limit_observations")

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tool: str = "kabuki"
    severity: str
    category: Optional[str] = None
    check: Optional[str] = None
    title: str
    description: Optional[str] = None
    target_url: Optional[str] = None
    evidence: Optional[str] = None
    cvss_score: Optional[str] = None
    confidence: Optional[str] = None
    detected_at: datetime


class WafDetectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    vendor: str
    product: Optional[str] = None
    confidence: Optional[str] = None
    detection_method: Optional[str] = None
    evidence: Optional[str] = None
    blocked: bool = False


class CdnObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    provider: str
    edge_nodes: Optional[str] = None
    origin_hidden: bool = False
    caching: Optional[str] = None
    evidence: Optional[str] = None


class ChallengeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    status_code: Optional[int] = None
    headers: Optional[str] = None
    bypass_indicators: Optional[str] = None
    response_time_ms: Optional[float] = None
    severity_hint: Optional[str] = None


class RateLimitObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scope: str
    limit: Optional[int] = None
    window_seconds: Optional[int] = None
    headers: Optional[str] = None
    threshold_estimate: Optional[int] = None
    recommended_delay_ms: Optional[int] = None


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: str
    analysis_type: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    findings: List[FindingRead] = []
    waf_detections: List[WafDetectionRead] = []
    cdn_observations: List[CdnObservationRead] = []
    challenges: List[ChallengeRead] = []
    rate_limit_observations: List[RateLimitObservationRead] = []


class AnalysisListItem(BaseModel):
    """Summary row for the analysis history (GET /api/analyses)."""

    id: int
    target: str
    status: str
    analysis_type: str
    created_at: datetime
    finding_count: int
    waf_count: int
    cdn_count: int
    challenge_count: int
    rate_limit_count: int


class AnalyzeRequest(BaseModel):
    target: str = Field(min_length=1)
    probe_mode: Literal["headers", "graduated"] = "headers"
    confirm: bool = False
    max_requests: int = Field(default=5, ge=1, le=20)


class GuardrailRead(BaseModel):
    probe_mode: str
    max_requests: int
    requests_sent: int
    aborted: bool = False
    abort_reason: Optional[str] = None
    delay_ms_min: int
    delay_ms_max: int


class AnalyzeResponse(BaseModel):
    analysis: AnalysisRead
    finding_count: int
    waf_count: int
    cdn_count: int
    challenge_count: int
    rate_limit_count: int
    guardrail: GuardrailRead

import csv
import io
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import analyzer, database, models, schemas, security
from .events import EventEmitter

SERVICE_VERSION = "0.1.0"
TOOL = "kabuki"

ERROR_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
    500: "INTERNAL",
    502: "UPSTREAM_ERROR",
    503: "SERVICE_UNAVAILABLE",
}
RETRYABLE_STATUS = {429, 502, 503}


def _error_payload(code: str, message: str, detail=None, retryable: bool = False) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "detail": detail,
            "retryable": retryable,
        }
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.wait_for_db()
    models.Base.metadata.create_all(bind=database.engine)
    yield


app = FastAPI(
    title="Kabuki API",
    description="WAF and CDN analysis with anti-blocking guardrails",
    version=SERVICE_VERSION,
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, **security.cors_settings())
app.middleware("http")(security.auth_middleware)
app.middleware("http")(security.rate_limit_middleware)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code = ERROR_CODES.get(exc.status_code, "HTTP_ERROR")
    message = exc.detail if isinstance(exc.detail, str) else code
    detail = exc.detail if isinstance(exc.detail, dict) else None
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload(code, message, detail, exc.status_code in RETRYABLE_STATUS),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=_error_payload(
            "VALIDATION_ERROR",
            "Request validation failed.",
            {"errors": jsonable_encoder(exc.errors())},
        ),
    )


class TokenRequest(BaseModel):
    password: str


class TokenResponse(BaseModel):
    token: str
    expires_in: int


def _utcnow() -> str:
    """UTC ISO-8601 timestamp for xwa-sdk events."""
    return datetime.now(timezone.utc).isoformat()


def _dbnow() -> datetime:
    """Naive UTC timestamp for database columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _counts(analysis: models.Analysis) -> dict:
    return {
        "finding_count": len(analysis.findings),
        "waf_count": len(analysis.waf_detections),
        "cdn_count": len(analysis.cdn_observations),
        "challenge_count": len(analysis.challenges),
        "rate_limit_count": len(analysis.rate_limit_observations),
    }


def _summary(analysis: models.Analysis) -> schemas.AnalysisListItem:
    return schemas.AnalysisListItem(
        id=analysis.id,
        target=analysis.target,
        status=analysis.status,
        analysis_type=analysis.analysis_type,
        created_at=analysis.created_at,
        **_counts(analysis),
    )


def _persist_result(db: Session, analysis: models.Analysis, result: dict) -> None:
    for detection in result["waf"]:
        db.add(
            models.WafDetection(
                analysis_id=analysis.id,
                vendor=detection.vendor,
                product=detection.product,
                confidence=detection.confidence,
                detection_method=detection.detection_method,
                evidence=detection.evidence,
                blocked=int(detection.blocked),
            )
        )

    cdn = result.get("cdn")
    if cdn is not None:
        db.add(
            models.CdnObservation(
                analysis_id=analysis.id,
                provider=cdn.provider,
                edge_nodes=json.dumps(cdn.edge_nodes),
                origin_hidden=int(cdn.origin_hidden),
                caching=cdn.caching,
                evidence=cdn.evidence,
            )
        )

    for challenge in result["challenges"]:
        db.add(
            models.Challenge(
                analysis_id=analysis.id,
                kind=challenge.kind,
                status_code=challenge.status_code,
                headers=json.dumps(challenge.headers),
                bypass_indicators=json.dumps(challenge.bypass_indicators),
                response_time_ms=challenge.response_time_ms,
                severity_hint=challenge.severity_hint,
            )
        )

    rate_limit = result["rate_limit"]
    db.add(
        models.RateLimitObservation(
            analysis_id=analysis.id,
            scope=rate_limit.scope,
            limit=rate_limit.limit,
            window_seconds=rate_limit.window_seconds,
            headers=json.dumps(rate_limit.headers),
            threshold_estimate=rate_limit.threshold_estimate,
            recommended_delay_ms=rate_limit.recommended_delay_ms,
        )
    )

    for finding in result["findings"]:
        db.add(
            models.Finding(
                analysis_id=analysis.id,
                tool=finding.tool,
                severity=finding.severity,
                category=finding.category,
                check=finding.check,
                title=finding.title,
                description=finding.description,
                target_url=finding.target_url,
                evidence=json.dumps(finding.evidence),
                cvss_score=finding.cvss_score,
                confidence=finding.confidence,
            )
        )

    db.commit()


def _analysis_export(analysis: models.Analysis) -> dict:
    """Full JSON export of an analysis as a downloadable file."""

    def maybe_json(value: str | None, fallback):
        if not value:
            return fallback
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value

    return {
        "id": analysis.id,
        "target": analysis.target,
        "status": analysis.status,
        "analysis_type": analysis.analysis_type,
        "created_at": _iso(analysis.created_at),
        "started_at": _iso(analysis.started_at),
        "finished_at": _iso(analysis.finished_at),
        "error_message": analysis.error_message,
        "findings": [
            {
                "tool": finding.tool,
                "severity": finding.severity,
                "category": finding.category,
                "check": finding.check,
                "title": finding.title,
                "description": finding.description,
                "target_url": finding.target_url,
                "evidence": maybe_json(finding.evidence, {}),
                "cvss_score": finding.cvss_score,
                "confidence": finding.confidence,
                "detected_at": _iso(finding.detected_at),
            }
            for finding in analysis.findings
        ],
        "waf_detections": [
            {
                "vendor": detection.vendor,
                "product": detection.product,
                "confidence": detection.confidence,
                "detection_method": detection.detection_method,
                "evidence": detection.evidence,
                "blocked": bool(detection.blocked),
            }
            for detection in analysis.waf_detections
        ],
        "cdn_observations": [
            {
                "provider": observation.provider,
                "edge_nodes": maybe_json(observation.edge_nodes, []),
                "origin_hidden": bool(observation.origin_hidden),
                "caching": observation.caching,
                "evidence": observation.evidence,
            }
            for observation in analysis.cdn_observations
        ],
        "challenges": [
            {
                "kind": challenge.kind,
                "status_code": challenge.status_code,
                "headers": maybe_json(challenge.headers, {}),
                "bypass_indicators": maybe_json(challenge.bypass_indicators, []),
                "response_time_ms": challenge.response_time_ms,
                "severity_hint": challenge.severity_hint,
            }
            for challenge in analysis.challenges
        ],
        "rate_limit_observations": [
            {
                "scope": observation.scope,
                "limit": observation.limit,
                "window_seconds": observation.window_seconds,
                "headers": maybe_json(observation.headers, {}),
                "threshold_estimate": observation.threshold_estimate,
                "recommended_delay_ms": observation.recommended_delay_ms,
            }
            for observation in analysis.rate_limit_observations
        ],
    }


CSV_HEADER = [
    "record_type",
    "analysis_id",
    "target",
    "severity",
    "category",
    "check",
    "title",
    "description",
    "target_url",
    "evidence",
    "confidence",
    "vendor",
    "product",
    "detection_method",
    "blocked",
    "provider",
    "edge_nodes",
    "origin_hidden",
    "caching",
    "headers",
    "challenge_kind",
    "status_code",
    "bypass_indicators",
    "response_time_ms",
    "scope",
    "limit",
    "window_seconds",
    "threshold_estimate",
    "recommended_delay_ms",
]


def _export_csv(analysis: models.Analysis) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_HEADER, restval="")
    writer.writeheader()
    base = {"analysis_id": analysis.id, "target": analysis.target}

    for finding in analysis.findings:
        writer.writerow(
            {
                **base,
                "record_type": "finding",
                "severity": finding.severity or "",
                "category": finding.category or "",
                "check": finding.check or "",
                "title": finding.title or "",
                "description": finding.description or "",
                "target_url": finding.target_url or "",
                "evidence": finding.evidence or "",
                "confidence": finding.confidence or "",
            }
        )

    for detection in analysis.waf_detections:
        writer.writerow(
            {
                **base,
                "record_type": "waf_detection",
                "vendor": detection.vendor or "",
                "product": detection.product or "",
                "confidence": detection.confidence or "",
                "detection_method": detection.detection_method or "",
                "evidence": detection.evidence or "",
                "blocked": int(detection.blocked or 0),
            }
        )

    for observation in analysis.cdn_observations:
        writer.writerow(
            {
                **base,
                "record_type": "cdn_observation",
                "provider": observation.provider or "",
                "edge_nodes": observation.edge_nodes or "",
                "origin_hidden": int(observation.origin_hidden or 0),
                "caching": observation.caching or "",
                "evidence": observation.evidence or "",
            }
        )

    for challenge in analysis.challenges:
        writer.writerow(
            {
                **base,
                "record_type": "challenge",
                "challenge_kind": challenge.kind or "",
                "status_code": challenge.status_code if challenge.status_code is not None else "",
                "headers": challenge.headers or "",
                "bypass_indicators": challenge.bypass_indicators or "",
                "response_time_ms": challenge.response_time_ms
                if challenge.response_time_ms is not None
                else "",
                "severity": challenge.severity_hint or "",
            }
        )

    for observation in analysis.rate_limit_observations:
        writer.writerow(
            {
                **base,
                "record_type": "rate_limit",
                "scope": observation.scope or "",
                "limit": observation.limit if observation.limit is not None else "",
                "window_seconds": observation.window_seconds
                if observation.window_seconds is not None
                else "",
                "headers": observation.headers or "",
                "threshold_estimate": observation.threshold_estimate
                if observation.threshold_estimate is not None
                else "",
                "recommended_delay_ms": observation.recommended_delay_ms
                if observation.recommended_delay_ms is not None
                else "",
            }
        )

    return buffer.getvalue()


@app.get("/")
def read_root():
    return {"status": "ok", "service": TOOL, "version": SERVICE_VERSION}


@app.get("/api/health")
def health():
    db_status = "ok" if database.ping() else "error"
    return JSONResponse(
        status_code=200 if db_status == "ok" else 503,
        content={
            "status": db_status,
            "database": db_status,
            "version": SERVICE_VERSION,
            "tool": TOOL,
        },
    )


@app.post("/api/auth/token", response_model=TokenResponse)
def issue_token(request: TokenRequest):
    """Issue a signed token. Only available when KABUKI_JWT_SECRET is set."""
    if not security.AUTH_REQUIRED:
        raise HTTPException(status_code=403, detail="Auth is disabled (no KABUKI_JWT_SECRET).")
    if request.password != security.AUTH_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid password.")
    return TokenResponse(
        token=security.issue_token(),
        expires_in=security.TOKEN_TTL_HOURS * 3600,
    )


@app.post("/api/waf/analyze", response_model=schemas.AnalyzeResponse)
async def waf_analyze(
    request: schemas.AnalyzeRequest,
    db: Session = Depends(database.get_db),
):
    """Run a WAF/CDN profile. ``graduated`` mode requires ``confirm=true``."""
    analysis = models.Analysis(target=request.target, status="RUNNING", started_at=_dbnow())
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    try:
        result = await analyzer.analyze_target(
            request.target,
            probe_mode=request.probe_mode,
            confirm=request.confirm,
            max_requests=request.max_requests,
        )
        _persist_result(db, analysis, result)
        analysis.status = "COMPLETED"
        analysis.finished_at = _dbnow()
        db.commit()
    except (analyzer.InvalidTargetError, analyzer.ProbeRefusedError) as exc:
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except analyzer.TargetError as exc:
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    db.refresh(analysis)
    return schemas.AnalyzeResponse(
        analysis=analysis,
        **_counts(analysis),
        guardrail=schemas.GuardrailRead(**result["guardrail"]),
    )


@app.get("/api/analyses", response_model=list[schemas.AnalysisListItem])
def list_analyses(db: Session = Depends(database.get_db)):
    rows = (
        db.query(models.Analysis).order_by(models.Analysis.id.desc()).limit(50).all()
    )
    return [_summary(row) for row in rows]


@app.get("/api/analyses/{analysis_id}", response_model=schemas.AnalysisRead)
def get_analysis(analysis_id: int, db: Session = Depends(database.get_db)):
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


@app.get("/api/analyses/{analysis_id}/export")
def export_analysis(
    analysis_id: int,
    fmt: Literal["json", "csv"] = Query("json", alias="format"),
    db: Session = Depends(database.get_db),
):
    """Download an analysis as JSON (default) or CSV."""
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    if fmt == "csv":
        return Response(
            content=_export_csv(analysis),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="kabuki-analysis-{analysis.id}.csv"'
            },
        )

    return JSONResponse(
        content=_analysis_export(analysis),
        headers={
            "Content-Disposition": f'attachment; filename="kabuki-analysis-{analysis.id}.json"'
        },
    )


@app.delete("/api/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: int, db: Session = Depends(database.get_db)):
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    db.delete(analysis)
    db.commit()
    return Response(status_code=204)


@app.delete("/api/analyses", status_code=204)
def delete_all_analyses(db: Session = Depends(database.get_db)):
    db.query(models.Analysis).delete()
    db.commit()
    return Response(status_code=204)


@app.websocket("/api/waf/live")
async def websocket_live(
    websocket: WebSocket,
    target: str,
    probe_mode: str = "headers",
    confirm: bool = False,
    max_requests: int = analyzer.DEFAULT_MAX_REQUESTS,
    token: str | None = None,
):
    """Persist the analysis and stream the WAF/CDN pipeline as xwa-sdk Events."""
    if security.AUTH_REQUIRED and not security.validate_ws_token(token):
        await websocket.close(code=1008, reason="Unauthorized")
        return

    await websocket.accept()

    db = database.SessionLocal()
    analysis = models.Analysis(target=target, status="RUNNING", started_at=_dbnow())
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    emitter = EventEmitter(websocket, tool=TOOL, analysis_id=analysis.id)

    async def on_progress(phase: str, message: str, data: dict | None = None) -> None:
        await emitter.progress(phase, message, data)

    try:
        await emitter.started(target, probe_mode=probe_mode, max_requests=max_requests)
        result = await analyzer.analyze_target(
            target,
            probe_mode=probe_mode,
            confirm=confirm,
            max_requests=max_requests,
            on_progress=on_progress,
        )
        _persist_result(db, analysis, result)
        analysis.status = "COMPLETED"
        analysis.finished_at = _dbnow()
        db.commit()

        for detection in result["waf"]:
            await emitter.item_found(
                {
                    "kind": "waf",
                    "vendor": detection.vendor,
                    "product": detection.product,
                    "confidence": detection.confidence,
                    "blocked": detection.blocked,
                    "severity": detection.severity,
                }
            )
        cdn = result.get("cdn")
        if cdn is not None:
            await emitter.item_found(
                {
                    "kind": "cdn",
                    "provider": cdn.provider,
                    "edge_nodes": cdn.edge_nodes,
                    "origin_hidden": cdn.origin_hidden,
                    "caching": cdn.caching,
                }
            )
        for challenge in result["challenges"]:
            await emitter.item_found(
                {
                    "kind": "challenge",
                    "challenge_kind": challenge.kind,
                    "status_code": challenge.status_code,
                    "severity": challenge.severity_hint,
                    "bypass_indicators": challenge.bypass_indicators,
                }
            )
        await emitter.item_found(
            {
                "kind": "rate_limit",
                "scope": result["rate_limit"].scope,
                "limit": result["rate_limit"].limit,
                "recommended_delay_ms": result["rate_limit"].recommended_delay_ms,
            }
        )
        for finding in result["findings"]:
            await emitter.item_found(
                {
                    "kind": "finding",
                    "severity": finding.severity,
                    "category": finding.category,
                    "title": finding.title,
                }
            )

        await emitter.completed(
            _counts(analysis),
            guardrail=result["guardrail"],
            status_code=result["status_code"],
            blocked=result["blocked"],
        )
    except (analyzer.InvalidTargetError, analyzer.ProbeRefusedError) as exc:
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        try:
            await emitter.error("INVALID_REQUEST", str(exc), retryable=False)
        except WebSocketDisconnect:
            return
    except analyzer.TargetError as exc:
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        try:
            await emitter.error("TARGET_ERROR", str(exc), retryable=True)
        except WebSocketDisconnect:
            return
    except WebSocketDisconnect:
        analysis.status = "CANCELLED"
        analysis.finished_at = _dbnow()
        db.commit()
    finally:
        db.close()

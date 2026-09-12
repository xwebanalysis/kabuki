"""xwa-sdk ``Event`` envelope helpers for the streaming WebSocket protocol.

Every WebSocket endpoint emits one JSON object per frame::

    {
      "seq": 1,                  # monotonic, scoped to the analysis stream
      "type": "analysis_progress",
      "tool": "kabuki",
      "analysis_id": "42",       # persisted analysis id (string)
      "ts": "2026-09-12T10:00:00+00:00",
      "payload": {...}
    }

If the optional ``xwa-sdk`` Python binding is installed the envelope is built
through its dataclasses so the wire format stays in sync with the canonical
schemas. Without the SDK (e.g. a bare Docker image) a structurally identical
dict is produced, so clients never notice the difference.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Protocol

try:  # pragma: no cover - exercised implicitly by the installed binding
    from xwa_sdk import Event as _SdkEvent
    from xwa_sdk import to_dict as _sdk_to_dict

    XWA_SDK_AVAILABLE = True
except Exception:  # pragma: no cover - fallback path
    _SdkEvent = None
    _sdk_to_dict = None
    XWA_SDK_AVAILABLE = False

TOOL = "kabuki"

EVENT_TYPES = (
    "analysis_started",
    "analysis_progress",
    "item_found",
    "analysis_completed",
    "analysis_error",
    "log",
)

PHASES = ("fingerprint", "challenge", "rate_limit", "cdn")


def utc_now_iso() -> str:
    """UTC timestamp in the ``date-time`` format used by xwa-sdk samples."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_event(
    seq: int,
    event_type: str,
    analysis_id: Any,
    payload: Any = None,
    tool: str = TOOL,
    ts: str | None = None,
) -> dict:
    """Build the xwa-sdk ``Event`` dict for one WebSocket frame."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unsupported event type: {event_type}")

    timestamp = ts or utc_now_iso()
    analysis_id_str = str(analysis_id)

    if XWA_SDK_AVAILABLE and _SdkEvent is not None and _sdk_to_dict is not None:
        event = _SdkEvent(
            seq=seq,
            type=event_type,
            tool=tool,
            analysis_id=analysis_id_str,
            ts=timestamp,
            payload=payload,
        )
        data = _sdk_to_dict(event)
        # ``to_dict`` drops falsy optional values; the payload key must always
        # be present so clients can rely on its shape.
        data.setdefault("payload", payload)
        return data

    return {
        "seq": seq,
        "type": event_type,
        "tool": tool,
        "analysis_id": analysis_id_str,
        "ts": timestamp,
        "payload": payload,
    }


def error_payload(
    code: str, message: str, detail: dict | None = None, retryable: bool = False
) -> dict:
    """Unified xwa-sdk error object (``error.json``) used as the event payload."""
    return {
        "code": code,
        "message": message,
        "detail": detail or {},
        "retryable": retryable,
    }


class SupportsSendJson(Protocol):
    """Minimal WebSocket surface required by :class:`EventEmitter`."""

    async def send_json(self, data: Any) -> None: ...


class EventEmitter:
    """Per-connection, monotonic sequence event emitter.

    ``seq`` starts at 1 for every analysis and only ever increases. Events are
    rejected until :meth:`bind` is called with the persisted analysis id, which
    guarantees no frame is emitted with a target instead of an id.
    """

    def __init__(self, websocket: SupportsSendJson, tool: str = TOOL, analysis_id: Any = None):
        self._ws = websocket
        self.tool = tool
        self._analysis_id: str | None = None
        self._seq = 0
        if analysis_id is not None:
            self.bind(analysis_id)

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def analysis_id(self) -> str | None:
        return self._analysis_id

    @property
    def is_bound(self) -> bool:
        return self._analysis_id is not None

    def bind(self, analysis_id: Any) -> None:
        self._analysis_id = str(analysis_id)

    async def emit(self, event_type: str, payload: Any = None) -> dict:
        if self._analysis_id is None:
            raise RuntimeError("EventEmitter.bind() must be called before emitting events")
        self._seq += 1
        event = build_event(self._seq, event_type, self._analysis_id, payload, tool=self.tool)
        await self._ws.send_json(event)
        return event

    async def started(self, target: str, **extra: Any) -> dict:
        payload: dict[str, Any] = {"target": target}
        payload.update(extra)
        return await self.emit("analysis_started", payload)

    async def progress(self, phase: str, message: str, data: dict | None = None) -> dict:
        payload: dict[str, Any] = {"phase": phase, "message": message}
        if data:
            payload["data"] = data
        return await self.emit("analysis_progress", payload)

    async def item_found(self, item: dict) -> dict:
        return await self.emit("item_found", item)

    async def completed(self, summary: dict, **extra: Any) -> dict:
        payload: dict[str, Any] = {"summary": summary}
        payload.update(extra)
        return await self.emit("analysis_completed", payload)

    async def error(
        self, code: str, message: str, detail: dict | None = None, retryable: bool = False
    ) -> dict:
        return await self.emit("analysis_error", error_payload(code, message, detail, retryable))

    async def close(self) -> None:
        """Close the underlying WebSocket, ignoring already-closed sockets."""
        try:
            await self._ws.close()
        except Exception:
            pass


def serialize_event(event: dict) -> str:
    """JSON encoding used by tests and non-WebSocket adapters."""
    return json.dumps(event, ensure_ascii=False)

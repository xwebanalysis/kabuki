"""API integration tests: health, analyze, persistence, history, export, WS."""

from datetime import datetime, timedelta

import httpx


def clean_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"server": "nginx", "content-type": "text/html; charset=utf-8"},
        text="<html><head><title>Clean</title></head><body>hello</body></html>",
    )


def cloudflare_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        403,
        headers={
            "server": "cloudflare",
            "cf-ray": "8a1b2c3d4e5f-MAD",
            "cf-mitigated": "challenge",
            "set-cookie": "cf_clearance=abc; Path=/",
        },
        text=(
            "<html><title>Just a moment...</title>"
            "<body><script>window._cf_chl_opt={};var jschl_answer;</script>"
            '<div id="challenge-platform">Enable JavaScript and cookies to continue</div>'
            "</body></html>"
        ),
    )


def imperva_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers={
            "server": "nginx",
            "x-cdn": "Incapsula",
            "x-iinfo": "10-123-456",
            "set-cookie": "incap_ses_123=abc; Path=/",
        },
        text="ok",
    )


def rate_limit_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers={
            "server": "nginx",
            "ratelimit-limit": "100",
            "ratelimit-policy": "100;w=60",
            "ratelimit-remaining": "99",
        },
        text="ok",
    )


def test_health_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["tool"] == "kabuki"
    assert body["version"] == "0.1.0"


def test_health_reports_database_error(client, monkeypatch):
    from app import database

    monkeypatch.setattr(database, "ping", lambda: False)
    response = client.get("/api/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "error"
    assert body["database"] == "error"


def test_analyze_clean_target(client, mock_transport):
    mock_transport(clean_handler)
    response = client.post("/api/waf/analyze", json={"target": "https://example.com"})
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["analysis"]["status"] == "COMPLETED"
    assert body["analysis"]["analysis_type"] == "waf_profile"
    assert body["waf_count"] == 0
    assert body["cdn_count"] == 0
    assert body["challenge_count"] == 0
    assert body["rate_limit_count"] == 1
    assert body["guardrail"]["probe_mode"] == "headers"
    assert body["guardrail"]["requests_sent"] == 1
    assert body["guardrail"]["aborted"] is False

    categories = {finding["category"] for finding in body["analysis"]["findings"]}
    assert categories == {"waf", "cdn", "rate_limit"}

    listed = client.get("/api/analyses").json()
    assert len(listed) == 1
    assert listed[0]["id"] == body["analysis"]["id"]
    assert listed[0]["finding_count"] == body["finding_count"]


def test_analyze_cloudflare_waf_and_challenge(client, mock_transport):
    mock_transport(cloudflare_handler)
    response = client.post("/api/waf/analyze", json={"target": "example.com"})
    assert response.status_code == 200
    body = response.json()

    assert body["waf_count"] == 1
    assert body["challenge_count"] == 1

    detection = body["analysis"]["waf_detections"][0]
    assert detection["vendor"] == "Cloudflare"
    assert detection["detection_method"] == "header"
    assert detection["blocked"] is True

    challenge = body["analysis"]["challenges"][0]
    assert challenge["kind"] == "js_challenge"
    assert challenge["status_code"] == 403
    assert challenge["severity_hint"] == "medium"

    severities = {finding["severity"] for finding in body["analysis"]["findings"]}
    assert "medium" in severities  # the challenge finding


def test_analyze_imperva_cookie_signature(client, mock_transport):
    mock_transport(imperva_handler)
    response = client.post("/api/waf/analyze", json={"target": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    detection = body["analysis"]["waf_detections"][0]
    assert detection["vendor"] == "Imperva"
    assert detection["detection_method"] in ("header", "cookie")
    assert detection["blocked"] is False


def test_analyze_rate_limit_headers(client, mock_transport):
    mock_transport(rate_limit_handler)
    response = client.post("/api/waf/analyze", json={"target": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    observation = body["analysis"]["rate_limit_observations"][0]
    assert observation["scope"] == "ip"
    assert observation["limit"] == 100
    assert observation["window_seconds"] == 60
    assert observation["recommended_delay_ms"] == 1200


def test_graduated_mode_blocked_without_confirm(client):
    response = client.post(
        "/api/waf/analyze",
        json={"target": "https://example.com", "probe_mode": "graduated", "confirm": False},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "BAD_REQUEST"
    assert "confirm=true" in body["error"]["message"]
    # the refused analysis is persisted for history
    listed = client.get("/api/analyses").json()
    assert listed[0]["status"] == "ERROR"


def test_graduated_mode_with_confirm_aborts_on_429(client, mock_transport):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] >= 3:
            return httpx.Response(429, headers={"retry-after": "30"}, text="slow down")
        return httpx.Response(200, headers={"server": "nginx"}, text="ok")

    mock_transport(handler)
    response = client.post(
        "/api/waf/analyze",
        json={
            "target": "https://example.com",
            "probe_mode": "graduated",
            "confirm": True,
            "max_requests": 10,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["guardrail"]["aborted"] is True
    assert "429" in body["guardrail"]["abort_reason"]
    assert body["guardrail"]["requests_sent"] == 3
    assert body["analysis"]["rate_limit_observations"][0]["threshold_estimate"] == 2


def test_invalid_target_envelope(client):
    response = client.post("/api/waf/analyze", json={"target": "ftp://example.com"})
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "BAD_REQUEST"
    assert body["error"]["retryable"] is False


def test_upstream_error_envelope(client, mock_transport):
    def failing(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    mock_transport(failing)
    response = client.post("/api/waf/analyze", json={"target": "https://bad.example"})
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "UPSTREAM_ERROR"
    assert body["error"]["retryable"] is True
    assert "connection refused" in body["error"]["message"]

    listed = client.get("/api/analyses").json()
    assert listed[0]["status"] == "ERROR"
    detail = client.get(f"/api/analyses/{listed[0]['id']}").json()
    assert "connection refused" in (detail["error_message"] or "")


def test_validation_error_envelope(client):
    response = client.post("/api/waf/analyze", json={})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    too_many = client.post(
        "/api/waf/analyze", json={"target": "example.com", "max_requests": 21}
    )
    assert too_many.status_code == 422
    assert too_many.json()["error"]["code"] == "VALIDATION_ERROR"


def test_detail_export_and_delete(client, mock_transport):
    mock_transport(clean_handler)
    created = client.post("/api/waf/analyze", json={"target": "https://example.com"}).json()
    analysis_id = created["analysis"]["id"]

    detail = client.get(f"/api/analyses/{analysis_id}")
    assert detail.status_code == 200
    assert detail.json()["id"] == analysis_id
    assert detail.json()["findings"]

    export_json = client.get(f"/api/analyses/{analysis_id}/export?format=json")
    assert export_json.status_code == 200
    assert export_json.headers["content-disposition"] == (
        f'attachment; filename="kabuki-analysis-{analysis_id}.json"'
    )
    payload = export_json.json()
    assert payload["target"] == "https://example.com"
    assert isinstance(payload["findings"][0]["evidence"], dict)
    assert payload["rate_limit_observations"][0]["recommended_delay_ms"] == 2000

    export_csv = client.get(f"/api/analyses/{analysis_id}/export?format=csv")
    assert export_csv.status_code == 200
    assert export_csv.headers["content-type"].startswith("text/csv")
    assert "attachment" in export_csv.headers["content-disposition"]
    assert "record_type" in export_csv.text
    assert "rate_limit" in export_csv.text

    bad_format = client.get(f"/api/analyses/{analysis_id}/export?format=xml")
    assert bad_format.status_code == 422

    deleted = client.delete(f"/api/analyses/{analysis_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/analyses/{analysis_id}").status_code == 404
    assert client.get("/api/analyses").json() == []


def test_delete_all(client, mock_transport):
    mock_transport(clean_handler)
    client.post("/api/waf/analyze", json={"target": "https://one.example"})
    client.post("/api/waf/analyze", json={"target": "https://two.example"})
    assert len(client.get("/api/analyses").json()) == 2

    assert client.delete("/api/analyses").status_code == 204
    assert client.get("/api/analyses").json() == []


def test_websocket_event_shape_and_persisted_analysis_id(client, mock_transport):
    mock_transport(cloudflare_handler)

    events: list[dict] = []
    with client.websocket_connect("/api/waf/live?target=https://example.com") as ws:
        while True:
            event = ws.receive_json()
            events.append(event)
            if event["type"] in ("analysis_completed", "analysis_error"):
                break
            assert len(events) < 40, "unexpected event flood"

    assert events[0]["type"] == "analysis_started"
    assert events[-1]["type"] == "analysis_completed"
    assert [event["seq"] for event in events] == list(range(1, len(events) + 1))
    assert all(event["tool"] == "kabuki" for event in events)

    analysis_id = events[0]["analysis_id"]
    assert isinstance(analysis_id, str)
    assert analysis_id.isdigit()
    persisted = client.get("/api/analyses").json()
    assert persisted[0]["id"] == int(analysis_id)

    for event in events:
        assert event["analysis_id"] == analysis_id
        parsed = datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
        assert parsed.utcoffset() == timedelta(0)

    phases = [event["payload"].get("phase") for event in events if event["type"] == "analysis_progress"]
    assert list(dict.fromkeys(phases)) == ["fingerprint", "challenge", "rate_limit", "cdn"]

    kinds = [event["payload"]["kind"] for event in events if event["type"] == "item_found"]
    assert "waf" in kinds
    assert "challenge" in kinds
    assert "rate_limit" in kinds
    assert "finding" in kinds

    assert events[-1]["payload"]["summary"]["waf_count"] == 1


def test_websocket_error_event(client, mock_transport):
    def failing(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns failure", request=request)

    mock_transport(failing)
    events: list[dict] = []
    with client.websocket_connect("/api/waf/live?target=https://bad.example") as ws:
        while True:
            event = ws.receive_json()
            events.append(event)
            if event["type"] in ("analysis_completed", "analysis_error"):
                break
            assert len(events) < 20

    assert events[-1]["type"] == "analysis_error"
    assert events[-1]["payload"]["code"] == "TARGET_ERROR"
    assert events[-1]["payload"]["retryable"] is True
    assert client.get("/api/analyses").json()[0]["status"] == "ERROR"


def test_rate_limit_envelope(client, monkeypatch):
    from app import security

    monkeypatch.setattr(security, "RATE_LIMIT_MAX", 2)
    security.reset_rate_limiter()

    assert client.get("/api/analyses").status_code == 200
    assert client.get("/api/analyses").status_code == 200
    blocked = client.get("/api/analyses")
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMITED"

    assert client.get("/api/health").status_code == 200


def test_optional_jwt_auth(client, monkeypatch):
    from app import security

    monkeypatch.setattr(security, "JWT_SECRET", "test-secret-0123456789-0123456789-abcdef")
    monkeypatch.setattr(security, "AUTH_REQUIRED", True)
    monkeypatch.setattr(security, "AUTH_PASSWORD", "s3cret")

    assert client.get("/api/analyses").status_code == 401

    token_response = client.post("/api/auth/token", json={"password": "s3cret"})
    assert token_response.status_code == 200
    token = token_response.json()["token"]

    authorized = client.get("/api/analyses", headers={"Authorization": f"Bearer {token}"})
    assert authorized.status_code == 200

    wrong = client.post("/api/auth/token", json={"password": "nope"})
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "UNAUTHORIZED"

    assert security.validate_ws_token(None) is False
    assert security.validate_ws_token(token) is True

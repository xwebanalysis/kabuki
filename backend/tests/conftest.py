"""Shared pytest fixtures: isolated SQLite database + TestClient.

The environment is configured before any ``app.*`` import so the engine binds to
a temporary SQLite file instead of the development database.
"""

import os
import tempfile
from pathlib import Path

_TMP_DIR = tempfile.mkdtemp(prefix="kabuki-tests-")
os.environ["DB_DRIVER"] = "sqlite"
os.environ["DB_PATH"] = str(Path(_TMP_DIR) / "test.db")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    """Recreate the schema and clear middleware state before every test."""
    from app import database, models, security

    models.Base.metadata.drop_all(bind=database.engine)
    models.Base.metadata.create_all(bind=database.engine)
    security.reset_rate_limiter()
    yield


@pytest.fixture()
def client():
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def mock_transport(monkeypatch):
    """Install an ``httpx.MockTransport`` into ``analyzer.analyze_target``.

    DNS and TLS inspection are disabled and the graduated delay is zeroed so
    tests are hermetic and fast.
    """
    from app import analyzer

    real = analyzer.analyze_target

    def _install(handler) -> httpx.MockTransport:
        transport = httpx.MockTransport(handler)

        async def patched(target, **kwargs):
            kwargs.setdefault("transport", transport)
            kwargs.setdefault("resolve_dns", False)
            kwargs.setdefault("inspect_tls", False)
            kwargs.setdefault("delay_ms", (0, 0))
            return await real(target, **kwargs)

        monkeypatch.setattr(analyzer, "analyze_target", patched)
        return transport

    return _install

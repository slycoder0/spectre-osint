from __future__ import annotations

from fastapi.testclient import TestClient

from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.web.app import app


def test_health_and_dashboard_render(settings) -> None:
    init_db(settings)
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        home = client.get("/")
        assert home.status_code == 200
        assert "SPECTRE" in home.text
        assert "Dashboard" in home.text
        inv = client.get("/investigations")
        assert inv.status_code == 200
        ent = client.get("/entities")
        assert ent.status_code == 200
        sessions = client.get("/sessions")
        assert sessions.status_code == 200
        assert "Authenticated public" in sessions.text or "Sessions" in sessions.text
        assert "spectre auth login instagram" in sessions.text
        assert "Use official API integration for this platform when available." in sessions.text
        assert "AUTHENTICATED_PUBLIC" in sessions.text
        assert "sessionid" not in sessions.text.lower()
        assert "TESTCOOKIE" not in sessions.text
        home = client.get("/")
        assert "Authenticated public sources" in home.text or "AUTHENTICATED" in home.text
    reset_engine()


def test_investigate_rejects_loopback(settings) -> None:
    init_db(settings)
    with TestClient(app) as client:
        response = client.post("/investigate", data={"target": "http://127.0.0.1/"})
        assert response.status_code == 400
    reset_engine()

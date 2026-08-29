"""Tests for safe alias input and explicit alias removal (B2-01B)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from spectre_osint.core.database import init_db, reset_engine
from spectre_osint.web.app import app
from spectre_osint.web.jobs import reset_jobs


def test_app_js_explicit_alias_removal_contract() -> None:
    """Verify that app.js does NOT contain implicit chip removal on Backspace/Delete."""
    js_path = Path("spectre_osint/web/static/app.js")
    assert js_path.exists()
    src = js_path.read_text(encoding="utf-8")

    # Extract initAliasFields function body
    start = src.find("function initAliasFields()")
    end = src.find("function initCopy()")
    assert start != -1 and end != -1
    alias_js = src[start:end]

    # Invariants: No implicit removal on Backspace or Delete
    assert "Backspace" not in alias_js
    assert "Delete" not in alias_js

    # Required triggers: Enter and comma commit new alias
    assert 'evt.key === "Enter" || evt.key === ","' in alias_js

    # Required triggers: Explicit remove button on click
    assert 'data-remove-alias' in alias_js
    assert 'chip.remove()' in alias_js


def test_alias_chip_state_machine_simulation() -> None:
    """Simulate the client-side alias chip state machine according to app.js semantics."""
    chips: list[str] = []

    def add_alias_chip(value: str) -> None:
        text = str(value or "").lstrip("@").strip()
        if not text:
            return
        if text in chips:
            return
        chips.append(text)

    def remove_alias_chip(index: int) -> None:
        if 0 <= index < len(chips):
            chips.pop(index)

    # 1. Add alice_shop via Enter / comma
    add_alias_chip("alice_shop")
    assert chips == ["alice_shop"]

    # 2. Add alice_dev with @ prefix
    add_alias_chip("@alice_dev")
    assert chips == ["alice_shop", "alice_dev"]

    # 3. Duplicate alias is ignored
    add_alias_chip("alice_shop")
    add_alias_chip("@alice_shop")
    assert chips == ["alice_shop", "alice_dev"]

    # 4. Empty input is ignored
    add_alias_chip("")
    add_alias_chip("   ")
    add_alias_chip("@")
    assert chips == ["alice_shop", "alice_dev"]

    # 5. Backspace / Delete with empty input DOES NOT remove chip
    # Under new contract, Backspace/Delete keydown on empty input does nothing to chips
    assert chips == ["alice_shop", "alice_dev"]

    # 6. Add third alias
    add_alias_chip("alice_store")
    assert chips == ["alice_shop", "alice_dev", "alice_store"]

    # 7. Explicit removal of second chip (alice_dev)
    remove_alias_chip(1)
    assert chips == ["alice_shop", "alice_store"]

    # 8. Remaining hidden inputs to submit
    hidden_inputs = [{"name": "alias", "value": val} for val in chips]
    assert len(hidden_inputs) == 2
    assert [item["value"] for item in hidden_inputs] == ["alice_shop", "alice_store"]


def test_web_investigate_form_receives_multiple_aliases(settings, monkeypatch) -> None:
    """Verify backend accepts and processes multiple aliases submitted from form."""
    init_db(settings)
    captured: dict[str, object] = {}

    def fake_start_collection_job(*args, **kwargs):
        captured["target"] = kwargs.get("target")
        captured["extra"] = kwargs.get("extra")
        return "job-123"

    monkeypatch.setattr("spectre_osint.web.app._start_collection_job", fake_start_collection_job)

    with TestClient(app) as client:
        # Submit form with primary target and 2 alias fields
        form_data = {
            "target": "alice_main",
            "mode": "new",
            "alias": ["alice_shop", "alice_store"],
        }
        response = client.post("/investigate", data=form_data, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/collecting/job-123"
        assert captured["target"] == "alice_main"
        extra = captured.get("extra") or {}
        inputs = extra.get("inputs") or {}
        assert inputs.get("aliases") == ["alice_shop", "alice_store"]
    reset_jobs()
    reset_engine()


def test_web_dashboard_html_contains_alias_controls(settings) -> None:
    """Verify dashboard HTML renders alias chip container, input and explicit button."""
    init_db(settings)
    with TestClient(app) as client:
        body = client.get("/").text
        assert 'data-alias-chips' in body
        assert 'data-chip-list' in body
        assert 'data-chip-input' in body
        assert 'data-add-alias' in body
        assert 'type="button"' in body
    reset_engine()

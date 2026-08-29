from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from spectre_osint.browser.auth import AuthService
from spectre_osint.browser.fake import FakeBrowserBackend
from spectre_osint.browser.manager import classify_browser_state, get_backend
from spectre_osint.browser.models import AUTH_PLATFORMS
from spectre_osint.browser.sessions import SessionStore
from spectre_osint.cli.commands import app
from spectre_osint.core.config import Settings, default_auth_dir
from spectre_osint.core.redaction import redact_mapping, redact_text, strip_auth_material
from spectre_osint.core.types import SessionStatus, UsernameCheckStatus
from spectre_osint.reporting.html import write_html_report
from spectre_osint.reporting.json import write_json_report

runner = CliRunner()
COOKIE = "TESTCOOKIE_NOT_A_REAL_SESSION"


def _settings(tmp_path: Path) -> Settings:
    s = Settings(
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        logs_dir=tmp_path / "logs",
        database_url=f"sqlite:///{tmp_path / 't.db'}",
        auth_dir=tmp_path / "auth",
        browser_profiles_dir=tmp_path / "browser-profiles",
        browser_backend="fake",
        keyring_enabled=False,
    )
    s.ensure_dirs()
    return s


@pytest.mark.asyncio
async def test_login_logout_and_permissions(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    profile = await service.login("instagram")
    assert profile.status == SessionStatus.ACTIVE
    stored = service.store.load_state("instagram")
    assert stored is not None
    path = service.store.storage_path("instagram")
    assert path.exists()
    if sys.platform != "win32":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600
        dir_mode = stat.S_IMODE(path.parent.stat().st_mode)
        assert dir_mode == 0o700
    service.logout("instagram")
    assert service.store.load_state("instagram") is None
    assert not path.exists()


@pytest.mark.asyncio
async def test_expired_captcha_challenge(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("x")
    FakeBrowserBackend.verify_status["x"] = SessionStatus.EXPIRED
    profile = await service.verify("x")
    assert profile.status == SessionStatus.EXPIRED
    FakeBrowserBackend.reset()
    FakeBrowserBackend.login_status["tiktok"] = SessionStatus.CAPTCHA_REQUIRED
    captcha = await service.login("tiktok")
    assert captcha.status == SessionStatus.CAPTCHA_REQUIRED
    FakeBrowserBackend.login_status["facebook"] = SessionStatus.CHALLENGE_REQUIRED
    challenge = await service.login("facebook")
    assert challenge.status == SessionStatus.CHALLENGE_REQUIRED
    FakeBrowserBackend.login_status["x"] = SessionStatus.TEMPORARILY_LIMITED
    limited = await service.login("x")
    assert limited.status == SessionStatus.TEMPORARILY_LIMITED


@pytest.mark.asyncio
async def test_session_expired_fetch(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = AuthService(settings)
    await service.login("instagram")
    FakeBrowserBackend.verify_status["instagram"] = SessionStatus.EXPIRED
    outcome = await service.fetch_public_profile(
        "Instagram", "alice_osint", "https://www.instagram.com/alice_osint/"
    )
    assert outcome is not None
    assert outcome.status == UsernameCheckStatus.SESSION_EXPIRED.value
    assert outcome.redirected_to_login


def test_cookies_never_rendered(tmp_path: Path, capsys) -> None:
    from spectre_osint.cli.display import print_result
    from spectre_osint.core.entities import Entity, Finding, InvestigationResult, utcnow
    from spectre_osint.core.types import Confidence, EntityType, FindingStatus

    settings = _settings(tmp_path)
    store = SessionStore(settings)
    store.save("instagram", {"cookies": [{"name": "sessionid", "value": COOKIE}]})
    blob = (settings.auth_dir / "instagram" / "storage_state.json").read_text(encoding="utf-8")
    assert COOKIE in blob
    redacted = redact_text(f"Cookie: sessionid={COOKIE}")
    assert COOKIE not in redacted
    stripped = strip_auth_material({"cookie": COOKIE, "sessionid": COOKIE, "platform": "Instagram"})
    assert "sessionid" not in stripped
    assert COOKIE not in str(stripped)
    mapping = redact_mapping({"Authorization": f"Bearer {COOKIE}", "ok": 1})
    assert COOKIE not in str(mapping)
    user = Entity.create(EntityType.USERNAME, "alice_osint", "user", Confidence.CONFIRMED)
    result = InvestigationResult(
        case_id="c",
        case_name="n",
        target="alice_osint",
        target_type=EntityType.USERNAME,
        mode="PASSIVE_OSINT",
        started_at=utcnow(),
        entities=[user],
        findings=[
            Finding(
                module="username",
                title="Instagram",
                status=FindingStatus.LOGIN_REQUIRED,
                summary="Instagram: LOGIN_REQUIRED",
                data={
                    "platform": "Instagram",
                    "check_status": "LOGIN_REQUIRED",
                    "cookie": COOKIE,
                    "sessionid": COOKIE,
                },
            )
        ],
    )
    print_result(result)
    cli = capsys.readouterr().out
    html = write_html_report(result, tmp_path).read_text(encoding="utf-8")
    json_text = write_json_report(result, tmp_path).read_text(encoding="utf-8")
    for body in (cli, html, json_text):
        assert COOKIE not in body
        assert "TESTCOOKIE" not in body


def test_session_not_in_sqlite_or_git(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    SessionStore(settings).save("twitch", {"cookies": [{"name": "auth-token", "value": COOKIE}]})
    db = tmp_path / "t.db"
    if db.exists():
        assert COOKIE.encode() not in db.read_bytes()
    gitignore = Path(__file__).resolve().parents[1] / ".gitignore"
    text = gitignore.read_text(encoding="utf-8")
    assert "storage_state.json" in text
    assert "data/auth/" in text
    assert "browser-profiles/" in text
    auth_default = default_auth_dir()
    repo = Path(__file__).resolve().parents[1]
    assert repo not in auth_default.parents and auth_default != repo


def test_auth_cli_status_and_login(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTRE_AUTH_DIR", str(tmp_path / "auth"))
    monkeypatch.setenv("SPECTRE_BROWSER_BACKEND", "fake")
    from spectre_osint.core.config import reload_settings

    reload_settings()
    status = runner.invoke(app, ["auth", "status"])
    assert status.exit_code == 0
    assert "Instagram" in status.stdout
    assert "NOT_CONFIGURED" in status.stdout
    assert COOKIE not in status.stdout
    login = runner.invoke(app, ["auth", "login", "instagram"])
    assert login.exit_code == 0
    assert "Authentication detected" in login.stdout
    assert COOKIE not in login.stdout
    assert "sessionid" not in login.stdout.lower() or "sessionid=" not in login.stdout.lower()
    listed = runner.invoke(app, ["auth", "list"])
    assert "ACTIVE" in listed.stdout
    logout = runner.invoke(app, ["auth", "logout", "instagram"])
    assert logout.exit_code == 0
    again = runner.invoke(app, ["auth", "status"])
    assert "NOT_CONFIGURED" in again.stdout


def test_classify_browser_states() -> None:
    spec = AUTH_PLATFORMS["instagram"]
    assert classify_browser_state(spec, "https://www.instagram.com/accounts/login/", "") is SessionStatus.EXPIRED
    assert classify_browser_state(spec, "https://www.instagram.com/", "captcha recaptcha") is SessionStatus.CAPTCHA_REQUIRED
    assert classify_browser_state(spec, "https://www.instagram.com/", "checkpoint challenge") is SessionStatus.CHALLENGE_REQUIRED
    x_spec = AUTH_PLATFORMS["x"]
    assert (
        classify_browser_state(
            x_spec,
            "https://x.com/i/flow/login",
            "We've temporarily limited your login. Please try again later.",
        )
        is SessionStatus.TEMPORARILY_LIMITED
    )
    assert (
        classify_browser_state(
            x_spec,
            "https://accounts.google.com/signin/oauth",
            "This browser or app may not be secure",
        )
        is SessionStatus.OAUTH_BROWSER_REJECTED
    )
    assert isinstance(get_backend("fake"), type(get_backend("fake")))


def test_unsupported_platform(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        AuthService(_settings(tmp_path)).spec("myspace")

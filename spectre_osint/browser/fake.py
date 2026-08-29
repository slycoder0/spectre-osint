"""In-process browser backend. Tests never open Chromium or perform real login."""

from __future__ import annotations

from pathlib import Path

from spectre_osint.browser.models import (
    FetchOutcome,
    LoginOutcome,
    PlatformSpec,
    cookie_names_present,
)
from spectre_osint.browser.storage import ensure_secret_dir
from spectre_osint.core.types import SessionStatus, UsernameCheckStatus

_ACTIVE_COOKIE = "TESTCOOKIE_NOT_A_REAL_SESSION"


class FakeBrowserBackend:
    """Deterministic stand-in for Playwright. Scenarios are class-level for tests."""

    login_status: dict[str, SessionStatus] = {}
    verify_status: dict[str, SessionStatus] = {}
    fetch_status: dict[str, str] = {}
    fetch_body: dict[str, str] = {}
    last_user_data_dir: Path | None = None
    login_gotos: list[str] = []
    login_calls: int = 0

    @classmethod
    def reset(cls) -> None:
        cls.login_status = {}
        cls.verify_status = {}
        cls.fetch_status = {}
        cls.fetch_body = {}
        cls.last_user_data_dir = None
        cls.login_gotos = []
        cls.login_calls = 0

    def _dummy_state(self, spec: PlatformSpec) -> dict:
        cookies = [{"name": name, "value": _ACTIVE_COOKIE, "domain": spec.slug} for name in spec.cookie_names]
        return {"cookies": cookies, "origins": []}

    async def interactive_login(
        self,
        spec: PlatformSpec,
        *,
        timeout_s: float = 300,
        keep_open: bool = False,
        user_data_dir: Path | None = None,
        attach: bool = False,
    ) -> LoginOutcome:
        FakeBrowserBackend.login_calls += 1
        if user_data_dir is not None:
            path = ensure_secret_dir(Path(user_data_dir))
            FakeBrowserBackend.last_user_data_dir = path
            marker = path / ".spectre-owned"
            if not marker.exists():
                marker.write_text("SPECTRE OSINT persistent Chromium profile. Not a personal browser.\n")
        status = self.login_status.get(spec.slug, SessionStatus.ACTIVE)
        if status in {
            SessionStatus.CAPTCHA_REQUIRED,
            SessionStatus.CHALLENGE_REQUIRED,
            SessionStatus.BLOCKED,
            SessionStatus.UNAVAILABLE,
            SessionStatus.TEMPORARILY_LIMITED,
            SessionStatus.OAUTH_BROWSER_REJECTED,
            SessionStatus.EXPIRED,
            SessionStatus.CHROME_NOT_FOUND,
            SessionStatus.CDP_UNAVAILABLE,
            SessionStatus.CHROME_PROFILE_LOCKED,
        }:
            return LoginOutcome(status=status, detail=f"fake:{status.value}", display_name=spec.display_name)
        return LoginOutcome(
            status=SessionStatus.ACTIVE,
            storage_state=self._dummy_state(spec),
            detail="fake backend: operator login simulated",
            display_name=spec.display_name,
        )

    async def verify_session(self, spec: PlatformSpec, storage_state: dict) -> SessionStatus:
        forced = self.verify_status.get(spec.slug)
        if forced is not None:
            return forced
        if not cookie_names_present(storage_state, spec.cookie_names):
            return SessionStatus.EXPIRED
        return SessionStatus.ACTIVE

    async def fetch_public(
        self,
        spec: PlatformSpec,
        url: str,
        storage_state: dict,
    ) -> FetchOutcome:
        verify = await self.verify_session(spec, storage_state)
        if verify == SessionStatus.EXPIRED:
            return FetchOutcome(
                status=UsernameCheckStatus.SESSION_EXPIRED.value,
                url=spec.login_url,
                status_code=302,
                detail="redirect to login",
                redirected_to_login=True,
            )
        if verify == SessionStatus.CAPTCHA_REQUIRED:
            return FetchOutcome(
                status=UsernameCheckStatus.CAPTCHA_REQUIRED.value,
                url=url,
                status_code=200,
                detail="captcha presented",
            )
        if verify == SessionStatus.CHALLENGE_REQUIRED:
            return FetchOutcome(
                status=UsernameCheckStatus.CHALLENGE_REQUIRED.value,
                url=url,
                status_code=200,
                detail="challenge presented",
            )
        if verify == SessionStatus.TEMPORARILY_LIMITED:
            return FetchOutcome(
                status=UsernameCheckStatus.TEMPORARILY_LIMITED.value,
                url=url,
                status_code=200,
                detail="temporarily limited",
            )
        if verify == SessionStatus.OAUTH_BROWSER_REJECTED:
            return FetchOutcome(
                status=UsernameCheckStatus.OAUTH_BROWSER_REJECTED.value,
                url=url,
                status_code=200,
                detail="oauth browser rejected",
            )
        if verify in {SessionStatus.BLOCKED, SessionStatus.UNAVAILABLE}:
            return FetchOutcome(status=verify.value, url=url, status_code=403, detail=verify.value)
        status = self.fetch_status.get(spec.slug, UsernameCheckStatus.LIKELY.value)
        username = url.rstrip("/").rsplit("/", 1)[-1].lstrip("@")
        body = self.fetch_body.get(
            spec.slug,
            f"<html><title>{username} | {spec.display_name}</title>"
            f"<meta property='og:title' content='{username}'/>public profile</html>",
        )
        return FetchOutcome(
            status=status,
            url=url,
            status_code=200,
            title=f"{username} | {spec.display_name}",
            body=body,
            detail="public profile rendered while authenticated",
            og_title=username,
            content_length=len(body),
            metadata_ready=True,
        )


class FakeChromeLauncher:
    """Tests never spawn Google Chrome or open a real CDP port."""

    executable: Path | None = Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe")
    spawned: list[list[str]] = []
    helper_spawned: int = 0
    wait_ok: bool = True
    last_endpoint: str | None = None
    write_devtools_on_spawn: bool = True
    write_devtools_on_helper: bool = False
    devtools_target: Path | None = None
    devtools_port: int = 9333
    live_ports: set[int] | None = None

    @classmethod
    def reset(cls) -> None:
        cls.executable = Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe")
        cls.spawned = []
        cls.helper_spawned = 0
        cls.wait_ok = True
        cls.last_endpoint = None
        cls.write_devtools_on_spawn = True
        cls.write_devtools_on_helper = False
        cls.devtools_target = None
        cls.devtools_port = 9333
        cls.live_ports = None

    def resolve_chrome(self) -> Path | None:
        return self.executable

    def cdp_http_ok(self, endpoint: str, timeout_s: float = 2.0) -> bool:
        del timeout_s
        FakeChromeLauncher.last_endpoint = endpoint
        if FakeChromeLauncher.live_ports is not None:
            try:
                port = int(str(endpoint).rstrip("/").rsplit(":", 1)[-1])
            except ValueError:
                return False
            return port in FakeChromeLauncher.live_ports
        return bool(FakeChromeLauncher.wait_ok)

    def _write_devtools(self) -> None:
        from spectre_osint.browser.chrome import MARKER_NAME, write_devtools_active_port

        target = self.devtools_target
        if target is None:
            return
        target.mkdir(parents=True, exist_ok=True)
        if not (target / MARKER_NAME).exists():
            (target / MARKER_NAME).write_text("SPECTRE OSINT dedicated Google Chrome profile.\n")
        write_devtools_active_port(target, FakeChromeLauncher.devtools_port, "/devtools/browser/fake")

    def spawn(self, args: list[str]) -> object:
        FakeChromeLauncher.spawned.append(list(args))
        if FakeChromeLauncher.write_devtools_on_spawn:
            self._write_devtools()
        return object()

    def spawn_windows_helper(self, args: list[str]) -> object:
        FakeChromeLauncher.helper_spawned += 1
        FakeChromeLauncher.spawned.append(["helper", *args])
        if FakeChromeLauncher.write_devtools_on_helper:
            self._write_devtools()
        return object()

    async def wait_cdp(self, endpoint: str, timeout_s: float = 30.0) -> bool:
        FakeChromeLauncher.last_endpoint = endpoint
        return self.wait_ok


class FakeCdpResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class FakeCdpSession:
    sent: list[tuple[str, dict]] = []

    def __init__(self) -> None:
        return

    async def send(self, method: str, params: dict | None = None) -> dict:
        FakeCdpSession.sent.append((method, dict(params or {})))
        if method == "Browser.getWindowForTarget":
            return {"windowId": 1}
        return {}


class FakeCdpPage:
    closed_count: int = 0
    _next_id: int = 1

    def __init__(
        self,
        spec: PlatformSpec,
        status: SessionStatus,
        *,
        created_by_spectre: bool = False,
        url: str | None = None,
    ) -> None:
        self._spec = spec
        self._status = status
        self.created_by_spectre = created_by_spectre
        self.closed = False
        self.context: FakeCdpContext | None = None
        self.page_id = f"p{FakeCdpPage._next_id}"
        FakeCdpPage._next_id += 1
        self.url = url if url is not None else (spec.home_url if status == SessionStatus.ACTIVE else spec.login_url)

    async def goto(self, url: str, wait_until: str = "domcontentloaded") -> FakeCdpResponse:
        del wait_until
        if self._status == SessionStatus.EXPIRED:
            self.url = self._spec.login_url
            return FakeCdpResponse(302)
        self.url = url
        return FakeCdpResponse(200)

    async def title(self) -> str:
        if self._status == SessionStatus.ACTIVE:
            handle = self.url.rstrip("/").rsplit("/", 1)[-1].lstrip("@")
            return f"{handle} | {self._spec.display_name}"
        return "Log in"

    async def evaluate(self, _script: str) -> str:
        if self._status == SessionStatus.TEMPORARILY_LIMITED:
            return "We've temporarily limited your login. Please try again later."
        if self._status == SessionStatus.OAUTH_BROWSER_REJECTED:
            return "This browser or app may not be secure. Try using a different browser."
        if self._status == SessionStatus.CAPTCHA_REQUIRED:
            return "please complete the captcha recaptcha"
        if self._status == SessionStatus.CHALLENGE_REQUIRED:
            return "checkpoint challenge required"
        if self._status == SessionStatus.ACTIVE:
            handle = self.url.rstrip("/").rsplit("/", 1)[-1].lstrip("@")
            return f"{handle} public profile"
        return "Sign in"

    async def close(self) -> None:
        self.closed = True
        FakeCdpPage.closed_count += 1
        if self.context is not None and self in self.context.pages:
            self.context.pages = [item for item in self.context.pages if item is not self]


class FakeCdpContext:
    bootstrap_url: str | None = None
    start_urls: list[str] | None = None

    def __init__(self, spec: PlatformSpec, status: SessionStatus, *, bootstrap: str | None = None) -> None:
        self._spec = spec
        self._status = status
        self.spectre_pages: list[FakeCdpPage] = []
        if FakeCdpContext.start_urls is not None:
            urls = list(FakeCdpContext.start_urls)
        elif bootstrap is not None or FakeCdpContext.bootstrap_url is not None:
            start = bootstrap if bootstrap is not None else FakeCdpContext.bootstrap_url
            urls = [start] if start is not None else []
        else:
            urls = None
        if urls is None:
            initial = FakeCdpPage(spec, status)
            initial.context = self
            self.pages = [initial]
        else:
            self.pages = []
            for start in urls:
                page = FakeCdpPage(spec, status, url=start)
                page.context = self
                self.pages.append(page)
        if status == SessionStatus.ACTIVE:
            self._cookies = [
                {"name": name, "value": _ACTIVE_COOKIE, "domain": spec.slug} for name in spec.cookie_names
            ]
        else:
            self._cookies = []

    async def cookies(self) -> list[dict]:
        return list(self._cookies)

    async def storage_state(self) -> dict:
        return {"cookies": list(self._cookies), "origins": []}

    async def new_page(self) -> FakeCdpPage:
        page = FakeCdpPage(self._spec, self._status, created_by_spectre=True, url="about:blank")
        page.context = self
        self.pages.append(page)
        self.spectre_pages.append(page)
        return page

    async def new_cdp_session(self, _page: FakeCdpPage) -> FakeCdpSession:
        return FakeCdpSession()


class FakeCdpBrowser:
    new_context_calls: list[dict] = []
    close_calls: int = 0

    def __init__(self, spec: PlatformSpec, status: SessionStatus) -> None:
        self.contexts = [FakeCdpContext(spec, status)]
        self.closed = False

    async def new_context(self, **kwargs: object) -> None:
        FakeCdpBrowser.new_context_calls.append(dict(kwargs))
        raise RuntimeError("Protocol error (Storage.setCookies): Invalid cookie fields")

    async def close(self) -> None:
        self.closed = True
        FakeCdpBrowser.close_calls += 1


class FakeCdpConnector:
    last_endpoint: str | None = None
    last_spec: str | None = None
    last_browser: FakeCdpBrowser | None = None
    fail_connect: bool = False
    disconnected: bool = False
    connect_calls: int = 0
    persist_browser: bool = False

    @classmethod
    def reset(cls) -> None:
        cls.last_endpoint = None
        cls.last_spec = None
        cls.last_browser = None
        cls.fail_connect = False
        cls.disconnected = False
        cls.connect_calls = 0
        cls.persist_browser = False
        FakeCdpBrowser.new_context_calls = []
        FakeCdpBrowser.close_calls = 0
        FakeCdpPage.closed_count = 0
        FakeCdpPage._next_id = 1
        FakeCdpSession.sent = []
        FakeCdpContext.bootstrap_url = None
        FakeCdpContext.start_urls = None

    async def connect(self, endpoint: str, spec: PlatformSpec | None = None) -> FakeCdpBrowser:
        if FakeCdpConnector.fail_connect:
            raise ConnectionError("CDP connect failed")
        if not str(endpoint).startswith("http://127.0.0.1:"):
            raise ValueError("CDP endpoint must be loopback")
        FakeCdpConnector.last_endpoint = endpoint
        FakeCdpConnector.connect_calls += 1
        if spec is None:
            raise ValueError("spec required")
        FakeCdpConnector.last_spec = spec.slug
        if FakeCdpConnector.persist_browser and FakeCdpConnector.last_browser is not None:
            return FakeCdpConnector.last_browser
        status = FakeBrowserBackend.login_status.get(spec.slug, SessionStatus.ACTIVE)
        browser = FakeCdpBrowser(spec, status)
        FakeCdpConnector.last_browser = browser
        return browser

    async def aclose(self) -> None:
        FakeCdpConnector.disconnected = True

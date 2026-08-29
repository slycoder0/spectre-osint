"""Browser backends. Playwright is isolated here — never imported from modules.

Interactive login uses a SPECTRE-owned persistent Chromium profile
(launch_persistent_context). It never launches a disposable context, never
touches the operator's real Chrome/Edge, and never reloads the login form
while waiting for the operator.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from spectre_osint.browser.chrome import (
    build_chrome_command,
    chrome_profile_locked,
    command_is_safe,
    discard_stale_devtools_active_port,
    ensure_chrome_profile,
    fetch_cdp_version,
    is_loopback_cdp_endpoint,
    probe_spectre_cdp,
    snapshot_spectre_devtools_active_port,
    stop_spectre_launched_chrome,
    wait_for_spectre_cdp_ready,
    websocket_matches_devtools_endpoint,
    write_windows_chrome_launcher,
)
from spectre_osint.browser.fake import FakeBrowserBackend, FakeCdpConnector, FakeChromeLauncher
from spectre_osint.browser.login_flow import (
    GOTO_HOME,
    GOTO_LOGIN,
    POLL_INTERVAL_S,
    STOP,
    SUCCESS,
    classify_browser_state,
    cookies_as_storage,
    is_login_url,
    next_login_action,
)
from spectre_osint.browser.models import (
    FetchOutcome,
    LoginOutcome,
    PlatformSpec,
    cdp_session_sentinel,
    cookie_names_present,
)
from spectre_osint.browser.userdata import ensure_platform_profile
from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.exceptions import BrowserUnavailable, PathSafetyError
from spectre_osint.core.logger import get_logger
from spectre_osint.core.types import SessionStatus, UsernameCheckStatus

logger = get_logger("spectre.browser")

# SPECTRE never enables stealth, anti-detect, or CAPTCHA solvers.
# navigator.webdriver is left at the Playwright Chromium default.


class BrowserBackend(Protocol):
    async def interactive_login(
        self,
        spec: PlatformSpec,
        *,
        timeout_s: float = 300,
        keep_open: bool = False,
        user_data_dir: Path | None = None,
        attach: bool = False,
    ) -> LoginOutcome: ...

    async def verify_session(self, spec: PlatformSpec, storage_state: dict) -> SessionStatus: ...

    async def fetch_public(
        self,
        spec: PlatformSpec,
        url: str,
        storage_state: dict,
    ) -> FetchOutcome: ...


def map_expected_session_failure(exc: BaseException) -> SessionStatus | None:
    """Map Playwright/CDP/OS failures to an explicit SessionStatus. None = unexpected."""
    if isinstance(exc, PathSafetyError):
        return SessionStatus.UNAVAILABLE
    if isinstance(exc, BrowserUnavailable):
        return SessionStatus.UNAVAILABLE
    if isinstance(exc, (OSError, TimeoutError, ConnectionError)):
        return SessionStatus.CDP_UNAVAILABLE
    name = type(exc).__name__.lower()
    module = type(exc).__module__.lower()
    msg = str(exc).lower()
    if "invalid cookie" in msg or "storage.setcookies" in msg:
        return SessionStatus.CDP_UNAVAILABLE
    if "playwright" in module or "protocol error" in msg or "targetclosed" in name:
        return SessionStatus.CDP_UNAVAILABLE
    if "websocket" in name or "cdp" in msg:
        return SessionStatus.CDP_UNAVAILABLE
    return None


_FETCH_SESSION_OK = frozenset(
    {
        UsernameCheckStatus.LIKELY.value,
        UsernameCheckStatus.CONFIRMED.value,
        UsernameCheckStatus.NOT_FOUND.value,
        UsernameCheckStatus.INCONCLUSIVE.value,
    }
)


def _session_status_from_fetch(outcome: FetchOutcome) -> SessionStatus:
    if outcome.redirected_to_login:
        return SessionStatus.EXPIRED
    if outcome.status in _FETCH_SESSION_OK:
        return SessionStatus.ACTIVE
    try:
        return SessionStatus(outcome.status)
    except ValueError:
        pass
    mapping = {
        UsernameCheckStatus.CAPTCHA_REQUIRED.value: SessionStatus.CAPTCHA_REQUIRED,
        UsernameCheckStatus.CHALLENGE_REQUIRED.value: SessionStatus.CHALLENGE_REQUIRED,
        UsernameCheckStatus.SESSION_EXPIRED.value: SessionStatus.EXPIRED,
        UsernameCheckStatus.BLOCKED.value: SessionStatus.BLOCKED,
        UsernameCheckStatus.TEMPORARILY_LIMITED.value: SessionStatus.TEMPORARILY_LIMITED,
        UsernameCheckStatus.OAUTH_BROWSER_REJECTED.value: SessionStatus.OAUTH_BROWSER_REJECTED,
        UsernameCheckStatus.PROVIDER_UNAVAILABLE.value: SessionStatus.UNAVAILABLE,
        UsernameCheckStatus.RATE_LIMITED.value: SessionStatus.TEMPORARILY_LIMITED,
    }
    return mapping.get(outcome.status, SessionStatus.UNAVAILABLE)


def _outcome_from_rendered_page(
    spec: PlatformSpec,
    *,
    final_url: str,
    visible: str,
    status_code: int,
    title: str,
    content: str,
) -> FetchOutcome:
    state = classify_browser_state(spec, final_url, visible)
    if state == SessionStatus.TEMPORARILY_LIMITED:
        status = UsernameCheckStatus.TEMPORARILY_LIMITED.value
    elif state == SessionStatus.OAUTH_BROWSER_REJECTED:
        status = UsernameCheckStatus.OAUTH_BROWSER_REJECTED.value
    elif state == SessionStatus.CAPTCHA_REQUIRED:
        status = UsernameCheckStatus.CAPTCHA_REQUIRED.value
    elif state == SessionStatus.CHALLENGE_REQUIRED:
        status = UsernameCheckStatus.CHALLENGE_REQUIRED.value
    elif state == SessionStatus.BLOCKED:
        status = UsernameCheckStatus.BLOCKED.value
    elif state == SessionStatus.EXPIRED or any(h in final_url.lower() for h in spec.login_url_hints):
        return FetchOutcome(
            status=UsernameCheckStatus.SESSION_EXPIRED.value,
            url=final_url,
            status_code=status_code,
            title=title,
            body=content,
            detail="session expired — manual login required",
            redirected_to_login=True,
        )
    else:
        status = UsernameCheckStatus.LIKELY.value
    return FetchOutcome(
        status=status,
        url=final_url,
        status_code=status_code,
        title=title,
        body=content,
        detail="public profile rendered while authenticated",
    )


async def _visible_text(page: Any) -> str:
    """Read-only innerText. Never serializes the DOM (page.content causes SPA flicker)."""
    try:
        text = await page.evaluate(
            "() => (document.body && document.body.innerText) ? document.body.innerText.slice(0, 4000) : ''"
        )
    except Exception:
        return ""
    return str(text or "")


# Public profile metadata only. Never cookies, never page.content() / full HTML.
_PUBLIC_METADATA_JS = """() => {
  const attr = (sel, name) => {
    const el = document.querySelector(sel);
    if (!el) return '';
    return String(el.getAttribute(name) || '').slice(0, 500);
  };
  const text = (document.body && document.body.innerText) ? document.body.innerText : '';
  return {
    canonical: attr('link[rel="canonical"]', 'href'),
    og_url: attr('meta[property="og:url"]', 'content'),
    og_title: attr('meta[property="og:title"]', 'content'),
    title: String(document.title || '').slice(0, 200),
    href: String(location.href || '').slice(0, 500),
    text_length: text.length,
    visible: text.slice(0, 4000),
    has_user_page: Boolean(document.querySelector(
      '[data-e2e="user-page"], [data-e2e="user-title"], [data-e2e="profile-info"], header h1, header h2, main h1'
    )),
  };
}"""

_METADATA_WAIT_S = 4.0
_METADATA_POLL_S = 0.2


def _username_from_profile_url(url: str) -> str:
    path = urlparse(url or "").path.rstrip("/")
    if not path or path == "/":
        return ""
    return path.rsplit("/", 1)[-1].lstrip("@")


def _needs_public_metadata_wait(url: str, username: str) -> bool:
    needle = (username or _username_from_profile_url(url)).lower().lstrip("@")
    if not needle:
        return False
    path = (urlparse(url or "").path or "").lower()
    return needle in path


def _has_public_profile_evidence(snapshot: dict[str, Any], username: str) -> bool:
    """Target-specific public metadata — never location.href alone (that is the request)."""
    needle = (username or "").lower().lstrip("@")
    if not needle:
        return False
    if snapshot.get("has_user_page"):
        return True
    for key in ("title", "canonical", "og_url", "og_title"):
        if needle in str(snapshot.get(key) or "").lower():
            return True
    return False


async def _read_public_page_snapshot(page: Any) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "canonical": "",
        "og_url": "",
        "og_title": "",
        "title": "",
        "href": str(getattr(page, "url", "") or ""),
        "text_length": 0,
        "visible": "",
        "has_user_page": False,
    }
    try:
        raw = await page.evaluate(_PUBLIC_METADATA_JS)
    except Exception:
        raw = None
    if isinstance(raw, dict):
        snapshot["canonical"] = str(raw.get("canonical") or "")[:500]
        snapshot["og_url"] = str(raw.get("og_url") or "")[:500]
        snapshot["og_title"] = str(raw.get("og_title") or "")[:200]
        snapshot["title"] = str(raw.get("title") or "")[:200]
        snapshot["href"] = str(raw.get("href") or snapshot["href"])[:500]
        try:
            snapshot["text_length"] = int(raw.get("text_length") or 0)
        except (TypeError, ValueError):
            snapshot["text_length"] = 0
        snapshot["visible"] = str(raw.get("visible") or "")[:4000]
        snapshot["has_user_page"] = bool(raw.get("has_user_page"))
    try:
        title = await page.title()
        if title:
            snapshot["title"] = str(title)[:200]
    except Exception:
        pass
    snapshot["href"] = str(getattr(page, "url", None) or snapshot["href"] or "")
    if not snapshot["visible"]:
        snapshot["visible"] = await _visible_text(page)
    if not snapshot["text_length"]:
        snapshot["text_length"] = len(str(snapshot["visible"] or ""))
    return snapshot


async def _wait_for_public_profile_evidence(
    page: Any,
    username: str,
    *,
    timeout_s: float = _METADATA_WAIT_S,
) -> dict[str, Any]:
    """Bounded wait for canonical/og/title/container. No arbitrary sleep, no full-DOM dump."""
    waiter = getattr(page, "wait_for_function", None)
    if callable(waiter):
        try:
            await waiter(
                """(u) => {
                  const needle = String(u || '').toLowerCase();
                  if (!needle) return false;
                  const title = String(document.title || '').toLowerCase();
                  const canon = String(document.querySelector('link[rel="canonical"]')?.getAttribute('href') || '').toLowerCase();
                  const og = String(document.querySelector('meta[property="og:url"]')?.getAttribute('content') || '').toLowerCase();
                  const ogt = String(document.querySelector('meta[property="og:title"]')?.getAttribute('content') || '').toLowerCase();
                  const box = document.querySelector(
                    '[data-e2e="user-page"], [data-e2e="user-title"], [data-e2e="profile-info"], header h1, header h2, main h1'
                  );
                  return title.includes(needle) || canon.includes(needle) || og.includes(needle)
                    || ogt.includes(needle) || Boolean(box);
                }""",
                arg=username.lstrip("@"),
                timeout=int(max(0.5, timeout_s) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Public profile metadata wait ended: %s", type(exc).__name__)
        return await _read_public_page_snapshot(page)
    deadline = asyncio.get_event_loop().time() + max(0.0, timeout_s)
    snapshot = await _read_public_page_snapshot(page)
    while not _has_public_profile_evidence(snapshot, username):
        if asyncio.get_event_loop().time() >= deadline:
            break
        await asyncio.sleep(_METADATA_POLL_S)
        snapshot = await _read_public_page_snapshot(page)
    return snapshot


async def _capture_authenticated_public_page(page: Any, url: str) -> dict[str, Any]:
    """After goto: optionally wait for public profile metadata, then snapshot."""
    username = _username_from_profile_url(url)
    snapshot = await _read_public_page_snapshot(page)
    waited = False
    if _needs_public_metadata_wait(url, username) and not _has_public_profile_evidence(snapshot, username):
        waited = True
        snapshot = await _wait_for_public_profile_evidence(page, username)
    snapshot["metadata_waited"] = waited
    snapshot["metadata_ready"] = _has_public_profile_evidence(snapshot, username)
    logger.debug(
        "AUTHENTICATED_PUBLIC page snapshot waited=%s ready=%s content_length=%s has_canonical=%s has_og_url=%s",
        snapshot["metadata_waited"],
        snapshot["metadata_ready"],
        int(snapshot.get("text_length") or 0),
        bool(snapshot.get("canonical")),
        bool(snapshot.get("og_url")),
    )
    return snapshot


class PlaywrightBackend:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings

    def _profile_dir(self, spec: PlatformSpec, user_data_dir: Path | None) -> Path:
        if user_data_dir is not None:
            return Path(user_data_dir)
        return ensure_platform_profile(self.settings or get_settings(), spec.slug)

    async def interactive_login(
        self,
        spec: PlatformSpec,
        *,
        timeout_s: float = 300,
        keep_open: bool = False,
        user_data_dir: Path | None = None,
        attach: bool = False,
    ) -> LoginOutcome:
        profile_dir = self._profile_dir(spec, user_data_dir)
        logger.info(
            "Opening SPECTRE-owned Chromium profile for %s (not the personal browser)",
            spec.display_name,
        )
        async with PlaywrightChromium() as chromium:
            try:
                context = await chromium.launch_persistent_context(
                    str(profile_dir),
                    headless=False,
                    viewport={"width": 1280, "height": 900},
                    accept_downloads=False,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Chromium persistent context failed: %s", type(exc).__name__)
                return LoginOutcome(
                    status=SessionStatus.UNAVAILABLE,
                    detail=f"browser launch failed: {type(exc).__name__}",
                    display_name=spec.display_name,
                )
            page = context.pages[0] if context.pages else await context.new_page()
            visited_login = is_login_url(spec, page.url)
            visited_home = False
            try:
                return await self._observe_login(
                    spec,
                    context,
                    page,
                    timeout_s=timeout_s,
                    visited_login=visited_login,
                    visited_home=visited_home,
                )
            finally:
                if not keep_open:
                    await context.close()

    async def _observe_login(
        self,
        spec: PlatformSpec,
        context: Any,
        page: Any,
        *,
        timeout_s: float,
        visited_login: bool,
        visited_home: bool,
    ) -> LoginOutcome:
        deadline = asyncio.get_event_loop().time() + timeout_s
        last = SessionStatus.EXPIRED
        while asyncio.get_event_loop().time() < deadline:
            url = page.url
            try:
                cookies = await context.cookies()
            except Exception:
                cookies = []
            visible = await _visible_text(page)
            action = next_login_action(
                spec,
                url=url,
                cookies=list(cookies or []),
                visible_text=visible,
                visited_login=visited_login,
                visited_home=visited_home,
            )
            if action.kind == STOP and action.status is not None:
                logger.info(
                    "Login stopped for %s: %s (no retry, no bypass)",
                    spec.display_name,
                    action.status.value,
                )
                return LoginOutcome(
                    status=action.status,
                    detail=action.status.value,
                    display_name=spec.display_name,
                )
            if action.kind == SUCCESS:
                try:
                    storage = await context.storage_state()
                except Exception:
                    storage = cookies_as_storage(list(cookies or []))
                if cookie_names_present(storage, spec.cookie_names):
                    return LoginOutcome(
                        status=SessionStatus.ACTIVE,
                        storage_state=storage,
                        detail="operator completed login in SPECTRE persistent profile",
                        display_name=spec.display_name,
                    )
            if action.kind == GOTO_HOME and not visited_home:
                visited_home = True
                try:
                    await page.goto(spec.home_url, wait_until="domcontentloaded")
                except Exception as exc:  # noqa: BLE001
                    return LoginOutcome(
                        status=SessionStatus.UNAVAILABLE,
                        detail=f"navigation failed: {type(exc).__name__}",
                        display_name=spec.display_name,
                    )
                continue
            if action.kind == GOTO_LOGIN and not visited_login:
                if is_login_url(spec, page.url):
                    visited_login = True
                    continue
                visited_login = True
                try:
                    await page.goto(spec.login_url, wait_until="domcontentloaded")
                except Exception as exc:  # noqa: BLE001
                    return LoginOutcome(
                        status=SessionStatus.UNAVAILABLE,
                        detail=f"navigation failed: {type(exc).__name__}",
                        display_name=spec.display_name,
                    )
                continue
            last = classify_browser_state(spec, url, visible)
            # WAIT: no goto, no reload, no full-DOM snapshot, no focus steal.
            await asyncio.sleep(POLL_INTERVAL_S)
        return LoginOutcome(
            status=last if last != SessionStatus.ACTIVE else SessionStatus.EXPIRED,
            detail="authentication not detected before timeout",
            display_name=spec.display_name,
        )

    async def verify_session(self, spec: PlatformSpec, storage_state: dict) -> SessionStatus:
        outcome = await self.fetch_public(spec, spec.home_url, storage_state)
        return _session_status_from_fetch(outcome)

    async def fetch_public(
        self,
        spec: PlatformSpec,
        url: str,
        storage_state: dict,
    ) -> FetchOutcome:
        async with PlaywrightChromium() as chromium:
            browser = await chromium.launch(headless=True)
            context = await browser.new_context(storage_state=storage_state)
            page = await context.new_page()
            try:
                response = await page.goto(url, wait_until="domcontentloaded")
                code = response.status if response is not None else 0
                snapshot = await _capture_authenticated_public_page(page, url)
                final_url = str(snapshot.get("href") or page.url or url)
                visible = str(snapshot.get("visible") or "")
                title = str(snapshot.get("title") or "")
            except Exception as exc:  # noqa: BLE001
                await browser.close()
                return FetchOutcome(
                    status=UsernameCheckStatus.PROVIDER_UNAVAILABLE.value,
                    url=url,
                    detail=type(exc).__name__,
                )
            await browser.close()
        outcome = _outcome_from_rendered_page(
            spec,
            final_url=final_url,
            visible=visible,
            status_code=code,
            title=title,
            content=visible,
        )
        return outcome.model_copy(
            update={
                "canonical_url": str(snapshot.get("canonical") or ""),
                "og_url": str(snapshot.get("og_url") or ""),
                "og_title": str(snapshot.get("og_title") or ""),
                "content_length": int(snapshot.get("text_length") or 0),
                "metadata_waited": bool(snapshot.get("metadata_waited")),
                "metadata_ready": bool(snapshot.get("metadata_ready")),
            }
        )


class PlaywrightCdpConnector:
    """connect_over_cdp to a loopback Chrome DevTools endpoint only."""

    def __init__(self) -> None:
        self._runtime: Any = None

    async def connect(self, endpoint: str, spec: Any | None = None) -> Any:
        if not is_loopback_cdp_endpoint(endpoint):
            raise PathSafetyError("CDP endpoint must be loopback (127.0.0.1)")
        self._runtime = PlaywrightChromium()
        chromium = await self._runtime.__aenter__()
        return await chromium.connect_over_cdp(endpoint)

    async def aclose(self) -> None:
        if self._runtime is not None:
            await self._runtime.__aexit__(None, None, None)
            self._runtime = None


class ChromeCdpBackend:
    """Launch SPECTRE-owned Google Chrome and attach via CDP. Never controls the login form."""

    def __init__(
        self,
        settings: Settings | None = None,
        launcher: Any | None = None,
        connector: Any | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.launcher = launcher
        self.connector = connector or PlaywrightCdpConnector()
        self.last_cdp_reused = False
        self.last_cdp_launched = False
        self.last_used_existing_context = False
        self.last_created_page_closed = False
        self.last_disconnected = False
        self.last_launch_minimized = False
        self.last_start_url = ""
        self.last_minimized_via_cdp = False
        self.last_bootstrap_pages_closed = 0
        self.last_collection_page_created = False
        self.last_bootstrap_retained = False
        self.last_pages_before = 0
        self.last_pages_remaining = 0
        self.last_created_ids: list[str] = []
        self.last_closed_ids: list[str] = []
        self.last_preexisting_ids: list[str] = []

    def _launcher(self) -> Any:
        if self.launcher is not None:
            return self.launcher
        from spectre_osint.browser.chrome import ProcessChromeLauncher

        return ProcessChromeLauncher(self.settings)

    def _cdp_http_ok(self, endpoint: str, timeout_s: float = 2.0) -> bool:
        from spectre_osint.browser.chrome import wait_cdp_http

        launcher = self._launcher()
        checker = getattr(launcher, "cdp_http_ok", None)
        if callable(checker):
            try:
                return bool(checker(endpoint, timeout_s))
            except TypeError:
                return bool(checker(endpoint))
        return wait_cdp_http(endpoint, timeout_s)

    def _cdp_endpoint_ready(self, endpoint: Any) -> bool:
        """One-shot readiness: never poll a frozen port. Re-read happens in the wait loop."""
        launcher = self._launcher()
        checker = getattr(launcher, "cdp_http_ok", None)
        if callable(checker):
            try:
                return bool(checker(endpoint.http_endpoint, 0.0))
            except TypeError:
                return bool(checker(endpoint.http_endpoint))
        version = fetch_cdp_version(endpoint.http_endpoint, timeout_s=1.0)
        return websocket_matches_devtools_endpoint(version, endpoint)

    async def _acquire_cdp_endpoint(
        self,
        spec: PlatformSpec,
        profile_dir: Path,
        *,
        timeout_s: float,
        start_url: str,
        attach: bool = False,
        visible: bool = True,
    ) -> tuple[str | None, SessionStatus, str]:
        """Reuse a valid SPECTRE CDP endpoint or launch the SPECTRE-owned profile.

        MANUAL_LOGIN (visible=True): open the login URL in a normal window.
        COLLECTION (visible=False): reuse existing CDP; otherwise launch
        SPECTRE Chrome with --no-startup-window (not headless, not personal).
        """
        self.last_cdp_reused = False
        self.last_cdp_launched = False
        self.last_launch_minimized = False
        self.last_start_url = start_url
        launcher = self._launcher()
        chrome_exe = launcher.resolve_chrome() if hasattr(launcher, "resolve_chrome") else None
        if chrome_exe is None:
            return (
                None,
                SessionStatus.CHROME_NOT_FOUND,
                "Google Chrome not found. SPECTRE will not launch Edge automatically.",
            )
        existing = probe_spectre_cdp(profile_dir, http_ok=self._cdp_http_ok)
        if existing is not None:
            logger.info(
                "Reusing SPECTRE Chrome CDP at %s (profile=%s)",
                existing.http_endpoint,
                profile_dir.name,
            )
            self.last_cdp_reused = True
            return existing.http_endpoint, SessionStatus.ACTIVE, "reused SPECTRE CDP endpoint"
        if attach:
            return (
                None,
                SessionStatus.CDP_UNAVAILABLE,
                "No SPECTRE Chrome CDP endpoint to attach. Personal Chrome is never used.",
            )
        if chrome_profile_locked(profile_dir):
            return (
                None,
                SessionStatus.CHROME_PROFILE_LOCKED,
                (
                    "SPECTRE Chrome profile is open but no valid SPECTRE CDP endpoint was found. "
                    "Close that SPECTRE Chrome window (not your personal Chrome), then retry. "
                    "If a previous WSL launch opened Chrome without DevTools, close it first."
                ),
            )
        try:
            stale = snapshot_spectre_devtools_active_port(profile_dir)
        except PathSafetyError as exc:
            return None, SessionStatus.UNAVAILABLE, str(exc)
        if stale.exists:
            logger.info(
                "Stale SPECTRE DevToolsActivePort port=%s (no live CDP) — discarding before launch",
                stale.port,
            )
            try:
                discard_stale_devtools_active_port(profile_dir)
            except PathSafetyError as exc:
                return None, SessionStatus.UNAVAILABLE, str(exc)
        try:
            args = build_chrome_command(
                Path(chrome_exe),
                profile_dir,
                0,
                start_url,
                minimized=not visible,
            )
        except PathSafetyError as exc:
            return None, SessionStatus.UNAVAILABLE, str(exc)
        if not command_is_safe(args):
            return None, SessionStatus.UNAVAILABLE, "refusing unsafe Chrome command line"
        write_windows_chrome_launcher(self.settings)
        if hasattr(launcher, "devtools_target"):
            launcher.devtools_target = profile_dir
        logger.info("Windows Chrome process starting for %s", spec.display_name)
        logger.info("Profile: %s", profile_dir.name)
        logger.info("Requested CDP: auto (DevToolsActivePort, port=0)")
        try:
            handle = launcher.spawn(args)
        except Exception as exc:  # noqa: BLE001
            return None, SessionStatus.CDP_UNAVAILABLE, f"chrome spawn failed: {type(exc).__name__}"
        self.last_cdp_launched = True
        self.last_launch_minimized = not visible
        self.last_start_url = start_url
        pid = getattr(handle, "pid", None)
        if pid:
            logger.info("PID: %s", pid)
        ignore = stale if stale.exists else None
        discovered = wait_for_spectre_cdp_ready(
            profile_dir,
            timeout_s=min(8.0, float(timeout_s)),
            ignore=ignore,
            ready_check=self._cdp_endpoint_ready,
        )
        if discovered is None and hasattr(launcher, "spawn_windows_helper"):
            still = snapshot_spectre_devtools_active_port(profile_dir)
            file_missing_or_stale = (not still.exists) or (
                ignore is not None and ignore.is_same_file_state(still)
            )
            if file_missing_or_stale:
                logger.info("DevToolsActivePort not found after WSL launch; trying Windows helper script")
                try:
                    launcher.spawn_windows_helper(args)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Windows helper launch failed: %s", type(exc).__name__)
                discovered = wait_for_spectre_cdp_ready(
                    profile_dir,
                    timeout_s=min(12.0, float(timeout_s)),
                    ignore=ignore,
                    ready_check=self._cdp_endpoint_ready,
                )
        if discovered is None:
            logger.info("CDP HTTP endpoint: not ready")
            stop_spectre_launched_chrome(profile_dir)
            return (
                None,
                SessionStatus.WINDOWS_CDP_LAUNCH_FAILED,
                (
                    "WINDOWS_CDP_LAUNCH_FAILED — Chrome opened but SPECTRE CDP did not listen. "
                    "Close the SPECTRE Chrome window (not personal Chrome). "
                    "On Windows PowerShell run %USERPROFILE%\\.spectre\\launchers\\Start-SpectreChrome.ps1 "
                    "then: spectre auth login "
                    f"{spec.slug} --browser chrome --attach"
                ),
            )
        endpoint = discovered.http_endpoint
        logger.info("DevToolsActivePort: found")
        logger.info("CDP HTTP endpoint: %s", endpoint)
        logger.info("CDP HTTP endpoint: ready")
        return endpoint, SessionStatus.ACTIVE, "launched SPECTRE Chrome CDP"

    async def interactive_login(
        self,
        spec: PlatformSpec,
        *,
        timeout_s: float = 300,
        keep_open: bool = False,
        user_data_dir: Path | None = None,
        attach: bool = False,
    ) -> LoginOutcome:
        profile_dir = Path(user_data_dir) if user_data_dir is not None else ensure_chrome_profile(
            self.settings, spec.slug
        )
        endpoint, status, detail = await self._acquire_cdp_endpoint(
            spec,
            profile_dir,
            timeout_s=timeout_s,
            start_url=spec.login_url,
            attach=attach,
            visible=True,
        )
        if endpoint is None:
            return LoginOutcome(status=status, detail=detail, display_name=spec.display_name)
        return await self._connect_and_observe(
            spec, endpoint, timeout_s=timeout_s, keep_open=keep_open
        )

    async def _connect_and_observe(
        self,
        spec: PlatformSpec,
        endpoint: str,
        *,
        timeout_s: float,
        keep_open: bool,
    ) -> LoginOutcome:
        try:
            browser = await self.connector.connect(endpoint, spec=spec)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CDP connect failed: %s", type(exc).__name__)
            return LoginOutcome(
                status=SessionStatus.CDP_UNAVAILABLE,
                detail=f"CDP connect failed: {type(exc).__name__}",
                display_name=spec.display_name,
            )
        try:
            context = browser.contexts[0] if getattr(browser, "contexts", None) else None
            if context is None:
                return LoginOutcome(
                    status=SessionStatus.CDP_UNAVAILABLE,
                    detail="CDP browser has no context",
                    display_name=spec.display_name,
                )
            page = context.pages[0] if getattr(context, "pages", None) else None
            if page is None:
                return LoginOutcome(
                    status=SessionStatus.CDP_UNAVAILABLE,
                    detail="CDP browser has no page",
                    display_name=spec.display_name,
                )
            visited_login = is_login_url(spec, page.url)
            return await self._observe_without_navigation(
                spec,
                context,
                page,
                timeout_s=timeout_s,
                visited_login=visited_login,
            )
        finally:
            closer = getattr(browser, "close", None)
            if closer is not None:
                try:
                    await closer()
                except Exception:
                    pass
            aclose = getattr(self.connector, "aclose", None)
            if aclose is not None:
                try:
                    await aclose()
                except Exception:
                    pass

    async def _observe_without_navigation(
        self,
        spec: PlatformSpec,
        context: Any,
        page: Any,
        *,
        timeout_s: float,
        visited_login: bool,
    ) -> LoginOutcome:
        """Read URL/cookies/innerText only. Never goto, reload, or focus the form."""
        deadline = asyncio.get_event_loop().time() + timeout_s
        last = SessionStatus.EXPIRED
        visited_home = False
        while asyncio.get_event_loop().time() < deadline:
            url = page.url
            try:
                cookies = await context.cookies()
            except Exception:
                cookies = []
            visible = await _visible_text(page)
            action = next_login_action(
                spec,
                url=url,
                cookies=list(cookies or []),
                visible_text=visible,
                visited_login=visited_login,
                visited_home=visited_home,
            )
            if action.kind == STOP and action.status is not None:
                return LoginOutcome(
                    status=action.status,
                    detail=action.status.value,
                    display_name=spec.display_name,
                )
            if action.kind == SUCCESS:
                try:
                    storage = await context.storage_state()
                except Exception:
                    storage = cookies_as_storage(list(cookies or []))
                if cookie_names_present(storage, spec.cookie_names):
                    return LoginOutcome(
                        status=SessionStatus.ACTIVE,
                        storage_state=cdp_session_sentinel(spec),
                        detail="operator completed login in SPECTRE-owned Chrome (CDP)",
                        display_name=spec.display_name,
                    )
            if action.kind == GOTO_LOGIN:
                visited_login = True
            if action.kind == GOTO_HOME:
                visited_home = True
            last = classify_browser_state(spec, url, visible)
            await asyncio.sleep(POLL_INTERVAL_S)
        return LoginOutcome(
            status=last if last != SessionStatus.ACTIVE else SessionStatus.EXPIRED,
            detail="authentication not detected before timeout",
            display_name=spec.display_name,
        )

    async def verify_session(self, spec: PlatformSpec, storage_state: dict) -> SessionStatus:
        try:
            outcome = await self.fetch_public_cdp(spec, spec.home_url, storage_state)
        except Exception as exc:  # noqa: BLE001
            mapped = map_expected_session_failure(exc)
            if mapped is None:
                raise
            logger.warning("CDP verify failed for %s: %s", spec.display_name, type(exc).__name__)
            return mapped
        return _session_status_from_fetch(outcome)

    async def fetch_public(
        self,
        spec: PlatformSpec,
        url: str,
        storage_state: dict,
    ) -> FetchOutcome:
        return await self.fetch_public_cdp(spec, url, storage_state)

    async def fetch_public_cdp(
        self,
        spec: PlatformSpec,
        url: str,
        storage_state: dict,
    ) -> FetchOutcome:
        """Fetch a public URL through the persistent SPECTRE Chrome profile.

        Chrome cookies in ``storage_state`` (legacy or sentinel) are never
        transplanted into Playwright ``browser.new_context``.
        """
        del storage_state
        self.last_used_existing_context = False
        self.last_created_page_closed = False
        self.last_disconnected = False
        self.last_minimized_via_cdp = False
        self.last_bootstrap_pages_closed = 0
        self.last_collection_page_created = False
        self.last_bootstrap_retained = False
        self.last_pages_before = 0
        self.last_pages_remaining = 0
        self.last_created_ids = []
        self.last_closed_ids = []
        self.last_preexisting_ids = []
        try:
            profile_dir = ensure_chrome_profile(self.settings, spec.slug)
        except PathSafetyError as exc:
            return FetchOutcome(status=SessionStatus.UNAVAILABLE.value, url=url, detail=str(exc))
        try:
            from spectre_osint.browser.chrome import COLLECTION_START_URL

            visible = bool(getattr(self.settings, "browser_visible", False))
            start_url = url if visible else COLLECTION_START_URL
            endpoint, status, detail = await self._acquire_cdp_endpoint(
                spec,
                profile_dir,
                timeout_s=20.0,
                start_url=start_url,
                visible=visible,
            )
        except PathSafetyError as exc:
            return FetchOutcome(status=SessionStatus.UNAVAILABLE.value, url=url, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            mapped = map_expected_session_failure(exc)
            if mapped is None:
                raise
            logger.warning("CDP acquire failed for %s: %s", spec.display_name, type(exc).__name__)
            return FetchOutcome(status=mapped.value, url=url, detail=type(exc).__name__)
        if endpoint is None:
            return FetchOutcome(status=status.value, url=url, detail=detail)
        return await self._fetch_via_existing_cdp(spec, url, endpoint)

    async def _fetch_via_existing_cdp(self, spec: PlatformSpec, url: str, endpoint: str) -> FetchOutcome:
        try:
            browser = await self.connector.connect(endpoint, spec=spec)
        except Exception as exc:  # noqa: BLE001
            mapped = map_expected_session_failure(exc) or SessionStatus.CDP_UNAVAILABLE
            logger.warning("CDP connect failed: %s", type(exc).__name__)
            await self._disconnect_cdp(None)
            return FetchOutcome(
                status=mapped.value,
                url=url,
                detail=f"CDP connect failed: {type(exc).__name__}",
            )
        created_page: Any = None
        context: Any = None
        preexisting: list[Any] = []
        try:
            contexts = getattr(browser, "contexts", None) or []
            context = contexts[0] if contexts else None
            if context is None:
                return FetchOutcome(
                    status=SessionStatus.CDP_UNAVAILABLE.value,
                    url=url,
                    detail="CDP browser has no context",
                )
            self.last_used_existing_context = True
            preexisting = list(getattr(context, "pages", None) or [])
            self.last_preexisting_ids = [self._page_id(item) for item in preexisting]
            self.last_pages_before = len(preexisting)
            page = await self._open_collection_page(context)
            created_page = page
            if page is None:
                return FetchOutcome(
                    status=SessionStatus.CDP_UNAVAILABLE.value,
                    url=url,
                    detail="CDP browser has no page",
                )
            await self._minimize_collection_window(page)
            response = await page.goto(url, wait_until="domcontentloaded")
            code = response.status if response is not None else 0
            snapshot = await _capture_authenticated_public_page(page, url)
            final_url = str(snapshot.get("href") or page.url or url)
            visible = str(snapshot.get("visible") or "")
            title = str(snapshot.get("title") or "")
            outcome = _outcome_from_rendered_page(
                spec,
                final_url=final_url,
                visible=visible,
                status_code=code,
                title=title,
                content=visible,
            )
            return outcome.model_copy(
                update={
                    "canonical_url": str(snapshot.get("canonical") or ""),
                    "og_url": str(snapshot.get("og_url") or ""),
                    "og_title": str(snapshot.get("og_title") or ""),
                    "content_length": int(snapshot.get("text_length") or 0),
                    "metadata_waited": bool(snapshot.get("metadata_waited")),
                    "metadata_ready": bool(snapshot.get("metadata_ready")),
                }
            )
        except Exception as exc:  # noqa: BLE001
            mapped = map_expected_session_failure(exc) or SessionStatus.CDP_UNAVAILABLE
            logger.warning("CDP fetch failed for %s: %s", spec.display_name, type(exc).__name__)
            return FetchOutcome(status=mapped.value, url=url, detail=type(exc).__name__)
        finally:
            if context is not None:
                await self._cleanup_collection_pages(context, created_page, preexisting)
            await self._disconnect_cdp(browser)

    def _page_url(self, page: Any) -> str:
        return str(getattr(page, "url", "") or "").strip().lower()

    def _page_id(self, page: Any) -> str:
        explicit = getattr(page, "page_id", None) or getattr(page, "guid", None)
        if explicit:
            return str(explicit)[:16]
        return f"p{id(page) & 0xFFFFFF:06x}"

    def _is_bootstrap_page(self, page: Any) -> bool:
        url = self._page_url(page)
        return url in {"", "about:blank", "chrome://newtab/", "chrome://new-tab-page/"} or url.startswith(
            "about:"
        )

    async def _open_collection_page(self, context: Any) -> Any:
        """Always create a collection-owned page. Never reuse operator tabs."""
        new_page = getattr(context, "new_page", None)
        if callable(new_page):
            created = await new_page()
            self.last_collection_page_created = True
            return created
        pages = list(getattr(context, "pages", None) or [])
        return pages[0] if pages else None

    async def _minimize_collection_window(self, page: Any) -> None:
        owner = getattr(page, "context", None)
        session_fn = getattr(owner, "new_cdp_session", None) if owner is not None else None
        if not callable(session_fn):
            return
        try:
            session = await session_fn(page)
            sender = getattr(session, "send", None)
            if not callable(sender):
                return
            info = await sender("Browser.getWindowForTarget")
            window_id = (info or {}).get("windowId") if isinstance(info, dict) else None
            if window_id is None:
                return
            await sender(
                "Browser.setWindowBounds",
                {"windowId": window_id, "bounds": {"windowState": "minimized"}},
            )
            self.last_minimized_via_cdp = True
        except Exception:  # noqa: BLE001
            logger.debug("CDP window minimize skipped", exc_info=True)

    async def _close_page(self, page: Any) -> bool:
        closer = getattr(page, "close", None)
        if closer is None:
            return False
        try:
            await closer()
            return True
        except Exception:
            return False

    async def _cleanup_collection_pages(
        self,
        context: Any,
        created_page: Any,
        preexisting: list[Any],
    ) -> None:
        """Close collection-owned pages and leftover SPECTRE about:blank only.

        Chrome started with --no-startup-window stays alive with zero pages.
        SPECTRE therefore does not keep a bootstrap about:blank. Preexisting
        operator tabs (login/profile) are never closed.
        """
        created_ids: list[str] = []
        closed_ids: list[str] = []
        closed = 0
        if created_page is not None:
            created_ids.append(self._page_id(created_page))
            if await self._close_page(created_page):
                closed_ids.append(self._page_id(created_page))
                self.last_created_page_closed = True
                closed += 1
        operator_ids = {
            self._page_id(item) for item in preexisting if not self._is_bootstrap_page(item)
        }
        for page in list(getattr(context, "pages", None) or []):
            if page is created_page:
                continue
            if self._page_id(page) in operator_ids:
                continue
            if self._is_bootstrap_page(page) and await self._close_page(page):
                closed_ids.append(self._page_id(page))
                closed += 1
        remaining = list(getattr(context, "pages", None) or [])
        self.last_created_ids = created_ids
        self.last_closed_ids = closed_ids
        self.last_pages_remaining = len(remaining)
        self.last_bootstrap_pages_closed = closed
        self.last_bootstrap_retained = False
        logger.debug(
            "cdp pages before=%s created=%s closed=%s remaining=%s",
            self.last_pages_before,
            ",".join(created_ids) or "-",
            ",".join(closed_ids) or "-",
            self.last_pages_remaining,
        )

    async def _disconnect_cdp(self, _browser: Any | None) -> None:
        """Drop the Playwright CDP connection. Never wipe the persistent Chrome profile."""
        aclose = getattr(self.connector, "aclose", None)
        if aclose is not None:
            try:
                await aclose()
            except Exception:
                pass
        self.last_disconnected = True


def resolve_browser_kind(spec: Any, requested: str | None, settings: Settings | None = None) -> str:
    """auto | playwright | chrome | fake. Never selects Edge."""
    cfg = settings or get_settings()
    req = (requested or "auto").strip().lower()
    backend_cfg = (cfg.browser_backend or "playwright").strip().lower()
    if backend_cfg in {"fake", "test", "mock"} and req in {"auto", "", "default", "playwright", "pw"}:
        return "fake"
    if req in {"chrome", "cdp", "chrome-cdp", "chrome_cdp"}:
        return "chrome"
    if req in {"playwright", "pw"}:
        return "playwright" if backend_cfg not in {"fake", "test", "mock"} else "fake"
    if req not in {"auto", "", "default"}:
        return "playwright"
    preferred = getattr(spec, "preferred_browser", "playwright")
    if preferred == "chrome":
        from spectre_osint.browser.chrome import chrome_available

        if backend_cfg in {"fake", "test", "mock"}:
            return "fake"
        if chrome_available(cfg):
            return "chrome"
    return "playwright" if backend_cfg not in {"fake", "test", "mock"} else "fake"


class PlaywrightChromium:
    def __init__(self) -> None:
        self._pw: Any = None

    async def __aenter__(self) -> Any:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserUnavailable(
                "Playwright is not installed. pip install playwright && playwright install chromium"
            ) from exc
        self._pw = await async_playwright().start()
        return self._pw.chromium

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._pw is not None:
            await self._pw.stop()


def get_backend(name: str | None, settings: Settings | None = None) -> BrowserBackend:
    chosen = (name or "playwright").strip().lower()
    cfg = settings or get_settings()
    if chosen in {"fake", "test", "mock"}:
        return FakeBrowserBackend()
    if chosen in {"chrome", "cdp", "chrome-cdp", "chrome_cdp"}:
        if (cfg.browser_backend or "").strip().lower() in {"fake", "test", "mock"}:
            return ChromeCdpBackend(cfg, launcher=FakeChromeLauncher(), connector=FakeCdpConnector())
        return ChromeCdpBackend(cfg)
    return PlaywrightBackend(settings)

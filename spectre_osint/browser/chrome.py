"""SPECTRE-owned Google Chrome profiles and CDP launch helpers.

Never uses the operator's default Chrome/Edge User Data directory.
Remote debugging is bound to loopback only. No stealth flags.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

from spectre_osint.browser.models import AUTH_PLATFORMS, normalize_platform
from spectre_osint.browser.storage import ensure_secret_dir
from spectre_osint.core.config import Settings, get_settings
from spectre_osint.core.exceptions import PathSafetyError
from spectre_osint.core.logger import get_logger

logger = get_logger("spectre.browser.chrome")

CDP_LOOPBACK = "127.0.0.1"
CDP_PORT_MIN = 9222
CDP_PORT_MAX = 9299
MARKER_NAME = ".spectre-owned"
MARKER_TEXT = "SPECTRE OSINT dedicated Google Chrome profile. Not the personal browser.\n"
DEVTOOLS_ACTIVE_PORT = "DevToolsActivePort"
LAUNCH_PID_FILE = ".spectre-launch.pid"
LAUNCHER_PS1 = "Start-SpectreChrome.ps1"
LAUNCHER_CMD = "Start-SpectreChrome.cmd"

PLATFORM_CDP_PORTS = {
    "instagram": 9222,
    "facebook": 9223,
    "threads": 9224,
    "tiktok": 9225,
    "x": 9226,
    "twitch": 9227,
}

_PERSONAL_PROFILE_FRAGMENTS = (
    "google/chrome/user data",
    "google\\chrome\\user data",
    "google chrome/user data",
    "microsoft/edge/user data",
    "microsoft\\edge\\user data",
    "appdata/local/google/chrome/user data",
    "appdata\\local\\google\\chrome\\user data",
    "library/application support/google/chrome",
    ".config/google-chrome",
)

_LOCK_NAMES = ("SingletonLock", "SingletonSocket", "SingletonCookie", "lockfile")

# Windows host processes (cmd.exe / powershell.exe) under WSL are not UTF-8 by default.
_WINDOWS_TEXT_ENCODINGS = (
    "utf-8-sig",
    "utf-8",
    "utf-16",
    "utf-16-le",
    "utf-16-be",
    "cp1252",
    "cp850",
    "cp437",
    "latin-1",
)

_POWERSHELL_FALLBACKS = (
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
)
_CMD_FALLBACKS = (
    "/mnt/c/Windows/System32/cmd.exe",
    "/mnt/c/WINDOWS/System32/cmd.exe",
)
_POWERSHELL_USERPROFILE = (
    "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
    "[Environment]::GetFolderPath('UserProfile')"
)


def is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        return False


def is_windows() -> bool:
    return sys.platform == "win32"


def decode_windows_bytes(data: bytes | None) -> str:
    """Decode Windows host process output. Never raises UnicodeDecodeError."""
    if not data:
        return ""
    encodings: list[str] = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or (
        len(data) >= 4 and data[1] == 0 and data[3] == 0
    ):
        encodings.extend(("utf-16", "utf-16-le", "utf-16-be"))
    encodings.extend(_WINDOWS_TEXT_ENCODINGS)
    seen: set[str] = set()
    for enc in encodings:
        if enc in seen:
            continue
        seen.add(enc)
        try:
            text = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if "\x00" in text and not enc.startswith("utf-16"):
            continue
        return text
    return data.decode("utf-8", errors="replace")


def run_capture_bytes(argv: list[str], timeout: float = 5.0) -> tuple[int, bytes, bytes] | None:
    """Run a process capturing raw bytes. Never decodes as UTF-8 implicitly."""
    try:
        proc = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=False,
            timeout=timeout,
        )
    except UnicodeDecodeError:
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None
    return int(proc.returncode), proc.stdout or b"", proc.stderr or b""


def windows_userprofile(settings: Settings | None = None) -> Path | None:
    """Windows %USERPROFILE% from WSL or native Windows. Never guessed as Chrome User Data."""
    try:
        cfg = settings or get_settings()
        override = getattr(cfg, "windows_userprofile", None) or os.environ.get(
            "SPECTRE_WINDOWS_USERPROFILE"
        )
        if override:
            return _coerce_path(str(override))
        raw = os.environ.get("USERPROFILE")
        if raw and _looks_like_windows_home(raw):
            return _coerce_path(raw)
        if is_windows():
            return Path.home()
        if is_wsl():
            from_host = windows_userprofile_from_host()
            if from_host is not None:
                return from_host
            return _wsl_users_fallback()
        return None
    except (UnicodeError, OSError, ValueError):
        logger.warning("Windows USERPROFILE discovery failed; using fallback")
        return _wsl_users_fallback() if is_wsl() else None


def _looks_like_windows_home(raw: str) -> bool:
    text = (raw or "").strip().strip('"').strip("'")
    if len(text) >= 3 and text[1] == ":" and text[2] in "\\/":
        return True
    lowered = text.replace("\\", "/").lower()
    return "/users/" in lowered


def _coerce_path(raw: str) -> Path:
    text = raw.strip().strip('"').strip("'")
    if len(text) >= 3 and text[1] == ":" and text[2] in "\\/" and not is_windows():
        drive = text[0].lower()
        rest = text[3:].replace("\\", "/").lstrip("/\\")
        return Path(f"/mnt/{drive}/{rest}")
    return Path(text)


def _wsl_users_fallback() -> Path | None:
    home = Path.home()
    for candidate in (
        Path("/mnt/c/Users") / home.name,
        Path("/mnt/c/Users") / os.environ.get("USER", ""),
    ):
        try:
            if candidate.name and candidate.is_dir():
                return candidate
        except OSError:
            continue
    return None


def _find_windows_exe(names: tuple[str, ...], fallbacks: tuple[str, ...]) -> Path | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)
    for raw in fallbacks:
        path = Path(raw)
        try:
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def windows_userprofile_from_host() -> Path | None:
    """Ask the Windows host for UserProfile. PowerShell UTF-8 first, then cmd.exe."""
    try:
        via_ps = _userprofile_via_powershell()
        if via_ps is not None:
            return via_ps
        return _userprofile_via_cmd()
    except (UnicodeError, OSError, ValueError):
        logger.warning("Windows host USERPROFILE probe failed")
        return None


def _parse_windows_home_output(stdout: bytes, stderr: bytes) -> Path | None:
    # Decode stderr so OEM banners cannot raise — then ignore it.
    decode_windows_bytes(stderr)
    text = decode_windows_bytes(stdout)
    for line in reversed(text.splitlines()):
        value = line.strip().strip('"').strip("'")
        if not value or "%" in value:
            continue
        if _looks_like_windows_home(value):
            return _coerce_path(value)
    return None


def _userprofile_via_powershell() -> Path | None:
    exe = _find_windows_exe(("powershell.exe",), _POWERSHELL_FALLBACKS)
    if exe is None:
        return None
    captured = run_capture_bytes(
        [str(exe), "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL_USERPROFILE],
        timeout=8.0,
    )
    if captured is None:
        return None
    _code, stdout, stderr = captured
    return _parse_windows_home_output(stdout, stderr)


def _userprofile_via_cmd() -> Path | None:
    exe = _find_windows_exe(("cmd.exe",), _CMD_FALLBACKS)
    if exe is None:
        return None
    captured = run_capture_bytes([str(exe), "/c", "echo", "%USERPROFILE%"], timeout=5.0)
    if captured is None:
        return None
    _code, stdout, stderr = captured
    return _parse_windows_home_output(stdout, stderr)


def to_windows_path(path: Path | str) -> str:
    raw = str(path)
    normalized = raw.replace("\\", "/")
    if len(normalized) >= 2 and normalized[1] == ":":
        return normalized.replace("/", "\\")
    if normalized.startswith("/mnt/") and len(normalized) >= 6 and normalized[5].isalpha():
        drive = normalized[5].upper()
        if len(normalized) == 6:
            return f"{drive}:\\"
        if normalized[6] == "/":
            rest = normalized[7:].replace("/", "\\")
            return f"{drive}:\\{rest}"
    wslpath = shutil.which("wslpath")
    if wslpath:
        captured = run_capture_bytes([wslpath, "-w", raw], timeout=5.0)
        if captured is not None:
            code, stdout, stderr = captured
            decode_windows_bytes(stderr)
            out = decode_windows_bytes(stdout).strip()
            if code == 0 and out:
                return out.splitlines()[-1].strip()
    return raw


def default_chrome_profiles_root(settings: Settings | None = None) -> Path:
    cfg = settings or get_settings()
    override = getattr(cfg, "chrome_profiles_dir", None)
    if override:
        return Path(str(override)).expanduser()
    env = os.environ.get("SPECTRE_CHROME_PROFILES_DIR")
    if env:
        return Path(env).expanduser()
    if is_windows() or is_wsl():
        home = windows_userprofile(cfg)
        if home is not None:
            return home / ".spectre" / "chrome"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "spectre" / "chrome"
    return Path.home() / ".local" / "share" / "spectre" / "chrome-profiles"


def chrome_profile_dir(settings: Settings | None, platform: str) -> Path:
    slug = normalize_platform(platform)
    return default_chrome_profiles_root(settings) / slug


def is_personal_chrome_profile(path: Path) -> bool:
    lowered = str(path).lower().replace("\\", "/")
    return any(fragment in lowered for fragment in _PERSONAL_PROFILE_FRAGMENTS)


def assert_spectre_chrome_profile(path: Path, root: Path) -> Path:
    resolved = path.expanduser().resolve()
    root_resolved = root.expanduser().resolve()
    if is_personal_chrome_profile(resolved):
        raise PathSafetyError("Refusing to use a personal Chrome/Edge User Data directory")
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise PathSafetyError(f"Chrome profile escaped SPECTRE chrome root: {resolved}") from exc
    if resolved.name.lower() not in AUTH_PLATFORMS and resolved != root_resolved:
        if resolved.parent.resolve() == root_resolved:
            raise PathSafetyError(f"Unknown SPECTRE Chrome profile platform dir: {resolved.name}")
    return resolved


def ensure_chrome_profile(settings: Settings | None, platform: str) -> Path:
    cfg = settings or get_settings()
    root = ensure_secret_dir(default_chrome_profiles_root(cfg))
    target = assert_spectre_chrome_profile(chrome_profile_dir(cfg, platform), root)
    ensure_secret_dir(target)
    marker = target / MARKER_NAME
    if not marker.exists():
        try:
            marker.write_text(MARKER_TEXT, encoding="utf-8")
            os.chmod(marker, 0o600)
        except OSError:
            logger.warning("Could not write SPECTRE Chrome profile marker")
    try:
        os.chmod(target, 0o700)
        os.chmod(root, 0o700)
    except OSError:
        logger.warning("Could not set 0700 on SPECTRE Chrome profile dir")
    return target


def wipe_chrome_profile(settings: Settings | None, platform: str) -> bool:
    """Delete the SPECTRE Chrome CDP profile. Idempotent. Personal Chrome untouched."""
    try:
        cfg = settings or get_settings()
        root = default_chrome_profiles_root(cfg).expanduser().resolve()
        target = assert_spectre_chrome_profile(chrome_profile_dir(cfg, platform), root)
        if not target.exists():
            return False
        shutil.rmtree(target)
        logger.info("Removed SPECTRE Chrome profile for %s (personal Chrome untouched)", platform)
        return True
    except (OSError, PathSafetyError, UnicodeError, ValueError):
        logger.warning("Chrome profile wipe skipped for %s", platform)
        return False


def chrome_profile_locked(profile_dir: Path) -> bool:
    if not profile_dir.exists():
        return False
    for name in _LOCK_NAMES:
        lock = profile_dir / name
        if lock.exists() or lock.is_symlink():
            return True
    return False


def preferred_cdp_port(platform: str) -> int:
    slug = (platform or "").strip().lower()
    return PLATFORM_CDP_PORTS.get(slug, CDP_PORT_MIN)


def bind_loopback_port(preferred: int) -> int | None:
    """Bind 127.0.0.1 only. Never 0.0.0.0."""
    candidates = [preferred, *range(CDP_PORT_MIN, CDP_PORT_MAX + 1)]
    seen: set[int] = set()
    for port in candidates:
        if port in seen or port < CDP_PORT_MIN or port > CDP_PORT_MAX:
            continue
        seen.add(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((CDP_LOOPBACK, port))
        except OSError:
            continue
        finally:
            sock.close()
        return port
    return None


def cdp_endpoint(port: int) -> str:
    return f"http://{CDP_LOOPBACK}:{int(port)}"


def is_loopback_cdp_endpoint(endpoint: str) -> bool:
    text = (endpoint or "").strip().lower()
    return text.startswith(f"http://{CDP_LOOPBACK}:") or text.startswith("http://localhost:")


def chrome_search_paths(settings: Settings | None = None) -> list[Path]:
    """Ordered candidate chrome.exe / google-chrome paths. Edge is never included."""
    cfg = settings or get_settings()
    paths: list[Path] = []
    explicit = getattr(cfg, "chrome_path", None) or os.environ.get("SPECTRE_CHROME_PATH")
    if explicit:
        paths.append(Path(str(explicit)).expanduser())
    win_home = windows_userprofile(cfg)
    local_app = None
    if win_home is not None:
        local_app = win_home / "AppData" / "Local" / "Google" / "Chrome" / "Application" / "chrome.exe"
    if is_wsl() or is_windows():
        paths.extend(
            [
                Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"),
                Path("/mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe"),
                Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
            ]
        )
        if local_app is not None:
            paths.append(local_app)
    if sys.platform == "darwin":
        paths.append(Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
    if not is_wsl():
        for name in ("google-chrome-stable", "google-chrome"):
            found = shutil.which(name)
            if found:
                paths.append(Path(found))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def resolve_chrome_executable(settings: Settings | None = None) -> Path | None:
    for path in chrome_search_paths(settings):
        try:
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def chrome_available(settings: Settings | None = None) -> bool:
    return resolve_chrome_executable(settings) is not None


def user_data_dir_arg(profile_dir: Path, chrome_exe: Path) -> str:
    exe = str(chrome_exe)
    if exe.lower().endswith(".exe") or "/mnt/c/" in exe.replace("\\", "/").lower():
        return to_windows_path(profile_dir)
    return str(profile_dir)


COLLECTION_START_URL = "about:blank"
# Windows Chrome does not honor --start-minimized, and Start-Process
# -WindowStyle Minimized only affects the wrapper process — Chrome still
# creates its own BrowserFrame, restores the SPECTRE profile session, and
# steals focus when an argv URL (including about:blank) is present.
# COLLECTION therefore launches with --no-startup-window and no URL so CDP
# can come up without a startup window. Each fetch creates one temporary
# page, minimizes it via CDP, and closes only that page. Operator tabs
# that already existed are never closed. Chrome launched with
# --no-startup-window stays alive with zero pages, so SPECTRE does not
# keep a leftover about:blank bootstrap. MANUAL_LOGIN stays a normal
# visible window with the login URL. Not headless: TikTok still needs a
# real persistent Chrome profile. A brief first-page flash can still
# happen when CDP creates the working tab; we do not pretend that is
# fully invisible.
COLLECTION_NO_WINDOW_FLAG = "--no-startup-window"


def build_chrome_command(
    chrome_exe: Path,
    profile_dir: Path,
    port: int,
    login_url: str,
    *,
    minimized: bool = False,
) -> list[str]:
    """Chrome 136+ requires a non-default --user-data-dir with remote debugging.

    port=0 lets Chrome pick a free port and write DevToolsActivePort.
    minimized=True (COLLECTION): --no-startup-window, no startup URL, not headless.
    Login stays visible with the login URL.
    """
    if is_personal_chrome_profile(profile_dir):
        raise PathSafetyError("Refusing default Chrome User Data dir for remote debugging")
    data_dir = user_data_dir_arg(profile_dir, chrome_exe)
    args = [
        str(chrome_exe),
        f"--remote-debugging-port={int(port)}",
        f"--remote-debugging-address={CDP_LOOPBACK}",
        f"--user-data-dir={data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
    ]
    if minimized:
        args.append(COLLECTION_NO_WINDOW_FLAG)
        return args
    args.append(login_url)
    return args


def powershell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def is_windows_chrome_executable(chrome_exe: Path | str) -> bool:
    text = str(chrome_exe).replace("\\", "/")
    lowered = text.lower()
    if lowered.endswith(".exe"):
        return True
    if "/mnt/c/" in lowered:
        return True
    raw = str(chrome_exe)
    return len(raw) >= 3 and raw[1] == ":" and raw[2] in "\\/"


def should_launch_chrome_via_start_process(chrome_exe: Path | str) -> bool:
    """WSL interop Popen(chrome.exe) does not create a CDP listener. Use Start-Process."""
    return is_wsl() and is_windows_chrome_executable(chrome_exe)


def build_powershell_start_process_argv(chrome_cmd: list[str]) -> list[str]:
    """Windows-native Chrome launch. SPECTRE never Popen()s chrome.exe from WSL."""
    if not chrome_cmd:
        raise PathSafetyError("empty Chrome command")
    if not command_is_safe(chrome_cmd):
        raise PathSafetyError("Refusing unsafe Chrome command line")
    powershell = _find_windows_exe(("powershell.exe",), _POWERSHELL_FALLBACKS)
    if powershell is None:
        raise OSError("powershell.exe not found; WSL cannot Start-Process Google Chrome")
    exe = to_windows_path(Path(chrome_cmd[0]))
    flags = chrome_cmd[1:]
    arglist = "@(" + ",".join(powershell_single_quote(flag) for flag in flags) + ")"
    window = "Hidden" if COLLECTION_NO_WINDOW_FLAG in flags or "--start-minimized" in flags else "Normal"
    script = (
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
        "Start-Process -FilePath "
        + powershell_single_quote(exe)
        + " -ArgumentList "
        + arglist
        + " -WindowStyle "
        + window
    )
    return [str(powershell), "-NoProfile", "-NonInteractive", "-Command", script]


def command_is_safe(args: list[str]) -> bool:
    joined = " ".join(args).lower().replace("\\", "/")
    if "--remote-debugging-address=127.0.0.1" not in " ".join(args):
        return False
    if "0.0.0.0" in joined:
        return False
    if any(fragment in joined for fragment in _PERSONAL_PROFILE_FRAGMENTS):
        return False
    if "--disable-blink-features=automationcontrolled" in joined:
        return False
    if "navigator.webdriver" in joined:
        return False
    return "--user-data-dir=" in joined


def wait_cdp_http(endpoint: str, timeout_s: float = 30.0) -> bool:
    if not is_loopback_cdp_endpoint(endpoint):
        return False
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if fetch_cdp_version(endpoint, timeout_s=1.0) is not None:
            return True
        time.sleep(0.2)
    return False


def fetch_cdp_version(endpoint: str, timeout_s: float = 1.0) -> dict[str, Any] | None:
    """One-shot GET /json/version on loopback. No retry; callers poll and re-read the port file."""
    if not is_loopback_cdp_endpoint(endpoint):
        return None
    url = endpoint.rstrip("/") + "/json/version"
    try:
        with urlopen(url, timeout=max(0.2, float(timeout_s))) as response:  # noqa: S310 — loopback CDP only
            if not (200 <= int(getattr(response, "status", 200)) < 300):
                return None
            raw = response.read()
    except (OSError, URLError, TimeoutError, ValueError):
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def websocket_matches_devtools_endpoint(version: dict[str, Any] | None, endpoint: DevToolsEndpoint) -> bool:
    """webSocketDebuggerUrl must point at the current loopback DevTools port (and path, if known)."""
    if not version or not isinstance(version, dict):
        return False
    ws = str(version.get("webSocketDebuggerUrl") or "").strip()
    if not ws:
        return False
    parsed = urlparse(ws)
    if parsed.scheme not in {"ws", "wss"}:
        return False
    host = (parsed.hostname or "").lower()
    if host not in {CDP_LOOPBACK, "localhost", "::1"}:
        return False
    if parsed.port != int(endpoint.port):
        return False
    if endpoint.websocket_path:
        expected = endpoint.websocket_path if endpoint.websocket_path.startswith("/") else f"/{endpoint.websocket_path}"
        path = parsed.path or ""
        if path.rstrip("/") != expected.rstrip("/") and expected not in path:
            return False
    return True


@dataclass(frozen=True)
class DevToolsEndpoint:
    port: int
    websocket_path: str = ""

    @property
    def http_endpoint(self) -> str:
        return cdp_endpoint(self.port)


@dataclass(frozen=True)
class DevToolsFileSnapshot:
    """Pre-launch DevToolsActivePort state. Used to ignore a stale file after spawn."""

    exists: bool = False
    content: bytes = b""
    mtime_ns: int | None = None
    port: int | None = None
    websocket_path: str = ""

    def is_same_file_state(self, other: DevToolsFileSnapshot) -> bool:
        if not self.exists or not other.exists:
            return False
        if self.content and other.content and self.content == other.content:
            return True
        return (
            self.port is not None
            and self.port == other.port
            and self.mtime_ns is not None
            and self.mtime_ns == other.mtime_ns
        )


def is_spectre_owned_profile(profile_dir: Path) -> bool:
    if is_personal_chrome_profile(profile_dir):
        return False
    return (profile_dir / MARKER_NAME).is_file()


def parse_devtools_active_port(text: str) -> DevToolsEndpoint | None:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return None
    try:
        port = int(lines[0])
    except ValueError:
        return None
    if port <= 0 or port > 65535:
        return None
    ws_path = lines[1] if len(lines) > 1 else ""
    return DevToolsEndpoint(port=port, websocket_path=ws_path)


def read_spectre_devtools_active_port(profile_dir: Path) -> DevToolsEndpoint | None:
    """Read DevToolsActivePort only from a SPECTRE-owned profile. Never personal Chrome."""
    if is_personal_chrome_profile(profile_dir):
        raise PathSafetyError("Refusing to read DevToolsActivePort from a personal Chrome profile")
    if not is_spectre_owned_profile(profile_dir):
        return None
    path = profile_dir / DEVTOOLS_ACTIVE_PORT
    if not path.is_file():
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    text = decode_windows_bytes(raw)
    return parse_devtools_active_port(text)


def wait_for_spectre_devtools_active_port(
    profile_dir: Path,
    timeout_s: float = 20.0,
    *,
    sleeper: Any = None,
    clock: Any = None,
) -> DevToolsEndpoint | None:
    sleep_fn = time.sleep if sleeper is None else sleeper
    clock_fn = time.time if clock is None else clock
    deadline = clock_fn() + max(0.0, timeout_s)
    while True:
        found = read_spectre_devtools_active_port(profile_dir)
        if found is not None:
            logger.info("DevToolsActivePort: found port=%s", found.port)
            return found
        if clock_fn() >= deadline:
            break
        sleep_fn(0.15)
    logger.info("DevToolsActivePort: not found")
    return None


def snapshot_spectre_devtools_active_port(profile_dir: Path) -> DevToolsFileSnapshot:
    """Capture DevToolsActivePort bytes/mtime from a SPECTRE-owned profile only."""
    if is_personal_chrome_profile(profile_dir):
        raise PathSafetyError("Refusing to read DevToolsActivePort from a personal Chrome profile")
    if not is_spectre_owned_profile(profile_dir):
        return DevToolsFileSnapshot()
    path = profile_dir / DEVTOOLS_ACTIVE_PORT
    if not path.is_file():
        return DevToolsFileSnapshot()
    try:
        raw = path.read_bytes()
        mtime_ns = path.stat().st_mtime_ns
    except OSError:
        return DevToolsFileSnapshot()
    parsed = parse_devtools_active_port(decode_windows_bytes(raw))
    return DevToolsFileSnapshot(
        exists=True,
        content=raw,
        mtime_ns=mtime_ns,
        port=parsed.port if parsed is not None else None,
        websocket_path=parsed.websocket_path if parsed is not None else "",
    )


def discard_stale_devtools_active_port(profile_dir: Path) -> bool:
    """Remove a dead SPECTRE DevToolsActivePort before a new launch. Never personal Chrome."""
    if is_personal_chrome_profile(profile_dir):
        raise PathSafetyError("Refusing to modify a personal Chrome profile")
    if not is_spectre_owned_profile(profile_dir):
        return False
    path = profile_dir / DEVTOOLS_ACTIVE_PORT
    if not path.is_file():
        return False
    try:
        path.unlink()
    except OSError:
        logger.warning("Could not remove stale SPECTRE DevToolsActivePort")
        return False
    logger.info("Removed stale SPECTRE DevToolsActivePort")
    return True


def wait_for_spectre_cdp_ready(
    profile_dir: Path,
    timeout_s: float = 20.0,
    *,
    ignore: DevToolsFileSnapshot | None = None,
    ready_check: Any | None = None,
    sleeper: Any = None,
    clock: Any = None,
) -> DevToolsEndpoint | None:
    """Poll DevToolsActivePort until a live matching CDP is ready.

    Re-reads the file on every iteration. Never freezes the first port.
    A stale pre-launch snapshot is skipped. CDP is ready only when the file
    is valid, /json/version responds, and webSocketDebuggerUrl matches.
    """
    sleep_fn = time.sleep if sleeper is None else sleeper
    clock_fn = time.time if clock is None else clock
    check = ready_check if ready_check is not None else _devtools_endpoint_ready
    deadline = clock_fn() + max(0.0, timeout_s)
    last_port: int | None = None
    while True:
        current = snapshot_spectre_devtools_active_port(profile_dir)
        found = None
        if current.exists and not (ignore is not None and ignore.is_same_file_state(current)):
            found = read_spectre_devtools_active_port(profile_dir)
        if found is not None:
            if last_port is not None and found.port != last_port:
                logger.info("DevToolsActivePort: port changed %s -> %s", last_port, found.port)
            last_port = found.port
            if check(found):
                logger.info("DevToolsActivePort: ready port=%s", found.port)
                return found
        if clock_fn() >= deadline:
            break
        sleep_fn(0.15)
    logger.info("DevToolsActivePort: not ready")
    return None


def _devtools_endpoint_ready(endpoint: DevToolsEndpoint) -> bool:
    version = fetch_cdp_version(endpoint.http_endpoint, timeout_s=1.0)
    return websocket_matches_devtools_endpoint(version, endpoint)


def write_devtools_active_port(profile_dir: Path, port: int, websocket_path: str = "") -> Path:
    path = profile_dir / DEVTOOLS_ACTIVE_PORT
    body = f"{int(port)}\n{websocket_path}\n"
    path.write_text(body, encoding="utf-8")
    return path


def spectre_launchers_dir(settings: Settings | None = None) -> Path:
    cfg = settings or get_settings()
    chrome_root = default_chrome_profiles_root(cfg)
    return chrome_root.parent / "launchers"


def write_windows_chrome_launcher(settings: Settings | None = None) -> Path:
    """Write a password-free Windows helper that only starts SPECTRE Chrome."""
    root = ensure_secret_dir(spectre_launchers_dir(settings))
    ps1 = root / LAUNCHER_PS1
    cmd = root / LAUNCHER_CMD
    ps1.write_text(_START_SPECTRE_CHROME_PS1, encoding="utf-8")
    cmd.write_text(_START_SPECTRE_CHROME_CMD, encoding="utf-8")
    try:
        os.chmod(ps1, 0o600)
        os.chmod(cmd, 0o600)
        os.chmod(root, 0o700)
    except OSError:
        pass
    return ps1


_START_SPECTRE_CHROME_PS1 = """# SPECTRE OSINT Chrome launcher. No passwords. No cookies. No tokens.
param(
    [Parameter(Mandatory = $true)][string]$ChromeExe,
    [Parameter(Mandatory = $true)][string]$UserDataDir,
    [Parameter(Mandatory = $true)][string]$LoginUrl
)
$ErrorActionPreference = 'Stop'
if ($UserDataDir -match '(?i)Google[\\\\/]Chrome[\\\\/]User Data') {
    throw 'Refusing personal Chrome User Data directory'
}
$chromeArgs = @(
    '--remote-debugging-port=0',
    '--remote-debugging-address=127.0.0.1',
    ('--user-data-dir=' + $UserDataDir),
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-sync'
)
if ([string]::IsNullOrWhiteSpace($LoginUrl) -or $LoginUrl -eq 'about:blank' -or $LoginUrl -eq '--no-startup-window') {
    $chromeArgs += '--no-startup-window'
    $window = 'Hidden'
} else {
    $chromeArgs += $LoginUrl
    $window = 'Normal'
}
$proc = Start-Process -FilePath $ChromeExe -ArgumentList $chromeArgs -WindowStyle $window -PassThru
if ($null -ne $proc) {
    Set-Content -Path (Join-Path $UserDataDir '.spectre-launch.pid') -Value $proc.Id -Encoding ASCII
}
"""

_START_SPECTRE_CHROME_CMD = """@echo off
REM SPECTRE OSINT Chrome launcher wrapper. No passwords. No cookies. No tokens.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-SpectreChrome.ps1" %*
"""


def parse_user_data_dir_arg(chrome_cmd: list[str]) -> str | None:
    for item in chrome_cmd:
        if item.startswith("--user-data-dir="):
            return item.split("=", 1)[1]
    return None


def spawn_via_windows_helper(chrome_cmd: list[str], settings: Settings | None = None) -> None:
    """Launch the helper through cmd.exe start so Windows owns the process."""
    if not command_is_safe(chrome_cmd):
        raise PathSafetyError("Refusing unsafe Chrome command line")
    cmd_exe = _find_windows_exe(("cmd.exe",), _CMD_FALLBACKS)
    if cmd_exe is None:
        raise OSError("cmd.exe not found; cannot start Windows Chrome helper")
    ps1 = write_windows_chrome_launcher(settings)
    cmd_wrapper = ps1.with_name(LAUNCHER_CMD)
    exe = to_windows_path(Path(chrome_cmd[0]))
    user_data = parse_user_data_dir_arg(chrome_cmd)
    login_url = chrome_cmd[-1] if chrome_cmd else ""
    if login_url.startswith("--"):
        login_url = COLLECTION_NO_WINDOW_FLAG
    if not user_data:
        raise PathSafetyError("Chrome helper requires --user-data-dir")
    argv = [
        str(cmd_exe),
        "/c",
        "start",
        "",
        to_windows_path(cmd_wrapper),
        "-ChromeExe",
        exe,
        "-UserDataDir",
        user_data,
        "-LoginUrl",
        login_url,
    ]
    captured = run_capture_bytes(argv, timeout=15.0)
    if captured is None:
        raise OSError("Windows Chrome helper failed to start")
    code, stdout, stderr = captured
    decode_windows_bytes(stdout)
    decode_windows_bytes(stderr)
    if code != 0:
        raise OSError("Windows Chrome helper exited with an error")


def read_spectre_launch_pid(profile_dir: Path) -> int | None:
    if is_personal_chrome_profile(profile_dir) or not is_spectre_owned_profile(profile_dir):
        return None
    path = profile_dir / LAUNCH_PID_FILE
    if not path.is_file():
        return None
    try:
        text = decode_windows_bytes(path.read_bytes()).strip().splitlines()
    except OSError:
        return None
    if not text:
        return None
    try:
        pid = int(text[0].strip())
    except ValueError:
        return None
    return pid if pid > 0 else None


def stop_spectre_launched_chrome(profile_dir: Path) -> bool:
    """Stop only the Chrome PID SPECTRE recorded. Never touches personal Chrome."""
    pid = read_spectre_launch_pid(profile_dir)
    if pid is None:
        return False
    powershell = _find_windows_exe(("powershell.exe",), _POWERSHELL_FALLBACKS)
    if powershell is None:
        return False
    script = (
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
        f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"
    )
    captured = run_capture_bytes(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=8.0,
    )
    pid_path = profile_dir / LAUNCH_PID_FILE
    try:
        pid_path.unlink(missing_ok=True)
    except OSError:
        pass
    return captured is not None


def probe_spectre_cdp(
    profile_dir: Path,
    *,
    http_ok: Any | None = None,
) -> DevToolsEndpoint | None:
    """Attach candidate: SPECTRE profile + DevToolsActivePort + live loopback CDP."""
    try:
        endpoint = read_spectre_devtools_active_port(profile_dir)
    except PathSafetyError:
        return None
    if endpoint is None:
        return None
    if not is_loopback_cdp_endpoint(endpoint.http_endpoint):
        return None
    if http_ok is not None:
        try:
            ok = bool(http_ok(endpoint.http_endpoint, 2.0))
        except TypeError:
            ok = bool(http_ok(endpoint.http_endpoint))
        return endpoint if ok else None
    deadline = time.time() + 2.0
    while True:
        version = fetch_cdp_version(endpoint.http_endpoint, timeout_s=1.0)
        if websocket_matches_devtools_endpoint(version, endpoint):
            return endpoint
        if time.time() >= deadline:
            return None
        time.sleep(0.2)



class ProcessChromeLauncher:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def resolve_chrome(self) -> Path | None:
        return resolve_chrome_executable(self.settings)

    def spawn(self, args: list[str]) -> Any:
        if not command_is_safe(args):
            raise PathSafetyError("Refusing unsafe Chrome command line")
        if should_launch_chrome_via_start_process(args[0]):
            ps_argv = build_powershell_start_process_argv(args)
            logger.info(
                "Launching SPECTRE-owned Chrome via Windows Start-Process (CDP loopback). "
                "Password is never collected."
            )
            captured = run_capture_bytes(ps_argv, timeout=15.0)
            if captured is None:
                raise OSError("PowerShell Start-Process failed to start")
            code, stdout, stderr = captured
            decode_windows_bytes(stdout)
            decode_windows_bytes(stderr)
            if code != 0:
                raise OSError("PowerShell Start-Process exited with an error")
            return None
        logger.info("Launching SPECTRE-owned Chrome (CDP loopback). Password is never collected.")
        return subprocess.Popen(  # noqa: S603 — args built internally, executable resolved
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def spawn_windows_helper(self, args: list[str]) -> Any:
        logger.info("Launching SPECTRE Chrome helper in Windows session (cmd start).")
        spawn_via_windows_helper(args, self.settings)
        return None

    async def wait_cdp(self, endpoint: str, timeout_s: float = 30.0) -> bool:
        return wait_cdp_http(endpoint, timeout_s=timeout_s)

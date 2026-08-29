# Authenticated Public Sessions

[English](authenticated-public.md) | [Português 🇧🇷](authenticated-public.pt-BR.md)

SPECTRE features an **Authenticated Public** collection mode (`AUTHENTICATED_PUBLIC`), enabling investigators to view public profiles on platforms that enforce login walls against anonymous scraping.

---

## What It Is vs. What It Is Not

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AUTHENTICATED PUBLIC PRINCIPLES                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✔  Operator's own session used to fetch public profile pages               │
│  ✔  Interactive manual login in a visible browser window                   │
│  ✔  Strictly isolated in a SPECTRE-owned Chromium profile                   │
│  ✖  NOT private access (no direct messages, friends-only posts, or vaults)  │
│  ✖  NOT a password manager (SPECTRE never asks for or stores passwords)     │
│  ✖  NOT a CAPTCHA solver or TLS stealth spoofer                             │
│  ✖  NEVER touches the operator's personal browser profile or cookies        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Supported Platforms

The following platforms are defined in `AUTH_PLATFORMS` (`browser/models.py`):
- `instagram`
- `facebook`
- `threads`
- `tiktok`
- `x`
- `twitch`

When no authenticated session is configured for a platform, SPECTRE queries the platform anonymously. If a login wall is encountered, it records `LOGIN_REQUIRED` and continues with the rest of the investigation.

---

## Browser Architecture & Profile Isolation

SPECTRE supports two browser backends (`SPECTRE_BROWSER_BACKEND`):
1. **Google Chrome CDP (Loopback):** Launches a separate Chrome instance binding strictly to `127.0.0.1` on a dynamic port (`9222–9299`).
2. **Playwright Backend:** Manages browser contexts via Playwright drivers.

### Safety Boundaries

- **Dedicated Profiles:** All profiles reside under `~/.local/share/spectre/browser-profiles` (or `SPECTRE_BROWSER_PROFILES_DIR`) and carry a `.spectre-owned` security marker.
- **Personal Browser Rejection:** The engine inspects paths and will immediately raise a `PathSafetyError` if pointed at a personal Chrome or Edge `User Data` directory.
- **Loopback Enforcement:** Remote debugging ports bind exclusively to `127.0.0.1` and refuse connections to `0.0.0.0` or external network adapters.

---

## Managing Sessions via CLI

### 1. Interactive Manual Login

To establish a session, initiate the login command:

```bash
spectre auth login instagram
```

A visible browser window will open displaying the official platform login page. The operator completes authentication (including 2FA/MFA if configured). Once logged in, press **Enter** in the terminal to save the session state.

### 2. Check Active Session Status

```bash
spectre auth status
```

Output:
```text
AUTHENTICATED PUBLIC SESSIONS
Platform     Status    Storage    Last Verified
Instagram    ACTIVE    file       2026-08-27 15:30 UTC
Facebook     OFF       -          -
X            ACTIVE    keyring    2026-08-27 14:15 UTC
```

### 3. Logout and Remove Session Data

```bash
spectre auth logout instagram
```

---

## Session Storage & Security

Session cookies are stored locally in `storage_state.json` under the platform auth directory or wrapped in the system OS Keyring (`keyring_enabled=True`).

- On POSIX filesystems, auth directories are created with `0700` mode and session files with `0600` mode.
- Session files, cookies, and tokens are **strictly ignored by git** and must never be committed to repositories.
- `spectre doctor` inspects only the boolean session state (`ACTIVE` vs `NOT_CONFIGURED`) and never reads or displays plaintext cookie values.

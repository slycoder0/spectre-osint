# Quick Start Guide

This guide walks you through installing and running your first investigation with **SPECTRE OSINT**.

---

## 1. Prerequisites

- **Python 3.12** or **3.13** installed.
- **Git** installed.

---

## 2. Installation

=== "Linux / macOS"
    ```bash
    git clone https://github.com/slycoder0/spectre-osint.git
    cd spectre-osint
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e .
    ```

=== "Windows (PowerShell)"
    ```powershell
    git clone https://github.com/slycoder0/spectre-osint.git
    cd spectre-osint
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -e .
    ```

---

## 3. Verify Health: `spectre doctor`

```bash
spectre doctor
```

---

## 4. Run First Investigation

```bash
spectre username alice_osint
```

Investigation findings will be output to your terminal and saved locally under `reports/`.

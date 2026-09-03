# SPECTRE OSINT (English Documentation)

Welcome to the English documentation hub for **SPECTRE OSINT**, a CLI-first public intelligence workstation for investigating digital footprints.

---

## 🧭 Navigation

- 🚀 [English Quick Start Guide](quick-start.md)
- 📖 [CLI Commands Reference](commands.md)
- 🇧🇷 [Full Portuguese Documentation Suite](../index.md)

---

## ⚡ 30-Second Example

```bash
# Verify environment readiness
spectre doctor

# Investigate a public username
spectre username alice_osint

# Comprehensive investigation with leads and HTML dossier
spectre investigate alice_osint --email alice@example.com --website https://alice.example
```

---

## 🛡️ Core Principles

- **CLI-First:** Built for high-speed terminal investigations and automated SOC pipelines.
- **Passive-First:** Collection is passive by default — public sources are read without probing the target's own infrastructure. The single exception is `spectre network`, an opt-in **active** TCP connect scan that is disabled by default and runs only when the operator passes `--authorized` and confirms authorization interactively. See [Privacidade & Segurança](../concepts/privacy-and-safety.md) (Portuguese).
- **Evidence-First:** Strict provenance tracking; identity is never assumed from HTTP 200 responses or matching handles alone.

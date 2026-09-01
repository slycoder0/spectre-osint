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
- **Passive-First:** Gathers public information without intrusive network probing.
- **Evidence-First:** Strict provenance tracking; identity is never assumed from HTTP 200 responses or matching handles alone.

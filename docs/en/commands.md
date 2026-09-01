# CLI Commands Reference

| Intent | Command | Description |
| :--- | :--- | :--- |
| **Check Environment** | `spectre doctor` | Verifies install, database, and providers without printing secrets. |
| **Username Investigation** | `spectre username <handle>` | Sweeps public platforms in Site Catalog with metadata extraction. |
| **Email Investigation** | `spectre email <email>` | Validates syntax, MX records, and public footprint. |
| **Domain Intelligence** | `spectre domain <domain>` | DNS, RDAP registration, CT logs, and host fingerprinting. |
| **IP Intelligence** | `spectre ip <ip>` | ASN, network allocation, and threat footprint. |
| **Full Investigation** | `spectre investigate <target>` | Full pipeline with correlation, entity graph, and HTML dossier. |
| **Generate Reports** | `spectre report [case]` | Regenerates investigation artifacts (HTML, JSON, Markdown, GraphML). |
| **Authenticated Public Status**| `spectre auth status` | Inspects status of dedicated browser sessions. |
| **Authenticated Login** | `spectre auth login <platform>`| Opens visible browser for interactive manual login. |
| **Authenticated Logout**| `spectre auth logout <platform>`| Removes local session state and wipes the dedicated SPECTRE browser profile for the platform (does not affect remote accounts or personal browser). |
| **Authenticated Clear** | `spectre auth clear <platform>` | Alias for logout — removes local session state and wipes the dedicated SPECTRE browser profile. |
| **Cache Status** | `spectre cache status` | Displays local cached records and expiration status. |
| **Cache Clear** | `spectre cache clear` | Clears local OSINT result cache entries. |

# Guia de Diagnóstico e Resolução de Problemas (Troubleshooting)

[English](troubleshooting.md) | [Português 🇧🇷](troubleshooting.pt-BR.md)

Este guia cobre dúvidas operacionais comuns, comportamentos de rate limit de plataformas e etapas de resolução de problemas no SPECTRE OSINT.

---

## 1. Status do `spectre doctor`

### `READY WITH OPTIONAL FEATURES MISSING`
- **É um erro?** Não. O SPECTRE é projetado para funcionar imediatamente sem a necessidade de chaves de API pagas ou serviços externos.
- **Por que os provedores estão como `NOT CONFIGURED`?** Recursos como VirusTotal, Shodan ou SearXNG local são complementos opcionais. Quando ausentes, essas consultas são ignoradas sem interromper a investigação.

### `ACTION REQUIRED`
- **Diretório de relatórios ou banco sem permissão de escrita:** Verifique as permissões de acesso nas pastas `./data` e `./reports`.
- **Endereço de bind fora do loopback:** Por padrão, o painel web escuta estritamente em `127.0.0.1`. Se `SPECTRE_WEB_HOST` for definido como `0.0.0.0`, você deve configurar `SPECTRE_ALLOW_PUBLIC_BIND=true` como reconhecimento explícito de risco.

---

## 2. Comportamentos de Plataformas e Filtragem de Borda

### `LOGIN_REQUIRED`
- **Causa:** Plataformas como Instagram, Facebook ou X bloqueiam o acesso anônimo a perfis públicos com telas de login.
- **Solução:** Utilize o modo de coleta [Authenticated Public](authenticated-public.pt-BR.md):
  ```bash
  spectre auth login instagram
  ```

### `RATE_LIMITED` / `BLOCKED`
- **Causa:** A plataforma retornou HTTP `429 Too Many Requests` ou tela de bloqueio de WAF/Cloudflare.
- **Comportamento:** O SPECTRE não utiliza rotação de proxies nem spoofing de TLS. Ele registra o status factual e avança para a próxima fonte. Aguarde alguns minutos antes de consultar a mesma plataforma novamente.

### `PROVIDER_UNAVAILABLE` (Circuit Breaker)
- **Causa:** Timeouts repetidos de rede ou falhas de DNS em um provedor remoto específico (ex.: `html.duckduckgo.com`).
- **Comportamento:** O SPECTRE aciona um circuit breaker por host para falhar rapidamente em consultas subsequentes ao mesmo provedor durante a mesma investigação, evitando esperas desnecessárias.

---

## 3. Especificidades de Plataforma: Windows e WSL2

- **Windows Nativo vs. WSL2:** O SPECTRE é validado tanto em Windows 11 nativo quanto em Ubuntu/WSL2.
- **Integração com Chrome CDP:** No WSL2, o SPECTRE conecta-se ao Google Chrome instalado no host Windows via PowerShell `Start-Process`. No Windows nativo, executa o `chrome.exe` diretamente.

---

## 4. Gerenciamento de Cache

Se você suspeitar de dados obsoletos de consultas anteriores:

```bash
# Ver métricas de cache
spectre cache stats

# Limpar o cache
spectre cache clear

# Ou forçar requisições ao vivo na investigação
spectre username alice_osint --refresh
```

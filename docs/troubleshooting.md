# Resolução de Problemas (Troubleshooting)

Problemas frequentes encontrados durante instalação, execução e testes do **SPECTRE OSINT**, com suas soluções.

---

## 1. Problemas no Windows (PowerShell)

### Política de Execução de Scripts Bloqueada
**Sintoma:** Ao ativar o ambiente virtual com `.\.venv\Scripts\Activate.ps1`, o PowerShell exibe:
> `File ...\Activate.ps1 cannot be loaded because running scripts is disabled on this system.`

**Solução:**
Execute no PowerShell atual:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### Erro de Permissão no Diretório Temporário do Pytest
**Sintoma:** Ao executar `pytest`, ocorre `PermissionError` em pasta temporária do Windows.

**Solução:**
Execute o pytest desativando o cache provider ou especificando pasta temporária:
```powershell
python -m pytest -q -p no:cacheprovider
```

---

## 2. Problemas com o Navegador (Playwright / Chromium)

### Chromium Não Encontrado para Sessões Autenticadas
**Sintoma:** `spectre auth login <plataforma>` falha informando ausência do executável do navegador.

**Solução:**
Instale o Chromium via Playwright:
```bash
playwright install chromium
```

### Erro `PathSafetyError`
**Sintoma:** O SPECTRE recusa iniciar a sessão informando `PathSafetyError`.

**Solução:**
O SPECTRE **recusa explicitamente** utilizar perfis pessoais do seu navegador padrão para proteger seus dados pessoais. As sessões usam sempre perfis dedicados do próprio SPECTRE, marcados com `.spectre-owned`, e os caminhos padrão **dependem do sistema operacional**. Além disso, os dois backends mantêm **raízes de perfil distintas**: uma para Chromium/Playwright (`SPECTRE_BROWSER_PROFILES_DIR`) e outra para o Google Chrome via CDP (`SPECTRE_CHROME_PROFILES_DIR`).

Os padrões por sistema operacional estão em [Configuração](configuration.md) e o detalhamento por backend em [Authenticated Public](technical/authenticated-public.md). Se uma dessas variáveis apontar para um diretório de perfil pessoal do Chrome/Edge, o `PathSafetyError` é exatamente o comportamento esperado.

---

## 3. Limites de Taxa e Bloqueios

### Resposta `RATE_LIMITED` (HTTP 429)
**Causa:** Plataformas como Reddit ou GitHub limitam consultas anônimas por IP por minuto.

**Soluções:**
1. O SPECTRE aplica backoff exponencial automaticamente.
2. Para o GitHub, configure um `GITHUB_TOKEN` no arquivo `.env` para elevar o limite de 60 requisições/hora para 5.000 requisições/hora.
3. Consulte o status do cache local com `spectre cache status`.

### Resposta `BLOCKED`
**Causa:** A plataforma retornou código 401/403 ou desafio de borda WAF. O SPECTRE não realiza evasão ativa. Para plataformas com login-wall (ex: Instagram), utilize o fluxo oficial `spectre auth login`.

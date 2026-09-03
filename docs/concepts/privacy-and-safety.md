# Privacidade & Limites Operacionais

O SPECTRE OSINT foi desenvolvido para conduzir investigações eficientes e transparentes, garantindo a segurança operacional do pesquisador e respeitando limites éticos.

---

## 1. Execução Local & Armazenamento Local

- **Processamento & Armazenamento Local:** Toda a análise, correlação, pontuação, banco SQLite (`data/spectre.db`), logs (`logs/`) e relatórios (`reports/`) residem e são executados exclusivamente no seu computador.
- **Requisições Externas da Investigação:** Para consultar dados públicos, o SPECTRE envia requisições HTTP de saída diretamente aos provedores configurados. Termos e identificadores derivados das pistas informadas pelo operador (como handles, nomes, e-mails ou domínios) podem ser incorporados às consultas enviadas aos motores de busca e APIs públicas correspondentes.
- **Sem Telemetria:** O SPECTRE não coleta nem transmite telemetria de uso, métricas analíticas ou rastreamento de comportamento do operador para servidores externos.

---

## 2. Política de SSRF (Server-Side Request Forgery)

O cliente HTTP central (`core/http_client.py`) aplica política de proteção SSRF ativada por padrão (`SPECTRE_SSRF_ENABLED=true`):

- **Bloqueio de Redes Locais/Privadas:** Bloqueia conexões a `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` e `::1`.
- **Bloqueio de Metadados de Nuvem:** O endereço `169.254.169.254` (usado para credenciais de instâncias em nuvem) é estritamente bloqueado.
- **Exceção Documentada:** Apenas a URL configurada explicitamente em `SEARXNG_URL` (para instância local SearXNG) pode utilizar loopback.

---

## 3. Isolamento Total de Sessões do Navegador

No modo `AUTHENTICATED_PUBLIC`:

- O SPECTRE gerencia seus próprios perfis dedicados com marcador `.spectre-owned`, em **duas árvores separadas**: uma para perfis do Chromium/Playwright (`SPECTRE_BROWSER_PROFILES_DIR`, por padrão `~/.local/share/spectre/browser-profiles/`) e outra para perfis do Google Chrome usados via CDP (`SPECTRE_CHROME_PROFILES_DIR`, por padrão `%USERPROFILE%\.spectre\chrome` no Windows/WSL). Os caminhos padrão por sistema operacional estão em [Configuração](../configuration.md).
- **Proteção do Navegador Pessoal:** O SPECTRE recusa categoricamente apontamentos para diretórios de dados pessoais de navegadores do usuário (`PathSafetyError`).
- **Zero Captura de Senhas:** O login é feito manualmente pelo operador em janela visível; o SPECTRE nunca recebe, manipula ou grava credenciais.
- **Estado de sessão não é apenas cookie.** O registro de sessão do backend Playwright pode conter cookies **e** estado por origem (`localStorage`); no backend Chrome CDP o registro salvo é apenas um sentinela sem segredos e o estado autenticado permanece no perfil dedicado do Chrome. Ao proteger, copiar ou apagar esses artefatos, trate também os diretórios de perfil — não só `storage_state.json`. O detalhamento por backend está em [Authenticated Public](../technical/authenticated-public.md).

---

## 4. Limites Éticos e Operacionais

- **Coleta Passiva por Padrão:** Por padrão, o SPECTRE coleta apenas informações tornadas públicas pelas plataformas, sem sondar diretamente a infraestrutura do alvo.
- **Exceção — Reconhecimento Ativo Autorizado:** O comando `spectre network` é a única exceção e executa reconhecimento **ativo**. Nunca ocorre automaticamente: exige a flag `--authorized` e, adicionalmente, confirmação interativa do operador no terminal. Restringe-se a sondagens TCP connect em uma lista limitada de portas, com leitura opcional de banner; não realiza exploração, força bruta, ataques a credenciais, varredura em massa nem evasão.
- **Sem Evasão Hostil:** Não resolve CAPTCHAs, não quebra autenticações, não manipula impressões digitais TLS e não realiza rotação de proxies.
- **Sem Acesso a Conteúdos Privados:** Não acessa mensagens diretas (DMs), feeds restritos a amigos ou áreas protegidas por controles de privacidade.

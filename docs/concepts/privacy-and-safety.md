# Privacidade & Limites Operacionais

O SPECTRE OSINT foi desenvolvido para conduzir investigações eficientes e transparentes, garantindo a segurança operacional do pesquisador e respeitando limites éticos.

---

## 1. Execução Local & Armazenamento Local

- **Processamento no Host:** Toda a lógica de análise, correlação, pontuação e geração de relatórios roda exclusivamente no seu computador.
- **Persistência Local:** Banco SQLite (`data/spectre.db`), logs (`logs/`) e relatórios (`reports/`) residem no seu disco. Nenhuma telemetria de uso ou dados de casos são enviados a servidores externos.
- **Coleta Externa Passiva:** Para obter os dados públicos, o SPECTRE realiza requisições HTTP de saída diretamente para os provedores públicos de internet configurados.

---

## 2. Política de SSRF (Server-Side Request Forgery)

O cliente HTTP central (`core/http_client.py`) aplica política de proteção SSRF ativada por padrão (`SPECTRE_SSRF_ENABLED=true`):

- **Bloqueio de Redes Locais/Privadas:** Bloqueia conexões a `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` e `::1`.
- **Bloqueio de Metadados de Nuvem:** O endereço `169.254.169.254` (usado para credenciais de instâncias em nuvem) é estritamente bloqueado.
- **Exceção Documentada:** Apenas a URL configurada explicitamente em `SEARXNG_URL` (para instância local SearXNG) pode utilizar loopback.

---

## 3. Isolamento Total de Sessões do Navegador

No modo `AUTHENTICATED_PUBLIC`:

- O SPECTRE gerencia seus próprios perfis dedicados do Chromium sob a pasta `~/.local/share/spectre/browser-profiles/` com marcador `.spectre-owned`.
- **Proteção do Navegador Pessoal:** O SPECTRE recusa categoricamente apontamentos para diretórios de dados pessoais de navegadores do usuário (`PathSafetyError`).
- **Zero Captura de Senhas:** O login é feito manualmente pelo operador em janela visível. O SPECTRE armazena apenas os cookies de sessão pública necessários para as consultas, nunca manipulando ou gravando senhas.

---

## 4. Limites Éticos e Operacionais

- **Coleta Passiva:** Coleta apenas informações tornadas públicas pelas plataformas.
- **Sem Evasão Hostil:** Não resolve CAPTCHAs, não quebra autenticações, não manipula impressões digitais TLS e não realiza rotação de proxies.
- **Sem Acesso a Conteúdos Privados:** Não acessa mensagens diretas (DMs), feeds restritos a amigos ou áreas protegidas por controles de privacidade.

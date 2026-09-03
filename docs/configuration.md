# Referência Completa de Configuração

O SPECTRE é configurado através de variáveis de ambiente e arquivos `.env` locais, gerenciados de forma tipada pelo Pydantic Settings (`spectre_osint/core/config.py`).

O fluxo principal de investigação opera sem chaves pagas. As integrações opcionais ampliam a cobertura e elevam os limites de quota.

---

## Arquivo `.env`

Para personalizar as opções, crie um arquivo `.env` na raiz do projeto:

```bash
cp .env.example .env
```

---

## Configurações Principais

### 1. Diretórios e Armazenamento Local

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `SPECTRE_DATA_DIR` | `./data` | Diretório para banco de dados SQLite e cache local. |
| `SPECTRE_REPORTS_DIR` | `./reports` | Diretório onde relatórios HTML, JSON e GraphML são salvos. |
| `SPECTRE_LOGS_DIR` | `./logs` | Diretório para arquivos de log de execução. |
| `SPECTRE_LOG_LEVEL` | `INFO` | Nível de verbosidade de log (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `SPECTRE_DATABASE_URL` | `""` (vazio) | URL de conexão SQLAlchemy. Quando vazia, o runtime deriva automaticamente `sqlite:///<SPECTRE_DATA_DIR>/spectre.db`. O `.env.example` sugere `sqlite:///./data/spectre.db`. |

### 2. Rede, Resiliência HTTP & SSRF

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `SPECTRE_HTTP_TIMEOUT` | `20.0` | Timeout padrão em segundos para requisições HTTP. |
| `SPECTRE_MAX_CONCURRENCY` | `8` | Concorrência máxima para varreduras paralelas do catálogo. |
| `SPECTRE_HTTP_MAX_RETRIES` | `3` | Número máximo de tentativas **totais** para requisições HTTP idempotentes (`GET`/`HEAD`) diante de códigos transitórios (429, 500, 502, 503, 504); o padrão permite a tentativa inicial mais até 2 retentativas, sujeito ao orçamento de retry. |
| `SPECTRE_HTTP_RETRY_BUDGET` | `20.0` | Orçamento total em segundos para tentativas de retry por requisição. |
| `SPECTRE_HTTP_MAX_BACKOFF` | `30.0` | Tempo máximo de espera exponencial de backoff. |
| `SPECTRE_HTTP_CIRCUIT_FAILURES`| `3` | Limiar de falhas consecutivas antes de desativar temporariamente um provedor. |
| `SPECTRE_USER_AGENT` | `SPECTRE-OSINT/0.1-alpha (+passive-osint)` | Header `User-Agent` padrão para requisições HTTP. |
| `SPECTRE_SSRF_ENABLED` | `true` | Bloqueia requisições a redes privadas, loopback e metadados de nuvem (`169.254.169.254`). |
| `SPECTRE_ALLOW_PRIVATE_TARGETS`| `false` | Permite explicitamente alvos em redes privadas se ativado pelo operador. |
| `SPECTRE_PIVOT_BUDGET` | `8` | Limite de pivôs automáticos por execução padrão. |

### 3. Inteligência de Busca & Discovery

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `SEARXNG_URL` | `None` | URL de instância local SearXNG (ex: `http://127.0.0.1:8888`). |
| `SPECTRE_SEARCH_QUERY_BUDGET` | `12` | Orçamento máximo de consultas dorking por execução de username. |
| `SPECTRE_SEARCH_MAX_PIVOTS` | `25` | Limite máximo de novos pivôs de descoberta extraídos por caso. |
| `SPECTRE_SEARCH_MAX_DEPTH` | `2` | Profundidade máxima de busca recursiva para pivôs. |
| `GOOGLE_API_KEY` | `None` | Chave de API para o Google Custom Search Engine (opcional; helper `spectre search`). |
| `GOOGLE_CSE_ID` | `None` | Identificador do Custom Search Engine do Google (opcional; helper `spectre search`). |

### 4. Cache TTL (Tempo de Expiração em Segundos)

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `SPECTRE_CACHE_DEFAULT_TTL` | `1800` (30 min) | TTL padrão para respostas HTTP em cache. |
| `SPECTRE_CACHE_DNS_TTL` | `600` (10 min) | Configuração existente no `ResultCache`, mas o resolver DNS atual consulta `dnspython` diretamente e não utiliza esse cache; alterar esta variável ainda não modifica o TTL efetivo das resoluções DNS nesta versão. |
| `SPECTRE_CACHE_RDAP_TTL` | `86400` (24 h) | TTL para dados de registro Whois/RDAP. |
| `SPECTRE_CACHE_VT_TTL` | `3600` (1 h) | TTL para consultas VirusTotal. |
| `SPECTRE_CACHE_CRTSH_TTL` | `21600` (6 h) | TTL para logs de Certificate Transparency. |
| `SPECTRE_CACHE_USERNAME_TTL` | `21600` (6 h) | TTL para varreduras de username no catálogo. |
| `SPECTRE_CACHE_WAYBACK_TTL` | `21600` (6 h) | Configuração existente, mas o `WaybackProvider` atual utiliza `SPECTRE_CACHE_DEFAULT_TTL`; alterar esta variável ainda não modifica o TTL efetivo do Wayback nesta versão. |
| `SPECTRE_CACHE_HEALTH_TTL` | `900` (15 min) | Configuração existente no `ResultCache`, mas as verificações de integridade de provedores atuais não utilizam entradas de cache com o tipo `health`; alterar esta variável ainda não modifica o TTL efetivo dos health checks nesta versão. |

### 5. Navegador & Sessões Autenticadas

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `SPECTRE_AUTH_DIR` | `None` | Diretório de armazenamento de sessões autenticadas. Padrão no Linux/BSD: `~/.local/share/spectre/auth` (respeita `XDG_DATA_HOME`); no macOS: `~/Library/Application Support/spectre/auth`. |
| `SPECTRE_BROWSER_PROFILES_DIR` | `None` | Diretório para perfis dedicados do Chromium (`.spectre-owned`). Padrão no Linux/BSD: `~/.local/share/spectre/browser-profiles`; no macOS: `~/Library/Application Support/spectre/browser-profiles`. |
| `SPECTRE_CHROME_PATH` | `None` | Caminho explícito do executável do Google Chrome no sistema. |
| `SPECTRE_CHROME_PROFILES_DIR` | `None` | Diretório dedicado para perfis do Google Chrome via CDP loopback — árvore separada dos perfis do Playwright. Padrão no Windows/WSL: `%USERPROFILE%\.spectre\chrome`; no macOS: `~/Library/Application Support/spectre/chrome`; no Linux/BSD: `~/.local/share/spectre/chrome-profiles`. Contém o estado autenticado real do backend Chrome CDP. |
| `SPECTRE_WINDOWS_USERPROFILE` | `None` | Caminho do perfil de usuário do Windows quando em ambiente WSL. |
| `SPECTRE_BROWSER_BACKEND` | `playwright` | Backend de automação de navegador (`playwright` ou `chrome_cdp`). |
| `SPECTRE_BROWSER_VISIBLE` | `false` | Executa o navegador de coleta em modo visível (o login manual é sempre visível). |
| `SPECTRE_KEYRING` | `true` | Utiliza armazenamento protegido no chaveiro do sistema operacional (Keyring) quando disponível, com fallback para arquivo local com permissão restrita 0600. Aplica-se apenas ao registro de sessão do `SessionStore`; os diretórios de perfil do navegador continuam em disco (protegidos por permissão `0700`, sem criptografia própria do SPECTRE). |

### 6. Provedores de Threat Intelligence

- **Keyless (sempre consultados sem chave):** `crt.sh`, `RDAP`, `Wayback Machine`.
- **Optional Key:** `GitHub`, `URLScan`, `IPinfo`, `GreyNoise` e `AlienVault OTX` não são bloqueados pela ausência da credencial na configuração; quando disponível, cada provedor utiliza sua credencial opcional conforme a implementação.
- **Required Key (ignorados se a chave não estiver configurada):** `VirusTotal`, `Shodan`, `Censys`, `AbuseIPDB`, `HIBP`.

| Variável | Provedor | Categoria | Descrição |
| :--- | :--- | :--- | :--- |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Requer chave | Reputação de domínios, IPs, URLs e hashes. |
| `SHODAN_API_KEY` | Shodan | Requer chave | Consulta de serviços históricos indexados (não realiza varredura ativa). |
| `CENSYS_API_ID` | Censys | Requer chave | ID da API Censys Search. |
| `CENSYS_API_SECRET` | Censys | Requer chave | Segredo da API Censys Search. |
| `URLSCAN_API_KEY` | URLScan | Chave opcional | Consulta de resultados públicos no URLScan; a chave opcional é enviada nas consultas ao endpoint de busca. |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Requer chave | Relatórios de reputação e abuso de IPs. |
| `HIBP_API_KEY` | HaveIBeenPwned | Requer chave | Histórico de vazamentos de e-mails. |
| `IPINFO_TOKEN` | IPinfo | Chave opcional | Geolocalização e ASN com limite ampliado. |
| `GREYNOISE_API_KEY` | GreyNoise | Chave opcional | Classificação de tráfego de scanner/ruído na internet. |
| `GITHUB_TOKEN` | GitHub API | Chave opcional | Eleva limite de requisições de 60/h para 5.000/h. |
| `OTX_API_KEY` | AlienVault OTX | Chave opcional | Indicadores de ameaça (pulses). |

### 7. Apresentação no Terminal (Banner)

Estas duas variáveis **não são campos de `Settings`**: são lidas diretamente do ambiente do processo por `_want_banner()` em `spectre_osint/cli/display.py`. Como o `Settings` carrega o `.env` apenas para os próprios campos (`env_file=".env"` com `extra="ignore"`) e o projeto não utiliza `load_dotenv`, **declará-las no arquivo `.env` não produz efeito** — elas precisam estar exportadas no ambiente do shell.

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `SPECTRE_NO_BANNER` | não definida | Qualquer valor **não vazio** suprime o banner ASCII nos comandos que o imprimem. Equivale à opção global `--no-banner`. |
| `NO_BANNER` | não definida | Mesma semântica, na convenção genérica sem prefixo. Qualquer valor não vazio também suprime o banner. |

Limites que o operador precisa conhecer:

- **O valor não é interpretado como booleano.** Apenas a presença de uma string não vazia é testada, portanto `SPECTRE_NO_BANNER=0` e `SPECTRE_NO_BANNER=false` **também suprimem** o banner. Para manter o banner, deixe a variável indefinida (ou com string vazia).
- **Basta uma das três formas.** `--no-banner`, `SPECTRE_NO_BANNER` e `NO_BANNER` são verificadas de forma independente; qualquer uma delas ativa é suficiente.
- **O escopo é apenas o banner.** Suprimi-lo não altera as tabelas de resultado, o nível de log, nem a apresentação controlada por `--compact` e `--verbose`.

---

## Configurações do Módulo LLM (Experimental / Não Conectado)

O SPECTRE opera por padrão com análise determinística sem modelos de linguagem. O helper de sumarização (`summarize_optional` em `spectre_osint/llm/`) existe no código, mas atualmente não está conectado ao pipeline principal de investigação. O helper existente implementa atualmente apenas um endpoint compatível com a API da OpenAI (configurado pelas variáveis `OPENAI_*`) e um fallback local para o Ollama (`OLLAMA_*`). Portanto, definir `LLM_ENABLED=true` nesta versão não executa sumarização nem produz achados `AI_ANALYSIS`:

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `LLM_ENABLED` | `false` | Flag de configuração experimental do módulo LLM. O helper de sumarização não está conectado ao pipeline principal nesta versão; definir como `true` isoladamente não executa sumarização durante investigações. |
| `OPENAI_API_KEY` | `None` | Chave de API da OpenAI (módulo experimental). |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | URL base da API compatível com OpenAI. |
| `OPENAI_MODEL` | `gpt-4o-mini` | Modelo para o helper experimental de sumarização. |
| `ANTHROPIC_API_KEY` | `None` | Setting reservada e inspecionada pelo `doctor`; não é consumida pelo helper LLM atual. |
| `OPENROUTER_API_KEY`| `None` | Setting reservada e inspecionada pelo `doctor`; não é consumida diretamente pelo helper LLM atual. |
| `GEMINI_API_KEY` | `None` | Setting reservada e inspecionada pelo `doctor`; não é consumida pelo helper LLM atual. |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | URL do servidor local Ollama para modelos locais abertos. |
| `OLLAMA_MODEL` | `llama3.1` | Modelo padrão do Ollama. |

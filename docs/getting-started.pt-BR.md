# Primeiros Passos com o SPECTRE OSINT

[English](getting-started.md) | [Português 🇧🇷](getting-started.pt-BR.md)

O SPECTRE é uma workstation de OSINT público, *passive-first*, executada em localhost e projetada para coleta de inteligência e correlação conservadora de identidades por um único operador.

---

## Requisitos do Sistema

- **Python:** `3.12` ou `3.13`
- **Sistemas Operacionais:** Linux (Ubuntu/Debian recomendado), macOS, Windows 11 (nativo ou via WSL2)
- **Navegador (Opcional):** Google Chrome / Chromium (necessário apenas para sessões authenticated-public)
- **Busca Local (Opcional):** SearXNG executando em loopback (`http://127.0.0.1:<porta>`)

---

## Instalação

### 1. Clonar o Repositório

```bash
git clone https://github.com/slycoder0/spectre-osint.git
cd spectre-osint
```

### 2. Criar e Ativar o Ambiente Virtual

**Linux / macOS / WSL2:**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

### 3. Instalar o SPECTRE

```bash
pip install -e .
```

*Para desenvolvimento e execução de testes:*
```bash
pip install -e ".[dev]"
```

---

## Configuração do Ambiente

O SPECTRE lê as configurações de variáveis de ambiente e do arquivo `.env` na raiz do projeto.

```bash
cp .env.example .env
chmod 600 .env  # em sistemas POSIX
```

### Principais Variáveis de Configuração

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `SPECTRE_DATA_DIR` | `./data` | Diretório do banco SQLite e cache HTTP |
| `SPECTRE_REPORTS_DIR` | `./reports` | Diretório de exportação de relatórios (HTML, JSON, MD, CSV, GraphML) |
| `SPECTRE_LOGS_DIR` | `./logs` | Diretório de logs da aplicação |
| `SPECTRE_WEB_HOST` | `127.0.0.1` | Interface de rede da interface web (apenas loopback por padrão) |
| `SPECTRE_ALLOW_PUBLIC_BIND` | `false` | Liberação explícita para bind fora do loopback |
| `SPECTRE_MAX_CONCURRENCY` | `8` | Máximo de requisições concorrentes na varredura de catálogo |
| `SPECTRE_PIVOT_BUDGET` | `8` | Limite de auto-pivots do pipeline principal (IP/Domínio) |
| `SPECTRE_SEARCH_QUERY_BUDGET` | `12` | Orçamento de consultas do planejador de busca |
| `SPECTRE_SEARCH_MAX_PIVOTS` | `25` | Orçamento de pivots de inteligência de busca |
| `SPECTRE_SEARCH_MAX_DEPTH` | `2` | Profundidade máxima de descoberta na busca |
| `SPECTRE_BROWSER_BACKEND` | `playwright` | Backend de navegador: `playwright` ou `chrome` (CDP) |
| `SPECTRE_SSRF_ENABLED` | `true` | Política de proteção e filtragem de IPs privados |
| `SEARXNG_URL` | *(não definido)* | URL opcional da instância local do SearXNG |

---

## Verificação de Diagnóstico: `spectre doctor`

Antes de iniciar investigações, verifique o estado do ambiente:

```bash
spectre doctor
```

```text
SPECTRE DOCTOR
Core
  Python                   3.13.x           OK
  SPECTRE                  0.1.0b1          OK
  Database                 SQLite           OK
  Database writable        OK               OK
  Reports directory        OK               OK
Browser
  Chrome/Chromium          detected         OK
  Chrome CDP               inactive         OPTIONAL
Search
  SearXNG                  missing          OPTIONAL
API providers
  VirusTotal               NOT CONFIGURED   OPTIONAL
Security
  Bind address             127.0.0.1        OK
  Secrets redaction        OK               OK
  SSRF policy              enabled          OK
Overall: READY WITH OPTIONAL FEATURES MISSING
```

> [!NOTE]
> O `spectre doctor` nunca executa investigações, nunca realiza logins e nunca expõe credenciais em texto claro.
> Provedores opcionais ausentes são marcados como `OPTIONAL` e **não** impedem o uso normal da ferramenta.

---

## Iniciando a Interface Web (Workstation GUI)

Inicie o painel local:

```bash
spectre dashboard
# ou
spectre web
```

Acesse o endereço `http://127.0.0.1:8000` no seu navegador.

Recursos disponíveis na interface web:
- **Dossiê ao Vivo:** Acompanhamento de achados em tempo real, varredura de catálogo e proveniência de menções.
- **Grafo Interativo:** Visualização de clusters de identidades correlacionadas e relacionamentos observados.
- **Gaveta de Evidências:** Inspeção de códigos de status HTTP brutos, regras de extração e novidade.
- **Gerenciador de Sessões:** Auditoria de perfis authenticated-public sem exibir cookies.

---

## Primeira Investigação via Linha de Comando (CLI)

Investigue um username público:

```bash
spectre username alice_osint
```

Com pistas adicionais do operador (aliases, nome completo, email inicial, website pessoal):

```bash
spectre username alice_osint \
  --alias alice-sec \
  --name "Alice Example" \
  --email alice@example.com \
  --website alice.example
```

---

## Próximos Passos

- Conheça o [Modelo de Evidências](evidence-model.pt-BR.md) para entender as classificações e pontuação.
- Aprenda sobre [Inteligência de Busca e Descoberta](search-discovery.pt-BR.md).
- Configure [Sessões Públicas Autenticadas](authenticated-public.pt-BR.md).
- Consulte a [Referência Completa da CLI](cli-reference.pt-BR.md).

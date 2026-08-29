# Manual de Referência da CLI do SPECTRE

[English](cli-reference.md) | [Português 🇧🇷](cli-reference.pt-BR.md)

O SPECTRE disponibiliza uma interface rica de linha de comando desenvolvida com Typer e Rich para executar investigações, gerenciar sessões autenticadas, inspecionar caches e validar a saúde do ambiente.

---

## Visão Geral dos Comandos

```text
spectre [OPÇÕES] COMANDO [ARGS]...
```

| Comando | Finalidade |
| :--- | :--- |
| `spectre username` | Coleta principal de username, varredura de menções, inteligência de busca e correlação. |
| `spectre investigate` | Investigação multientidade com detecção automática de tipo de entrada. |
| `spectre email` | Análise de formato de email, registros MX, reputação de domínio e vazamentos. |
| `spectre domain` | Inteligência de domínio: DNS, WHOIS/RDAP e Certificados de Transparência (crt.sh). |
| `spectre ip` | Geolocalização de IP, consultas ASN, DNS reverso e reputação de abusos. |
| `spectre url` | Análise heurística de URLs, extração de domínios e inteligência contra ameaças. |
| `spectre hash` | Consulta de hashes criptográficos contra repositórios de malware (VirusTotal). |
| `spectre company` | Mapeamento de presença corporativa e domínios registrados. |
| `spectre person` | Inteligência centrada em pessoas combinando nomes, emails e handles. |
| `spectre threat` | Agregador de inteligência contra ameaças entre os feeds configurados. |
| `spectre wayback` | Busca de capturas históricas usando a API do Wayback Machine. |
| `spectre metadata` | Extração de metadados em arquivos locais (EXIF, PDF, datas de criação). |
| `spectre network` | Varredura ativa autorizada de portas TCP (requer `--authorized`). |
| `spectre auth` | Gerenciamento de sessões authenticated-public (`login`, `status`, `logout`). |
| `spectre cache` | Inspeção e limpeza do cache local de respostas HTTP. |
| `spectre doctor` | Diagnóstico do ambiente e integridade das dependências. |
| `spectre dashboard` | Inicialização da workstation web local (`spectre web`) *(Obsoleto / Deprecated)*. |
| `spectre version` | Exibição da versão instalada e status da compilação. |

---

## Especificações Detalhadas dos Comandos

### 1. `spectre username`

Investiga um username público no catálogo de plataformas, busca e menções.

```bash
spectre username ALVO [OPÇÕES]
```

**Opções:**
- `--alias TEXT`: Handles ou apelidos adicionais associados ao alvo (pode ser repetido).
- `--name TEXT`: Nome real ou de exibição observado para correlação contextual.
- `--email TEXT`: Endereço de email inicial conhecido ou suspeito.
- `--website TEXT`: Website pessoal ou domínio de portfólio conhecido.
- `--refresh`: Ignora o cache HTTP local e força requisições em tempo real.
- `--no-report`: Desabilita a gravação de arquivos de relatório em disco.

**Exemplo:**
```bash
spectre username alice_osint \
  --alias alice-dev \
  --name "Alice Example" \
  --email alice@example.com \
  --website alice.example
```

---

### 2. `spectre investigate`

Ponto de entrada genérico que detecta automaticamente o tipo de entidade (IP, Domínio, Email, Username, Hash, URL) e despacha os analisadores pertinentes.

```bash
spectre investigate ALVO [--type TIPO] [--refresh]
```

---

### 3. `spectre auth`

Gerencia as sessões do operador para coleta authenticated-public.

- **Login na plataforma:**
  ```bash
  spectre auth login [instagram|facebook|threads|tiktok|x|twitch]
  ```
- **Verificar status das sessões:**
  ```bash
  spectre auth status
  ```
- **Logout e remoção de credenciais locais:**
  ```bash
  spectre auth logout [PLATAFORMA]
  ```

---

### 4. `spectre doctor`

Executa verificações não invasivas de instalação e diagnóstico do ambiente.

```bash
spectre doctor [--json]
```

**Códigos de saída (Exit Codes):**
- `0`: Ambiente pronto (`READY` ou `READY WITH OPTIONAL FEATURES MISSING`).
- `1`: Ação requerida (ex.: diretório de banco ou relatórios sem permissão de escrita).

---

### 5. `spectre cache`

Inspeciona ou limpa o cache de respostas HTTP (`data/cache/`).

- **Exibir estatísticas:**
  ```bash
  spectre cache stats
  ```
- **Limpar entradas do cache:**
  ```bash
  spectre cache clear
  ```

---

### 6. `spectre network` (Reconhecimento Ativo)

Executa varredura de conexões TCP contra infraestruturas autorizadas.

> [!CAUTION]
> A varredura ativa envia pacotes TCP diretos aos hosts de destino. Está desativada por padrão e exige a flag `--authorized` acompanhada de confirmação interativa.

```bash
spectre network ALVO --authorized
```

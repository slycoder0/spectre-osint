# Manual de Comandos CLI

O SPECTRE adota uma arquitetura **CLI-first**. Todos os comandos são implementados através do Typer com saída estruturada no terminal, tabelas Rich e códigos de retorno padronizados.

---

## Sintaxe Global

```bash
spectre [OPÇÕES GLOBAIS] COMANDO [ARGUMENTOS] [OPÇÕES]
```

### Opções Globais

| Opção | Descrição |
| :--- | :--- |
| `--version` | Exibe a versão instalada do SPECTRE e sai. |
| `--no-banner` | Suprime a exibição do banner inicial no terminal. |
| `--compact` | Saída compacta orientada a resumo. |
| `--verbose` | Exibe detalhes técnicos completos e logs de cada achado. |
| `--help` | Exibe a mensagem de ajuda e opções do comando. |

---

## 1. Diagnóstico e Ambiente

### `spectre doctor`
Verifica a prontidão da instalação local, dependências, banco SQLite, navegador e chaves de API opcionais. **Nunca inicia investigações e nunca imprime segredos**.

```bash
# Diagnóstico visual padrão
spectre doctor

# Diagnóstico em formato JSON para automações/scripts
spectre doctor --json
```

### `spectre version`
Exibe a versão instalada do SPECTRE OSINT (equivalente à opção global `--version`).

```bash
spectre version
```

---

## 2. Investigação de Indicadores

### `spectre username`
Realiza a varredura passiva de um username em dezenas de plataformas públicas do Site Catalog.

```bash
# Varredura básica
spectre username alice_osint

# Varredura com pistas do analista e criação de caso
spectre username alice_osint \
  --alias alice-sec \
  --name "Alice Example" \
  --email alice@example.com \
  --website "https://alice.example"

# Forçar atualização ignorando o cache local
spectre username alice_osint --refresh
```

### `spectre email`
Coleta inteligência pública a partir de um endereço de e-mail (validação de formato, registros MX/DNS e presença pública).

```bash
spectre email alice@example.com
```

### `spectre domain`
Coleta inteligência de domínio: resolução DNS, registros RDAP/Whois, histórico de certificados SSL/TLS (Certificate Transparency) e fingerprinting de host.

```bash
spectre domain example.com

# Com auto-pivot ativado para subdomínios e infraestrutura relacionada
spectre domain example.com --auto-pivot --depth 2
```

### `spectre ip`
Coleta inteligência de endereço IPv4 ou IPv6 (ASN, alocação de rede, geolocalização e histórico de reputação).

```bash
spectre ip 1.1.1.1
```

### `spectre url`
Analisa uma URL com avaliação heurística explicável de risco, redirecionamentos e metadados.

```bash
spectre url "https://example.com/login"
```

### `spectre hash`
Consulta reputação pública de hashes de arquivos (MD5, SHA-1, SHA-256). **O SPECTRE nunca faz download de arquivos maliciosos**.

```bash
spectre hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### `spectre threat`
Detecta automaticamente o tipo do indicador (IP, domínio, URL ou hash) e executa o pipeline de investigação correspondente. Os provedores de threat intelligence aplicáveis são consultados quando configurados; o comando não utiliza um pipeline separado exclusivamente de threat intel.

```bash
spectre threat 1.1.1.1
spectre threat example.com
```

### `spectre wayback`
Apesar do nome, nesta versão o comando normaliza o alvo como domínio e executa o pipeline de investigação de domínio, que inclui a consulta Wayback/CDX entre as demais coletas aplicáveis. URLs fornecidas como alvo são reduzidas ao host durante a normalização; o comando não realiza uma consulta Wayback exclusiva de um caminho URL específico.

```bash
spectre wayback example.com
```

### `spectre metadata`
Extrai metadados locais de arquivos fornecidos pelo operador (PDF, imagens, documentos). A análise é estritamente local; nenhuma macro ou código ativo é executado.

```bash
spectre metadata documento.pdf
```

### `spectre company`
Registra uma empresa/organização como alvo e consulta o perfil público correspondente no GitHub Organizations (convertendo espaços em hífen para o slug da organização, como `Example-Corp`). O comando não realiza pesquisa corporativa ampla nem infere domínio nesta versão.

```bash
spectre company "Example Corp"
```

### `spectre person`
Estabelece o contexto investigativo para uma pessoa física. Na implementação atual, o comando não realiza busca ampla de menções na web apenas pelo nome; ele utiliza o nome como delimitador de contexto e executa investigações estruturadas quando acompanhado de `--username` (varredura de catálogo) e/ou `--email` (análise de e-mail e MX). Sem `--username`, o fallback consulta o GitHub tratando o nome fornecido como login exato.

```bash
# Investigação de pessoa associando username conhecido
spectre person "Alice Example" --username alice_osint

# Investigação completa com username e e-mail
spectre person "Alice Example" \
  --username alice_osint \
  --email alice@example.com
```

---

## 3. Investigação Abrangente & Casos

### `spectre investigate`
Executa o pipeline unificado completo: detecção automática do tipo de alvo, varredura de catálogo, busca pública de menções, extração de indicadores, correlação conservadora de identidades e geração de relatório HTML interativo.

```bash
spectre investigate alice_osint --name "Alice Example" --auto-pivot
```

### `spectre search`
Executa o helper de busca pública via Google Custom Search Engine (Google CSE). Requer `GOOGLE_API_KEY` e `GOOGLE_CSE_ID`; sem ambos o comando retorna `NOT_CONFIGURED`. Os resultados são links públicos de busca e não constituem confirmação de identidade.

```bash
spectre search "alice_osint github"
```

### `spectre case`
Gerencia casos de investigação locais para agrupar múltiplas consultas sob o mesmo contexto investigativo.

```bash
# Listar casos existentes
spectre case list

# Criar um novo caso
spectre case create "Operacao-Alpha"

# Selecionar caso ativo
spectre case select "Operacao-Alpha"

# Listar execuções de um caso
spectre case runs "Operacao-Alpha"

# Reverter dados de uma execução no banco
spectre case rollback <run_id>
```

### `spectre report`
Regenera relatórios locais a partir da última execução concluída no banco de dados SQLite.

```bash
# Gerar relatório HTML padrão
spectre report

# Exportar em múltiplos formatos
spectre report --format all
# Opções de formato: html, markdown, json, csv, graphml, all
```

---

## 4. Sessões Autenticadas (Authenticated Public)

### `spectre auth`
Gerencia sessões do navegador dedicadas para inspeção de perfis públicos em plataformas que exigem login (Instagram, Facebook, Threads, TikTok, X, Twitch).

```bash
# Exibir o status de todas as sessões suportadas
spectre auth status

# Iniciar login manual interativo em janela visível
spectre auth login instagram

# Verificar se a sessão salva ainda é válida
spectre auth verify instagram

# Encerrar e remover a sessão local e o perfil dedicado do SPECTRE para a plataforma (não afeta contas remotas nem o navegador pessoal)
spectre auth logout instagram

# Alias para logout — remove a sessão salva e limpa o perfil de navegador dedicado do SPECTRE para a plataforma informada
spectre auth clear instagram

# Listar plataformas e status de sessão
spectre auth list
```

---

## 5. Provedores e Cache

### `spectre providers`
Exibe os provedores registrados no registro de provedores em tempo de execução (`core/registry.py`), com o respectivo estado de configuração e de saúde. Alterar `providers.yaml` isoladamente não altera o registro de provedores usado pela CLI.

```bash
# Listar provedores
spectre providers

# Testar conectividade de todos os provedores
spectre providers --probe

# Testar um provedor específico
spectre providers --probe --name github
```

### `spectre cache`
Gerencia o cache local de resultados de consultas OSINT.

```bash
# Exibir status e registros do cache
spectre cache status

# Limpar todo o cache
spectre cache clear

# Limpar cache de um provedor específico
spectre cache clear --provider github
```

---

## 6. Reconhecimento de Rede Ativo

### `spectre network`
Executa varredura de portas via connect scan contra um host ou domínio. **Desativada por padrão**, esta funcionalidade exige autorização explícita via flag `--authorized` e confirmação interativa no terminal. O SPECTRE não realiza exploração de vulnerabilidades nem evasão de segurança.

```bash
# Reconhecimento ativo em ambiente de teste local autorizado
spectre network 127.0.0.1 --authorized
```

---

## 7. Interface Web Legada (Depreciação)

### `spectre web`
Inicia o dashboard local FastAPI em loopback. **Comando depreciado e agendado para remoção na versão 0.1.0b2** em favor da arquitetura CLI-first e relatórios estáticos standalone.

- **Endereço de Bind:** O comando CLI utiliza `--host 127.0.0.1` como padrão (mascarando `SPECTRE_WEB_HOST` se a flag for omitida). Vincular a interfaces de rede externas via `--host` exige opt-in explícito do operador com `SPECTRE_ALLOW_PUBLIC_BIND=true`.
- **Porta:** Padrão `8000` (configurável via `--port`).

```bash
# Iniciar servidor local na porta padrão 8000
spectre web

# Especificar porta alternativa
spectre web --port 8080
```

### `spectre dashboard`
Alias legado para o comando `spectre web`. Também depreciado e agendado para remoção na versão 0.1.0b2.

```bash
spectre dashboard
```

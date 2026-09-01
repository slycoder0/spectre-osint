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

### `spectre company`
Consulta inteligência pública e registros de organizações/empresas.

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
Exibe a lista de provedores e o status de configuração das integrações no `providers.yaml`.

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

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
| `--verbose` | Expande a apresentação do resultado: exibe a tabela de entidades, acrescenta a coluna de detalhe na tabela de plataformas e mantém os pivôs visíveis em modo compacto. Não altera `SPECTRE_LOG_LEVEL` nem emite logs por achado; as tabelas de entidades e de achados seguem limitadas a 40 linhas e o texto de detalhe é truncado. |
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

# Varredura com pistas do analista (um caso novo é criado automaticamente)
spectre username alice_osint \
  --alias alice-sec \
  --name "Alice Example" \
  --email alice@example.com \
  --website "https://alice.example"

# Anexar a varredura a um caso nomeado em vez de criar um novo
spectre username alice_osint --case "Operacao-Alpha"

# Ampliar a coleta com pivôs automáticos
spectre username alice_osint --auto-pivot --depth 2

# Forçar atualização ignorando o cache local
spectre username alice_osint --refresh
```

A semântica de `--case` está detalhada em [Opção `--case`](#opcao-case).

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

# Anexar a execução a um caso nomeado
spectre investigate alice_osint --case "Operacao-Alpha" --auto-pivot --depth 2
```

Aceita o mesmo conjunto de pistas de `spectre username` (`--alias`, `--name`, `--email`, `--website`) e a mesma opção `--case`.

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

#### Opção `--case`

A opção `--case <nome>` existe **apenas** em `spectre username` e `spectre investigate`. Nenhum outro comando de indicador (`email`, `domain`, `ip`, `url`, `hash`, `company`, `person`, `threat`, `wayback`, `metadata`, `search`, `network`) a aceita.

| Situação | Comportamento |
| :--- | :--- |
| `--case` com nome de caso existente | O caso é selecionado, passa a ser o **caso ativo** e a execução é anexada a ele. |
| `--case` com nome inexistente | O caso é **criado** e passa a ativo. Nomear um caso novo não é erro. |
| Sem `--case` | Um caso novo é sempre criado, com nome único no formato `case-<tipo>-<alvo>-<sufixo hexadecimal de 8 caracteres>`. O caso ativo anterior nunca é reutilizado. |

O nome informado é normalizado para slug (`validate_case_name`, limite de 80 caracteres) e é o slug — não a string original — que fica gravado. Nomes vazios ou que contenham `/`, `\` ou `..` são rejeitados.

`spectre report` **não** utiliza `--case`: recebe o caso como argumento posicional opcional (`spectre report "Operacao-Alpha"`) e, se omitido, usa o caso ativo.

### `spectre report`
Regenera relatórios locais a partir da última execução concluída no banco de dados SQLite.

```bash
# Gerar relatório HTML padrão (usa o caso ativo)
spectre report

# Regenerar os relatórios de um caso específico (argumento posicional, não `--case`)
spectre report "Operacao-Alpha"

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

#### Opções de `spectre auth login`

| Opção | Padrão | Comportamento |
| :--- | :--- | :--- |
| `--profile <nome>` | `osint-research` | **Rótulo** gravado no registro de sessão (`profile_name`). Não seleciona diretório: o perfil em disco é derivado do slug da plataforma (`ensure_platform_profile` / `ensure_chrome_profile`), portanto trocar `--profile` não cria nem alterna árvores de perfil. |
| `--keep-open` | desativado | No backend Playwright/Chromium, mantém o contexto do navegador aberto após a observação do login em vez de fechá-lo. No backend Chrome CDP o parâmetro é aceito, mas a conexão é encerrada ao final de qualquer forma — ali a opção não tem efeito. |
| `--timeout <segundos>` | `300` | Prazo de espera pela autenticação manual. Faixa aceita: mínimo `30`, máximo `1800`; valores fora da faixa são rejeitados antes da execução. |
| `--browser <modo>` | `auto` | `auto` resolve pelo navegador preferido da plataforma e pela disponibilidade do Chrome; `chrome` (ou `cdp`) força o Google Chrome do SPECTRE via CDP; `playwright` (ou `pw`) força o Chromium do Playwright. Valores não reconhecidos caem para `playwright` sem erro. **O Edge nunca é selecionado.** |
| `--attach` | desativado | Aplica-se apenas ao caminho Chrome CDP: reutiliza um endpoint CDP do Chrome do SPECTRE já em execução e **nunca inicia o navegador**. Sem nenhum endpoint disponível, o comando falha com `CDP_UNAVAILABLE`. Sem `--attach`, um endpoint existente também é reutilizado, mas o SPECTRE inicia o perfil dedicado quando não há nenhum. |

Quando `SPECTRE_BROWSER_BACKEND` está definido como `fake`, `test` ou `mock`, a resolução de `--browser` retorna o backend de testes em vez de abrir um navegador real.

```bash
# Login manual com prazo maior e navegador explícito
spectre auth login instagram --browser chrome --timeout 900

# Reaproveitar uma janela do Chrome do SPECTRE já aberta (não inicia o navegador)
spectre auth login instagram --browser chrome --attach

# Manter a janela do Chromium aberta após o login (backend Playwright)
spectre auth login instagram --browser playwright --keep-open

# Rótulo alternativo no registro de sessão
spectre auth login instagram --profile investigacao-2026
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
Gerencia o cache local de resultados de investigação (`ResultCache`, em `data/cache/results.sqlite`). Este comando **não** atua sobre o cache de respostas HTTP usado pelo `HttpClient` (`ResponseCache`, em `data/cache/cache.sqlite`), que permanece intacto e pode continuar servindo respostas em cache dentro do respectivo TTL.

```bash
# Exibir status e registros do cache de resultados
spectre cache status

# Limpar todo o cache de resultados (não remove o cache de respostas HTTP)
spectre cache clear

# Limpar entradas do cache de resultados de um provedor específico
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

## 7. Interface Web Legada (Removida)

Os comandos `spectre web` e `spectre dashboard` foram **removidos** no milestone de desenvolvimento 0.1.0b2. Invocá-los falha como comando desconhecido. O SPECTRE é CLI-first: use os comandos de investigação acima e o `spectre report` para gerar relatórios estáticos em arquivo único. Consulte [Interface Web Legada](technical/legacy-web.md) para o registro histórico da remoção.

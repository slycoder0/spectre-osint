# Camada de Apresentação (B2-06)

Como o SPECTRE separa **dados** de **apresentação** no terminal. Esta é a base do menu
interativo (Fase 3): o menu usa os mesmos serviços e as mesmas views; só troca o renderer.

---

## 1. Camadas

```text
cli/commands.py            Typer: lê flags, chama o serviço, entrega a view ao renderer
  │
  ├─ services/investigations.py   InvestigationRequest -> run_investigation() -> InvestigationResult
  │                               (sem print, sem Rich, sem Typer; progresso por callback)
  ├─ services/views.py            InvestigationResult -> UsernameView (neutra de idioma)
  │
  ├─ cli/render.py                UsernameView -> texto Rich, traduzido por core/i18n.py
  ├─ cli/progress_bar.py          barra de progresso ao vivo (stderr, só em TTY)
  └─ cli/display.py               print_result(): compacto por padrão; seções detalhadas no --verbose
```

| Camada | Pode | Não pode |
| :--- | :--- | :--- |
| `services/` | rodar investigações, contar, classificar, montar views | imprimir, importar Rich/Typer, traduzir |
| `services/views.py` | decidir o que é "encontrado", "não encontrado" e "não verificado" | escolher palavras, cores ou layout |
| `cli/render.py` | escolher texto, cor e alinhamento no idioma ativo | calcular fatos ou reclassificar achados |
| `reporting/` | gerar HTML/JSON/Markdown/CSV/GraphML completos | ser afetado pela compactação do terminal |

O `doctor` segue o mesmo princípio dentro de `cli/doctor.py`: `run_doctor()` produz o
relatório neutro (o contrato do `--json`) e `render_doctor()` o traduz.

---

## 2. `spectre username` — saída compacta (padrão)

```text
alice_osint — 3 profiles found (sites checked: 8)
  GitHub        https://github.com/alice_osint
  Hugging Face  https://huggingface.co/alice_osint
  Keybase       https://keybase.io/alice_osint (likely)

Names observed on each platform (not proof of the same person):
  GitHub: Alice Example
  Hugging Face: A. Example

4 not verified: 1 blocked, 1 needs login, 1 rate-limited, 1 inconclusive (--verbose lists them)
Full report: reports/alice_osint.html
```

Regras (aplicadas em `services/views.py`, testadas em `tests/test_username_presentation.py`):

- **Encontrado** = perfil do catálogo com `check_status` `CONFIRMED` ou `LIKELY`. `LIKELY`
  leva o sufixo `(likely)` / `(provável)`. Candidatos de busca (`discovered_profile`) e
  menções públicas são de outros módulos e **nunca** aparecem como perfil.
- **Toda** plataforma consultada cai em exatamente um balde:
  `checked == encontrados + não encontrados + não verificados`. Um status desconhecido
  conta como **não verificado** (inconclusivo), nunca some.
- **Linha de não verificados**: sempre impressa, inclusive `0 not verified` /
  `0 não verificados`. Esconder essa linha transformaria "não consultado" em "não existe".
  Baldes: bloqueado (`BLOCKED`, `CHALLENGE_REQUIRED`, `CAPTCHA_REQUIRED`,
  `OAUTH_BROWSER_REJECTED`), login (`LOGIN_REQUIRED`, `SESSION_EXPIRED`), limite de
  requisições (`RATE_LIMITED`, `TEMPORARILY_LIMITED`) e inconclusivo (todo o resto).
- **Nomes observados por plataforma**, um por linha (`GitHub: Linus Torvalds`,
  `Hugging Face: Hemant`), **nunca fundidos** numa linha só. Fonte única: o canal
  `observed` validado por `read_observed()`; só para perfis encontrados; nunca um campo
  rejeitado (`rejected_by`), nunca `source_method=INPUT` (entrada do operador) e nunca um
  nome que é só o próprio handle (`is_generic_display_name`).
- **Score e risco ficam ocultos** por padrão, assim como banner e métricas internas
  (entidades, relacionamentos, provedores consultados).

## 3. `--verbose`

Superconjunto do compacto: imprime antes as seções detalhadas (todas as plataformas com
status, menções, descoberta, correlação de identidade, painel de score/risco, pivôs e
métricas internas) e termina com o mesmo bloco compacto. O painel `INTELLIGENCE SUMMARY`
não tem mais a linha `Observed name` que fundia nomes de perfis diferentes. O banner ASCII
só aparece no `--verbose` (e respeita `--no-banner`, `SPECTRE_NO_BANNER`, `NO_BANNER`).

As seções detalhadas ainda estão só em inglês (follow-up registrado em
`docs/audit/STATUS.md`).

## 4. Progresso, logs e fluxos de saída

| Fluxo | Padrão | `--verbose` | `--debug` |
| :--- | :--- | :--- | :--- |
| stdout | resultado compacto | detalhes + resultado | resultado compacto |
| stderr — progresso | barra Rich transitória, **só se stderr for TTY** | linhas factuais por fase | barra (se TTY) |
| stderr — logs | nada | `INFO` | `DEBUG` |
| `logs/spectre-osint.log` | sempre | sempre | sempre (nível `DEBUG`) |

- A barra mostra a fase traduzida e contagens reais quando o pipeline as informa
  (sites consultados no catálogo). Fases sem total conhecido pulsam; nenhuma porcentagem
  é inventada (contrato de `core/progress.py`).
- Com saída redirecionada ou em pipe, stderr não é TTY: nenhuma barra é desenhada.
- Logs passam pelo `RedactingFormatter` em qualquer destino (`core/logger.py`): segredos
  mascarados, mensagens de exceção retidas nos tracebacks e valores do alvo da execução
  trocados por referência (`core/redaction.py`).
- **Logs nunca contêm dados do alvo (B2-07).** Uma chamada de log registra slug do provedor,
  status HTTP, contagens, duração e a classe da exceção (`exc_label`). Para ligar linhas do
  mesmo valor use `target_ref(valor)` / `host_ref(url)`: HMAC-SHA256 truncado (8 hex) com sal
  aleatório que só existe na memória — não reversível e diferente a cada investigação, mesmo no
  mesmo processo (o menu roda várias). Quando o host é o alvo (domínio, IP, URL investigados)
  ele também só aparece como `h:…`; IPv6 sem `://` é lido como endereço, não cortado no `:`.
- **Rede de segurança por investigação.** `InvestigationRunner.run` (e o recon ativo) abrem um
  `target_scope()` (contextvar; tarefas asyncio e `asyncio.to_thread` herdam). Dentro dele o
  alvo, as pistas do operador e cada pivô vão para `register_target_values()`, e o formatter
  troca o que ainda escapar (rede de segurança, não licença para logar). Ao sair: valores
  descartados, padrão vazio, sal novo. Limite duro de 256 formas por escopo. Só troca
  ocorrências delimitadas (nunca dentro de palavra/identificador), só formas com 6+ caracteres
  (parte local / domínio do e-mail: 8+; e-mail completo sempre) e nunca uma palavra do
  vocabulário do log, derivado do código em `core/log_vocabulary.py` (sites do catálogo,
  valores de enums, classes de exceção, palavras dos templates de log). Alvo curto ou comum
  é responsabilidade do call site e do canário, não da rede.
- O guarda é `tests/test_logs_no_target_data.py` (canário dinâmico + varredura AST de toda
  chamada de log, `print(file=sys.stderr)`, `sys.stderr.write` e `warn`).
- Erros de formatação (`logger.warning("%s: %s", url)`) viram uma linha
  `SPECTRE logging error in <logger>: <Classe>`, sem mensagem nem argumentos. Avisos
  (WARNING+) de bibliotecas de terceiros vão para o arquivo pelo mesmo formatter, nunca crus
  para o stderr.
- Logs de versões anteriores ficam em `logs/spectre.log` e nunca são tocados; o `spectre
  doctor` aponta para eles com uma linha `[INFO]` que não muda o resultado geral (o padrão
  `./logs` é relativo à pasta onde o `spectre` roda). `httpx` / `httpcore` (que logam URLs
  completas em INFO) ficam limitados a WARNING.
- O arquivo segue `SPECTRE_LOG_LEVEL` (exceto com `--debug`, que grava DEBUG); o terminal segue a
  flag. Com `SPECTRE_LOG_LEVEL=WARNING` e `--verbose`, o INFO aparece no stderr e não no arquivo.
  As flags valem para todo comando que configura logs (`username`, demais investigações, `auth`)
  via `configure_cli_logging()` em `cli/display.py`.
- Um resultado de username sem nenhuma linha de site (só o finding de sweep) também usa a view
  compacta: a linha de não verificados aparece como `0`.

## 5. Texto não confiável

Nomes, plataformas e URLs vêm de páginas de terceiros. O renderer remove caracteres de
controle C0/C1 (incluindo `ESC`) e marcas/overrides bidi (`U+202A–U+202E`,
`U+2066–U+2069`, `U+200E/F`, `U+061C`), troca quebras de linha e tabs por espaço, e
imprime via `rich.text.Text` — um nome como `[bold]Admin[/bold]` aparece literalmente,
sem virar markup, e sequências ANSI não chegam ao terminal.

## 6. Relatórios continuam completos

A compactação é só do terminal. `print_result()` não muda o `InvestigationResult`, e os
geradores de `reporting/` recebem o resultado inteiro: plataformas não encontradas e não
verificadas, score, risco e nomes observados continuam no HTML, JSON, Markdown, CSV e
GraphML (`tests/test_cli_presentation.py::test_reports_keep_everything_the_compact_terminal_hides`).

## 7. `spectre doctor`

Padrão com cerca de oito linhas: núcleo e segurança resumidos, itens configurados numa
linha, itens que pedem ação ou atenção listados com a dica, e opcionais não configurados
**colapsados numa única linha** com contagem. `spectre doctor --all` lista todas as
verificações agrupadas. O `--json` não mudou (status e textos continuam em inglês, neutros).

## 8. User-Agent

Toda requisição do `HttpClient` leva o mesmo User-Agent honesto:
`SPECTRE-OSINT/<versão> (+https://github.com/slycoder0/spectre-osint)`. Até a B2-06,
~35% das requisições usavam um UA de navegador sorteado de `data/user_agents.txt`; essa
rotação e o arquivo foram removidos. `SPECTRE_USER_AGENT` continua permitido e é enviado
literalmente. A política SSRF, a fixação de IP com `Host` original e o limite de
redirecionamentos não mudaram (`tests/test_honest_user_agent.py`).

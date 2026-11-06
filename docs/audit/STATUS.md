# STATUS — retomada do SPECTRE

Arquivo vivo. **Atualize em todo PR de fase.** É o ponto de partida depois de um `/clear`.
Roadmap e achados: [`2026-11-05-auditoria.md`](2026-11-05-auditoria.md) (seção 5).

_Última atualização: 2026-11-06 — PR #18 (Fase 2.5): segunda revisão do Grok aplicada._

## Fase atual

**Fase 2.5 — `fix/b2-07-logs-no-target-data`** (logs e avisos sem dados do alvo em todo o
pacote): **PR #18 aberto; ajustes da primeira e da segunda revisão aplicados, aguardando
merge (só com pedido explícito).** Não mergeado. A Fase 2 (PR #17) foi mergeada em `main`
(merge `b2f8d89`).

### Segunda revisão do PR #18 (Grok, 2026-11-06) — aplicada, sem blocker

1. **Vocabulário engolia domínios reais.** `log_vocabulary()` só aceita tokens
   `[A-Za-z0-9_]+`: `Chess.com`, `WordPress.org`, `About.me`, `Dev.to`, `Last.fm`, `crates.io`,
   `itch.io`, `Docker Hub`, `Hugging Face`, `Ko-fi` saíram; o slug (`chess_com`) fica. Antes, com
   alvo `chess.com`, a forma crua era descartada e `GET https://chess.com/member/1` ia ao log.
2. **Teto de 256 formas** reserva todas as formas de um valor ou nenhuma (antes, com 255
   ocupadas, o e-mail entrava cru e `%40` / domínio ficavam de fora). Aviso de teto: uma vez.
3. **Contrato de `target_scope()`** documentado na docstring e fixado por testes, sem mudar o
   comportamento: tarefa criada no escopo e aguardada depois loga em claro (e o `target_ref`
   muda); tarefa criada antes do `with` nunca vê o escopo. "Toda tarefa que loga o alvo
   precisa terminar dentro do escopo."
4. **Testes da fronteira** que caem sem o lookaround (`xxalice_osint` / `alice_osintyy`
   intactos; `pre-`, `%2F`, `.example.com` trocados; `longlocalextra` × `longlocal`), validados
   por mutação manual.
5. **`warnings.warn`** capturado (`logging.captureWarnings(True)`): vai para o arquivo pelo
   `RedactingFormatter`, nunca cru no stderr.

### Ajustes da revisão do PR #18 (2026-11-06)

Duas revisões independentes: nenhum vazamento ativo; 1 blocker funcional e alguns importantes.
Cada item começou por um teste de regressão que falhou antes da correção.

1. **Blocker — a rede de segurança deformava o log.** Agora só troca ocorrências delimitadas
   (`(?<![A-Za-z0-9_])…(?![A-Za-z0-9_])`; um `%XX` antes também delimita, para query strings
   codificadas); piso de 6 caracteres (parte local / domínio do e-mail: 8; e-mail completo
   sempre); nunca registra uma palavra do vocabulário do log, derivado do código em
   `core/log_vocabulary.py` (slugs do catálogo e nomes que são token — ver 2ª revisão, nomes/valores de enums do pacote, classes
   de exceção carregadas, palavras de todos os templates de log — conferidas contra a AST).
2. **Escopo por investigação:** `target_scope()` (contextvar) em `InvestigationRunner.run` e no
   recon ativo; ao sair descarta valores, esvazia o padrão e troca o sal; aninhado = o mesmo
   escopo; limite de 256 formas. Referência muda a cada investigação, não "a cada execução".
3. **Guarda AST e canário:** 17 trechos que escapavam viraram casos do teste (receptores
   `self.logger` / `sink` / `getLogger()` / `logging`, nomes contaminados, itens de
   `gather(return_exceptions=True)`, `.get()` de chave negada, objetos de domínio, `.error`,
   `print`/`sys.stderr.write`/`warn`, placeholders × argumentos). A correlação de identidade
   loga `validation_label(authority)` (mesmo texto, montado só de contagem + códigos). Canário:
   `authority.error` a partir de `ValidationError` com o alvo, piso alinhado + parte local do
   e-mail, CLI também com `email` / `ip` / `url`, site da falha vindo de `load_sites()`.
4. **`handleError`:** chamada mal formada imprime só `SPECTRE logging error in <logger>: <Classe>`.
5. **Terceiros:** WARNING+ de bibliotecas vai para o arquivo pelo `RedactingFormatter`, nunca cru
   no stderr (handler na raiz); teto de `httpx` / `httpcore` mantido.
6. **IPv6:** `host_ref("2001:db8::1") != host_ref("2001:db8::2")`.
7. **Doctor:** "Logs antigos" é `[INFO]` (estado `info`), não muda o resultado geral; a dica diz
   que o padrão `./logs` é relativo à pasta onde o `spectre` roda.

Regressões: `tests/test_target_redaction.py`, `tests/test_target_scope.py`,
`tests/test_log_sinks_privacy.py`, `tests/test_logs_no_target_data.py`. Os acréscimos do canário
que passaram de primeira foram validados com mutantes (vazamento injetado → teste falha).

### O que a Fase 2.5 fez

- **Auditoria de todas as chamadas `logger.*`** (~105 em 19 arquivos; nenhum `warnings.warn`;
  stderr só via handler de log, barra de progresso e `_cli_fail`). 20 pontos carregavam dado
  do alvo: `url=` + `str(exc)` no `http_client` (5 linhas), host cru (7 linhas), valor do pivô
  e `str(exc)` no `pipeline`, caminho do relatório no erro do GraphML, `str(exc)` em
  fingerprint de domínio / falha de site / provedor indisponível, `username=` no
  enriquecimento, `plataforma::username` na correlação, URLs/títulos/og:* e `reason` na
  evidência autenticada, host do candidato descoberto, host do recon ativo. Tabela completa
  na descrição do PR #18.
- **Helpers em `core/redaction.py`:** `exc_label(exc)` (só a classe), `target_ref()` /
  `host_ref()` (`t:` / `h:` + 8 hex de HMAC-SHA256 com sal aleatório por processo, nunca
  gravado), e a rede de segurança `register_target_values()` / `scrub_target_values()`.
- **`core/logger.py`:** arquivo novo `spectre-osint.log` (o `spectre.log` antigo nunca é
  aberto, alterado nem apagado; `legacy_log_files()` o aponta); tracebacks com frames e sem
  mensagem; valores registrados trocados por referência só na mensagem; `httpx` / `httpcore`
  limitados a WARNING.
- **`spectre doctor`:** linha "Logs antigos" (estado OPCIONAL) enquanto existir `spectre.log`.
- **Guarda:** `tests/test_logs_no_target_data.py` — canário dinâmico offline (username com
  pistas, domínio com auto-pivô, CLI `--debug`; timeout, TLS, 4xx/5xx/429, status não-RFC,
  SSRF, validação, callbacks que quebram), registros brutos + arquivo + stderr em todas as
  formas derivadas, varredura AST de toda chamada de log, autotestes do detector.
- **Correção extra, commit separado:** `spectre domain example.com` saía com `TypeError`
  (linha do tempo com datas com e sem fuso). Pré-existente em `main`; achado na verificação
  ao vivo. Typer fixado em `pretty_exceptions_show_locals=False`.

### Correção dentro do PR #17 — cache servindo resultados de código antigo

Sintoma (rodando no repo, não em diretórios isolados): títulos de página apareciam como
"Nomes observados" (Codeberg, Scratch, Telegram, SoundCloud, Launchpad) e geravam conflitos
`distinct_display_name` na correlação.

Causa raiz, confirmada com evidência: `core/result_cache.py` guarda `Finding.data` **derivado**
e o devolve literalmente (`engine._bundle_from_cached`); a chave era só
`kind|provider|subject|access_mode`, sem versão. As 55 linhas de `torvalds` foram gravadas às
14:44 UTC (11:44 local) com o HEAD em `chore/b2-05-resume-hygiene` (99c0f30), **antes** da
rejeição de títulos da Fase 1 (052f6bf, 12:49 local), e ainda tinham ~2h18 de TTL. O relatório
problemático tinha 55/57 findings `CACHED`. Reprodução A/B com uma cópia do cache: com cache →
títulos aparecem; mesma pasta com `--refresh` → só GitHub e Hugging Face. Nenhum outro escritor:
os caminhos ao vivo (HTML anônimo, JSON API, autenticado) passam por `enrich_profile`. O
"value/original invertido" era um defeito do formato antigo (`original=og_title or title`).

Correção: (1) `RESULT_SCHEMA_VERSION` (= 2) e `__version__` na chave; ao abrir, linhas de outro
esquema (`PRAGMA user_version`) e expiradas são apagadas; (2) defesa em profundidade:
`display_name` de `html_title` / `html_og.title` é inativo mesmo sem `rejected_by`
(`PAGE_TITLE_SOURCES` em `observed.py`), cobrindo view, correlação, relatórios e
`flatten_observed()`. Regra de quando subir a versão: docstring de `core/result_cache.py`,
`CONTRIBUTING.md` e `docs/commands.md`.

Roadmap revisado (decisão de produto de 2026-11-05): apresentação + i18n viraram a Fase 2
porque são a base do menu. O antigo "A2 — discovery page chrome" (`fix/b2-06-discovery-page-chrome`)
passou para a Fase 5. Ordem atual: 2 apresentação/i18n → 3 menu (fluxo de username primeiro)
→ 4 menu completo + testes dos módulos cyber → 5 ruído de discovery + saúde do catálogo →
6 release `0.1.0b2` → depois B2-03B3, B2-04, limpeza.

### Revisão independente do PR #17 — 5 ajustes (sem blockers)

1. `print_result`: alvo username ou finding de sweep → view compacta mesmo sem linhas de site
   (a linha "0 não verificados" não some); email/domain seguem na tabela legada.
2. `ResultCache`: limpeza de esquema em `BEGIN IMMEDIATE`, relendo `user_version` dentro da
   transação (corrida de primeira abertura entre dois processos).
3. `spectre auth` honra `--verbose` / `--debug` (`configure_cli_logging()` compartilhado).
4. Nível do logger = o mais verboso entre arquivo e terminal; `FileHandler` em `SPECTRE_LOG_LEVEL`.
5. `clean_text()` troca U+2028 / U+2029 por espaço.

Regressões em `tests/test_pr17_review_fixes.py` (todas falharam antes da correção).

## Feito

| Fase | Marco | PR | Estado |
| :--- | :--- | :--- | :--- |
| — | Auditoria 2026-11-05 | #14 | mergeado |
| 0 | `chore/b2-05-resume-hygiene` (Pillow `>=13,<14`, strings `0.1.0b1`, UA) | #15 | mergeado |
| 1 | `fix/b2-03b2-display-name-rejection` | #16 | mergeado (`5ee5fd7`) |
| 2 | `feat/b2-06-presentation-i18n` | #17 | mergeado (`b2f8d89`) |
| 2.5 | `fix/b2-07-logs-no-target-data` | #18 | aberto; 1ª e 2ª revisão aplicadas |

Fase 2, em poucas linhas (detalhes em `docs/technical/presentation.md` e `docs/technical/i18n.md`):

- `services/` (sem UI) roda investigações e monta `UsernameView`; `cli/render.py` renderiza com Rich + i18n.
- `spectre username` compacto: perfis encontrados (plataforma + URL), nomes **por plataforma**,
  linha fixa "N não verificados" (sempre, inclusive 0). Score/risco/banner/métricas só no `--verbose`.
- Barra de progresso em stderr só em TTY; logs só em arquivo (`--verbose` INFO, `--debug` DEBUG em stderr).
- `spectre doctor` com ~6–8 linhas; `--all` lista tudo; `--json` inalterado.
- `core/i18n.py` + `core/locales/{en,pt_br}.py`: `--lang` → `SPECTRE_LANG` → config → locale → EN.
- UA honesto e fixo `SPECTRE-OSINT/<versão> (+https://github.com/slycoder0/spectre-osint)`;
  removida a rotação que mandava UA de navegador em ~35% das requisições.

## Próximo

1. Merge do PR #18 (só com pedido explícito).
2. **`fix/b2-08-tldextract-offline`** (PR próprio, antes da Fase 3): `tldextract` busca a lista
   de sufixos fora do `HttpClient` (ver Follow-ups).
3. **Fase 3 — menu interativo (fluxo de username primeiro) + identidade visual.** `spectre` sem
argumentos abre o menu sobre a mesma camada `services/` e as mesmas views; tela de
Configurações grava o idioma com `core.i18n.save_language()`. O plano da Fase 3 foi entregue
ao arquiteto junto com o PR #18 (texto, sem branch) e espera revisão antes de começar.

## Últimos resultados dos portões (PR #18 com a segunda revisão, 2026-11-06)

```text
pytest -q        1178 passed in 115.95s   (local: --basetemp por PermissionError no %TEMP%)
ruff check       All checks passed!
mypy             Success: no issues found in 135 source files
pip check        No broken requirements found.
pip-audit        No known vulnerabilities found
                 (spectre-osint: not on PyPI, skipped — esperado)
```

Ao vivo depois da segunda revisão: `spectre --debug domain chess.com` → saída 0; 6 linhas de log
nesta execução; `chess.com` (sem diferenciar caixa) no log: **0**; no stderr: **0**; stdout: 15.
As 6 linhas usam `host=h:…` no call site, então não passam pela rede de segurança; o cenário da
revisão foi conferido em A/B pelo `FileHandler` real (alvo `chess.com` registrado, linha
`GET https://chess.com/member/1 host=chess.com provider=chess_com`): HEAD `1483d9d` → 2
ocorrências cruas; esta branch → 0, `provider=chess_com` intacto.

Verificação ao vivo depois dos ajustes da primeira revisão (dentro do repo, rede real, só os bytes desta execução):

- `spectre --debug username torvalds` → saída 0; 281 linhas; `torvalds` no log: **0**; stderr:
  **0**; stdout: 19.
- `spectre --debug domain example.com` → saída 0; `example.com` no log: **0**; stderr: **0**;
  stdout: 10 (`example` sozinho: 0 / 0).
- `spectre --debug username github` → saída 0; 477 linhas; nenhuma palavra deformada
  (`provider=t:`, `Readt:`, `AUt:`: 0). As 37 ocorrências de `github` são vocabulário
  (`provider=GitHub`, `github::t:dbd48626` na correlação, `github-search`, `github_api.*`); o
  username só aparece como `t:…`. Com `SPECTRE_HTTP_TIMEOUT=0.3 --refresh`: 33 linhas
  `HTTP timeout provider=<Site> host=h:… err=ReadTimeout`, todas legíveis.
- `logs/spectre.log` antigo intacto (2915 bytes); `spectre doctor` mostra
  `[INFO] Logs antigos: logs\spectre.log — …` (o resultado geral do repo continua "com recursos
  opcionais ausentes" por causa dos 20 opcionais, não dessa linha).

Verificação ao vivo anterior (2026-11-05, antes dos ajustes):

- `spectre --debug username torvalds` → saída 0; 244 linhas de log; `torvalds` no log desta
  execução: **0**; no stderr (`--debug`): **0**; no stdout (resultado): 19 (esperado).
- `spectre --debug domain example.com` → saída 0 (depois da correção da linha do tempo; antes
  saía 1, também em `main`); `example.com` no log: **0**; no stderr: **0**; no stdout: 10.
- O `logs/spectre.log` antigo (2915 bytes) ficou intacto nas duas execuções; o `spectre
  doctor` do repo mostra `[OPCIONAL] Logs antigos: logs\spectre.log — …` (7 linhas, saída 0).

Resultados da Fase 2 (PR #17): `pytest -q` 1068 passed; demais portões verdes.

Ao vivo **dentro do repo, com o cache antigo** (`spectre username torvalds`, sem `--lang`,
locale `pt_BR`): cache foi de `user_version 0` / 55 linhas antigas para `user_version 2` / 53
linhas novas; saída com `15 perfis encontrados`, nomes só `GitHub: Linus Torvalds` e
`Hugging Face: Hemant`, `27 não verificados`; relatório com 57 findings `LIVE`, títulos com
`rejected_by="page_title_unverified"` e nenhum conflito `distinct_display_name`.

Execução anterior da Fase 2 (diretórios isolados, cwd fora do repo, stderr não-TTY):

- EN: `torvalds — 16 profiles found (sites checked: 57)`; `GitHub: Linus Torvalds`,
  `Hugging Face: Hemant` em linhas separadas; `25 not verified: 9 blocked, 8 need login,
  1 rate-limited, 7 inconclusive`; stderr 0 bytes.
- PT-BR: `torvalds — 15 perfis encontrados (sites consultados: 57)`; mesmos nomes por
  plataforma; `25 não verificados: 9 bloqueados, 9 exigem login, 1 com limite de
  requisições, 6 inconclusivos`; stderr 0 bytes; 5 linhas no `spectre.log`.
- A diferença 16 × 15 é variação da rede entre as duas execuções (Last.fm), não do código.
- `spectre doctor` sem `--lang` saiu em PT-BR (locale `pt_BR` da máquina): 6 linhas; `--all`: 39.

## Decisões em aberto

- Quando cortar o `0.1.0b2` (Fase 6) — depois da Fase 3 ou só no fim do roadmap.
- Comando de CLI para salvar o idioma (`spectre config lang …`) ou só pelo menu.
- Fase 3: biblioteca do menu (questionary × prompt_toolkit) e perguntas abertas do plano.
- (Resolvida na Fase 2.5) a regra "mudou o que é cacheado → suba `RESULT_SCHEMA_VERSION`"
  agora está nos invariantes do `CLAUDE.md`.

## Follow-ups registrados

- **Sink de progresso sem proteção em menções e busca:** `modules/mentions` e
  `modules/search` chamam o callback de progresso direto; se ele lançar, a passada inteira é
  pulada ("Search intelligence skipped"). O pipeline e o catálogo já protegem. Proteger no
  pipeline (passar um wrapper seguro) — achado pelo canário da Fase 2.5.
- **`tldextract` fora do `HttpClient` → próximo PR `fix/b2-08-tldextract-offline` (antes da
  Fase 3).** `core/validators.py` (~linhas 94 e 101) chama `tldextract.extract()`, que com cache
  frio busca a lista de sufixos públicos na rede sozinho: fura a política SSRF e o UA do
  `HttpClient` e faz teste depender de rede. Usar a lista embutida (sem fetch) ou um extrator
  configurado offline.
- **`_cli_fail` / stderr com `str(exc)` → Fase 3**, junto com as mensagens de erro do menu:
  `SSRFBlocked` mostra o IP, `ConnectError` mostra a URL. Não é log (não é gravado), mas aparece
  no terminal. Mensagens de exceção continuam nos achados e relatórios por desenho.
- ~~Rede de segurança por processo, nunca limpa~~ — **resolvido na revisão do PR #18**
  (`target_scope()` por investigação, limite de 256 formas).
- **Build congelado (.exe, fase futura):** `core/log_vocabulary.py` lê as palavras dos templates
  de log dos `.py` do pacote; sem fontes no bundle o vocabulário perde essas palavras e a rede
  troca mais (só legibilidade, nunca vazamento). Incluir as fontes ou gerar o vocabulário no
  build.
- **Rede de segurança: variantes que ela não gera** (segunda revisão do PR #18, sem correção
  nesta fase). Só as formas do `quote` / `quote_plus` padrão entram: escapes de caracteres não
  reservados (`%5F` para `_`, `%2D` para `-`, `%2E` para `.`), codificação dupla (`%252F`,
  `alice%2540example.com`) e Unicode em outra normalização (NFD × NFC) passam crus se chegarem
  ao log por um call site errado. O guarda real continua sendo a regra do call site.
- **`spectre search <consulta>`** não abre `target_scope()` nem registra a consulta: só a regra
  do call site (guarda AST) protege esse comando. Abrir um escopo quando o menu chamar a busca.
- **Avisos de bibliotecas de terceiros** vão só para o arquivo de log (decisão desta revisão);
  com `--debug` eles não aparecem no terminal.
- **Guarda AST é heurística** (nomes/chaves/atributos com cara de alvo); o canário dinâmico
  cobre os caminhos exercitados. Caminhos de navegador/autenticação só pela varredura AST e
  por `test_username_auth_evidence.py`.
- **`[!] <provedor> unavailable (Classe)`** não diz mais "timeout" × "HTTP 503": as linhas do
  `spectre.http` logo antes trazem o status.

- **Achados sem `observed` (anteriores à B2-03A)** continuam no fallback de nível superior da
  correlação: sem `source`, não há como distinguir um título de um nome. Só afeta casos muito
  antigos recarregados do SQLite (`spectre report`); o cache de resultados já não os serve.

- **i18n restante:** seções detalhadas do `--verbose` (`cli/display.py`: tabela, painéis
  USERNAME SUMMARY / PUBLIC MENTIONS / DISCOVERY GAIN / INTELLIGENCE SUMMARY / IDENTITY
  CORRELATION / Scoring), saída genérica dos demais comandos (`email`, `domain`, `ip`, `url`,
  `hash`, `company`, `person`, `threat`, `wayback`, `investigate` não-username), `auth`,
  `cache`, `case`, `providers`, `report`, mensagens de erro de `_cli_fail`, o
  `CliProgressReporter` do modo verbose e os textos de `--help` do Typer.
- ~~Logs com dados do alvo~~ — **resolvido na Fase 2.5 (PR #18).** Logs antigos
  (`logs/spectre.log`) podem conter dados do alvo; o doctor avisa, nada é apagado.
- **Texto não confiável no `--verbose`:** as seções legadas imprimem títulos de menção,
  plataforma/URL/detalhe como markup Rich (`[...]` pode virar estilo ou `MarkupError`).
  O bloco compacto já usa `clean_text()` + `rich.text.Text`; aplicar o mesmo no verbose.
- **HIBP manda o próprio `user-agent: SPECTRE-OSINT`** (honesto, mas sem versão/URL);
  alinhar com `Settings.user_agent`.
- **`build_intelligence_summary()["observed_names"]`** continua sendo uma lista fundida nos
  dados (não é mais exibida). Remover ou tornar por plataforma quando o menu/relatório precisar.
- **Barra de progresso** validada por testes com terminal forçado; a captura ao vivo desta
  fase não tinha TTY. Conferir visualmente num terminal real.
- **Fallbacks brutos de nível superior no motor** (`engine.py`, caminho HTML anônimo):
  `bio = ... or description`, `avatar_url = ... or avatar`, `website = ... or website` ainda
  copiam metadados brutos da página para `Finding.data` (e portanto para o relatório JSON).
  Não são evidência quando `observed` existe (B2-03B1), mas são a mesma classe de defeito
  que a Fase 1 corrigiu para `display_name` / `public_name`.
- **Originais brutos por item de lista** (parte adiada de B2-03B2): não muda o que o usuário vê.
- `page_title` (finding) e `title` (evidência) guardam o título bruto **com rótulo honesto**;
  não é defeito, só registro.
- **Ramo `json_name` da elevação de confiança é código morto** (`engine.py`, ~linha 755):
  `json_name` só é preenchido no caminho `json_api`, onde o status é `CONFIRMED` (ou negativo),
  nunca `LIKELY`; e o caminho autenticado já é excluído por `not is_authenticated`. Decidir
  remover a elevação inteira numa fase própria (com score oculto por padrão, prioridade baixa).
- **`~` no caminho não conta como identidade de URL** (`username_in_url_identity`): canonical
  `…/~handle` (estilo Launchpad) não gera `canonical_match`. Fora do escopo; só registrado.

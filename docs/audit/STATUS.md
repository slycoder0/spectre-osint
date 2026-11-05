# STATUS — retomada do SPECTRE

Arquivo vivo. **Atualize em todo PR de fase.** É o ponto de partida depois de um `/clear`.
Roadmap e achados: [`2026-11-05-auditoria.md`](2026-11-05-auditoria.md) (seção 5).

_Última atualização: 2026-11-05 — PR #17 (Fase 2) com a correção do cache de resultados._

## Fase atual

**Fase 2 — `feat/b2-06-presentation-i18n`** (camada de apresentação + base i18n PT-BR/EN):
**PR #17 aberto**, aguardando revisão. Não mergeado. Inclui a correção do cache de resultados
abaixo, pedida antes do review.

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

## Feito

| Fase | Marco | PR | Estado |
| :--- | :--- | :--- | :--- |
| — | Auditoria 2026-11-05 | #14 | mergeado |
| 0 | `chore/b2-05-resume-hygiene` (Pillow `>=13,<14`, strings `0.1.0b1`, UA) | #15 | mergeado |
| 1 | `fix/b2-03b2-display-name-rejection` | #16 | mergeado (`5ee5fd7`) |
| 2 | `feat/b2-06-presentation-i18n` | #17 | aberto, em revisão |

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

**Próximo PR (antes da Fase 3): logs sem dados do alvo** — corrigir o defeito pré-existente
descrito em "Follow-ups" (URLs de perfil e valores de pivô nos logs). Decisão do usuário em
2026-11-05.

**Depois: Fase 3 — menu interativo (fluxo de username primeiro).** `spectre` sem argumentos abre o
menu (questionary/prompt_toolkit + Rich) sobre a mesma camada `services/` e as mesmas views;
tela de Configurações grava o idioma com `core.i18n.save_language()`.

## Últimos resultados dos portões (PR #17 com a correção do cache, 2026-11-05)

```text
pytest -q        1061 passed in 87.13s
ruff check       All checks passed!
mypy             Success: no issues found in 134 source files
pip check        No broken requirements found.
pip-audit        No known vulnerabilities found
                 (spectre-osint: not on PyPI, skipped — esperado)
```

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
- Incluir em `CLAUDE.md` (invariantes) a regra "mudou o que é cacheado → suba
  `RESULT_SCHEMA_VERSION`" — hoje está em `CONTRIBUTING.md` e na docstring do cache.

## Follow-ups registrados

- **Achados sem `observed` (anteriores à B2-03A)** continuam no fallback de nível superior da
  correlação: sem `source`, não há como distinguir um título de um nome. Só afeta casos muito
  antigos recarregados do SQLite (`spectre report`); o cache de resultados já não os serve.

- **i18n restante:** seções detalhadas do `--verbose` (`cli/display.py`: tabela, painéis
  USERNAME SUMMARY / PUBLIC MENTIONS / DISCOVERY GAIN / INTELLIGENCE SUMMARY / IDENTITY
  CORRELATION / Scoring), saída genérica dos demais comandos (`email`, `domain`, `ip`, `url`,
  `hash`, `company`, `person`, `threat`, `wayback`, `investigate` não-username), `auth`,
  `cache`, `case`, `providers`, `report`, mensagens de erro de `_cli_fail`, o
  `CliProgressReporter` do modo verbose e os textos de `--help` do Typer.
- **Logs com dados do alvo (pré-existente, agora só no arquivo):** `core/http_client.py`
  registra `url=%s` (URL de perfil contém o username) em avisos de timeout/TLS/HTTP;
  `core/pipeline.py` registra o valor do pivô (`Pivot failed for %s`) e `str(exc)` das
  coletas opcionais de e-mail/website. Viola o invariante "logs sem dados do alvo";
  trocar por host/classe da exceção — **agendado para o próximo PR**.
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

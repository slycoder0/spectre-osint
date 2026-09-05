# Changelog

All notable changes to SPECTRE OSINT are documented here.

The format is based on Keep a Changelog.

## [Unreleased]

### Added
- **Contrato validado de campo observado (B2-03A):** `spectre_osint/modules/username/observed.py`
  introduz `ObservedField`, o container `ObservedFields` e o parser `parse_observed()`,
  validando com Pydantic (`extra="forbid"`) o que o enriquecimento de perfis escreve em
  `Finding.data["observed"]`;
- `enrich_profile()` passa a construir e validar cada observação como `ObservedField`
  internamente e serializa para o mesmo mapeamento JSON de sempre — `Finding.data["observed"]`
  continua sendo o transporte, e consumidores que leem apenas `value`, `original`, `source`
  e `observed_at` não mudam;
- chaves aditivas de proveniência, omitidas quando desconhecidas: `provider_slug` (o `slug`
  declarado pelo catálogo, nunca re-derivado do nome de exibição), `source_method`
  (`INPUT` / `JSON_API` / `HTML` / `AUTHENTICATED_PUBLIC` / `DERIVED`), `source_url` (a URL
  efetivamente lida, **proibida em `INPUT`**), `derived_from` (`personal_domain` a partir de
  `website`) e `rejected_by` — metadado **de campo** (`ObservedField`), reservado para
  B2-03B e **nunca emitido** em B2-03A;
- **proveniência exata por item em campos de lista:** `ObservedItem` e a chave `items`
  registram qual extrator observou cada membro de `social_links` / `external_links`. Um
  extrator posterior acrescenta itens e nunca reescreve a proveniência dos anteriores, e o
  mesmo valor observado por duas origens aparece uma vez em `value` e duas em `items`;
- quando os itens de uma lista têm origens diferentes, o nível da linha passa a declarar
  `source: "multiple"` e `source_method: "MIXED"` em vez de nomear o último extrator —
  **a única alteração de string de `source` neste marco**. Observações escalares e listas
  de origem única mantêm suas strings byte a byte idênticas;
- uma linha que carrega `items` é rejeitada na validação se contradisser a projeção que
  esses itens produzem, para que a leitura legada (`value` / `source`) e a leitura exata
  (`items`) nunca divirjam;
- `MIXED` é recusado em um item e em uma linha sem `items`: só `INPUT`, `JSON_API`,
  `HTML`, `AUTHENTICATED_PUBLIC` e `DERIVED` (`EXTRACTION_METHODS`) descrevem uma
  aquisição real;
- `MIXED` fica reservado para **dois ou mais métodos conhecidos e distintos** entre os
  itens. Se o método de qualquer item for desconhecido, a linha **omite** o método em vez
  de declarar `MIXED`: proveniência desconhecida não prova uma segunda origem de
  aquisição;
- `value` e `original` precisam usar a **mesma forma** — ambos escalares ou ambos listas —
  e, quando são listas, a **mesma cardinalidade**. As duas uniões eram validadas de forma
  independente, e nem um `value` escalar com `original` em lista nem duas listas de
  tamanhos diferentes (`["a", "b"]` com `["raw-a"]`) permitem associar cada valor
  normalizado ao seu texto de origem. Linhas legadas seguem válidas em qualquer uma das
  duas formas, desde que suas próprias listas casem; ordem, deduplicação e normalização
  não mudam;
- `derived_from` e `DERIVED` passam a concordar nos dois sentidos, na linha e no item:
  uma observação derivada precisa nomear sua origem, e só uma observação derivada pode
  nomear uma. O token não é interpretado, apenas exigido não vazio — uma origem presente
  vazia ou só com espaços em branco é **recusada**, nunca aparada, e um token válido nunca
  é reescrito;
- uma linha **agregada** cujos itens são todos `DERIVED` mas nomeiam origens **diferentes**
  mantém `source_method: DERIVED` e **omite** `derived_from`, deferindo as origens exatas
  a `items`: cada item prova o método, nenhuma origem única descreve a lista, e nomear a de
  um item para todos seria falso. A exceção vale só para a linha com `items` e só quando a
  projeção dos próprios itens também omite a origem; item, linha escalar e linha sem
  `items` seguem obrigados a nomear a sua;
- `source: "multiple"` exige `items`, como já valia para `MIXED` sem itens: o marcador diz
  que a proveniência autoritativa está nos itens, e sem eles não aponta para nada. Apenas
  o marcador reservado participa da regra;
- `source: "multiple"` é **de linha, e só de linha**: um `ObservedItem` não pode declará-lo,
  como já não pode declarar `source_method: MIXED`. Um item é um dos membros que o marcador
  manda inspecionar, e um único item marcado assim fazia a projeção declarar uma linha
  `"multiple"` sem heterogeneidade de extrator alguma provada. Só a string reservada exata
  é recusada;
- `rejected_by` é metadado **de campo**, e apenas de campo: `ObservedItem` não tem a
  chave, e um item serializado que a traga é recusado na validação (`extra="forbid"`),
  para que a lista de compatibilidade `value` não possa expor um item como aceito
  enquanto a proveniência desse mesmo item se diz rejeitada. **B2-03A não passa a
  registrar rejeições** e não introduz semântica de rejeição por item;
- uma observação `INPUT` não pode declarar `source_url`, nem na linha nem em um item:
  entrada do operador não veio de página alguma, e `source_method` / `source_url` eram
  tipados de forma independente, o que permitia registrar **proveniência de rede
  fabricada** dentro do contrato validado. O invariante passa a ser validado no modelo,
  em `ObservedField` e em `ObservedItem`. As origens reais de rede seguem carregando a
  URL, e **a extração não mudou**: `enrich_profile()` já emitia `INPUT` sem URL;
- `spectre_osint/modules/username/engine.py` passa o `AccessMode` e a `effective_url` que já
  possuía, para que uma observação vinda de sessão autenticada-pública seja atribuída como
  tal em vez de indistinguível de HTML anônimo — sem alterar comportamento de autenticação;
- linhas gravadas antes do contrato continuam legíveis: as quatro chaves originais bastam e
  um `observed_at` sem fuso é interpretado como UTC. **Sem migração de banco**
  (`Finding.data` já é coluna JSON) e sem alteração de quais valores são aceitos, rejeitados
  ou pontuados — as strings de `source` existentes seguem byte a byte idênticas, e a
  correlação de identidades ainda não usa o modelo como autoridade (escopo de B2-03B).

### Changed
- **Site Catalog identity is now explicit (B2-02B):** all 57 production entries in
  `spectre_osint/data/sites.yaml` declare a stable `slug`, and loading the bundled
  production catalog rejects an entry that omits or blanks it instead of deriving one
  from the display name;
- display names are presentation labels only: renaming a provider no longer moves
  its stable identifier;
- production catalog validation inspects the *declared* slug before model
  normalization, so leading/trailing whitespace (`" github "`) and uppercase
  (`GitHub`) are rejected rather than silently rewritten, alongside missing, blank,
  malformed (outside `^[a-z0-9_]+$`) and duplicate values — each with a diagnostic
  naming the site and field;
- every declared slug is the identifier the entry already resolved to, so no
  effective provider identifier changed and no provider behavior changed;
- `slugify_name()` is retained as a compatibility fallback for custom and legacy
  definitions, reachable through `SiteCatalog.from_dict()`,
  `SiteCatalog.from_yaml_file()`, `SiteDefinition.model_validate()`, and
  `load_catalog()` / `load_sites()` for any path that is not the bundled catalog;
- `load_catalog()` and `load_sites()` accept `require_explicit_slug`: the default
  resolves the contract from the target — strict for the bundled production catalog,
  lenient for a custom path, preserving pre-B2-02B behavior for existing
  `load_sites(custom_path)` callers — and `True` / `False` state it deliberately;
- the in-memory catalog cache is keyed by path *and* validation mode, so a
  leniently loaded catalog can never be served to a strict caller.

### Removed
- **BREAKING:** the deprecated `spectre web` and `spectre dashboard` commands were
  removed; invoking either now fails as an unknown command with a non-zero exit;
- the legacy web runtime `spectre_osint/web/` was deleted (FastAPI application,
  Jinja2 templates, static assets, bundled fonts, i18n catalogs, in-memory job
  runner and the dashboard graph view);
- dashboard-only configuration retired with no compatibility aliases:
  `SPECTRE_WEB_HOST` / `Settings.web_host`, `SPECTRE_ALLOW_PUBLIC_BIND` /
  `Settings.allow_public_bind`, and the `spectre doctor` "Bind address" check;
- web-only runtime dependencies dropped: `fastapi`, `starlette`,
  `uvicorn[standard]`, `python-multipart`;
- container plumbing that only served the dashboard removed (`EXPOSE 8000`, the
  published loopback port and the `command: ["web", ...]` compose override).

### Documentation
- documentation consolidated into a single MkDocs Material site (`mkdocs.yml`), with
  PT-BR as the canonical language and the previous paths kept as redirect stubs;
- CLI reference, configuration reference and evidence/provenance semantics aligned
  with the current runtime behavior;
- `docs` optional-dependency group added (`mkdocs`, `mkdocs-material`,
  `pymdown-extensions`) and the generated `site/` directory ignored by git;
- command, configuration, architecture, contributing and security docs updated for
  the post-removal state.

### Notes
- SPECTRE is CLI-first: investigations run from the CLI and are reviewed through
  the standalone single-file HTML/JSON/Markdown/CSV/GraphML report artifacts;
- `SPECTRE_SSRF_ENABLED` and `SPECTRE_ALLOW_PRIVATE_TARGETS` are unchanged — they
  govern outbound request safety, not a listening socket;
- evidence, scoring, correlation, provider and pipeline semantics are unchanged;
- `docs/technical/legacy-web.md` is kept as the historical removal record.

## [0.1.0b1] - 2026-08-27

### Reliability / resilience
- deterministic TLS verification failures no longer consume retries;
- repeated host-level outages fail fast within the same investigation;
- new investigations start with fresh host resilience state.

### Evidence quality
- generic platform branding/marketing titles are rejected as identity evidence;
- generic pages no longer become LIKELY from weak boilerplate-only signals.

### Progress / workstation
- factual structured investigation progress events;
- CLI displays real investigation phases;
- Web collecting screen displays live factual phases and degraded providers;
- no fabricated percentages for unknown workloads.

### Platform compatibility
- Windows/POSIX tests made portable without weakening POSIX assertions;
- WSL -> Windows Chrome path normalization improved;
- native Windows suite reached 475 passed / 0 failed.

### Documentation
- README redesigned as compact public landing page;
- full EN and PT-BR documentation paths;
- deeper documentation split into focused clickable guides.

### Release hardening
- dependency/security preflight passed;
- artifact/secret audit passed;
- doctor reports ready with optional features missing.

### Notes
- `0.1.0b1` validated on CI (Python 3.12 / 3.13) and Windows native; tagged as the
  annotated tag `0.1.0b1` and pushed to `origin`.

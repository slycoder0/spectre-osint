# SPECTRE OSINT — guia para agentes

CLI de OSINT passive-first em Python (Typer + httpx + Pydantic v2 + SQLAlchemy/SQLite).
Ponto de entrada: `spectre = spectre_osint.main:app`. Versão em `spectre_osint/__init__.py`.

Leia antes de mexer: `docs/technical/architecture.md`, `docs/technical/testing.md`,
`CONTRIBUTING.md`. Auditoria e roadmap atuais: `docs/audit/2026-11-05-auditoria.md`.
**Estado atual (fase, próximos passos, portões, follow-ups): `docs/audit/STATUS.md` — leia
primeiro depois de um `/clear`.**

## Ambiente (Windows, PowerShell)

```powershell
py -3.13 -m venv .venv        # CI testa 3.12 e 3.13; 3.14 NÃO é suportado
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Portões obrigatórios (os mesmos da CI)

```bash
pytest -q                       # ~900 testes, ~90 s, 100% offline
ruff check spectre_osint tests
mypy spectre_osint
pip check
pip-audit                       # falha a CI se houver CVE
```

Se `pytest` falhar com `PermissionError` no diretório temporário, rode com
`--basetemp=<pasta gravável>`. Nunca diga que algo passou sem ter rodado o comando.

## Invariantes que não podem quebrar

- HTTP 200 sozinho nunca é `CONFIRMED`. Mesmo username nunca é mesma pessoa.
- Entrada do operador (`--name`, `--email`) nunca vira evidência observada.
- Candidato de busca/menção nunca vira perfil `CONFIRMED`/`LIKELY`.
- `WEIGHTS`, `CONFLICTS`, `BANDS`, `CLUSTER_MIN` em `modules/username/identity.py` são
  congelados por testes. Só mudam num marco explícito (B2-04), com justificativa e
  regressões.
- Se `Finding.data["observed"]` existe, ele é a autoridade (lido via `read_observed()`
  em `modules/username/observed.py`); chaves de nível superior são só compatibilidade.
- Logs e avisos nunca podem conter dados do alvo (chaves de payload, `str(exc)` de
  validação, URLs com PII). Use `core/redaction.py`.
- Logs nunca contêm dados do alvo — o teste canário `tests/test_logs_no_target_data.py` é o
  guarda. Registre provider, status, contagens e `exc_label(exc)`; para correlacionar use
  `target_ref()` / `host_ref()` (nunca o valor, nem o host quando ele é o alvo).
- Mudou o formato do que é cacheado → suba `RESULT_SCHEMA_VERSION` em `core/result_cache.py`.
- Toda requisição sai pelo `HttpClient` com a política SSRF (`core/ssrf.py`).
- Nada de CAPTCHA solving, stealth, proxy rotation, scraping de conteúdo privado.
- Fixtures sintéticas (`alice_osint`, `Alice Example`); testes nunca dependem de rede.
- Nunca commitar `.env`, `*.db`, cookies, perfis de navegador ou relatórios reais.

## Fluxo de trabalho

- Um marco por branch/PR (`feat/<id>-<slug>`, `fix/<id>-<slug>`), commits convencionais.
- TDD: teste de regressão primeiro, depois a correção.
- `CHANGELOG.md` → seção `[Unreleased]`; entradas curtas (o que muda para o usuário),
  detalhes de design vão na descrição do PR.
- Não crie tag, não faça push, não abra release sem pedido explícito do usuário.

## Protocolo de fim de fase

- Todo PR de fase atualiza `docs/audit/STATUS.md` (fase atual, feito, próximo, portões,
  decisões em aberto, follow-ups).
- Ao abrir o PR de uma fase, termine a resposta com um bloco **FIM DE FASE** de 5 linhas:
  1. o que mudou; 2. o que falta; 3. saída real dos portões; 4. riscos; 5. follow-ups.
- Depois do bloco, lembre o usuário de dar `/clear` antes da próxima fase.

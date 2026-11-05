# STATUS — retomada do SPECTRE

Arquivo vivo. **Atualize em todo PR de fase.** É o ponto de partida depois de um `/clear`.
Roadmap e achados: [`2026-11-05-auditoria.md`](2026-11-05-auditoria.md) (seção 5).

_Última atualização: 2026-11-05 — PR da Fase 1._

## Fase atual

**Fase 1 — `fix/b2-03b2-display-name-rejection`** (A1 + B2-03B2): PR aberto, aguardando
revisão. Não mergeado.

## Feito

| Fase | Marco | PR | Estado |
| :--- | :--- | :--- | :--- |
| — | Auditoria 2026-11-05 | #14 | mergeado |
| 0 | `chore/b2-05-resume-hygiene` (Pillow `>=13,<14`, strings `0.1.0b1`, UA) | #15 | mergeado |
| 1 | `fix/b2-03b2-display-name-rejection` | aberto | em revisão |

Fase 1, em uma linha: título de página (`og:title` / `<title>`) não vira mais nome ativo;
fica em `observed` com `rejected_by="page_title_unverified"`. Exceção única: `og:title` do
Instagram com `(@handle)` exato. Detalhes em `docs/technical/enrichment.md` (B2-03B2).

## Próximo

**Fase 2 — `fix/b2-06-discovery-page-chrome`** (A2): links de rodapé/navegação e contas
oficiais da própria plataforma não viram links de perfil nem pivôs.

## Últimos resultados dos portões (branch da Fase 1, 2026-11-05)

```text
pytest -q        923 passed in 84.20s
ruff check       All checks passed!
mypy             Success: no issues found in 125 source files
pip check        No broken requirements found.
pip-audit        No known vulnerabilities found
```

Ao vivo (`spectre username torvalds`, diretórios isolados): `Observed name  Linus Torvalds, Hemant`.
Os dois vêm de API JSON (`github_api.name`, `hugging_face_api.fullname`). "Hemant" é o nome
público real da conta `torvalds` no Hugging Face — mesmo username, outra pessoa, como esperado.

## Decisões em aberto

- Quando cortar o `0.1.0b2` (Fase 8) — depois da Fase 3 ou só no fim do roadmap.

## Follow-ups registrados

- **Fallbacks brutos de nível superior no motor** (`engine.py`, caminho HTML anônimo):
  `bio = ... or description`, `avatar_url = ... or avatar`, `website = ... or website` ainda
  copiam metadados brutos da página para `Finding.data` (e portanto para o relatório JSON).
  Não são evidência quando `observed` existe (B2-03B1), mas são a mesma classe de defeito
  que a Fase 1 corrigiu para `display_name` / `public_name`.
- **Originais brutos por item de lista** (parte adiada de B2-03B2): não muda o que o usuário vê.
- `page_title` (finding) e `title` (evidência) guardam o título bruto **com rótulo honesto**;
  não é defeito, só registro.

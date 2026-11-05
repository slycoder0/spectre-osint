# Auditoria independente — SPECTRE OSINT

**Data:** 2026-11-05 · **Commit auditado:** `2422c97` (main, merge do PR #13) · **Versão:** `0.1.0b1` (tag) + `[Unreleased]` rumo a `0.1.0b2`

---

## 1. Resumo executivo

O projeto está **saudável e funcional**, mas **parado no meio de um marco interno** e com
**prioridades desalinhadas**: as últimas duas semanas de trabalho foram gastas endurecendo um
contrato de dados interno até o nível de microssegundos de fuso horário, enquanto defeitos
que o usuário vê na primeira execução continuam abertos.

| Item | Estado |
| :--- | :--- |
| Instalação (`pip install -e ".[dev]"`, Python 3.13) | OK |
| `spectre doctor` | `READY WITH OPTIONAL FEATURES MISSING` |
| Testes | **897 passando**, 0 falhas (~95 s, offline) |
| Cobertura | **77 %** de branches no total, mas muito desigual (seção 4) |
| `ruff` / `mypy` / `pip check` | limpos |
| `pip-audit` | **FALHA — 21 CVEs no Pillow 12.3.0** (corrigidos no 13.0.0, bloqueado por `Pillow<13`). A próxima execução da CI na `main` vai ficar vermelha. |
| CI no GitHub | verde na última execução (06/set), antes desses CVEs saírem |
| Smoke test ao vivo (`spectre username torvalds`) | roda de ponta a ponta e gera os 5 relatórios, mas com problemas de qualidade (seção 3) |

**De onde você parou:** marco **B2-03B1** concluído e mergeado (PR #13, 05/set/2026).
Os próximos marcos que você mesmo deixou declarados são **B2-03B2**, **B2-03B3** e **B2-04**.
Nenhum foi iniciado. Não existe branch aberta nem trabalho sem commit.

---

## 2. Histórico reconstruído

O projeto inteiro foi construído em ~8 dias (29/ago → 05/set/2026): 67 commits, 13 PRs,
todos mergeados. Revisão feita pelo Codex nos PRs.

| Marco | O que entregou | PR | Estado |
| :--- | :--- | :--- | :--- |
| 0.1.0b1 | beta público inicial (tag) | — | lançado 27/ago |
| B2-01B/C/D | segurança de alias de entrada, higiene de config/encoding | — | feito |
| Site Catalog 2.0 (B2-02A) | catálogo `sites.yaml` validado por esquema Pydantic | #1 | feito |
| Contratos JSON | contratos de identidade para providers JSON (flat/nested) | #3, #4 | feito |
| Docs | reforma completa da documentação (MkDocs, PT-BR canônico) | #5 | feito |
| Remoção do web legado | `spectre web`/`dashboard` removidos; produto é CLI-first | #6 | feito |
| B2-02B | slugs explícitos para as 57 entradas do catálogo | #7 | feito |
| B2-03 (fixes) | sem inflação de score com uma observação; identidade exata de URL | #8, #9 | feito |
| B2-03A | contrato validado `ObservedField` / `ObservedItem` | #10 | feito |
| B2-03B0 | comparação por instante; parser total; bug CPython 3.12 de fuso subsegundo | #11, #12 | feito |
| B2-03B1 | consumidores tratam `observed` como autoridade; logs sem PII | #13 | **feito — último** |
| **B2-03B2** | produtor passa a emitir `rejected_by`; originais brutos por item | — | **não iniciado** |
| **B2-03B3** | explicação item-exata de `cross_profile_link` | — | **não iniciado** |
| **B2-04** | recalibrar `WEIGHTS`/`CONFLICTS`/`BANDS`/`CLUSTER_MIN`, clusterização | — | **não iniciado** |
| 0.1.0b2 | release (bump, changelog, tag) | — | **não feito** |

---

## 3. Achados — o que o usuário vê (smoke test ao vivo)

Execução real de `spectre username torvalds` em 2026-11-05: 57 sites, 5 CONFIRMED,
11 LIKELY, 16 NOT_FOUND, 9 BLOCKED, 8 LOGIN_REQUIRED, 6 INCONCLUSIVE, 1 RATE_LIMITED,
1 PROVIDER_UNAVAILABLE.

### A1 — Título da página vira "nome observado" (ALTA)
O fallback de HTML (`enrichment.py`, `og:title` → `<title>`) usa uma lista fixa de sufixos
por site (`_TITLE_SUFFIXES`) que não cobre o catálogo. Resultado real:

| Site | `display_name` gravado | Fonte |
| :--- | :--- | :--- |
| Codeberg | `torvalds - Codeberg.org` | `html_title` |
| SoundCloud | `Stream Torvalds music \| Listen to songs, albums, …` | `html_title` |
| Telegram | `Contact @torvalds` | `html_title` |
| Scratch | `Imagine, Program, Share` (título genérico do site) | `html_og.title` |
| Launchpad | `Torvalds does not use Launchpad` | `html_og.title` |

**Por que importa além da estética:** a correlação aplica `distinct_display_name = -28`.
Lixo no nome gera conflito falso entre perfis que deveriam se aproximar (ex.: GitHub
"Linus Torvalds" × Codeberg "torvalds - Codeberg.org"). O "Intelligence Summary" também
exibe esse lixo como "Observed name". Isso fere diretamente a promessa central do produto
(não transformar suposição em fato).

**Encaixe com o roadmap:** é exatamente o caso de uso de **B2-03B2** — um título rejeitado
deveria ser registrado com `rejected_by` (observado e rejeitado), não silenciosamente
aceito nem silenciosamente omitido.

### A2 — Ruído de descoberta vindo do "chrome" da página (MÉDIA)
"Top discoveries" trouxe `fosstodon.org` e `https://fosstodon.org/@sourceforge` — que é a
conta oficial do **SourceForge** no rodapé da página, não do alvo — e o handle
`@agent-torvalds`. Links de navegação/rodapé da plataforma estão sendo tratados como links
do perfil e viram pivôs.

### A3 — Saúde do catálogo (MÉDIA)
- 16 de 57 sites (28 %) não deram resposta útil (BLOCKED/INCONCLUSIVE/RATE_LIMITED/UNAVAILABLE)
  — Reddit, Medium, npm, Tumblr, ArtStation, NameMC, Letterboxd, Ko-fi, CodePen, Bitbucket,
  PyPI, Kaggle, Pinterest, Steam, Mastodon, Flickr. Mais 8 são login-wall.
- Scratch marcou `LIKELY/HIGH` com o título genérico do site — suspeita de falso positivo.
- Não existe ferramenta para medir isso de forma repetível: as assinaturas de 2 meses atrás
  só são verificadas por fixtures offline, então a deriva dos sites é invisível.

### A4 — Comportamento correto que vale registrar
Hugging Face `torvalds` é outra pessoa (`Hemant`) e o sistema **não** a juntou ao GitHub
("Max pairwise score: 6 — same username is not identity"). A disciplina probatória funciona.

---

## 4. Achados — código, testes e engenharia

### B1 — CVEs de dependência quebram a CI (CRÍTICA, trivial)
`Pillow>=10.4.0,<13` → 21 CVEs, correção em `13.0.0`. `playwright<1.56` está 9 minors atrás
(1.64.1). Primeiro commit da retomada deve ser este.

### B2 — Cobertura concentrada só no username (ALTA)
Total 77 %, mas a metade "cyber" do produto praticamente não tem teste:

| Módulo | Cobertura |
| :--- | ---: |
| `modules/url/analyzer.py` | 10 % |
| `modules/metadata/extractor.py` | 13 % |
| `modules/domain/analyzer.py` | 14 % |
| `modules/threatintel/aggregator.py` | 16 % |
| `modules/ip/analyzer.py` | 17 % |
| `modules/person/analyzer.py` | 17 % |
| `modules/dns/resolver.py` | 18 % |
| `modules/email/analyzer.py` | 22 % |
| `cli/commands.py` | 38 % |
| `core/presentation.py` | 53 % |
| `core/pipeline.py` | 70 % |

Os comandos `domain`, `ip`, `email`, `url`, `hash`, `metadata` estão no README como
funcionalidades principais, mas não têm rede de segurança.

### B3 — Código morto (BAIXA)
- `modules/certificates/` — só se importa a si mesmo (0 %).
- `core/correlation.py` — não referenciado (0 %).
- `modules/files/` — pacote vazio.
- `llm/summarizer.py` — 0 %, documentado como "experimental, não conectado". Decidir: conectar
  atrás de flag ou remover.

### B4 — Excesso de engenharia e perda de foco (PROCESSO — a constatação mais importante)
- `observed.py` tem **847 linhas** para validar um dicionário de proveniência; o arquivo de
  teste do contrato tem **> 2 400 linhas**.
- Dois PRs inteiros (#11, #12) trataram de deslocamentos de fuso **subsegundo** e de um bug
  do CPython 3.12 — casos que o SPECTRE nunca produz em uso real.
- Entradas de CHANGELOG com 20–40 linhas cada; um único bullet chega a um parágrafo de
  design. O CHANGELOG tem 26 KB e é ilegível para um usuário.
- Enquanto isso, A1 (lixo como nome observado) está visível na **primeira** execução.

Recomendação: **timebox por marco** e priorizar pelo que muda o resultado que o usuário lê.
Endurecimento de contrato só quando um defeito real o justificar.

### B5 — Pontos menores
- `pyproject.toml`: descrição diz `v0.1-alpha`, classifier `Alpha`, sem `Operating System ::
  Microsoft :: Windows` embora o desenvolvimento seja no Windows; `docker-compose.yml` usa a
  tag `0.1.0-alpha`; `.env.example` usa UA `0.1-alpha`. Inconsistente com `0.1.0b1`.
- Python 3.14 (o `python` padrão desta máquina) não está na matriz; `requires-python = ">=3.12"`
  permite instalar sem testar.
- Docs com stubs de redirecionamento duplicados (`docs/ARCHITECTURE.md`, `docs/RELEASE.md`,
  `docs/*.pt-BR.md`, `docs/cli-reference*.md`).
- 24 `except Exception` em `browser/manager.py` e 14 em `core/pipeline.py` — aceitável para
  resiliência, mas vale revisar se algum engole erro de programação.
- Não havia `CLAUDE.md`/guia para agentes (criado nesta auditoria, na raiz).

### Pontos fortes (manter)
- Invariantes probatórias claras e testadas (HTTP 200 ≠ perfil; username ≠ pessoa).
- Política SSRF séria (pinagem de IP, checagem por redirect, metadata de nuvem, IPv4-mapped).
- Redação de segredos e logs sem PII; testes "canário" de segredos.
- Catálogo validado por esquema; testes 100 % offline; CI com ruff + mypy + pip-audit.

---

## 5. Roadmap recomendado

A ordem abaixo **diverge** do roadmap interno (B2-03B2 → B2-03B3 → B2-04) de propósito:
coloca primeiro o que o usuário vê e funde B2-03B2 com a correção que precisa dele.

| Fase | Marco | Conteúdo | Valor | Tamanho |
| :--- | :--- | :--- | :--- | :--- |
| 0 | `chore/b2-05-resume-hygiene` | Pillow `<14`, avaliar teto do Playwright, CI verde; commitar `CLAUDE.md` e esta auditoria; alinhar strings `alpha` → `0.1.0b1`/`b2` | desbloqueia tudo | P |
| 1 | `fix/b2-03b2-display-name-rejection` | **A1 + B2-03B2**: regra genérica para limpar/rejeitar títulos (nome do site/host do catálogo, títulos genéricos do site, frases tipo "does not use"); títulos rejeitados gravados com `rejected_by`; originais brutos por item. Fixtures sintéticas reproduzindo os 5 casos da seção 3 | alto | M |
| 2 | `fix/b2-06-discovery-page-chrome` | **A2**: links de rodapé/navegação e contas oficiais da própria plataforma não viram links de perfil nem pivôs | alto | M |
| 3 | `feat/b2-07-catalog-health` | **A3**: comando/script opt-in (fora da CI) que roda handles conhecidos presente/ausente por site e reporta deriva; corrigir assinaturas quebradas e o falso positivo do Scratch | alto | M |
| 4 | `feat/b2-03b3-item-link-explanation` | B2-03B3 como planejado, **timeboxed** | médio | P/M |
| 5 | `feat/b2-04-scoring-calibration` | B2-04 **só com um conjunto de avaliação rotulado** (sintético) e métricas antes/depois; sem conjunto, não mexer nos pesos | médio | G |
| 6 | `test/b2-08-cyber-coverage` | testes offline para `domain`, `ip`, `dns`, `email`, `url`, `metadata`, `threatintel` (meta ≥ 70 % cada) | médio | M |
| 7 | `chore/b2-09-dead-code-docs` | remover código morto (B3), decidir o destino do `llm`, limpar stubs de docs, condensar o CHANGELOG | baixo | P |
| 8 | release `0.1.0b2` | bump, CHANGELOG, `smoke_install.sh`, `release_check.sh`; tag/push **só com sua ordem** | entrega | P |

Fases 2, 3 e 6 são independentes entre si e podem rodar em paralelo, em worktrees separadas.

---

## 6. O que você precisa ter

- **Já tem:** Git, `gh` autenticado, Python 3.13 e 3.14, Chrome, Claude Code com os plugins
  `superpowers`, `engineering` e `playwright`. O `.venv` (Python 3.13) foi criado nesta
  auditoria e já tem as dependências de dev.
- **Recomendado:** instalar Python 3.12 (a CI testa 3.12 e há código específico para um bug
  do 3.12): `py install 3.12` ou `winget install Python.Python.3.12`.
- **Não precisa:** chaves de API pagas, SearXNG, sessões autenticadas — tudo é opcional e os
  testes são offline. Nenhum plugin novo é obrigatório.

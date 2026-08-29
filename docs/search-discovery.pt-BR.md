# Inteligência de Busca e Motor de Descoberta

[English](search-discovery.md) | [Português 🇧🇷](search-discovery.pt-BR.md)

O motor de inteligência de busca do SPECTRE (`modules/search/`) vai muito além de simples consultas de busca (Dorks). Ele gera consultas determinísticas, descobre URLs de perfis candidatos, extrai novos indicadores com proveniência explícita, classifica a novidade dos achados e orça pivots de aprofundamento sem poluir o dossiê com domínios de plataformas redundantes.

---

## O Pipeline de Inteligência de Busca

Para investigações de username, o motor executa etapas sequenciais estruturadas:

```mermaid
flowchart LR
    Planner[1. Planejador de Busca] --> Search[2. Provedores de Busca]
    Search --> Discover[3. Motor de Descoberta]
    Discover --> Extract[4. Extrator de Indicadores]
    Extract --> Novelty[5. Classificador de Novidade]
    Novelty --> Pivot[6. Motor de Pivots]
    Pivot --> Summary[7. Sumário de Inteligência]
```

### Detalhamento das Etapas

| Etapa | Módulo | Função |
| :--- | :--- | :--- |
| **1. PLANNER** | `planner.py` | Gera consultas determinísticas e focadas a partir das pistas fornecidas e handles encontrados. |
| **2. SEARCH** | `providers.py` | Consulta endpoints públicos: DuckDuckGo HTML, Hacker News, Reddit, GitHub, SearXNG local opcional e Google CSE opcional. |
| **3. DISCOVER** | `discover.py` | Identifica URLs candidatas a perfis. **Candidatos nunca são promovidos a perfis CONFIRMED automaticamente.** |
| **4. EXTRACT** | `extract.py` | Extrai indicadores acionáveis (handles, emails, domínios, links sociais) com tags de regras de extração (`extraction_rule`). |
| **5. NOVELTY** | `novelty.py` | Categoriza indicadores por novidade para priorizar achados inéditos e evitar pivots redundantes. |
| **6. PIVOT** | `pivots.py` | Gera desdobramentos orçados (`SPECTRE_SEARCH_MAX_PIVOTS=25`, profundidade máxima 2). |
| **7. SUMMARY** | `summary.py` | Produz sumários determinísticos de inteligência e métricas de ganho de descoberta (*discovery gain*). |

---

## Classificações de Novidade (Novelty)

Para evitar consumir orçamento de busca com domínios genéricos de plataformas ou re-pesquisar dados já conhecidos, os indicadores são classificados em 6 estados de novidade:

| Classificação | Significado | Prioridade de Pivot |
| :--- | :--- | :--- |
| `OPERATOR_INPUT` | Valor fornecido explicitamente pelo operador na CLI ou GUI (`--alias`, `--email`, etc.). | Ignorado (pista já conhecida). |
| `KNOWN` | URL ou handle correspondente a um achado prévio da varredura de catálogo. | Ignorado (já verificado). |
| `OBSERVED` | Observado diretamente no conteúdo de um perfil extraído. | Qualificado para enriquecimento. |
| `DERIVED` | Extraído de metadados estruturados de perfil (`rel="me"`, bio, contato público). | Alta prioridade. |
| `NOVEL` | Indicador público inédito, não presente nos inputs do operador nem no catálogo inicial. | Prioridade máxima. |
| `REDUNDANT` | Pertence a hosts de plataformas padrão (`github.com`, `instagram.com`, `x.com`) que não devem consumir orçamento de pivot de domínio. | Suprimido para pivots de domínio. |

---

## Exceção para Hubs de Links (Link Hubs)

Plataformas sociais padrão são marcadas como `REDUNDANT` para evitar que o SPECTRE gaste consultas descobrindo `github.com` ou `instagram.com` como se fossem domínios pessoais.

No entanto, **plataformas agregadoras de links (Link Hubs)** são tratadas explicitamente como alvos prioritários de pivot:
- `linktr.ee`
- `beacons.ai`
- `about.me`
- `carrd.co`
- `bio.link`
- `bento.me`

Quando um link hub é descoberto, ele recebe prioridade alta de extração para revelar blogs pessoais, portfólios e identidades secundárias interligadas.

---

## Orçamento de Busca e Controle de Taxa

O motor de busca respeita limites operacionais estritos configurados em `core/config.py`:
- `SPECTRE_SEARCH_QUERY_BUDGET` (Padrão: `12`): Máximo de consultas de busca distintas por execução.
- `SPECTRE_SEARCH_MAX_PIVOTS` (Padrão: `25`): Máximo de pivots de descoberta gerados.
- `SPECTRE_SEARCH_MAX_DEPTH` (Padrão: `2`): Limite de profundidade recursiva para pivots.

Esses controles garantem finalização rápida, respeito a rate limits e máxima densidade probatória nos relatórios.

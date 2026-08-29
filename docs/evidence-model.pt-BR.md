# Modelo de Evidências e Invariantes do SPECTRE

[English](evidence-model.md) | [Português 🇧🇷](evidence-model.pt-BR.md)

O SPECTRE é construído sobre limites probatórios rigorosos. Ele trata investigações digitais com integridade técnica e honestidade: **os dados públicos observados são registrados com fidelidade, a proveniência é preservada e a identidade nunca é presumida.**

---

## Invariantes Probatórios Fundamentais

As seguintes regras são fixadas na arquitetura e não podem ser violadas:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                      INVARIANTES PROBATÓRIOS FUNDAMENTAIS                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Mesmo username ≠ Mesma pessoa (reutilização de handle não prova identity) │
│  2. HTTP 200 isolado ≠ Status CONFIRMED (exige marcadores de perfil real)    │
│  3. Entrada do operador ≠ Evidência observada (pistas são mantidas distintas)│
│  4. Candidato de busca ≠ Perfil confirmado (descobertas não viram CONFIRMED)│
│  5. AUTHENTICATED_PUBLIC ≠ Acesso privado (sessão própria em páginas abertas)│
│  6. NOT_FOUND ≠ Conta inexistente (significa apenas ausência na URL checada) │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Classificações de Status do Catálogo

Quando o SPECTRE consulta plataformas públicas em `data/sites.yaml`, cada provedor produz um `UsernameCheckStatus` determinístico:

| Status | Significado | Interpretação Probatória |
| :--- | :--- | :--- |
| `CONFIRMED` | Marcadores específicos de perfil confirmados com precisão. | Presença de perfil público verificada. **Não** confirma identidade civil. |
| `LIKELY` | Fortes indícios públicos encontrados, sem âncora definitiva. | Presença provável. Requer validação do operador. |
| `INCONCLUSIVE` | Página carregada mas conteúdo ambíguo ou com desafio anti-bot. | Achado inconclusivo. Nenhuma suposição de identidade é feita. |
| `NOT_FOUND` | Retornou 404 padrão ou indicador de conta inexistente. | Perfil não observado na URL pesquisada. |
| `BLOCKED` | WAF, Cloudflare ou filtro de borda bloqueou a requisição. | Plataforma inacessível. O SPECTRE não burla filtros. |
| `LOGIN_REQUIRED` | Plataforma exige login para exibir o conteúdo do perfil. | Perfil murado. Pode ser visto via `AUTHENTICATED_PUBLIC`. |
| `RATE_LIMITED` | HTTP 429 recebido ou cota da plataforma excedida. | Limite temporário. Backoff sem rotação de IP. |
| `OBSERVED` | Menção ou referência pública indexada encontrada na busca. | Menção pública. **Nunca** promovida a `LIKELY`/`CONFIRMED`. |
| `NOT_CONFIGURED` | Chave de API opcional ou SearXNG não configurado. | Provedor ignorado. A investigação continua normalmente. |
| `PROVIDER_UNAVAILABLE`| Timeout de rede ou falha determinística após retentativas. | Fonte indisponível. A investigação continua com as demais fontes. |

---

## Entrada do Operador vs. Proveniência Observada

O SPECTRE mantém distinção absoluta entre o que o investigador digita e o que foi de fato observado na web pública:

- **Entrada do Operador (`source="user"`):**
  - Username alvo, `--alias`, `--name`, `--email`, `--website`.
  - Tratados como hipóteses e pistas de pesquisa.
  - Armazenados com `confidence=CONFIRMED` apenas no sentido semântico de *"este é o alvo declarado pelo operador"*, nunca como prova de identidade real.
- **Evidência Observada (`source="observed"` / `source="platform"`):**
  - Títulos, biografias, URLs de avatar, links externos (`rel="me"`), emails públicos extraídos de perfis.
  - Carregam proveniência imutável detalhando URL, plataforma e regra de extração.
  - Títulos genéricos de plataformas (ex.: `"TryHackMe | Cyber Security Training"`) são rejeitados e removidos do sumário de identidade.

---

## Correlação Conservadora de Identidades

O motor de correlação de identidades (`modules/username/identity.py`) correlaciona pares de perfis confirmados e prováveis:

1. **Pesos Fixos e Conservadores:** Pesos determinísticos são atribuídos a atributos compartilhados (hash de avatar, links sociais verificados, handles bio exclusivos, emails idênticos).
2. **Mesmo Username como Sinal Fraco:** O mero compartilhamento de um mesmo handle entre plataformas é considerado um sinal fraco, evitando agrupamentos falso-positivos.
3. **Detecção de Conflitos:** Divergências biográficas explícitas penalizam o score de correlação.
4. **Faixas de Sobreposição Pública (Bands):**
   - `LOW` (Score < 30): Sobreposição pública fraca.
   - `POSSIBLE` (Score 30–59): Sobreposição pública possível.
   - `LIKELY` (Score 60–84): Sobreposição pública provável.
   - `STRONG` (Score >= 85): Sobreposição pública forte.

---

## Modelo de Pontuação

O motor de pontuação (`core/scoring.py`) calcula confiança, indicadores de risco e pegada pública para a investigação atual:
- **Pontuação de Confiança:** Baseada exclusivamente em evidências verificadas e links fortes de correlação.
- **Indicadores de Risco:** Sinais como exposição em vazamentos conhecidos, histórico de infraestrutura ou menções de segurança.
- **Métricas de Pegada Digital:** Amplitude de presença pública observada entre domínios e redes.

Artefatos, banco de dados SQLite e relatórios HTML permanecem armazenados estritamente no seu disco local.
